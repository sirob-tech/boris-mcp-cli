package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type fakeMCP struct {
	tools      []tool
	callResult []byte
	// github serves the update endpoints. Left nil, any GitHub request is a
	// hard test failure rather than a silent trip to the real network — which
	// is what makes the "tool calls never check for updates" tests meaningful.
	github         *fakeGitHub
	githubRequests int
	// listCalls counts tools/list round trips. A degraded server must not be
	// asked more than once per command, so the count is the assertion.
	listCalls int
	// pageSize > 0 makes tools/list paginate, the way a compliant MCP server is
	// free to. cursorFor overrides the cursor a page advertises, so a test can
	// hand back one that never terminates.
	pageSize  int
	cursorFor func(next int) string
	// malformedPageAt is the 1-based tools/list page that answers with a
	// well-formed JSON-RPC success carrying no tools array at all.
	malformedPageAt int
	// staleIDPageAt is the 1-based tools/list page that answers with the id of
	// the request before it, as a server confusing two in-flight pages would.
	staleIDPageAt int
}

func (m *fakeMCP) Do(req *http.Request) (*http.Response, error) {
	if req.URL != nil && (req.URL.Host == "github.com" || req.URL.Host == "api.github.com") {
		m.githubRequests++
		if m.github == nil {
			return nil, fmt.Errorf("unexpected GitHub request: %s", req.URL)
		}
		return m.github.Do(req)
	}
	// Guarded because a HEAD carries no body, and io.ReadAll(nil) panics.
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	var rpc jsonRPCRequest
	_ = json.Unmarshal(body, &rpc)
	header := http.Header{"Content-Type": {"application/json"}}
	respond := func(payload string) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(payload))}, nil
	}
	switch rpc.Method {
	case "initialize":
		return respond(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"test","version":"0"}}}`)
	case "notifications/initialized":
		return respond("")
	case "tools/list":
		m.listCalls++
		if m.malformedPageAt == m.listCalls {
			env, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": rpc.ID, "result": json.RawMessage(`{}`)})
			return respond(string(env))
		}
		page := m.tools
		result := map[string]any{}
		if m.pageSize > 0 {
			var params struct {
				Cursor string `json:"cursor"`
			}
			_ = json.Unmarshal(rpc.Params, &params)
			start := 0
			if params.Cursor != "" {
				// Tolerant: a test driving cursorFor hands back opaque values it
				// never expects the server to interpret.
				if _, err := fmt.Sscanf(params.Cursor, "offset-%d", &start); err != nil || start < 0 || start > len(m.tools) {
					start = 0
				}
			}
			end := start + m.pageSize
			if end > len(m.tools) {
				end = len(m.tools)
			}
			page = m.tools[start:end]
			if next := m.cursorFor; next != nil {
				result["nextCursor"] = next(end)
			} else if end < len(m.tools) {
				result["nextCursor"] = fmt.Sprintf("offset-%d", end)
			}
		}
		toolsOut := make([]map[string]any, 0, len(page))
		for _, t := range page {
			toolsOut = append(toolsOut, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": json.RawMessage(nonEmptySchema(t.InputSchema)),
			})
		}
		result["tools"] = toolsOut
		payload, _ := json.Marshal(result)
		// Echoing the request id, as JSON-RPC requires. A hardcoded id passed
		// only because nothing checked it, which made the fake unable to notice
		// a client that mismatched pages against responses.
		id := rpc.ID
		if m.staleIDPageAt == m.listCalls {
			id--
		}
		env, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": json.RawMessage(payload)})
		return respond(string(env))
	case "tools/call":
		env, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": rpc.ID, "result": json.RawMessage(m.callResult)})
		return respond(string(env))
	}
	return respond(`{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"unexpected"}}`)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}

type failingDoer struct{}

func (failingDoer) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func staticCreds() credentialsFunc {
	return func(context.Context, effectiveConfig) (aws.Credentials, string, error) {
		return aws.Credentials{AccessKeyID: "AKIATEST", SecretAccessKey: "secret", Source: "test"}, "us-east-1", nil
	}
}

func TestValidateURL(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		allowHTTP bool
		wantErr   bool
	}{
		{name: "https", raw: "https://example.agentcore.aws/mcp"},
		{name: "localhost", raw: "http://localhost:8080/mcp"},
		{name: "loopback", raw: "http://127.0.0.1:8080/mcp"},
		{name: "plain http rejected", raw: "http://example.com/mcp", wantErr: true},
		{name: "plain http allowed", raw: "http://example.com/mcp", allowHTTP: true},
		{name: "missing", raw: "", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateURL(tc.raw, tc.allowHTTP)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestInitParsesPostCommandFlags(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BMCP_HOME", home)
	t.Setenv("HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{},
		credentials: staticCreds(),
		lookPath:    func(string) (string, error) { return "", os.ErrNotExist },
	}
	code := a.run([]string{"init", "--url", "http://localhost:8787/mcp"})
	if code != 0 {
		t.Fatalf("init exit code %d, stderr: %s", code, stderr.String())
	}
	cfg, err := readConfig(filepath.Join(home, "config.toml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if cfg.URL != "http://localhost:8787/mcp" {
		t.Fatalf("url mismatch: %q", cfg.URL)
	}
}

func TestInitPromptSaysAWSProfileIsOptional(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BMCP_HOME", home)
	t.Setenv("HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader("\n\n"),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{},
		credentials: staticCreds(),
		lookPath:    func(string) (string, error) { return "", os.ErrNotExist },
	}
	code := a.run([]string{"init", "--url", "http://localhost:8787/mcp"})
	if code != 0 {
		t.Fatalf("init exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "AWS profile (optional, blank uses AWS defaults)") {
		t.Fatalf("prompt should explain optional profile, got: %s", stderr.String())
	}
}

func TestMissingConfigNonInteractiveFailsFast(t *testing.T) {
	t.Setenv("BMCP_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"--non-interactive", "list"})
	if code != exitConfig {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "bmcp init --url <url>") {
		t.Fatalf("missing remediation in stderr: %s", stderr.String())
	}
}

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := configFile{
		URL:            "https://example.agentcore.aws/mcp",
		AWSProfile:     "customer-dev",
		Region:         "us-east-1",
		Service:        "bedrock-agentcore",
		SyncTTL:        2 * time.Hour,
		ConnectTimeout: 3 * time.Second,
		SyncTimeout:    4 * time.Second,
		CallTimeout:    5 * time.Second,
	}
	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig: %v", err)
	}
	if got != cfg {
		t.Fatalf("config mismatch:\n got: %#v\nwant: %#v", got, cfg)
	}
}

func TestReadConfigPreservesExplicitZeroSyncTTL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	err := os.WriteFile(path, []byte(`url = "https://example.agentcore.aws/mcp"
sync_ttl = "0"
connect_timeout = "30s"
sync_timeout = "60s"
call_timeout = "10m"
`), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig: %v", err)
	}
	if cfg.SyncTTL != 0 {
		t.Fatalf("sync_ttl should remain explicit zero, got %s", cfg.SyncTTL)
	}
}

func TestShouldReadPayloadFromStdin(t *testing.T) {
	if !shouldReadPayloadFromStdin(strings.NewReader(`{"ok":true}`)) {
		t.Fatal("non-file readers should be readable")
	}
	tmp, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer tmp.Close()
	if !shouldReadPayloadFromStdin(tmp) {
		t.Fatal("redirected file stdin should be readable")
	}
}

func TestMCPProtocolVersionHeaderAlwaysSet(t *testing.T) {
	client := &mcpClient{url: "https://example.agentcore.aws/mcp"}
	req, err := client.newRequest(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}
	if got := req.Header.Get("MCP-Protocol-Version"); got != "2025-06-18" {
		t.Fatalf("protocol header mismatch without session: %q", got)
	}
	if got := req.Header.Get("Mcp-Session-Id"); got != "" {
		t.Fatalf("session header should be absent, got %q", got)
	}

	client.sessionID = "session-1"
	req, err = client.newRequest(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("newRequest with session: %v", err)
	}
	if got := req.Header.Get("MCP-Protocol-Version"); got != "2025-06-18" {
		t.Fatalf("protocol header mismatch with session: %q", got)
	}
	if got := req.Header.Get("Mcp-Session-Id"); got != "session-1" {
		t.Fatalf("session header mismatch: %q", got)
	}
}

// Agents pipe `bmcp list` through head/grep, so stdout must carry nothing but
// one self-contained record per tool.
func TestListEmitsOneNDJSONRecordPerTool(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{
		{Name: "tools___search_aws", Description: "Semantic search — scope it with <region> & tags."},
		{Name: "tools___search_infrastructure_graph", Description: "Multi-hop queries.\n\nExamples:\n- one\n- two"},
	})
	cache, err := readCache(filepath.Join(borisHome, "tools.json"))
	if err != nil {
		t.Fatalf("readCache: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	if code := a.run([]string{"--non-interactive", "list"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	// Golden raw lines, not a decode into toolRecord: the record's own struct
	// tags would appear on both sides of that comparison and cancel out, so a
	// renamed key or a re-enabled HTML escape would pass unnoticed. `<region> &`
	// staying raw is what lets an agent grep the lines it printed.
	stamp := cache.LastSync.UTC().Format(time.RFC3339)
	want := []string{
		`{"name":"tools___search_aws","display_name":"search_aws","description":"Semantic search — scope it with <region> & tags.","last_sync":"` + stamp + `"}`,
		`{"name":"tools___search_infrastructure_graph","display_name":"search_infrastructure_graph","description":"Multi-hop queries.\n\nExamples:\n- one\n- two","last_sync":"` + stamp + `"}`,
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("expected one record per tool, got %d lines:\n%s", len(lines), stdout.String())
	}
	for i, line := range lines {
		if line != want[i] {
			t.Fatalf("record %d mismatch:\n got: %s\nwant: %s", i, line, want[i])
		}
	}
	if !strings.Contains(stderr.String(), "2 tools synced") {
		t.Fatalf("count header belongs on stderr, got: %s", stderr.String())
	}
	// --json means structured errors; it must not restructure the catalog.
	var jsonStdout bytes.Buffer
	a.stdout = &jsonStdout
	if code := a.run([]string{"--non-interactive", "--json", "list"}); code != 0 {
		t.Fatalf("--json list exit code %d, stderr: %s", code, stderr.String())
	}
	if jsonStdout.String() != stdout.String() {
		t.Fatalf("--json should not change list output:\n got: %q\nwant: %q", jsonStdout.String(), stdout.String())
	}
}

// Every accepted --output spelling, in both flag positions and both syntaxes,
// through both `list` and its `ls` alias.
func TestListOutputFormatSpellings(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	cache, err := readCache(filepath.Join(borisHome, "tools.json"))
	if err != nil {
		t.Fatalf("readCache: %v", err)
	}
	ndjson := `{"name":"tools___search_aws","display_name":"search_aws","description":"Search.","last_sync":"` +
		cache.LastSync.UTC().Format(time.RFC3339) + "\"}\n"
	human := "search_aws\n  Search.\n"
	cases := []struct {
		args []string
		want string
	}{
		{args: []string{"list"}, want: ndjson},
		{args: []string{"ls"}, want: ndjson},
		{args: []string{"list", "--output", "ndjson"}, want: ndjson},
		{args: []string{"list", "--output=ndjson"}, want: ndjson},
		{args: []string{"list", "--output", "json"}, want: ndjson},
		{args: []string{"--output", "json", "list"}, want: ndjson},
		{args: []string{"list", "--output", "human"}, want: human},
		{args: []string{"list", "--output=human"}, want: human},
		{args: []string{"--output=human", "ls"}, want: human},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
			if code := a.run(append([]string{"--non-interactive"}, tc.args...)); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if stdout.String() != tc.want {
				t.Fatalf("stdout mismatch:\n got: %q\nwant: %q", stdout.String(), tc.want)
			}
		})
	}
}

// Names sit flush left and every description line is indented under them, no
// matter how long the name is — a length-dependent layout switch made mixed
// catalogs look misaligned.
func TestRenderToolListIndentsEveryDescriptionLine(t *testing.T) {
	var out bytes.Buffer
	err := renderToolList(&out, []tool{
		{
			Name:        "tools___short_name",
			Description: "Search for relevant context before making changes.",
		},
		{
			Name:        "tools___this_name_is_far_too_long_for_the_table_column",
			Description: "Multi-hop queries.\n\nExamples:\n- one",
		},
		{Name: "tools___bare"},
		{Name: "tools___blank", Description: "   \n  "},
		{Name: "tools___trailing", Description: "Ends with a newline.\n"},
		{Name: "tools___crlf", Description: "First.\r\nSecond.\r\n"},
	})
	if err != nil {
		t.Fatalf("renderToolList: %v", err)
	}
	want := "short_name\n" +
		"  Search for relevant context before making changes.\n" +
		"this_name_is_far_too_long_for_the_table_column\n" +
		"  Multi-hop queries.\n" +
		"\n" +
		"  Examples:\n" +
		"  - one\n" +
		"bare\n" +
		"blank\n" +
		"trailing\n" +
		"  Ends with a newline.\n" +
		"crlf\n" +
		"  First.\n" +
		"  Second.\n"
	if got := out.String(); got != want {
		t.Fatalf("layout mismatch:\ngot:\n%q\nwant:\n%q", got, want)
	}
}

// A short write must not pass for a complete catalog in either format.
func TestListReportsOutputWriteFailures(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	for _, output := range []string{"ndjson", "human"} {
		t.Run(output, func(t *testing.T) {
			var stderr bytes.Buffer
			a := &app{stdin: strings.NewReader(""), stdout: failingWriter{}, stderr: &stderr, now: time.Now}
			if code := a.run([]string{"--non-interactive", "list", "--output", output}); code != exitGeneric {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "disk full") {
				t.Fatalf("stderr should report the write failure, got: %s", stderr.String())
			}
		})
	}
}

// Empty stdout is the signal for an empty catalog; a non-zero exit would trip
// `set -e` and read as "BORIS is broken".
func TestListEmptyCatalogExitsZeroWithEmptyStdout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, nil)
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	if code := a.run([]string{"--non-interactive", "list"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "0 tools") {
		t.Fatalf("stderr should report an empty catalog, got: %s", stderr.String())
	}
}

// name, display_name and description are unconditional so consumers can rely on
// the record shape; only last_sync drops out, and only when it is zero.
func TestToolRecordKeepsEveryFieldButAZeroLastSync(t *testing.T) {
	var out bytes.Buffer
	if err := writeToolRecords(&out, []tool{{Name: "tools___search_aws"}}, time.Time{}); err != nil {
		t.Fatalf("writeToolRecords: %v", err)
	}
	if got := out.String(); got != `{"name":"tools___search_aws","display_name":"search_aws","description":""}`+"\n" {
		t.Fatalf("zero last_sync should be the only omitted field, got: %q", got)
	}
}

// parseFlags maps every error to exitGeneric, so --output has to be validated
// in run() before any command touches config or the network — and before the
// bare-usage return, which would otherwise swallow a bad value with exit 0.
func TestInvalidOutputValueFailsValidationBeforeDispatch(t *testing.T) {
	t.Setenv("BMCP_HOME", t.TempDir())
	cases := [][]string{
		{"--output", "bogus", "sync"},
		{"list", "--output", "bogus"},
		{"list", "--output="},
		{"--output=", "list"},
		{"--output", "bogus"},
		{"--output", "NDJSON", "list"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
			if code := a.run(args); code != exitValidation {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout should be empty, got %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), "--output") {
				t.Fatalf("stderr should name the offending flag, got: %s", stderr.String())
			}
		})
	}
}

// bmcp is driven mostly by coding agents, and --help is the first thing an agent
// tries against an unfamiliar binary. It has to reach stdout and exit 0 wherever
// it appears, without touching config or the network — a non-zero exit reads as
// "this tool is broken" and the agent abandons it.
func TestHelpFlagPrintsUsageToStdoutAndExitsZero(t *testing.T) {
	// No BMCP_HOME and no config on purpose: help must not require either.
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	cases := [][]string{
		{"--help"},
		{"-h"},
		{"help"},
		{"--json", "--help"},
		// Post-command: a known command must answer --help rather than reject it
		// as an unknown flag.
		{"doctor", "--help"},
		{"list", "-h"},
		{"describe", "--help"},
		{"update", "--help"},
		// install and version are rawArgs, so parseFlags never sees their
		// arguments and each answers --help itself.
		{"install", "--help"},
		{"install", "claude-code", "-h"},
		{"version", "--help"},
		// After `--` the flag cannot fire, because `--` stops flag interpretation.
		// The command-table aliases are what keep this working; without them the
		// token is treated as an unknown tool and costs a sync round trip.
		{"--", "--help"},
		{"--", "-h"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin:  strings.NewReader(""),
				stdout: &stdout,
				stderr: &stderr,
				now:    time.Now,
				// Every HTTP call fails, so a help path that reached the network
				// could not accidentally succeed here. It does not *prove* no call
				// was attempted — failingDoer returns an error rather than failing
				// the test, and under `go test` inspectUpdate short-circuits as a
				// source build before any request is built. That guarantee is pinned
				// separately by TestHelpNeverReachesTheNetwork.
				httpClient: failingDoer{},
			}
			if code := a.run(args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("usage should go to stdout, got stdout %q stderr %q", stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "unknown") {
				t.Fatalf("stderr should not report an unknown flag, got: %s", stderr.String())
			}
		})
	}
}

// Both orderings in run() are load-bearing and neither is expressible in the
// table above, because both cases exit non-zero.
//
// --output is validated before the help check on purpose: the comment at the top
// of run() records that a bad value must never exit 0, and `--output bogus
// --help` is exactly the hole that would open if help were checked first.
func TestInvalidOutputStillLosesToValidationWhenHelpIsAsked(t *testing.T) {
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	for _, args := range [][]string{
		{"--output", "bogus", "--help"},
		{"--help", "--output", "bogus"},
		{"doctor", "--help", "--output", "bogus"},
		{"doctor", "--output", "bogus", "-h"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now, httpClient: failingDoer{}}
			if code := a.run(args); code != exitValidation {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "--output") {
				t.Fatalf("stderr should name the offending flag, got: %s", stderr.String())
			}
			if strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("a bad --output must not be answered with usage: %s", stdout.String())
			}
		})
	}
}

// The other ordering: the help check sits before maybeAutoUpdate, so asking a
// command for help cannot cost a network round trip or a binary swap. This needs
// a release build to be meaningful — under `go test` the default buildCommit
// makes inspectUpdate short-circuit as a source build before any request is
// constructed, so the check would pass either way.
func TestHelpNeverReachesTheNetwork(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"help"},
		{"doctor", "--help"},
		{"sync", "--help"},
		{"init", "--help"},
		{"--", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// github is nil, so fakeMCP.Do turns any GitHub request into an error and
			// counts it; githubRequests is what makes the assertion real.
			m := &fakeMCP{tools: []tool{{Name: "search_aws_memory", Description: "d"}}}
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: m, credentials: staticCreds(),
				lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
				executable: func() (string, error) { return path, nil },
			}
			if code := a.run(args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if m.githubRequests != 0 {
				t.Fatalf("%v made %d GitHub requests; help must not check for updates", args, m.githubRequests)
			}
			if strings.Contains(stderr.String(), "Syncing tools") {
				t.Fatalf("%v reached the MCP server; help must not sync: %s", args, stderr.String())
			}
		})
	}
	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("no help invocation may replace the binary, got %q", got)
	}
}

// doctor --json used to write its document to stderr, which syncTools also
// writes "Syncing tools..." to — so the stream was not a parseable JSON
// document and consumers had to scan for the first `{`. It now follows the same
// split as cmdList: machine output on stdout, prose on stderr.
func TestDoctorJSONIsParseableOnStdoutWithProseOnStderr(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{tools: []tool{{Name: "tools___search_aws", Description: "Search."}}},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"doctor", "--json"}); code != 0 {
		t.Fatalf("doctor exit %d, stderr: %s", code, stderr.String())
	}
	// Unmarshalling the whole of stdout is the assertion: it rejects any leading
	// or trailing prose, which is exactly what the bug produced.
	var payload struct {
		OK     bool `json:"ok"`
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if !payload.OK || len(payload.Checks) == 0 {
		t.Fatalf("expected passing checks, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Syncing tools") {
		t.Fatalf("progress prose belongs on stderr, got: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), `"checks"`) {
		t.Fatalf("the document must not also reach stderr: %s", stderr.String())
	}
	// Without --json the rows stay human and stdout carries no JSON.
	stdout.Reset()
	stderr.Reset()
	if code := a.run([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), `"checks"`) {
		t.Fatalf("plain doctor should print rows, not JSON: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "config") {
		t.Fatalf("expected human check rows on stdout, got: %s", stdout.String())
	}
}

// A cache with no timestamp reaches cmdList through the same stale fallback; the
// header then has no timestamp to print and the records carry no last_sync.
func TestListReportsCountWithoutTimestampWhenCacheHasNoSync(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	stale := &toolCache{Version: 1, URL: "http://localhost:8787/mcp", Tools: []tool{{Name: "tools___search_aws", Description: "Search."}}}
	if err := writeCache(filepath.Join(borisHome, "tools.json"), stale); err != nil {
		t.Fatalf("writeCache: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  failingDoer{},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"--non-interactive", "list"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if got := stdout.String(); got != `{"name":"tools___search_aws","display_name":"search_aws","description":"Search."}`+"\n" {
		t.Fatalf("record should carry no last_sync: %q", got)
	}
	if !strings.Contains(stderr.String(), "1 tools\n") {
		t.Fatalf("header should omit an absent timestamp, got: %s", stderr.String())
	}
}

// The stale-cache fallback keeps exit 0, so its warning has to stay on stderr —
// one line of prose on stdout would break every consumer.
func TestListKeepsStaleCacheWarningOffStdout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	cache, err := readCache(filepath.Join(borisHome, "tools.json"))
	if err != nil {
		t.Fatalf("readCache: %v", err)
	}
	// Expire the cache so the catalog refresh runs, then fail that refresh.
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         func() time.Time { return cache.LastSync.Add(defaultTTL + time.Hour) },
		httpClient:  failingDoer{},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"--non-interactive", "list"}); code != 0 {
		t.Fatalf("stale cache should still exit 0, got %d, stderr: %s", code, stderr.String())
	}
	want := `{"name":"tools___search_aws","display_name":"search_aws","description":"Search.","last_sync":"` +
		cache.LastSync.UTC().Format(time.RFC3339) + "\"}\n"
	if stdout.String() != want {
		t.Fatalf("stdout should be records only:\n got: %q\nwant: %q", stdout.String(), want)
	}
	if !strings.Contains(stderr.String(), "using stale cache") {
		t.Fatalf("stale-cache warning belongs on stderr, got: %s", stderr.String())
	}
}

func TestDisplayToolNameStripsNamespacePrefix(t *testing.T) {
	if got := displayToolName("tools___graph_query"); got != "graph_query" {
		t.Fatalf("displayToolName mismatch: %q", got)
	}
	if got := displayToolName("graph_query"); got != "graph_query" {
		t.Fatalf("displayToolName should leave plain names alone: %q", got)
	}
	// A bare prefix has an empty suffix; falling back to the full name keeps
	// display_name and the human list from rendering a nameless entry.
	if got := displayToolName("tools___"); got != "tools___" {
		t.Fatalf("empty suffix should fall back to the full name: %q", got)
	}
}

func TestResolveToolAcceptsDisplayAlias(t *testing.T) {
	cache := &toolCache{Tools: []tool{{Name: "tools___search_aws"}}}
	got, err := resolveTool(cache, "search_aws")
	if err != nil {
		t.Fatalf("resolveTool: %v", err)
	}
	if got.Name != "tools___search_aws" {
		t.Fatalf("resolved tool mismatch: %q", got.Name)
	}
}

func TestResolveToolRejectsAmbiguousDisplayAlias(t *testing.T) {
	cache := &toolCache{Tools: []tool{{Name: "tools___search_aws"}, {Name: "other___search_aws"}}}
	_, err := resolveTool(cache, "search_aws")
	if err == nil || !strings.Contains(err.Error(), "Ambiguous tool alias") {
		t.Fatalf("expected ambiguous alias error, got: %v", err)
	}
}

func TestDynamicHelpUsesDisplayAlias(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BMCP_HOME", home)
	cfg := configFile{URL: "http://localhost:8787/mcp"}
	applyDefaults(&cfg)
	if err := writeConfig(filepath.Join(home, "config.toml"), cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	cache := &toolCache{
		Version:  1,
		URL:      cfg.URL,
		LastSync: time.Now(),
		Tools: []tool{{
			Name:        "tools___search_aws",
			Description: "Semantic search for AWS resources.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
			SchemaHash:  "sha256:test",
		}},
	}
	if err := writeCache(filepath.Join(home, "tools.json"), cache); err != nil {
		t.Fatalf("writeCache: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"--non-interactive", "search_aws", "--help"})
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "search_aws") || strings.Contains(stdout.String(), "tools___search_aws\n") {
		t.Fatalf("help should use display alias in heading, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "bmcp call search_aws") {
		t.Fatalf("help should use alias in call example, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "bmcp search_aws --query") {
		t.Fatalf("help should use alias in subcommand example, got:\n%s", stdout.String())
	}
	// A tool's --help must resolve to that tool, not to the global usage. The
	// global flag scope stops at the first non-flag token, which is what keeps
	// this argv reaching cmdDynamic at all.
	if strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("a tool's --help should print its schema, not the global usage, got:\n%s", stdout.String())
	}
}

func TestDescribeUsesDisplayAlias(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BMCP_HOME", home)
	cfg := configFile{URL: "http://localhost:8787/mcp"}
	applyDefaults(&cfg)
	if err := writeConfig(filepath.Join(home, "config.toml"), cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	cache := &toolCache{
		Version:  1,
		URL:      cfg.URL,
		LastSync: time.Now(),
		Tools: []tool{{
			Name:        "tools___search_aws",
			Description: "Semantic search for AWS resources.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
			SchemaHash:  "sha256:test",
		}},
	}
	if err := writeCache(filepath.Join(home, "tools.json"), cache); err != nil {
		t.Fatalf("writeCache: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"--non-interactive", "describe", "search_aws"})
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bmcp call search_aws") {
		t.Fatalf("describe should use alias examples, got:\n%s", stdout.String())
	}
}

func TestInstallClaudeCodeGlobalWritesReferenceAndBackup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{
		Name:        "tools___search_aws",
		Description: "Semantic search across indexed infrastructure, code, and dependency context.",
	}})
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	claudePath := filepath.Join(claudeDir, "CLAUDE.md")
	if err := os.WriteFile(claudePath, []byte("existing instructions\n"), 0o644); err != nil {
		t.Fatalf("write claude: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "claude-code"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	instructions, err := os.ReadFile(filepath.Join(claudeDir, "BORIS.md"))
	if err != nil {
		t.Fatalf("read BORIS.md: %v", err)
	}
	if !strings.Contains(string(instructions), "bmcp doctor") {
		t.Fatalf("missing BORIS guidance: %s", instructions)
	}
	if !strings.Contains(string(instructions), "Tools available when these instructions were generated") || !strings.Contains(string(instructions), "`search_aws`: Semantic search") {
		t.Fatalf("missing dynamic tool catalog: %s", instructions)
	}
	if strings.Contains(string(instructions), "bmcp --non-interactive") {
		t.Fatalf("instructions should not prefer non-interactive calls: %s", instructions)
	}
	claude, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatalf("read CLAUDE.md: %v", err)
	}
	if !strings.Contains(string(claude), "@BORIS.md") {
		t.Fatalf("CLAUDE.md should reference BORIS.md: %s", claude)
	}
	backups, err := filepath.Glob(claudePath + ".bak-*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != 1 {
		t.Fatalf("expected one backup, got %#v; stderr: %s", backups, stderr.String())
	}
	if !strings.Contains(stderr.String(), "backup "+backups[0]) {
		t.Fatalf("stderr should mention backup, got: %s", stderr.String())
	}
}

// Keeping a single backup made any two consecutive bad writes unrecoverable:
// the first backed up the good file, the second backed up the damaged one and
// deleted the good copy. Several generations have to survive a write, and the
// oldest beyond that has to go so the .bak-* set stays bounded.
func TestWriteFileWithBackupKeepsSeveralGenerations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "BORIS.md")
	if err := os.WriteFile(path, []byte("good\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// Literal counts, not backupGenerations: a test parameterized by the
	// constant it is testing passes at one generation too, which is the
	// regression. Five pre-existing plus the one this write takes is one more
	// than can survive, so exactly the oldest is expected to go.
	const wantKept = 5
	oldest := path + ".bak-20260601T000000.000000000Z"
	preexisting := []string{
		oldest,
		path + ".bak-20260602T000000.000000000Z",
		path + ".bak-20260603T000000.000000000Z",
		path + ".bak-20260604T000000.000000000Z",
		path + ".bak-20260605T000000.000000000Z",
	}
	for i, backup := range preexisting {
		if err := os.WriteFile(backup, []byte(fmt.Sprintf("gen%d\n", i)), 0o600); err != nil {
			t.Fatalf("write backup %s: %v", backup, err)
		}
	}

	result := writeFileWithBackup(path, []byte("damaged\n"))
	if !result.Changed || result.Backup == "" {
		t.Fatalf("expected changed file with backup, got: %#v", result)
	}

	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != wantKept {
		t.Fatalf("expected %d backups, got %#v", wantKept, backups)
	}
	// The copy this write just took must be one of them, or the write that
	// damaged the file left nothing to restore from.
	if _, err := os.Stat(result.Backup); err != nil {
		t.Fatalf("backup from this write should survive: %v", err)
	}
	if got, err := os.ReadFile(result.Backup); err != nil || string(got) != "good\n" {
		t.Fatalf("backup should hold the pre-write content, got %q, err %v", got, err)
	}
	if _, err := os.Stat(oldest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest backup should be pruned, stat err: %v", err)
	}
}

// The stamp in a backup name used to have one-second resolution, so two writes
// inside the same second landed on the same name — the second overwriting the
// first backup, collapsing two generations into one and destroying the good
// copy when the first write was the good one.
func TestWriteFileWithBackupSurvivesTwoWritesInQuickSuccession(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "BORIS.md")
	if err := os.WriteFile(path, []byte("good\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	first := writeFileWithBackup(path, []byte("damaged\n"))
	second := writeFileWithBackup(path, []byte("damaged again\n"))
	if first.Backup == "" || second.Backup == "" {
		t.Fatalf("expected both writes to back up, got %q and %q", first.Backup, second.Backup)
	}
	if first.Backup == second.Backup {
		t.Fatalf("both writes reused backup path %q", first.Backup)
	}
	if got, err := os.ReadFile(first.Backup); err != nil || string(got) != "good\n" {
		t.Fatalf("good copy should still be restorable, got %q, err %v", got, err)
	}
}

// tools/list is paginated, and ignoring nextCursor silently produced a short
// catalog: written to tools.json stamped LastSync: now, rendered into every
// instruction file, and then indistinguishable to an agent from a tool that
// does not exist. The empty-catalog guard does not cover it — 1 of 5 is not 0.
func TestSyncFollowsToolsListPagination(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good tool."}})

	all := []tool{
		{Name: "tools___alpha", Description: "A."},
		{Name: "tools___bravo", Description: "B."},
		{Name: "tools___charlie", Description: "C."},
		{Name: "tools___delta", Description: "D."},
		{Name: "tools___echo", Description: "E."},
	}
	m := &fakeMCP{tools: all, pageSize: 2}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code != 0 {
		t.Fatalf("sync exit code %d, stderr: %s", code, stderr.String())
	}
	if m.listCalls != 3 {
		t.Fatalf("expected 3 tools/list pages for 5 tools at 2 per page, got %d", m.listCalls)
	}
	cache, err := readCache(filepath.Join(borisHome, "tools.json"))
	if err != nil {
		t.Fatalf("readCache: %v", err)
	}
	if len(cache.Tools) != len(all) {
		t.Fatalf("expected %d tools, got %d: %#v", len(all), len(cache.Tools), cache.Tools)
	}
	for i, want := range all {
		if cache.Tools[i].Name != want.Name {
			t.Fatalf("tool %d: expected %q, got %q", i, want.Name, cache.Tools[i].Name)
		}
	}
}

// A first sync against a genuinely empty server is allowed to write, because
// there is nothing to lose. tools.json is a documented file people read with
// jq, so the empty catalog has to serialize as [] — iterating null is an error
// there, and an accumulator declared as a nil slice marshals to null.
func TestFirstSyncOfAnEmptyCatalogWritesAnEmptyArray(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Configured but never synced, so the guard sees no prior catalog to protect.
	borisHome := setupInstallCatalog(t, home, nil)
	if err := os.Remove(filepath.Join(borisHome, "tools.json")); err != nil {
		t.Fatalf("remove seeded cache: %v", err)
	}

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: &fakeMCP{tools: []tool{}}, credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code != 0 {
		t.Fatalf("first sync should be allowed to write, exit %d, stderr: %s", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(borisHome, "tools.json"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if !strings.Contains(string(raw), `"tools": []`) {
		t.Fatalf("expected an empty JSON array for tools, got: %s", raw)
	}
}

// A server that always hands back a cursor must not be able to spin out the
// sync timeout, and the partial catalog it produced must never be written: a
// truncated catalog reported as success is the failure this whole guard exists
// to prevent.
func TestSyncRefusesAnUnboundedToolsListCursor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good tool."}})
	cachePath := filepath.Join(borisHome, "tools.json")
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}

	m := &fakeMCP{
		tools:    []tool{{Name: "tools___alpha", Description: "A."}, {Name: "tools___bravo", Description: "B."}},
		pageSize: 1,
		// Never terminates: every page advertises a further one.
		cursorFor: func(next int) string { return fmt.Sprintf("offset-%d", next%2) },
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code == 0 {
		t.Fatalf("sync should refuse an unbounded cursor, stderr: %s", stderr.String())
	}
	// Exactly the cap: fewer would mean it gave up early for some other reason,
	// more would mean the cap does not bound anything.
	if m.listCalls != maxToolPages {
		t.Fatalf("expected the page cap of %d to stop it, got %d calls", maxToolPages, m.listCalls)
	}
	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("cache was overwritten with a partial catalog:\nbefore %s\nafter %s", before, after)
	}
}

// The subtlest way a short catalog can still be written: a later page answers
// with a JSON-RPC success carrying no tools array. Decoded into a plain slice
// that reads as an empty final page, so the tools gathered so far look like a
// complete catalog — and being non-empty they clear the empty-catalog guard and
// overwrite the real one, reported as success.
func TestSyncRefusesAToolsListPageWithNoToolsArray(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{
		{Name: "tools___good_tool", Description: "Known good tool."},
		{Name: "tools___other_tool", Description: "Another known tool."},
	})
	cachePath := filepath.Join(borisHome, "tools.json")
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}

	m := &fakeMCP{
		tools: []tool{
			{Name: "tools___alpha", Description: "A."},
			{Name: "tools___bravo", Description: "B."},
			{Name: "tools___charlie", Description: "C."},
			{Name: "tools___delta", Description: "D."},
		},
		pageSize:        2,
		malformedPageAt: 2,
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code == 0 {
		t.Fatalf("sync should refuse a page with no tools array, stderr: %s", stderr.String())
	}
	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("cache was overwritten with a partial catalog:\nbefore %s\nafter %s", before, after)
	}
}

// One request per id made response ids academic; paging puts several in one
// session, so a server that answers a page with the id of the one before it
// would have that earlier page counted twice and the catalog silently reshaped.
func TestSyncRefusesAToolsListPageAnsweringTheWrongRequest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good tool."}})
	cachePath := filepath.Join(borisHome, "tools.json")
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}

	m := &fakeMCP{
		tools: []tool{
			{Name: "tools___alpha", Description: "A."},
			{Name: "tools___bravo", Description: "B."},
			{Name: "tools___charlie", Description: "C."},
			{Name: "tools___delta", Description: "D."},
		},
		pageSize:      2,
		staleIDPageAt: 2,
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code == 0 {
		t.Fatalf("sync should refuse a mismatched response id, stderr: %s", stderr.String())
	}
	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("cache was overwritten:\nbefore %s\nafter %s", before, after)
	}
}

// A cursor that does not advance is the other way a server can loop forever,
// and it deserves an error that names the cause rather than the page cap.
func TestSyncRefusesARepeatedToolsListCursor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good tool."}})

	m := &fakeMCP{
		tools:     []tool{{Name: "tools___alpha", Description: "A."}, {Name: "tools___bravo", Description: "B."}},
		pageSize:  1,
		cursorFor: func(int) string { return "stuck" },
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code == 0 {
		t.Fatalf("sync should refuse a repeated cursor, stderr: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "repeated the same tools/list cursor") {
		t.Fatalf("error should name the repeated cursor, got: %s", stderr.String())
	}
	// Two round trips: the first page, then the one that repeats the cursor.
	if m.listCalls != 2 {
		t.Fatalf("expected 2 tools/list calls before giving up, got %d", m.listCalls)
	}
}

// An interrupted in-place write leaves a truncated file. tools.json is the case
// that matters: readCache then fails, which is what the empty-catalog guard in
// syncTools is preconditioned against, so the guard silently stops engaging.
//
// A reader that opened the file before the write is the observable difference
// between replacing an inode and truncating one, and it is what a half-finished
// write would expose. Asserting only the final content would pass against the
// os.WriteFile this replaced.
func TestWriteFileAtomicReplacesRatherThanTruncates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	if err := writeFileAtomic(path, []byte("second\n"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	held, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read from the pre-existing handle: %v", err)
	}
	if string(held) != "first\n" {
		t.Fatalf("a reader open across the write saw %q; the old file was modified in place", held)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "second\n" {
		t.Fatalf("expected the new content at the path, got %q, err %v", got, err)
	}
	// The temp file must not outlive the write: a stray .tools.json.tmp* next to
	// the real file is the partial content this exists to avoid.
	leftovers, err := filepath.Glob(filepath.Join(dir, ".tools.json.tmp*"))
	if err != nil {
		t.Fatalf("glob temps: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %#v", leftovers)
	}
}

// Replacing the inode is what makes the write atomic, and it is also what makes
// it capable of two silent regressions os.WriteFile could not have: resetting a
// mode the user chose, and turning a symlinked instruction file into a regular
// one — detaching it from the dotfiles repo that was managing it.
func TestWriteFileAtomicPreservesModeAndSymlinks(t *testing.T) {
	dir := t.TempDir()

	tightened := filepath.Join(dir, "BORIS.md")
	if err := os.WriteFile(tightened, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// 0o644 is what writeFileWithBackup passes for instruction files.
	if err := writeFileAtomic(tightened, []byte("new\n"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	info, err := os.Stat(tightened)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("a mode the user tightened was reset to %v", info.Mode().Perm())
	}

	target := filepath.Join(dir, "dotfiles-BORIS.md")
	link := filepath.Join(dir, "linked-BORIS.md")
	if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("seed link target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := writeFileAtomic(link, []byte("new\n"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic through symlink: %v", err)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat link: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced by a regular file")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "new\n" {
		t.Fatalf("the link target should hold the new content, got %q, err %v", got, err)
	}
}

// A directory whose name carries glob metacharacters used to make
// filepath.Glob's pattern match nothing and return no error, so pruning became
// a silent no-op and backups grew without bound.
func TestPruneOldBackupsHandlesGlobMetacharactersInThePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "service[1]")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "BORIS.md")
	if err := os.WriteFile(path, []byte("v0\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	for i := 0; i < 8; i++ {
		if result := writeFileWithBackup(path, []byte(fmt.Sprintf("v%d\n", i+1))); !result.Changed {
			t.Fatalf("write %d did not change the file", i)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	backups := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "BORIS.md.bak-") {
			backups++
		}
	}
	if backups != 5 {
		t.Fatalf("expected pruning to cap backups at 5, got %d", backups)
	}
}

// A truncated tools.json disarms the empty-catalog guard, because the guard can
// only refuse an empty catalog when it can read the old one. Atomic writes are
// what keep that state from existing; this pins the consequence if it ever does.
//
// Zero bytes is the case that matters most and is easiest to wave through: it is
// not an empty catalog, it is an in-place write killed after O_TRUNC and before
// its first byte — what the old writer left behind, on exactly the machine that
// is about to upgrade to the binary with this guard in it.
func TestCorruptCacheDoesNotLetAnEmptyCatalogThrough(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(good []byte) []byte
	}{
		{name: "half written", spoil: func(good []byte) []byte { return good[:len(good)/2] }},
		{name: "zero bytes", spoil: func([]byte) []byte { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good tool."}})
			cachePath := filepath.Join(borisHome, "tools.json")
			good, err := os.ReadFile(cachePath)
			if err != nil {
				t.Fatalf("read cache: %v", err)
			}
			if err := os.WriteFile(cachePath, tc.spoil(good), 0o600); err != nil {
				t.Fatalf("spoil cache: %v", err)
			}

			var stdout, stderr bytes.Buffer
			a := &app{
				stdin:       strings.NewReader(""),
				stdout:      &stdout,
				stderr:      &stderr,
				now:         time.Now,
				httpClient:  &fakeMCP{tools: []tool{}},
				credentials: staticCreds(),
			}
			if code := a.run([]string{"sync"}); code == 0 {
				t.Fatalf("sync reported success writing an empty catalog over a corrupt cache, stderr: %s", stderr.String())
			}
		})
	}
}

// The integration point #31 is actually about. The helper's own tests pass
// against an in-place writer wired into writeCache, so the wiring needs its own
// assertion: a reader holding tools.json across a sync must not observe the
// file being rewritten under it.
func TestSyncWritesTheCacheAtomically(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good tool."}})
	cachePath := filepath.Join(borisHome, "tools.json")
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	reader, err := os.Open(cachePath)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer reader.Close()

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient:  &fakeMCP{tools: []tool{{Name: "tools___fresh_tool", Description: "Newly listed."}}},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code != 0 {
		t.Fatalf("sync exit code %d, stderr: %s", code, stderr.String())
	}

	held, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read from the pre-existing handle: %v", err)
	}
	if !bytes.Equal(held, before) {
		t.Fatal("a reader open across the sync saw the cache change; writeCache is not going through writeFileAtomic")
	}
	if got, err := os.ReadFile(cachePath); err != nil || !strings.Contains(string(got), "tools___fresh_tool") {
		t.Fatalf("the new catalog should be at the path, got %q, err %v", got, err)
	}
}

// Ordering backups by the timestamp in the name trusts the clock that wrote it.
// A backup stamped with a future date — a clock that jumped forward and came
// back — sorts last by name forever, so it survives every prune while genuinely
// recent copies below it are deleted as "oldest". That is the two-bad-writes
// loss again, wearing a different hat. mtime is what the filesystem observed.
func TestPruneOldBackupsIgnoresAFutureDatedName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "BORIS.md")
	if err := os.WriteFile(path, []byte("good\n"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	// Four damaged backups whose names claim 2099 but which were written long
	// before the good copy this write is about to take.
	longAgo := time.Now().Add(-72 * time.Hour)
	for i := 0; i < 4; i++ {
		backup := fmt.Sprintf("%s.bak-20990101T00000%d.000000000Z", path, i)
		if err := os.WriteFile(backup, []byte("damaged\n"), 0o600); err != nil {
			t.Fatalf("write backup: %v", err)
		}
		if err := os.Chtimes(backup, longAgo, longAgo); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}

	first := writeFileWithBackup(path, []byte("damaged\n"))
	if first.Backup == "" {
		t.Fatal("expected the first write to take a backup")
	}
	if second := writeFileWithBackup(path, []byte("damaged again\n")); second.Backup == "" {
		t.Fatal("expected the second write to take a backup")
	}

	got, err := os.ReadFile(first.Backup)
	if err != nil {
		t.Fatalf("the only good copy was pruned in favour of future-dated names: %v", err)
	}
	if string(got) != "good\n" {
		t.Fatalf("expected the good copy, got %q", got)
	}
}

// A dotfiles setup that symlinks an instruction file into place before it has
// ever been written leaves a dangling link. EvalSymlinks fails on one, and
// falling back to the link's own path means the rename replaces the link —
// detaching it from the repo meant to be managing it.
func TestWriteFileAtomicFollowsADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "dotfiles")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(targetDir, "BORIS.md")
	link := filepath.Join(dir, "BORIS.md")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := writeFileAtomic(link, []byte("new\n"), 0o644); err != nil {
		t.Fatalf("writeFileAtomic through a dangling symlink: %v", err)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat link: %v", err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the dangling symlink was replaced by a regular file")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "new\n" {
		t.Fatalf("the link target should have been created with the content, got %q, err %v", got, err)
	}
}

// A write that fails must not cost a backup generation. Pruning beside the
// backup rather than after the replacement spent one on a write that never
// happened, deleting a good restore point in exchange for nothing — and the
// README promises rotation only "when a file changes".
func TestFailedWriteDoesNotConsumeABackupGeneration(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, directory permissions do not deny the write")
	}
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(targetDir, "target.md")
	if err := os.WriteFile(target, []byte("good\n"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	// The link is what gets written; the backup lands beside it in a writable
	// directory, while the resolved target sits in one that denies writes.
	path := filepath.Join(dir, "BORIS.md")
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	oldest := path + ".bak-20260601T000000.000000000Z"
	for i, backup := range []string{
		oldest,
		path + ".bak-20260602T000000.000000000Z",
		path + ".bak-20260603T000000.000000000Z",
		path + ".bak-20260604T000000.000000000Z",
		path + ".bak-20260605T000000.000000000Z",
	} {
		if err := os.WriteFile(backup, []byte(fmt.Sprintf("gen%d\n", i)), 0o600); err != nil {
			t.Fatalf("write backup: %v", err)
		}
	}
	if err := os.Chmod(targetDir, 0o500); err != nil {
		t.Fatalf("chmod target dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(targetDir, 0o700) })

	if result := writeFileWithBackup(path, []byte("new\n")); result.Changed {
		t.Fatal("the write into a read-only directory should have failed")
	}
	if _, err := os.Stat(oldest); err != nil {
		t.Fatalf("a failed write pruned the oldest backup: %v", err)
	}
}

func TestInstallCodexProjectWritesInlineAgentsInstructions(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___graph_query", Description: "Read-only topology queries."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "codex", "--scope", "project"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	agents, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	if strings.Contains(string(agents), "@BORIS.md") {
		t.Fatalf("AGENTS.md should not use a Codex include reference: %s", agents)
	}
	if !strings.Contains(string(agents), "<!-- BEGIN BMCP BORIS -->") ||
		!strings.Contains(string(agents), "bmcp doctor") ||
		!strings.Contains(string(agents), "`graph_query`: Read-only topology queries.") {
		t.Fatalf("unexpected AGENTS.md: %s", agents)
	}
	if _, err := os.Stat(filepath.Join(dir, "BORIS.md")); err != nil {
		t.Fatalf("BORIS.md should exist: %v", err)
	}
}

func TestInstallCodexGlobalInlinesAgentsInstructions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "codex"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	agents, err := os.ReadFile(filepath.Join(home, ".codex", "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	if strings.Contains(string(agents), "@BORIS.md") {
		t.Fatalf("AGENTS.md should not use a Codex include reference: %s", agents)
	}
	if !strings.Contains(string(agents), "bmcp doctor") || !strings.Contains(string(agents), "`search_aws`: Search.") {
		t.Fatalf("missing inline BORIS guidance: %s", agents)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "BORIS.md")); err != nil {
		t.Fatalf("BORIS.md should exist: %v", err)
	}
}

func TestInstallOpenCodeGlobalInlinesAgentsInstructions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "opencode"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	agents, err := os.ReadFile(filepath.Join(home, ".config", "opencode", "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	if strings.Contains(string(agents), "@BORIS.md") {
		t.Fatalf("AGENTS.md should not use an include reference: %s", agents)
	}
	if !strings.Contains(string(agents), "<!-- BEGIN BMCP BORIS -->") ||
		!strings.Contains(string(agents), "bmcp doctor") ||
		!strings.Contains(string(agents), "`search_aws`: Search.") {
		t.Fatalf("missing inline BORIS guidance: %s", agents)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "opencode", "BORIS.md")); err != nil {
		t.Fatalf("BORIS.md should exist: %v", err)
	}
}

func TestInstallCursorGlobalWritesRule(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___dependency_search", Description: "Search dependency metadata."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "cursor"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	rule, err := os.ReadFile(filepath.Join(home, ".cursor", "rules", "boris.mdc"))
	if err != nil {
		t.Fatalf("read cursor rule: %v", err)
	}
	if !strings.Contains(string(rule), "alwaysApply: true") || !strings.Contains(string(rule), "`dependency_search`: Search dependency metadata.") {
		t.Fatalf("unexpected cursor rule: %s", rule)
	}
}

func TestInstallKiroGlobalWritesSteering(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___memory_search", Description: "Search prior decisions."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "kiro"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	steering, err := os.ReadFile(filepath.Join(home, ".kiro", "steering", "boris.md"))
	if err != nil {
		t.Fatalf("read Kiro steering: %v", err)
	}
	if !strings.Contains(string(steering), "bmcp doctor") || !strings.Contains(string(steering), "`memory_search`: Search prior decisions.") {
		t.Fatalf("unexpected Kiro steering: %s", steering)
	}
}

func TestInstallKiroProjectWritesSteering(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___graph_query", Description: "Read topology context."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "kiro", "--scope", "project"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	steering, err := os.ReadFile(filepath.Join(dir, ".kiro", "steering", "boris.md"))
	if err != nil {
		t.Fatalf("read Kiro steering: %v", err)
	}
	if !strings.Contains(string(steering), "`graph_query`: Read topology context.") {
		t.Fatalf("unexpected Kiro steering: %s", steering)
	}
}

func TestSyncRefreshesExistingInstructions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "BORIS.md"), []byte("old instructions\n"), 0o644); err != nil {
		t.Fatalf("write old instructions: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(""),
		stdout: &stdout,
		stderr: &stderr,
		now:    time.Now,
		httpClient: &fakeMCP{tools: []tool{
			{Name: "tools___new_tool", Description: "Newly synced infrastructure context."},
		}},
		credentials: staticCreds(),
	}
	code := a.run([]string{"sync"})
	if code != 0 {
		t.Fatalf("sync exit code %d, stderr: %s", code, stderr.String())
	}
	instructions, err := os.ReadFile(filepath.Join(claudeDir, "BORIS.md"))
	if err != nil {
		t.Fatalf("read refreshed instructions: %v", err)
	}
	if !strings.Contains(string(instructions), "`new_tool`: Newly synced infrastructure context.") {
		t.Fatalf("instructions were not refreshed: %s", instructions)
	}
	if !strings.Contains(stderr.String(), "Refreshed BORIS instructions") {
		t.Fatalf("stderr should mention refresh, got: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "BORIS.md")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sync should not install new codex instructions, stat err: %v", err)
	}
}

// A tools/list that succeeds at the transport level and returns nothing used to
// replace a known-good catalog with an empty one stamped LastSync: now, then
// rewrite every installed instruction file with the "no tools available"
// placeholder — while pruneOldBackups deleted the older .bak-* copies that could
// have restored them. Recovery needed the server back *and* a fresh sync.
func TestEmptyCatalogDoesNotOverwriteAGoodCacheOrInstructions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good tool."}})
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	instructionsPath := filepath.Join(claudeDir, "BORIS.md")
	good := "# BORIS\n\n- `good_tool`: Known good tool.\n"
	if err := os.WriteFile(instructionsPath, []byte(good), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
	}
	cachePath := filepath.Join(borisHome, "tools.json")
	before, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(""),
		stdout: &stdout,
		stderr: &stderr,
		now:    time.Now,
		// An empty catalog: transport fine, zero tools.
		httpClient:  &fakeMCP{tools: []tool{}},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code != exitSync {
		t.Fatalf("sync should refuse an empty catalog, exit %d, stderr: %s", code, stderr.String())
	}

	after, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read cache after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("cache was rewritten:\nbefore %s\nafter %s", before, after)
	}
	got, err := os.ReadFile(instructionsPath)
	if err != nil {
		t.Fatalf("read instructions after: %v", err)
	}
	if string(got) != good {
		t.Fatalf("instructions were rewritten: %s", got)
	}
	if strings.Contains(string(got), "No tools were available") {
		t.Fatalf("instructions carry the empty placeholder: %s", got)
	}
	if matches, _ := filepath.Glob(instructionsPath + ".bak-*"); len(matches) != 0 {
		t.Fatalf("a refusal should not have produced a backup: %v", matches)
	}
	if !strings.Contains(stderr.String(), "returned no tools") {
		t.Fatalf("stderr should explain the refusal, got: %s", stderr.String())
	}
}

// The refusal protects data; it must not make the CLI unusable while upstream is
// degraded. The cache was left untouched precisely because it is still good, so
// a tool call has to keep working off it — cmdCall asks for a fresh catalog
// (allowStale=false) and would otherwise fail hard.
func TestToolCallsStillWorkAfterAnEmptyCatalogIsRefused(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{
		Name:        "tools___search_aws",
		Description: "Search.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
	}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(""),
		stdout: &stdout,
		stderr: &stderr,
		// Forces the TTL check to treat the cache as due, so syncTools runs and
		// returns the refusal on this very call.
		now:         func() time.Time { return time.Now().Add(400 * time.Hour) },
		httpClient:  &fakeMCP{tools: []tool{}, callResult: []byte(`{"content":[{"type":"text","text":"served"}]}`)},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"search_aws", "--query", "vpc"}); code != 0 {
		t.Fatalf("tool call exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "served") {
		t.Fatalf("expected the call to be served from the preserved cache, stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "returned no tools") {
		t.Fatalf("stderr should warn that the catalog came back empty, got: %s", stderr.String())
	}
}

// The guard protects existing data; it must not block the two cases where an
// empty catalog is the truth.
func TestEmptyCatalogIsWrittenWhenThereIsNothingToProtect(t *testing.T) {
	t.Run("no prior cache", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		borisHome := filepath.Join(home, ".bmcp")
		t.Setenv("BMCP_HOME", borisHome)
		var stdout, stderr bytes.Buffer
		a := &app{
			stdin:       strings.NewReader(""),
			stdout:      &stdout,
			stderr:      &stderr,
			now:         time.Now,
			httpClient:  &fakeMCP{tools: []tool{}},
			credentials: staticCreds(),
			interactive: func() bool { return false },
		}
		if code := a.run([]string{"init", "--url", "http://localhost:8787/mcp"}); code != 0 {
			t.Fatalf("first init exit %d, stderr: %s", code, stderr.String())
		}
		cache, err := readCache(filepath.Join(borisHome, "tools.json"))
		if err != nil {
			t.Fatalf("read cache: %v", err)
		}
		if len(cache.Tools) != 0 {
			t.Fatalf("expected the empty catalog to be written, got %d tools", len(cache.Tools))
		}
	})

	// A cache from a different server is not a catalog worth keeping: after
	// pointing bmcp at another URL, that server's empty list is the truth.
	t.Run("cache belongs to another url", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___old_server_tool", Description: "From the old server."}})
		cachePath := filepath.Join(borisHome, "tools.json")
		cache, err := readCache(cachePath)
		if err != nil {
			t.Fatalf("read cache: %v", err)
		}
		cache.URL = "http://localhost:9999/other"
		if err := writeCache(cachePath, cache); err != nil {
			t.Fatalf("writeCache: %v", err)
		}
		var stdout, stderr bytes.Buffer
		a := &app{
			stdin:       strings.NewReader(""),
			stdout:      &stdout,
			stderr:      &stderr,
			now:         time.Now,
			httpClient:  &fakeMCP{tools: []tool{}},
			credentials: staticCreds(),
		}
		if code := a.run([]string{"sync"}); code != 0 {
			t.Fatalf("sync exit %d, stderr: %s", code, stderr.String())
		}
		got, err := readCache(cachePath)
		if err != nil {
			t.Fatalf("read cache after: %v", err)
		}
		if len(got.Tools) != 0 {
			t.Fatalf("another server's catalog should not have been preserved, got %d tools", len(got.Tools))
		}
	})
}

// The guard keys off the cache's URL, so a cosmetic difference that still
// addresses the same server must not disarm it. It fails open, so getting this
// wrong destroys the catalog it exists to protect.
func TestEmptyCatalogGuardSurvivesACosmeticURLDifference(t *testing.T) {
	// Only spellings validateURL accepts, since it runs first: it requires https
	// except for a literal lowercase `http://localhost`, so scheme- and host-case
	// variants cannot reach the guard at all and are covered by TestSameServer.
	for _, override := range []string{
		"http://localhost:8787/mcp/",  // one trailing slash
		"http://localhost:8787/mcp//", // more than one
		"http://localhost:8787/mcp?",  // empty query
	} {
		t.Run(override, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good."}})
			cachePath := filepath.Join(borisHome, "tools.json")
			before, err := os.ReadFile(cachePath)
			if err != nil {
				t.Fatalf("read cache: %v", err)
			}
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin:       strings.NewReader(""),
				stdout:      &stdout,
				stderr:      &stderr,
				now:         time.Now,
				httpClient:  &fakeMCP{tools: []tool{}},
				credentials: staticCreds(),
			}
			if code := a.run([]string{"--url", override, "sync"}); code != exitSync {
				t.Fatalf("sync should still refuse, exit %d, stderr: %s", code, stderr.String())
			}
			after, err := os.ReadFile(cachePath)
			if err != nil {
				t.Fatalf("read cache after: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("cache was rewritten via %s:\nbefore %s\nafter %s", override, before, after)
			}
		})
	}
}

// sameServer decides whether the empty-catalog guard engages, and it fails open,
// so a false negative destroys the catalog the guard protects. A false positive
// only preserves a catalog from a genuinely different server, which the next
// successful sync replaces anyway.
func TestSameServer(t *testing.T) {
	same := [][2]string{
		{"https://a.example/mcp", "https://a.example/mcp"},
		{"https://a.example/mcp", "https://a.example/mcp/"},
		{"https://a.example/mcp", "https://a.example/mcp//"},
		{"https://a.example/mcp", "HTTPS://a.example/mcp"},
		{"https://a.example/mcp", "https://A.EXAMPLE/mcp"},
		{"https://a.example/mcp", "https://a.example/mcp?"},
		{"https://a.example/mcp?x=1", "https://a.example/mcp/?x=1"},
		// A default port spelled out is the same origin as one left off. This is
		// the direction that loses data if it is wrong.
		{"https://a.example/mcp", "https://a.example:443/mcp"},
		{"http://a.example/mcp", "http://a.example:80/mcp"},
		{"https://[::1]/mcp", "https://[::1]:443/mcp"},
	}
	for _, pair := range same {
		if !sameServer(pair[0], pair[1]) {
			t.Errorf("sameServer(%q, %q) = false, want true", pair[0], pair[1])
		}
	}
	// Differences that can change which server answers must stay distinct, or the
	// guard would preserve another server's catalog.
	different := [][2]string{
		{"https://a.example/mcp", "https://b.example/mcp"},
		{"https://a.example/mcp", "https://a.example/other"},
		{"https://a.example/mcp", "https://a.example:8443/mcp"},
		{"https://a.example/mcp", "http://a.example/mcp"},
		{"https://a.example/mcp?x=1", "https://a.example/mcp?x=2"},
		{"https://a.example/mcp", "https://a.example/mcp/sub"},
		// A non-default port is part of the identity.
		{"https://a.example/mcp", "https://a.example:8443/mcp"},
		{"https://[::1]/mcp", "https://[::2]/mcp"},
		// Percent-encoding is preserved: these are different request targets, and
		// comparing the decoded path would conflate them.
		{"https://a.example/a%2Fb", "https://a.example/a/b"},
	}
	for _, pair := range different {
		if sameServer(pair[0], pair[1]) {
			t.Errorf("sameServer(%q, %q) = true, want false", pair[0], pair[1])
		}
	}
}

// The refusal must name a way out. Without one, a server whose catalog is
// genuinely empty now leaves sync, doctor and init failing forever — and `bmcp
// init` is not an escape, since it only clears the cache when the URL changes.
func TestRefusalNamesTheEscapeHatch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good."}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{tools: []tool{}},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"sync"}); code != exitSync {
		t.Fatalf("exit %d, stderr: %s", code, stderr.String())
	}
	cachePath := filepath.Join(borisHome, "tools.json")
	if !strings.Contains(stderr.String(), cachePath) {
		t.Fatalf("the refusal should name the cache path to delete, got: %s", stderr.String())
	}
	// Singular, because the count is 1 — the message is only ever read on the
	// degraded path, which is exactly when it should not look sloppy.
	if !strings.Contains(stderr.String(), "1 tool,") {
		t.Fatalf("expected a singular tool count, got: %s", stderr.String())
	}
}

// The refusal deliberately leaves LastSync stale so the next command retries.
// Within one command that must not turn into repeated handshakes: cmdDynamic
// resolves the tool and then runCall resolves it again, so an unmemoised refusal
// asks a struggling server twice and warns twice.
func TestRefusedSyncAsksTheServerOnlyOncePerCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{
		Name:        "tools___search_aws",
		Description: "Search.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
	}})
	m := &fakeMCP{tools: []tool{}, callResult: []byte(`{"content":[{"type":"text","text":"served"}]}`)}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(""),
		stdout: &stdout,
		stderr: &stderr,
		// Past the TTL, so the catalog lookup is due and the refusal happens here.
		now:         func() time.Time { return time.Now().Add(400 * time.Hour) },
		httpClient:  m,
		credentials: staticCreds(),
	}
	if code := a.run([]string{"search_aws", "--query", "vpc"}); code != 0 {
		t.Fatalf("tool call exit %d, stderr: %s", code, stderr.String())
	}
	if m.listCalls != 1 {
		t.Fatalf("expected 1 tools/list for one tool call, got %d", m.listCalls)
	}
	if got := strings.Count(stderr.String(), "returned no tools"); got != 1 {
		t.Fatalf("expected the warning once, got %d:\n%s", got, stderr.String())
	}
}

// doctor is the one command that should still fail during the refusal. Tool calls
// keep working off the preserved cache, but an empty upstream catalog *is* a
// BORIS-side fault, and the precedent in cmdDoctor is that only non-BORIS
// failures (a GitHub outage) are kept out of the exit code.
func TestDoctorFailsWhileUpstreamListsNoTools(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___good_tool", Description: "Known good."}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{tools: []tool{}},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"doctor"}); code != exitGeneric {
		t.Fatalf("doctor should fail while the catalog is empty, exit %d", code)
	}
	if !strings.Contains(stdout.String(), "remote") || !strings.Contains(stdout.String(), "returned no tools") {
		t.Fatalf("the remote check should report the refusal, got:\n%s", stdout.String())
	}
	// The cache row still reports the preserved catalog, so the two rows together
	// say "upstream is empty, your catalog survived".
	if !strings.Contains(stdout.String(), "1 tools") {
		t.Fatalf("the cache row should still report the preserved catalog, got:\n%s", stdout.String())
	}
}

// installHarness renders the same catalog into the same files, so it needs the
// same rule as refreshExistingInstructions. This path is not only reached by an
// explicit `bmcp install`: an all-defaults interactive `bmcp init` accepts the
// harness prompts, so without the guard a machine with an empty cache would
// overwrite good instruction files without the user typing "install".
func TestInstallRefusesAnEmptyCatalogRatherThanWipingInstructions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{})
	// A fresh, non-due cache with no tools: what an older binary left behind.
	if err := writeCache(filepath.Join(borisHome, "tools.json"), &toolCache{
		Version: 1, URL: "http://localhost:8787/mcp", LastSync: time.Now().UTC(), Tools: []tool{},
	}); err != nil {
		t.Fatalf("writeCache: %v", err)
	}
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	path := filepath.Join(claudeDir, "BORIS.md")
	good := "# BORIS\n\n- `good_tool`: Known good tool.\n"
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{tools: []tool{}},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"install", "claude-code"}); code == 0 {
		t.Fatalf("install should refuse an empty catalog, stderr: %s", stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read instructions: %v", err)
	}
	if string(got) != good {
		t.Fatalf("instructions were overwritten: %s", got)
	}
	if matches, _ := filepath.Glob(path + ".bak-*"); len(matches) != 0 {
		t.Fatalf("a refusal should not have produced a backup: %v", matches)
	}
	if !strings.Contains(stderr.String(), "bmcp sync") {
		t.Fatalf("the refusal should name the recovery command, got: %s", stderr.String())
	}
}

// Belt and braces behind the syncTools guard: an empty cache that arrived some
// other way — hand-edited, or written by a binary predating the guard — must
// still not be able to overwrite a populated instruction file.
func TestRefreshExistingInstructionsIgnoresAnEmptyCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	path := filepath.Join(claudeDir, "BORIS.md")
	good := "# BORIS\n\n- `good_tool`: Known good tool.\n"
	if err := os.WriteFile(path, []byte(good), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
	}
	for _, cache := range []*toolCache{nil, {Version: 1, Tools: []tool{}}} {
		if results := refreshExistingInstructions(cache); len(results) != 0 {
			t.Fatalf("expected no refresh for an empty cache, got %+v", results)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read instructions: %v", err)
	}
	if string(got) != good {
		t.Fatalf("instructions were rewritten: %s", got)
	}
}

func TestSyncRefreshesExistingKiroSteering(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})
	kiroDir := filepath.Join(home, ".kiro", "steering")
	if err := os.MkdirAll(kiroDir, 0o700); err != nil {
		t.Fatalf("mkdir kiro: %v", err)
	}
	if err := os.WriteFile(filepath.Join(kiroDir, "boris.md"), []byte("old instructions\n"), 0o644); err != nil {
		t.Fatalf("write old instructions: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(""),
		stdout: &stdout,
		stderr: &stderr,
		now:    time.Now,
		httpClient: &fakeMCP{tools: []tool{
			{Name: "tools___new_tool", Description: "New Kiro context."},
		}},
		credentials: staticCreds(),
	}
	code := a.run([]string{"sync"})
	if code != 0 {
		t.Fatalf("sync exit code %d, stderr: %s", code, stderr.String())
	}
	steering, err := os.ReadFile(filepath.Join(kiroDir, "boris.md"))
	if err != nil {
		t.Fatalf("read refreshed steering: %v", err)
	}
	if !strings.Contains(string(steering), "`new_tool`: New Kiro context.") {
		t.Fatalf("steering was not refreshed: %s", steering)
	}
	if !strings.Contains(stderr.String(), "Refreshed BORIS instructions for Kiro") {
		t.Fatalf("stderr should mention Kiro refresh, got: %s", stderr.String())
	}
}

func TestSyncMigratesLegacyCodexAgentsReference(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o700); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "BORIS.md"), []byte("old instructions\n"), 0o644); err != nil {
		t.Fatalf("write old instructions: %v", err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "AGENTS.md"), []byte("personal instructions\n@BORIS.md\n"), 0o644); err != nil {
		t.Fatalf("write legacy agents: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(""),
		stdout: &stdout,
		stderr: &stderr,
		now:    time.Now,
		httpClient: &fakeMCP{tools: []tool{
			{Name: "tools___new_tool", Description: "Newly synced infrastructure context."},
		}},
		credentials: staticCreds(),
	}
	code := a.run([]string{"sync"})
	if code != 0 {
		t.Fatalf("sync exit code %d, stderr: %s", code, stderr.String())
	}
	agents, err := os.ReadFile(filepath.Join(codexDir, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	if strings.Contains(string(agents), "@BORIS.md") {
		t.Fatalf("legacy Codex reference should be removed: %s", agents)
	}
	if !strings.Contains(string(agents), "personal instructions") ||
		!strings.Contains(string(agents), "<!-- BEGIN BMCP BORIS -->") ||
		!strings.Contains(string(agents), "`new_tool`: Newly synced infrastructure context.") {
		t.Fatalf("AGENTS.md was not migrated: %s", agents)
	}
}

func setupInstallCatalog(t *testing.T, home string, tools []tool) string {
	t.Helper()
	borisHome := filepath.Join(home, ".bmcp")
	t.Setenv("BMCP_HOME", borisHome)
	if err := os.MkdirAll(borisHome, 0o700); err != nil {
		t.Fatalf("mkdir boris home: %v", err)
	}
	cfg := configFile{URL: "http://localhost:8787/mcp"}
	applyDefaults(&cfg)
	if err := writeConfig(filepath.Join(borisHome, "config.toml"), cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	for i := range tools {
		if tools[i].InputSchema == nil {
			tools[i].InputSchema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		if tools[i].SchemaHash == "" {
			tools[i].SchemaHash = schemaHash(tools[i].InputSchema)
		}
	}
	cache := &toolCache{
		Version:  1,
		URL:      cfg.URL,
		LastSync: time.Now(),
		Tools:    tools,
	}
	if err := writeCache(filepath.Join(borisHome, "tools.json"), cache); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	return borisHome
}

func TestToolCallUnwrapsEnvelopeByDefaultThroughCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{callResult: []byte(`{"isError":false,"content":[{"type":"text","text":"{\"ok\":true}"}]}`)},
		credentials: staticCreds(),
	}
	code := a.run([]string{"search_aws"})
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "{\"ok\":true}\n" {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Calling search_aws...") {
		t.Fatalf("stderr should show call progress, got: %s", stderr.String())
	}
}

func TestToolCallRawPreservesEnvelopeThroughCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	envelope := `{"isError":false,"content":[{"type":"text","text":"{\"ok\":true}"}]}`
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{callResult: []byte(envelope)},
		credentials: staticCreds(),
	}
	code := a.run([]string{"--raw", "search_aws"})
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != envelope {
		t.Fatalf("unexpected raw stdout: %q", stdout.String())
	}
}

func TestToolCallPrettyFormatsUnwrappedJSONThroughCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{callResult: []byte(`{"content":[{"type":"text","text":"{\"ok\":true}"}]}`)},
		credentials: staticCreds(),
	}
	code := a.run([]string{"--pretty", "search_aws"})
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "{\n  \"ok\": true\n}\n" {
		t.Fatalf("unexpected pretty stdout: %q", stdout.String())
	}
}

func TestInitPromptsForDetectedHarnessesDefaultYes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := filepath.Join(home, ".bmcp")
	t.Setenv("BMCP_HOME", borisHome)
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader("\n\n"),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		interactive: func() bool { return true },
		lookPath: func(name string) (string, error) {
			if name == "claude" || name == "codex" || name == "opencode" || name == "cursor" || name == "kiro-cli" {
				return "/bin/" + name, nil
			}
			return "", os.ErrNotExist
		},
		httpClient: &fakeMCP{tools: []tool{
			{Name: "tools___search_aws", Description: "Search."},
		}},
		credentials: staticCreds(),
	}
	code := a.run([]string{"init", "--url", "http://localhost:8787/mcp"})
	if code != 0 {
		t.Fatalf("init exit code %d, stderr: %s", code, stderr.String())
	}
	for _, path := range []string{
		filepath.Join(home, ".claude", "BORIS.md"),
		filepath.Join(home, ".codex", "BORIS.md"),
		filepath.Join(home, ".config", "opencode", "BORIS.md"),
		filepath.Join(home, ".cursor", "rules", "boris.mdc"),
		filepath.Join(home, ".kiro", "steering", "boris.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected install path %s: %v", path, err)
		}
	}
	if strings.Count(stderr.String(), "Install BORIS instructions for") != 5 {
		t.Fatalf("expected separate prompts for five harnesses, got: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "Refreshed BORIS instructions") {
		t.Fatalf("interactive init should not refresh instructions before install prompts, got: %s", stderr.String())
	}
}

func TestInitNonInteractiveSkipsHarnessPrompts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BMCP_HOME", filepath.Join(home, ".bmcp"))
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		interactive: func() bool { return true },
		lookPath:    func(string) (string, error) { return "/bin/claude", nil },
		httpClient:  &fakeMCP{},
		credentials: staticCreds(),
	}
	code := a.run([]string{"--non-interactive", "init", "--url", "http://localhost:8787/mcp"})
	if code != 0 {
		t.Fatalf("init exit code %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "Install BORIS instructions") {
		t.Fatalf("non-interactive init should not prompt, got: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "BORIS.md")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-interactive init should not install instructions, stat err: %v", err)
	}
}

func TestDetectHarnessesUsesConfigDirectories(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatalf("mkdir cursor: %v", err)
	}
	a := &app{lookPath: func(string) (string, error) { return "", os.ErrNotExist }}
	got := a.detectHarnesses()
	if len(got) != 1 || got[0].name != "cursor" {
		t.Fatalf("detectHarnesses mismatch: %#v", got)
	}
}

func TestDetectHarnessesUsesOpenCodeConfigDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".config", "opencode"), 0o700); err != nil {
		t.Fatalf("mkdir opencode: %v", err)
	}
	a := &app{lookPath: func(string) (string, error) { return "", os.ErrNotExist }}
	got := a.detectHarnesses()
	if len(got) != 1 || got[0].name != "opencode" {
		t.Fatalf("detectHarnesses mismatch: %#v", got)
	}
}

func TestDetectHarnessesUsesKiroCommandsAndConfigDirectory(t *testing.T) {
	for _, command := range []string{"kiro-cli", "kiro"} {
		t.Run(command, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			a := &app{lookPath: func(name string) (string, error) {
				if name == command {
					return "/bin/" + name, nil
				}
				return "", os.ErrNotExist
			}}
			got := a.detectHarnesses()
			if len(got) != 1 || got[0].name != "kiro" {
				t.Fatalf("detectHarnesses mismatch: %#v", got)
			}
		})
	}

	t.Run("config-dir", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		if err := os.MkdirAll(filepath.Join(home, ".kiro"), 0o700); err != nil {
			t.Fatalf("mkdir kiro: %v", err)
		}
		a := &app{lookPath: func(string) (string, error) { return "", os.ErrNotExist }}
		got := a.detectHarnesses()
		if len(got) != 1 || got[0].name != "kiro" {
			t.Fatalf("detectHarnesses mismatch: %#v", got)
		}
	})
}

func TestInstallAllAndReferenceIdempotency(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"install", "all"})
	if code != 0 {
		t.Fatalf("install exit code %d, stderr: %s", code, stderr.String())
	}
	code = a.run([]string{"install", "claude-code"})
	if code != 0 {
		t.Fatalf("second install exit code %d, stderr: %s", code, stderr.String())
	}
	claude, err := os.ReadFile(filepath.Join(home, ".claude", "CLAUDE.md"))
	if err != nil {
		t.Fatalf("read CLAUDE.md: %v", err)
	}
	if strings.Count(string(claude), "@BORIS.md") != 1 {
		t.Fatalf("CLAUDE.md should contain one reference, got: %s", claude)
	}
	for _, path := range []string{
		filepath.Join(home, ".codex", "BORIS.md"),
		filepath.Join(home, ".config", "opencode", "BORIS.md"),
		filepath.Join(home, ".cursor", "rules", "boris.mdc"),
		filepath.Join(home, ".kiro", "steering", "boris.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected install path %s: %v", path, err)
		}
	}
}

func TestInstallRejectsInvalidScopeAndUnknownHarness(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	if code := a.run([]string{"install", "codex", "--scope", "team"}); code != exitValidation {
		t.Fatalf("invalid scope exit code %d, stderr: %s", code, stderr.String())
	}
	stderr.Reset()
	if code := a.run([]string{"install", "unknown"}); code != exitValidation {
		t.Fatalf("unknown harness exit code %d, stderr: %s", code, stderr.String())
	}
}

func TestSchemaHashCanonicalizesObjectKeys(t *testing.T) {
	a := json.RawMessage(`{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"number"}}}`)
	b := json.RawMessage(`{"properties":{"a":{"type":"number"},"b":{"type":"string"}},"type":"object"}`)
	if schemaHash(a) != schemaHash(b) {
		t.Fatalf("expected equal hashes, got %s and %s", schemaHash(a), schemaHash(b))
	}
}

func TestParseToolFlags(t *testing.T) {
	tl := tool{
		Name: "deploy_service",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"required":["service","filter"],
			"properties":{
				"service":{"type":"string"},
				"replicas":{"type":"integer"},
				"dry_run":{"type":"boolean"},
				"tag":{"type":"array","items":{"type":"string"}},
				"filter":{"type":"object"}
			}
		}`),
	}
	got, err := tl.ParseFlags([]string{
		"--service", "api",
		"--replicas=3",
		"--dry_run",
		"--tag", "prod",
		"--tag", "pci",
		"--filter", `{"severity":"high"}`,
	})
	if err != nil {
		t.Fatalf("parseToolFlags: %v", err)
	}
	if got["service"] != "api" || got["dry_run"] != true {
		t.Fatalf("unexpected scalar values: %#v", got)
	}
	if got["replicas"] != int64(3) {
		t.Fatalf("replicas mismatch: %#v", got["replicas"])
	}
	tags, ok := got["tag"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "prod" || tags[1] != "pci" {
		t.Fatalf("tags mismatch: %#v", got["tag"])
	}
	filter, ok := got["filter"].(map[string]any)
	if !ok || filter["severity"] != "high" {
		t.Fatalf("filter mismatch: %#v", got["filter"])
	}
}

func TestParseToolFlagsJSONPositionalSuggestsCall(t *testing.T) {
	tl := tool{
		Name:        "tools___call_aws_api",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"parameters":{"type":"object"}}}`),
	}
	_, err := tl.ParseFlags([]string{`{"account_id":"123"}`})
	if err == nil {
		t.Fatal("expected error for JSON positional argument")
	}
	if !strings.Contains(err.Error(), "bmcp call call_aws_api") {
		t.Fatalf("expected suggestion to use the call subcommand, got: %v", err)
	}
}

func TestValidateInputErrors(t *testing.T) {
	tl := tool{
		Name: "tools___deploy_service",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"required":["service"],
			"properties":{"service":{"type":"string"},"environment":{"type":"string"}}
		}`),
	}
	err := tl.Validate(map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "Missing required argument: service") {
		t.Fatalf("missing required error mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), "bmcp call deploy_service") {
		t.Fatalf("missing required example should use display alias: %v", err)
	}
	err = tl.Validate(map[string]any{"service": "api", "enviroment": "prod"})
	if err == nil || !strings.Contains(err.Error(), "Did you mean: --environment?") {
		t.Fatalf("unknown argument suggestion mismatch: %v", err)
	}
}

func TestNormalizeSSE(t *testing.T) {
	body := []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n")
	got := normalizeMCPResponse("text/event-stream", body)
	if string(got) != `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}` {
		t.Fatalf("unexpected SSE payload: %s", got)
	}
}

func TestUnwrapMCPTextEnvelope(t *testing.T) {
	raw := []byte(`{"isError":false,"content":[{"type":"text","text":"{\"ok\":true}"}]}`)
	got := unwrapMCPTextEnvelope(raw)
	if string(got) != `{"ok":true}` {
		t.Fatalf("unexpected unwrapped payload: %s", got)
	}
}

func TestUnwrapMCPTextEnvelopeFallsBackToRaw(t *testing.T) {
	raw := []byte(`{"content":[{"type":"image","data":"abc"}]}`)
	got := unwrapMCPTextEnvelope(raw)
	if !bytes.Equal(got, raw) {
		t.Fatalf("expected raw fallback, got: %s", got)
	}
}

func TestGeneratedInstructionsDoNotDependOnJQ(t *testing.T) {
	cache := &toolCache{LastSync: time.Now(), Tools: []tool{{Name: "tools___search_aws", Description: "Find infrastructure context."}}}
	got := borisInstructionsMarkdown(cache)
	if strings.Contains(got, "jq") {
		t.Fatalf("instructions should not depend on jq: %s", got)
	}
	if !strings.Contains(got, "requires AWS credentials for any account in the AWS Organization") {
		t.Fatalf("instructions should explain AWS credential requirement: %s", got)
	}
	if strings.Contains(got, "refresh AWS SSO") || strings.Contains(got, "Do not try to fix auth") {
		t.Fatalf("instructions should not prescribe auth remediation: %s", got)
	}
	if !strings.Contains(got, "unwraps MCP text envelopes internally") {
		t.Fatalf("instructions should explain internal unwrapping: %s", got)
	}
	if !strings.Contains(got, "`bmcp --raw <tool> ...`") {
		t.Fatalf("instructions should mention raw debugging mode: %s", got)
	}
}

func TestSchemaDiff(t *testing.T) {
	oldTool := tool{
		Name:        "deploy_service",
		InputSchema: json.RawMessage(`{"type":"object","required":["environment"],"properties":{"environment":{"type":"string"},"replicas":{"type":"integer"}}}`),
	}
	newTool := tool{
		Name:        "deploy_service",
		InputSchema: json.RawMessage(`{"type":"object","required":["target_environment"],"properties":{"target_environment":{"type":"string"},"replicas":{"type":"number"}}}`),
	}
	diff := oldTool.Diff(newTool)
	kinds := map[string]bool{}
	for _, change := range diff {
		kinds[change["kind"]] = true
	}
	for _, want := range []string{"removed_required_arg", "added_required_arg", "changed_type"} {
		if !kinds[want] {
			t.Fatalf("missing diff kind %q in %#v", want, diff)
		}
	}
}
