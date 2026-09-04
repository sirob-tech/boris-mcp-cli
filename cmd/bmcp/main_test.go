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
	"reflect"
	"strconv"
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

// stdout is a line-oriented stream, so it must carry nothing but one
// self-contained record per tool: `grep` and `while read -r line` see whole
// records, and a consumer can parse them as they arrive.
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
	// Plain `bmcp list` selects no contract, so it behaves exactly as it did before
	// --format existed: records on stdout, the count header on stderr. Suppressing
	// that header is the contract's business, and only a caller that spelled
	// --format has asked for it — see TestContractSuppressesProseOnlyWhenSelected.
	if !strings.Contains(stderr.String(), "2 tools synced") {
		t.Fatalf("count header belongs on stderr, got: %s", stderr.String())
	}
	// --json means structured errors; it must not restructure the catalog. That was
	// true before --format and stays true, which is the whole point of giving the
	// contract a flag of its own.
	var jsonStdout bytes.Buffer
	a.stdout = &jsonStdout
	if code := a.run([]string{"--non-interactive", "--json", "list"}); code != 0 {
		t.Fatalf("--json list exit code %d, stderr: %s", code, stderr.String())
	}
	if jsonStdout.String() != stdout.String() {
		t.Fatalf("--json should not change list output:\n got: %q\nwant: %q", jsonStdout.String(), stdout.String())
	}
}

// `list --output json` is the enveloped form, and the one to reach for when
// completeness matters: `head` on the NDJSON stream is silently short, and
// nothing in that stream says how many records there should have been.
func TestListJSONDocumentCarriesCountAndTools(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{
		{Name: "tools___search_aws", Description: "Semantic search — scope it with <region> & tags."},
		{Name: "tools___search_infrastructure_graph", Description: "Multi-hop queries."},
	})
	cache, err := readCache(filepath.Join(borisHome, "tools.json"))
	if err != nil {
		t.Fatalf("readCache: %v", err)
	}
	for _, args := range [][]string{{"list", "--format", "json"}, {"--format", "json", "list"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
			if code := a.run(append([]string{"--non-interactive"}, args...)); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			var doc struct {
				OK       bool   `json:"ok"`
				Command  string `json:"command"`
				Count    int    `json:"count"`
				LastSync string `json:"last_sync"`
				Tools    []struct {
					Name        string          `json:"name"`
					Description string          `json:"description"`
					InputSchema json.RawMessage `json:"input_schema"`
				} `json:"tools"`
			}
			// Unmarshalling the whole of stdout is itself the assertion that no prose
			// shares the channel: json.Unmarshal rejects trailing non-whitespace.
			if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
				t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
			}
			if !doc.OK || doc.Command != "list" {
				t.Fatalf("unexpected envelope: %s", stdout.String())
			}
			if doc.Count != 2 || len(doc.Tools) != 2 {
				t.Fatalf("expected 2 tools and count 2, got count %d and %d tools", doc.Count, len(doc.Tools))
			}
			if doc.LastSync != cache.LastSync.UTC().Format(time.RFC3339) {
				t.Fatalf("unexpected last_sync %q", doc.LastSync)
			}
			// Same raw-byte guarantee the NDJSON stream makes: HTML escaping stays off,
			// so what the tool said is what a caller reads.
			if !strings.Contains(doc.Tools[0].Description, "<region> & tags") {
				t.Fatalf("description should not be HTML-escaped: %q", doc.Tools[0].Description)
			}
			// Schemas are opt-in in this format too, for the reason they are in NDJSON.
			if doc.Tools[0].InputSchema != nil {
				t.Fatalf("schemas should need --schemas, got %s", doc.Tools[0].InputSchema)
			}
			if stderr.Len() != 0 {
				t.Fatalf("a machine format must leave stderr empty, got: %s", stderr.String())
			}
		})
	}
}

// An empty catalog is `"tools":[]`, never `"tools":null`: this command exits 0
// on an empty catalog, so a consumer ranging over the field should not have to
// special-case the case it is most likely to meet.
func TestListJSONDocumentHasEmptyArrayForEmptyCatalog(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, nil)
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	if code := a.run([]string{"--non-interactive", "list", "--format", "json"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"tools": []`) {
		t.Fatalf("expected an empty array, got: %s", stdout.String())
	}
}

// Every accepted --output spelling, in both flag positions and both syntaxes,
// through both `list` and its `ls` alias. `json` is not here: it used to be an
// alias for `ndjson` and is now its own format, pinned by
// TestListJSONDocumentCarriesCountAndTools.
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
		{args: []string{"list", "--format", "ndjson"}, want: ndjson},
		{args: []string{"list", "--output=ndjson"}, want: ndjson},
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
	// The count is prose, so the human format is where it is reported now — see
	// TestListEmitsOneNDJSONRecordPerTool.
	stdout.Reset()
	stderr.Reset()
	if code := a.run([]string{"--non-interactive", "list", "--output", "human"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "0 tools") {
		t.Fatalf("the human format should report an empty catalog, got: %s", stderr.String())
	}
}

// name, display_name and description are unconditional so consumers can rely on
// the record shape; only last_sync drops out, and only when it is zero.
func TestToolRecordKeepsEveryFieldButAZeroLastSync(t *testing.T) {
	var out bytes.Buffer
	if err := writeToolRecords(&out, []tool{{Name: "tools___search_aws"}}, time.Time{}, false); err != nil {
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
	// --deep because a routine doctor answers from local state and emits no
	// progress prose at all, so it cannot demonstrate prose landing on the wrong
	// stream. The deep path is the one that has a stream split to get wrong.
	if code := a.run([]string{"doctor", "--deep", "--json"}); code != 0 {
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
	// --json selects no contract, so the split is the one it always was: document
	// on stdout, prose on stderr. Suppressing the prose is the contract's business
	// — see TestContractSuppressesProseOnlyWhenSelected.
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
	// The header is prose, suppressed in a machine format; --verbose is where it
	// can still be observed.
	stdout.Reset()
	stderr.Reset()
	if code := a.run([]string{"--non-interactive", "--verbose", "list"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "1 tools\n") {
		t.Fatalf("header should omit an absent timestamp, got: %s", stderr.String())
	}
}

// The stale-cache fallback keeps exit 0, so its warning must never reach stdout
// — one line of prose there would break every consumer. In a machine format it
// is not written at all, because a caller merging the streams would be back in
// the same position; --verbose is where a human can still see it.
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
	// Under the contract it is suppressed rather than redirected, so a caller
	// merging the streams still gets one parseable document.
	stdout.Reset()
	stderr.Reset()
	if code := a.run([]string{"--non-interactive", "--format", "ndjson", "list"}); code != 0 {
		t.Fatalf("stale cache should still exit 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != want {
		t.Fatalf("--format must not disturb stdout:\n got: %q\nwant: %q", stdout.String(), want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("the contract must leave stderr empty, got: %s", stderr.String())
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
	// --deep: an empty upstream is only observable by asking it. A routine doctor
	// answers from the cache, which is intact here, and reporting that as broken
	// would be wrong — cacheForCatalog serves calls from exactly this cache while
	// upstream lists nothing.
	if code := a.run([]string{"doctor", "--deep"}); code != exitGeneric {
		t.Fatalf("doctor should fail while the catalog is empty, exit %d", code)
	}
	if !strings.Contains(stdout.String(), "remote") || !strings.Contains(stdout.String(), "returned no tools") {
		t.Fatalf("the remote check should report the refusal, got:\n%s", stdout.String())
	}
	// The cache row still reports the preserved catalog, so the two rows together
	// say "upstream is empty, your catalog survived".
	if !strings.Contains(stdout.String(), "1 tool,") {
		t.Fatalf("the cache row should still report the preserved catalog, got:\n%s", stdout.String())
	}
}

// doctorRows parses the human check rows into name -> state. Matching row names
// as substrings of the whole of stdout does not work: the cache row's message
// contains the word "tools", so a `tools` row would appear to be present on
// every run that printed a catalog of two or more.
func doctorRows(t *testing.T, stdout string) map[string]string {
	t.Helper()
	rows := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		rows[fields[0]] = fields[1]
	}
	return rows
}

// refusingCreds fails the test if credentials are ever loaded. The audited
// failures were not slow credential loads but failed ones — an expired SSO
// session in a sandbox that could not reach device authorization — so "did not
// authenticate" is the property, not "authenticated quickly".
func refusingCreds(t *testing.T) credentialsFunc {
	t.Helper()
	return func(context.Context, effectiveConfig) (aws.Credentials, string, error) {
		t.Error("doctor loaded AWS credentials while the cached catalog was fresh")
		return aws.Credentials{}, "", errors.New("credentials must not be loaded")
	}
}

// staleCache backdates the seeded catalog so it falls outside sync_ttl.
func staleCache(t *testing.T, borisHome string, age time.Duration) {
	t.Helper()
	path := filepath.Join(borisHome, "tools.json")
	cache, err := readCache(path)
	if err != nil {
		t.Fatalf("read seeded cache: %v", err)
	}
	cache.LastSync = time.Now().Add(-age)
	if err := writeCache(path, cache); err != nil {
		t.Fatalf("write backdated cache: %v", err)
	}
}

// The whole point of the change: the command the generated instructions put in
// front of every agent session must not authenticate or reach the server to
// answer the routine question. In the audit this path had a 3.55s median and an
// 11s maximum, and failed outright three times on credentials that the first
// real tool call would have loaded anyway.
func TestDoctorMakesNoRemoteCallWhileTheCatalogIsFresh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	m := &fakeMCP{tools: []tool{{Name: "tools___search_aws", Description: "Search."}}}
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  m,
		credentials: refusingCreds(t),
	}
	if code := a.run([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit %d, stderr: %s", code, stderr.String())
	}
	if m.listCalls != 0 {
		t.Fatalf("doctor synced the catalog on the routine path: %d tools/list calls", m.listCalls)
	}
	// Named rows rather than a count, because the failure this guards against is
	// a check quietly reappearing, not the total changing.
	rows := doctorRows(t, stdout.String())
	for _, row := range []string{"auth", "remote", "tools"} {
		if _, ok := rows[row]; ok {
			t.Fatalf("the routine path must not report %q, got:\n%s", row, stdout.String())
		}
	}
	for _, row := range []string{"config", "url", "cache"} {
		if rows[row] != "ok" {
			t.Fatalf("expected %q to pass locally, got %q in:\n%s", row, rows[row], stdout.String())
		}
	}
}

// The escalation, and its converse. A fresh cache is the only thing that earns
// the local answer; anything that leaves the local catalog unusable has to go
// and get one, or doctor would report ready on a machine that is not.
func TestDoctorGoesRemoteWhenLocalStateCannotAnswer(t *testing.T) {
	fresh := []tool{{Name: "tools___search_aws", Description: "Search."}}
	for _, tc := range []struct {
		name    string
		degrade func(t *testing.T, borisHome string)
		args    []string
	}{
		{
			name:    "stale cache",
			degrade: func(t *testing.T, home string) { staleCache(t, home, 8*24*time.Hour) },
			args:    []string{"doctor"},
		},
		{
			name: "missing cache",
			degrade: func(t *testing.T, home string) {
				if err := os.Remove(filepath.Join(home, "tools.json")); err != nil {
					t.Fatalf("remove cache: %v", err)
				}
			},
			args: []string{"doctor"},
		},
		{
			name: "unreadable cache",
			degrade: func(t *testing.T, home string) {
				if err := os.WriteFile(filepath.Join(home, "tools.json"), []byte("{"), 0o600); err != nil {
					t.Fatalf("corrupt cache: %v", err)
				}
			},
			args: []string{"doctor"},
		},
		{
			// --deep overrides a perfectly good local state, which is what makes it
			// useful after a call has already failed on auth or connectivity.
			name:    "--deep while fresh",
			degrade: func(t *testing.T, home string) {},
			args:    []string{"doctor", "--deep"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Chdir(t.TempDir())
			borisHome := setupInstallCatalog(t, home, fresh)
			tc.degrade(t, borisHome)
			var stdout, stderr bytes.Buffer
			m := &fakeMCP{tools: fresh}
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: m, credentials: staticCreds(),
			}
			// Exit 0 including the missing- and unreadable-cache cases: doctor
			// rebuilt the catalog in the same run, and BORIS.md teaches agents to
			// read a failing doctor as "BORIS is broken" and stop using it. Before
			// the cache row moved after the escalation, those two exited 1 having
			// just fixed the thing they were complaining about.
			if code := a.run(tc.args); code != 0 {
				t.Fatalf("doctor exit %d, stdout:\n%s\nstderr: %s", code, stdout.String(), stderr.String())
			}
			if m.listCalls != 1 {
				t.Fatalf("expected exactly one sync, got %d tools/list calls", m.listCalls)
			}
			rows := doctorRows(t, stdout.String())
			for _, row := range []string{"auth", "remote", "tools", "cache"} {
				if rows[row] != "ok" {
					t.Fatalf("expected %q to pass, got %q in:\n%s", row, rows[row], stdout.String())
				}
			}
		})
	}
}

// The local path still carries every catalog change that has already reached
// this machine — one an earlier tool call synced, a template a self-update
// changed, or a file whose last refresh failed. That is what keeps the
// per-session cadence #44 added after doctor stopped syncing; only server-side
// drift now waits for sync_ttl.
func TestDoctorRefreshesInstructionsWithoutSyncing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	setupInstallCatalog(t, home, []tool{{Name: "tools___cached_tool", Description: "Already synced."}})
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	instructionsPath := filepath.Join(claudeDir, "BORIS.md")
	if err := os.WriteFile(instructionsPath, []byte("# BORIS\n\n- `gone_tool`: Removed upstream.\n"), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
	}
	var stdout, stderr bytes.Buffer
	m := &fakeMCP{tools: []tool{{Name: "tools___cached_tool", Description: "Already synced."}}}
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: refusingCreds(t),
	}
	if code := a.run([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit %d, stderr: %s", code, stderr.String())
	}
	if m.listCalls != 0 {
		t.Fatalf("the refresh must come from the cache, not a sync: %d tools/list calls", m.listCalls)
	}
	got, err := os.ReadFile(instructionsPath)
	if err != nil {
		t.Fatalf("read instructions: %v", err)
	}
	if !strings.Contains(string(got), "`cached_tool`: Already synced.") {
		t.Fatalf("the local refresh did not render the cached catalog: %s", got)
	}
	if strings.Contains(string(got), "gone_tool") {
		t.Fatalf("the stale entry survived the refresh: %s", got)
	}
}

// The other half of the rehoming: once doctor stops syncing, the lazy sync a
// tool call performs is what carries a server-side catalog change to the
// instruction files agents actually read. Hanging that off doctor alone would
// have meant hanging it off nothing.
func TestLazySyncDuringAToolCallRefreshesInstructions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})
	staleCache(t, borisHome, 8*24*time.Hour)
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	instructionsPath := filepath.Join(claudeDir, "BORIS.md")
	if err := os.WriteFile(instructionsPath, []byte("# BORIS\n\n- `old_tool`: Old description.\n"), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now,
		httpClient: &fakeMCP{
			tools:      []tool{{Name: "tools___new_tool", Description: "Newly synced."}},
			callResult: []byte(`{"ok":true}`),
		},
		credentials: staticCreds(),
	}
	// A tool call, not doctor and not sync: the point is that the refresh rides
	// on whichever command discovers the new catalog.
	if code := a.run([]string{"new_tool"}); code != 0 {
		t.Fatalf("tool call exit %d, stderr: %s", code, stderr.String())
	}
	got, err := os.ReadFile(instructionsPath)
	if err != nil {
		t.Fatalf("read instructions: %v", err)
	}
	if !strings.Contains(string(got), "`new_tool`: Newly synced.") {
		t.Fatalf("the lazy sync did not refresh the tool list: %s", got)
	}
	if strings.Contains(string(got), "old_tool") {
		t.Fatalf("the removed tool is still listed: %s", got)
	}
}

// doctor --json says which question it answered. A consumer that finds no `auth`
// row has to be able to tell "not checked" from "checked and gone".
func TestDoctorJSONReportsWhichModeItRan(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{args: []string{"doctor", "--json"}, want: "local"},
		{args: []string{"doctor", "--deep", "--json"}, want: "deep"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Chdir(t.TempDir())
			tools := []tool{{Name: "tools___search_aws", Description: "Search."}}
			setupInstallCatalog(t, home, tools)
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: &fakeMCP{tools: tools}, credentials: staticCreds(),
			}
			if code := a.run(tc.args); code != 0 {
				t.Fatalf("doctor exit %d, stderr: %s", code, stderr.String())
			}
			var payload struct {
				Mode string `json:"mode"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
				t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
			}
			if payload.Mode != tc.want {
				t.Fatalf("expected mode %q, got %q", tc.want, payload.Mode)
			}
		})
	}
}

// A stale cache is not the same failure as a cache from another server or one a
// zero TTL never reuses, and "age 200h" does not say which. Each branch names
// the conjunct of catalogIsFresh that actually failed, or the row sends a reader
// to look at something that is fine.
//
// Asserted on cacheStatus rather than through doctor, because doctor cannot
// exhibit these strings on a healthy machine: every one of them triggers the
// escalation, the sync succeeds, and the row then correctly describes the fresh
// catalog it ended with. They reach a user on the run where that sync also
// failed — so the row has to be right independently of it.
func TestCacheStatusNamesWhyACatalogIsNotFresh(t *testing.T) {
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	a := &app{now: func() time.Time { return now }}
	cfg := effectiveConfig{URL: "http://localhost:8787/mcp", SyncTTL: 168 * time.Hour}
	fresh := &toolCache{URL: cfg.URL, LastSync: now.Add(-time.Hour), Tools: make([]tool, 3)}

	for _, tc := range []struct {
		name  string
		cfg   effectiveConfig
		cache *toolCache
		want  string
		// absent guards the fresh case, where any explanation at all is wrong.
		absent []string
	}{
		{
			name:   "fresh",
			cfg:    cfg,
			cache:  fresh,
			want:   "3 tools, age 1h0m0s",
			absent: []string{"older than", "different URL", "sync_ttl is 0"},
		},
		{
			name:  "past the ttl",
			cfg:   cfg,
			cache: &toolCache{URL: cfg.URL, LastSync: now.Add(-200 * time.Hour), Tools: make([]tool, 3)},
			want:  "older than sync_ttl 168h0m0s",
		},
		{
			name:  "another server",
			cfg:   cfg,
			cache: &toolCache{URL: "http://localhost:9999/mcp", LastSync: now.Add(-time.Hour), Tools: make([]tool, 3)},
			want:  "synced from a different URL",
		},
		{
			// A zero TTL disables reuse outright, so age is not the reason and
			// saying "older than sync_ttl 0s" would send the reader to the clock.
			name:  "zero ttl",
			cfg:   effectiveConfig{URL: cfg.URL, SyncTTL: 0},
			cache: fresh,
			want:  "sync_ttl is 0 so it is never reused",
		},
		{
			// The pluralisation is load-bearing for nothing, but "1 tools" in the
			// one-tool case is the kind of wrongness that erodes trust in the rest
			// of the row.
			name:  "one tool",
			cfg:   cfg,
			cache: &toolCache{URL: cfg.URL, LastSync: now, Tools: make([]tool, 1)},
			want:  "1 tool, age 0s",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each case must actually be in the state it claims, or it would assert
			// a string the code happens to produce for another reason.
			if wantFresh := tc.name == "fresh" || tc.name == "one tool"; a.catalogIsFresh(tc.cfg, tc.cache, nil) != wantFresh {
				t.Fatalf("fixture precondition: catalogIsFresh should be %v", wantFresh)
			}
			got := a.cacheStatus(tc.cfg, tc.cache)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("expected %q in the cache row, got %q", tc.want, got)
			}
			for _, no := range tc.absent {
				if strings.Contains(got, no) {
					t.Fatalf("a fresh catalog must not be explained away with %q, got %q", no, got)
				}
			}
		})
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
		if results := refreshExistingInstructions(cache, true); len(results) != 0 {
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

// `bmcp sync` refreshed the tool list agents read; `bmcp doctor` refreshed only
// tools.json. BORIS.md tells agents to run doctor, and never mentions sync — so
// a tool added, renamed or removed upstream stayed invisible to every agent
// indefinitely, and the names they did read could point at tools the server had
// stopped serving.
func TestDoctorRefreshesTheInstructionToolList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Anywhere but the repository. refreshExistingInstructions consults the
	// working directory, which under `go test` is the package directory, and a
	// test that writes a BORIS.md into the source tree passes while quietly
	// leaving an untracked file and a .bak- beside it.
	t.Chdir(t.TempDir())
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})
	oldCache, err := readCache(filepath.Join(borisHome, "tools.json"))
	if err != nil {
		t.Fatalf("read seeded cache: %v", err)
	}
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	// Seeded with a genuinely generated document rather than a hand-written stub,
	// so this exercises replacing one rendered catalog with another — which is
	// what happens in the field, and what makes the "old_tool is gone" assertion
	// mean something.
	instructionsPath := filepath.Join(claudeDir, "BORIS.md")
	if err := os.WriteFile(instructionsPath, []byte(borisInstructionsMarkdown(oldCache)), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
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
	// --deep: the change under test is one the *server* made, and no local answer
	// can carry it. The seeded cache is fresh, so a routine doctor refreshes from
	// that cache and correctly never learns new_tool exists.
	// TestDoctorRefreshesInstructionsWithoutSyncing covers the local half.
	if code := a.run([]string{"doctor", "--deep"}); code != 0 {
		t.Fatalf("doctor exit %d, stderr: %s", code, stderr.String())
	}
	got, err := os.ReadFile(instructionsPath)
	if err != nil {
		t.Fatalf("read refreshed instructions: %v", err)
	}
	if !strings.Contains(string(got), "`new_tool`: Newly synced infrastructure context.") {
		t.Fatalf("doctor did not refresh the tool list: %s", got)
	}
	// "old_tool" and not "old": the generated prose is full of common words, and a
	// fixture token that appears in it would make this assertion fail for reasons
	// having nothing to do with the catalog.
	if strings.Contains(string(got), "old_tool") {
		t.Fatalf("the removed tool is still listed: %s", got)
	}
}

// doctor runs unattended, every agent session, from whatever directory an agent
// happens to be working in. A project-scope instruction file is claimed by
// filename alone — nothing in a BORIS.md marks it as ours — so refreshing
// project scope from doctor would rewrite an unrelated file of that name in
// someone's repository. `bmcp sync` still refreshes it, because a human typed
// that in a directory they chose.
func TestDoctorLeavesProjectScopeInstructionsAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := t.TempDir()
	t.Chdir(project)
	setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})

	// Not ours: someone else's file that happens to carry the name.
	projectPath := filepath.Join(project, "BORIS.md")
	mine := "# Our own BORIS notes\n\nNothing to do with bmcp.\n"
	if err := os.WriteFile(projectPath, []byte(mine), 0o644); err != nil {
		t.Fatalf("write project file: %v", err)
	}
	kiroPath := filepath.Join(project, ".kiro", "steering", "boris.md")
	if err := os.MkdirAll(filepath.Dir(kiroPath), 0o700); err != nil {
		t.Fatalf("mkdir kiro: %v", err)
	}
	if err := os.WriteFile(kiroPath, []byte(mine), 0o644); err != nil {
		t.Fatalf("write kiro file: %v", err)
	}

	newApp := func(stdout, stderr *bytes.Buffer) *app {
		return &app{
			stdin:  strings.NewReader(""),
			stdout: stdout,
			stderr: stderr,
			now:    time.Now,
			httpClient: &fakeMCP{tools: []tool{
				{Name: "tools___new_tool", Description: "Newly synced infrastructure context."},
			}},
			credentials: staticCreds(),
		}
	}

	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit %d, stderr: %s", code, stderr.String())
	}
	for _, path := range []string{projectPath, kiroPath} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != mine {
			t.Fatalf("doctor rewrote a project-scope file it does not own\n%s:\n%s", path, got)
		}
		if backups := backupsFor(t, path); len(backups) != 0 {
			t.Fatalf("doctor left backups beside %s: %v", path, backups)
		}
	}

	// The counterpart: sync still does refresh project scope, so this is a
	// narrowing of doctor and not a silent removal of the feature.
	stdout.Reset()
	stderr.Reset()
	if code := newApp(&stdout, &stderr).run([]string{"sync"}); code != 0 {
		t.Fatalf("sync exit %d, stderr: %s", code, stderr.String())
	}
	got, err := os.ReadFile(projectPath)
	if err != nil {
		t.Fatalf("read project file after sync: %v", err)
	}
	if !strings.Contains(string(got), "`new_tool`") {
		t.Fatalf("sync should still refresh project scope, got: %s", got)
	}
}

// Once doctor refreshes instruction files it runs against them every agent
// session, so a refresh against an unchanged catalog has to be a true no-op. It
// is one only because renderInstructionToolList is a pure function of the
// catalog: the render used to carry a sync timestamp, which made every run
// produce different bytes, defeated writeFileWithBackup's bytes.Equal
// short-circuit, and rotated a backup generation per session — five sessions and
// the last copy predating any damage is gone, the amplifier backupGenerations
// exists to prevent.
//
// The clock advances between runs precisely to pin that: if anything time-varying
// creeps back into the render, these runs stop being identical and this test
// fails.
func TestRepeatedDoctorRunsDoNotSpendBackupGenerations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	instructionsPath := filepath.Join(claudeDir, "BORIS.md")
	original := "# BORIS\n\n- `old_tool`: Old description.\n"
	if err := os.WriteFile(instructionsPath, []byte(original), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
	}

	// One reading per run, advanced between runs rather than on every call. A
	// clock that moved on each call would hand syncTools and doctor's cache-age
	// row different times within a single run, which no real run does — it printed
	// a negative cache age, and a minute of age on a cache that same run wrote.
	base := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	runClock := base
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         func() time.Time { return runClock },
		httpClient:  &fakeMCP{tools: []tool{{Name: "tools___new_tool", Description: "Newly synced infrastructure context."}}},
		credentials: staticCreds(),
	}

	run := func(i int) {
		runClock = base.Add(time.Duration(i) * time.Minute)
		stdout.Reset()
		stderr.Reset()
		if code := a.run([]string{"doctor"}); code != 0 {
			t.Fatalf("doctor run %d exit %d, stderr: %s", i, code, stderr.String())
		}
	}
	run(0)
	afterFirst, err := os.ReadFile(instructionsPath)
	if err != nil {
		t.Fatalf("read instructions: %v", err)
	}
	// mtime, not just content: a rewrite with identical bytes still churns the
	// file, and dotfiles under version control notice.
	firstInfo, err := os.Stat(instructionsPath)
	if err != nil {
		t.Fatalf("stat instructions: %v", err)
	}
	for i := 1; i < 8; i++ {
		run(i)
		if strings.Contains(stderr.String(), "Refreshed BORIS instructions") {
			t.Fatalf("run %d announced a refresh against an unchanged catalog: %s", i, stderr.String())
		}
	}

	backups := backupsFor(t, instructionsPath)
	// One, from the first run — the only run that changed the catalog. The seven
	// after it found the same catalog and wrote nothing.
	if len(backups) != 1 {
		t.Fatalf("expected one backup from the single real change, got %d: %v", len(backups), backups)
	}
	kept, err := os.ReadFile(backups[0])
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(kept) != original {
		t.Fatalf("the surviving restore point should still hold the pre-refresh file, got: %s", kept)
	}

	afterLast, err := os.ReadFile(instructionsPath)
	if err != nil {
		t.Fatalf("read instructions: %v", err)
	}
	if !bytes.Equal(afterFirst, afterLast) {
		t.Fatalf("an unchanged catalog must render identically:\nfirst %s\nlast %s", afterFirst, afterLast)
	}
	lastInfo, err := os.Stat(instructionsPath)
	if err != nil {
		t.Fatalf("stat instructions: %v", err)
	}
	if !lastInfo.ModTime().Equal(firstInfo.ModTime()) {
		t.Fatal("the repeat runs rewrote the file; an unchanged catalog must not touch it at all")
	}
}

// A render that does not vary with time is what makes the per-session doctor
// refresh free, so pin that the renderer is a pure function of the catalog.
// Anything reintroduced here that changes run to run re-arms the backup-eviction
// bug this replaced.
func TestInstructionRenderIsAPureFunctionOfTheCatalog(t *testing.T) {
	tools := []tool{{Name: "tools___search_aws", Description: "Search."}}
	early := &toolCache{Version: 1, URL: "http://localhost:8787/mcp", LastSync: time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC), Tools: tools}
	later := &toolCache{Version: 1, URL: "http://localhost:8787/mcp", LastSync: time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC), Tools: tools}
	never := &toolCache{Version: 1, URL: "http://localhost:8787/mcp", Tools: tools}

	want := borisInstructionsMarkdown(early)
	for name, cache := range map[string]*toolCache{"a later sync": later, "no sync timestamp at all": never} {
		if got := borisInstructionsMarkdown(cache); got != want {
			t.Fatalf("%s changed the render:\n%s", name, got)
		}
	}
	if strings.Contains(want, "_Synced:") {
		t.Fatalf("the sync timestamp is back in the render:\n%s", want)
	}
	// The catalog itself must of course still move the bytes.
	changed := &toolCache{Version: 1, URL: "http://localhost:8787/mcp", LastSync: early.LastSync,
		Tools: []tool{{Name: "tools___search_aws", Description: "Search."}, {Name: "tools___other", Description: "Other."}}}
	if borisInstructionsMarkdown(changed) == want {
		t.Fatal("a changed catalog must change the render")
	}
}

// The report is the only signal that a refresh failed: the exit code is pinned
// at 0 on purpose, so a refresh that silently did nothing would leave agents
// reading a stale catalog with nothing anywhere saying so.
func TestDoctorReportsInstructionFilesItCouldNotWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	setupInstallCatalog(t, home, []tool{{Name: "tools___old_tool", Description: "Old description."}})
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o700); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	instructionsPath := filepath.Join(claudeDir, "BORIS.md")
	if err := os.WriteFile(instructionsPath, []byte("# BORIS\n\n- `old_tool`: Old description.\n"), 0o644); err != nil {
		t.Fatalf("write instructions: %v", err)
	}
	// Readable, so the refresh is attempted and gets as far as writing.
	if err := os.Chmod(claudeDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(claudeDir, 0o700) })

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader(""),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  &fakeMCP{tools: []tool{{Name: "tools___new_tool", Description: "New."}}},
		credentials: staticCreds(),
	}
	// Exit 0 regardless: BORIS.md teaches agents to read a failing doctor as
	// "BORIS is broken" and stop, and an unwritable ~/.claude is not that.
	if code := a.run([]string{"doctor"}); code != 0 {
		t.Fatalf("a failed refresh must not fail doctor, exit %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Could not write") {
		t.Fatalf("a failed refresh must be reported, stderr: %s", stderr.String())
	}

	// Prose on stderr is no use to a fleet watching `ok`, which stays true here on
	// purpose. The JSON document has to carry the failure too.
	stdout.Reset()
	stderr.Reset()
	if code := a.run([]string{"doctor", "--json"}); code != 0 {
		t.Fatalf("doctor --json exit %d, stderr: %s", code, stderr.String())
	}
	var payload struct {
		OK           bool `json:"ok"`
		Instructions *struct {
			Refreshed int `json:"refreshed"`
			Failed    int `json:"failed"`
		} `json:"instructions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if payload.Instructions == nil {
		t.Fatalf("doctor --json must report the refresh, got: %s", stdout.String())
	}
	if payload.Instructions.Failed == 0 {
		t.Fatalf("the failed write must be counted, got: %s", stdout.String())
	}
	// Naming a remedy that goes through this same code path and fails the same
	// way would be a per-session instruction to do something that cannot work.
	if strings.Contains(stderr.String(), "bmcp sync` to retry") {
		t.Fatalf("the report should not prescribe a remedy that fails identically: %s", stderr.String())
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

// backupsFor lists the .bak-* copies of a file. Deliberately not filepath.Glob:
// pruneOldBackups abandoned Glob because a directory named like `service[1]` is
// read as pattern syntax and matches nothing while returning no error. These are
// the tests guarding that very decision, so using Glob here would let them pass
// identically against the implementation it was replaced for — and the absence
// assertions would be the ones to go vacuous.
func backupsFor(t *testing.T, path string) []string {
	t.Helper()
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var found []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), base+".bak-") {
			found = append(found, filepath.Join(dir, entry.Name()))
		}
	}
	return found
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

// callApp wires an app around one canned tool result, which is all most of the
// machine-output cases need.
//
// The tool carries a schema with one optional argument. Optional so that a bare
// call is valid, declared so that an undeclared flag is not — which is how these
// cases reach a local validation failure without a second fixture.
func callApp(t *testing.T, result string, stdout, stderr *bytes.Buffer) *app {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	tools := []tool{{
		Name:        "tools___search_aws",
		Description: "Search.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
	}}
	setupInstallCatalog(t, home, tools)
	return &app{
		stdin:  strings.NewReader(""),
		stdout: stdout,
		stderr: stderr,
		now:    time.Now,
		// The same catalog the cache holds, so a command that does sync — `sync`
		// itself — is not answered with an empty-catalog refusal.
		httpClient:  &fakeMCP{tools: tools, callResult: []byte(result)},
		credentials: staticCreds(),
	}
}

// A tool call in a machine format is an envelope, not a bare payload: the caller
// gets the tool it reached, the result, and — the part no payload can carry —
// whether that result is all of it.
func TestToolCallJSONEnvelopeCarriesResultAndCompleteness(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":"{\"ok\":true,\"hits\":2}"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--format", "json", "search_aws"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		OK          bool            `json:"ok"`
		Command     string          `json:"command"`
		Tool        string          `json:"tool"`
		DisplayName string          `json:"display_name"`
		Result      json.RawMessage `json:"result"`
		ResultText  *string         `json:"result_text"`
		ResultBytes int             `json:"result_bytes"`
		Truncated   bool            `json:"truncated"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if !doc.OK || doc.Command != "call" {
		t.Fatalf("unexpected envelope: %s", stdout.String())
	}
	// The full name is what is callable; the display name is the convenience. Both
	// are present for the same reason both are in a catalog record.
	if doc.Tool != "tools___search_aws" || doc.DisplayName != "search_aws" {
		t.Fatalf("unexpected tool identity: %q / %q", doc.Tool, doc.DisplayName)
	}
	// A JSON payload lands in `result` as JSON, not as a string holding JSON: a
	// consumer indexes into it rather than parsing twice.
	var inner struct {
		Hits int `json:"hits"`
	}
	if err := json.Unmarshal(doc.Result, &inner); err != nil || inner.Hits != 2 {
		t.Fatalf("result should be the unwrapped payload as JSON, got %s", doc.Result)
	}
	if doc.ResultText != nil {
		t.Fatalf("a JSON payload must not also appear as text: %q", *doc.ResultText)
	}
	if doc.ResultBytes != len(`{"ok":true,"hits":2}`) || doc.Truncated {
		t.Fatalf("unexpected completeness fields: %d bytes, truncated=%v", doc.ResultBytes, doc.Truncated)
	}
	if stderr.Len() != 0 {
		t.Fatalf("a machine format must leave stderr empty, got: %s", stderr.String())
	}
}

// Not every tool returns JSON. A text payload keeps its own field rather than
// being wrapped into `result`, so the type of `result` never depends on what the
// server happened to send.
func TestToolCallJSONEnvelopeSeparatesTextResults(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":"no matching resources"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--format", "json", "search_aws"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		Result     json.RawMessage `json:"result"`
		ResultText *string         `json:"result_text"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if doc.Result != nil {
		t.Fatalf("a text payload must not appear as result: %s", doc.Result)
	}
	if doc.ResultText == nil || *doc.ResultText != "no matching resources" {
		t.Fatalf("expected the text in result_text, got %v", doc.ResultText)
	}
}

// json is indented and ndjson is one line, for every command. Asserted on the
// bytes, not on the parsed value: the earlier version of this test unmarshalled
// both and compared the maps, so it passed while `--format json` was quietly
// emitting the compact form for seven of nine commands — flags.output was being
// threaded into encodeMachineDoc, and that field can never hold "json".
func TestJSONIsIndentedAndNDJSONIsOneLineForEveryCommand(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		// sameDoc compares the two documents for equality. False for `list`, whose
		// ndjson is a record stream rather than the enveloped document — the one
		// carve-out in the contract — and for `install`, which honestly reports
		// changed:false the second time because the files already match.
		sameDoc bool
	}{
		{name: "version", args: []string{"version"}, sameDoc: true},
		{name: "sync", args: []string{"sync"}, sameDoc: true},
		{name: "doctor", args: []string{"doctor"}, sameDoc: true},
		{name: "list", args: []string{"list"}},
		{name: "describe", args: []string{"describe", "search_aws"}, sameDoc: true},
		{name: "call", args: []string{"search_aws"}, sameDoc: true},
		{name: "install", args: []string{"install", "claude-code"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			// One app, so both runs see the same home and the documents differ only
			// in the way this test is about.
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{\"ok\":true}"}]}`, &stdout, &stderr)
			run := func(format string) string {
				stdout.Reset()
				args := append([]string{"--non-interactive", "--format", format}, tc.args...)
				if code := a.run(args); code != 0 {
					t.Fatalf("--format %s exit %d, stderr: %s", format, code, stderr.String())
				}
				return stdout.String()
			}
			indented, compact := run("json"), run("ndjson")
			if lines := strings.Count(strings.TrimSuffix(compact, "\n"), "\n"); lines != 0 {
				t.Fatalf("ndjson must be one line, got %d newlines:\n%s", lines, compact)
			}
			// The property the earlier version of this test missed: it unmarshalled
			// both and compared the maps, so it passed while --format json was
			// quietly emitting the compact form for seven of nine commands.
			if !strings.Contains(indented, "\n  \"") {
				t.Fatalf("json must be indented, got: %q", indented)
			}
			if !tc.sameDoc {
				return
			}
			var a1, a2 map[string]any
			if err := json.Unmarshal([]byte(indented), &a1); err != nil {
				t.Fatalf("json is not one document: %v\n%s", err, indented)
			}
			if err := json.Unmarshal([]byte(compact), &a2); err != nil {
				t.Fatalf("ndjson is not one document: %v\n%s", err, compact)
			}
			if !reflect.DeepEqual(a1, a2) {
				t.Fatalf("the two formats should differ only in whitespace:\n%v\n%v", a1, a2)
			}
		})
	}
}

// A legacy invocation writes no document to stdout. `sync` and `install` are the
// two whose contract guard nothing else pins, and both are side-effecting, so a
// stray document there would be the easiest kind of regression to miss.
func TestLegacyCommandsWriteNoDocumentToStdout(t *testing.T) {
	for _, args := range [][]string{
		{"sync"},
		{"install", "claude-code"},
		{"--json", "sync"},
		{"--output", "json", "sync"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Chdir(t.TempDir())
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(append([]string{"--non-interactive"}, args...)); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("no --format means no document, got stdout: %q", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Fatalf("the prose these commands have always printed should still be there")
			}
		})
	}
}

// --help is prose in every format, which is a documented exception rather than a
// hole: it is a request for the human text, and stdout carrying it is the answer.
func TestHelpStaysProseUnderTheContract(t *testing.T) {
	for _, args := range [][]string{
		{"--format", "json", "--help"},
		{"--format", "ndjson", "--help"},
		{"--format", "json", "help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("--help should answer with usage, got: %s", stdout.String())
			}
		})
	}
}

// --max-bytes is the only sanctioned way to shorten a result, and what earns it
// that is the marker: `truncated` set, and the full `result_bytes` reported, so
// a clipped answer never reads as a complete one.
func TestMaxBytesMarksATruncatedResultInsteadOfSilentlyClippingIt(t *testing.T) {
	payload := `{"items":["aaaaaaaaaa","bbbbbbbbbb","cccccccccc"]}`
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":`+strconv.Quote(payload)+`}]}`, &stdout, &stderr)
	if code := a.run([]string{"--format", "json", "--max-bytes", "12", "search_aws"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		Result      json.RawMessage `json:"result"`
		ResultText  *string         `json:"result_text"`
		ResultBytes int             `json:"result_bytes"`
		Truncated   bool            `json:"truncated"`
		Excerpt     string          `json:"result_excerpt"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("a truncated result must still be a parseable document: %v\n%s", err, stdout.String())
	}
	if !doc.Truncated || doc.ResultBytes != len(payload) {
		t.Fatalf("expected truncated=true and the full size, got %v / %d", doc.Truncated, doc.ResultBytes)
	}
	// The clipped bytes are text, never `result`: a prefix of a JSON document is
	// not a JSON document, and offering one as `result` would hand the consumer a
	// parse error where it asked for a truncation flag.
	if doc.Result != nil || doc.ResultText != nil {
		t.Fatalf("a clipped payload must appear only as an excerpt: %s / %v", doc.Result, doc.ResultText)
	}
	if doc.Excerpt != payload[:12] {
		t.Fatalf("excerpt should be the kept prefix, got %q", doc.Excerpt)
	}
	// Under the cap nothing changes, so `truncated` is a fact about this result
	// rather than about the flag being present.
	stdout.Reset()
	if code := a.run([]string{"--format", "json", "--max-bytes", "8192", "search_aws"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Truncated || doc.Result == nil {
		t.Fatalf("a result under the cap should be complete: %s", stdout.String())
	}
}

// The human format has no field to carry the flag, so it says so in prose. A
// clipped JSON payload does not parse, and this line is the difference between
// that and a server that returned something malformed.
func TestMaxBytesReportsTruncationInTheHumanFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":"{\"ok\":true,\"hits\":2}"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--max-bytes", "5", "search_aws"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "{\"ok\"\n" {
		t.Fatalf("stdout should carry the kept prefix, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Truncated to 5 of 20 bytes") {
		t.Fatalf("stderr should say the payload is incomplete, got: %s", stderr.String())
	}
}

// Cutting mid-rune would put a replacement character in the excerpt and make it
// disagree with the prefix of the payload it claims to be.
func TestMaxBytesCutsOnARuneBoundary(t *testing.T) {
	// Written as escapes rather than literals: the point of the test is which
	// byte the cut lands on, and a source file that normalised a two-byte rune
	// into a letter plus a combining mark would silently change that.
	const s = "\u00fcber" // 5 bytes: the u-umlaut is two of them.
	for _, tc := range []struct {
		max  int
		want string
	}{
		// A cap that would split the leading rune keeps nothing rather than half
		// of it, which is the case a plain slice gets wrong.
		{1, ""},
		{2, "\u00fc"},
		{3, "\u00fcb"},
		{99, s},
		// Zero is "no limit", not "keep nothing" — see parseMaxBytes.
		{0, s},
	} {
		if got := string(truncateBytes([]byte(s), tc.max)); got != tc.want {
			t.Fatalf("truncateBytes(%q, %d) = %q, want %q", s, tc.max, got, tc.want)
		}
	}
}

func TestMaxBytesRejectsNonPositiveValues(t *testing.T) {
	for _, v := range []string{"0", "-1", "lots", "8k", ""} {
		t.Run(v, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run([]string{"--max-bytes", v, "search_aws"}); code != exitValidation {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("a rejected flag must not call the tool: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), "--max-bytes") {
				t.Fatalf("stderr should name the offending flag, got: %s", stderr.String())
			}
		})
	}
}

// The headline property of the contract, stated as the thing agents actually do.
// 322 of 907 audited shell calls post-processed BMCP output, and merging stderr
// into stdout to keep hold of errors is what made valid payloads unparseable.
// Both outcomes have to survive the merge, or the merge remains unsafe and the
// plumbing comes back.
func TestMachineFormatSurvivesMergedStreams(t *testing.T) {
	for _, format := range []string{"json", "ndjson"} {
		t.Run(format, func(t *testing.T) {
			// One buffer standing in for `2>&1`: both streams write to it, in order.
			var merged bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{\"ok\":true}"}]}`, &merged, &merged)
			if code := a.run([]string{"--format", format, "search_aws"}); code != 0 {
				t.Fatalf("exit code %d, merged: %s", code, merged.String())
			}
			var doc map[string]any
			if err := json.Unmarshal(merged.Bytes(), &doc); err != nil {
				t.Fatalf("merged success stream is not one document: %v\n%s", err, merged.String())
			}
			if doc["ok"] != true {
				t.Fatalf("expected ok=true, got: %s", merged.String())
			}
			// The failure half. The tool is real and the flag is not, so this fails
			// after the same progress prose a success would have printed.
			merged.Reset()
			if code := a.run([]string{"--format", format, "search_aws", "--nonsense", "x"}); code == 0 {
				t.Fatalf("expected a failure, merged: %s", merged.String())
			}
			if err := json.Unmarshal(merged.Bytes(), &doc); err != nil {
				t.Fatalf("merged failure stream is not one document: %v\n%s", err, merged.String())
			}
			if doc["ok"] != false {
				t.Fatalf("expected ok=false, got: %s", merged.String())
			}
		})
	}
}

// One invocation, one document — including on the paths that report through
// more than one layer. An unconfigured machine used to run first-run setup from
// inside requireConfig, and cmdInit reports its own failures: in a machine format
// that put cmdInit's error document and the caller's on stderr back to back,
// which is not a parseable stream however good either document is.
func TestUnconfiguredMachineInvocationEmitsExactlyOneDocument(t *testing.T) {
	for _, format := range []string{"json", "ndjson"} {
		t.Run(format, func(t *testing.T) {
			t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
				// Interactive, which is what used to trigger the first-run setup. A
				// machine format declines it: there is no channel left to ask on.
				interactive: func() bool { return true },
			}
			if code := a.run([]string{"--format", format, "list"}); code != exitConfig {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			var doc struct {
				OK      bool   `json:"ok"`
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			// Two documents back to back fail this parse; one does not.
			if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
				t.Fatalf("stderr should be exactly one document: %v\n%s", err, stderr.String())
			}
			if doc.OK || doc.Error != "not_configured" {
				t.Fatalf("unexpected error document: %+v", doc)
			}
			// The full guidance survives into the message rather than being replaced
			// by the "first-run setup failed" the inner call used to produce.
			if !strings.Contains(doc.Message, "bmcp init --url") {
				t.Fatalf("the message should still say how to configure it, got %q", doc.Message)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failure must not write to stdout, got %q", stdout.String())
			}
		})
	}
}

// The JSON-argument call form, which issue #34 names in scope alongside the
// `bmcp <tool> --arg value` one. Every other machine-format call assertion goes
// through the dynamic form, so without this a `cmdCall` that ignored the format
// entirely would pass the suite.
func TestJSONFormToolCallAnswersInTheSelectedFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":"{\"hits\":1}"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--format", "json", "call", "search_aws", `{"query":"x"}`}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		OK      bool            `json:"ok"`
		Command string          `json:"command"`
		Tool    string          `json:"tool"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if !doc.OK || doc.Command != "call" || doc.Tool != "tools___search_aws" {
		t.Fatalf("unexpected envelope: %s", stdout.String())
	}
	// Decoded rather than byte-compared: --output json indents the whole document,
	// and json.RawMessage is indented along with everything around it.
	var inner struct {
		Hits int `json:"hits"`
	}
	if err := json.Unmarshal(doc.Result, &inner); err != nil || inner.Hits != 1 {
		t.Fatalf("unexpected result: %s", doc.Result)
	}
	// The same call reads its payload from stdin when none is given, and that path
	// must reach the same document rather than bypassing the format.
	stdout.Reset()
	a.stdin = strings.NewReader(`{"query":"x"}`)
	if code := a.run([]string{"--format", "json", "call", "search_aws"}); code != 0 {
		t.Fatalf("stdin form exit code %d, stderr: %s", code, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("the stdin form should answer with the same document: %v\n%s", err, stdout.String())
	}
	if !doc.OK || doc.Command != "call" {
		t.Fatalf("unexpected envelope from the stdin form: %s", stdout.String())
	}
}

// --max-bytes caps what is actually written, so it composes with the two flags
// that change what that is. Under --raw it caps the envelope rather than the
// unwrapped payload; under --pretty it caps the indented bytes, not the compact
// ones they were reformatted from.
func TestMaxBytesComposesWithRawAndPretty(t *testing.T) {
	const envelope = `{"content":[{"type":"text","text":"{\"ok\":true}"}]}`
	t.Run("raw", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		a := callApp(t, envelope, &stdout, &stderr)
		if code := a.run([]string{"--format", "json", "--raw", "--max-bytes", "12", "search_aws"}); code != 0 {
			t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
		}
		var doc struct {
			ResultBytes int     `json:"result_bytes"`
			Truncated   bool    `json:"truncated"`
			Excerpt     *string `json:"result_excerpt"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, stdout.String())
		}
		// The envelope, not the 11-byte payload inside it — which would not have
		// been truncated at all.
		if !doc.Truncated || doc.ResultBytes != len(envelope) {
			t.Fatalf("--raw should cap the envelope, got %d bytes truncated=%v", doc.ResultBytes, doc.Truncated)
		}
		if doc.Excerpt == nil || *doc.Excerpt != envelope[:12] {
			t.Fatalf("unexpected excerpt: %v", doc.Excerpt)
		}
	})
	t.Run("pretty", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		a := callApp(t, envelope, &stdout, &stderr)
		if code := a.run([]string{"--pretty", "--max-bytes", "8", "search_aws"}); code != 0 {
			t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
		}
		// `{"ok":true}` is 11 bytes compact and 16 indented. Reporting 16 is what
		// says the cap was applied to what was actually written.
		if !strings.Contains(stderr.String(), "Truncated to 8 of 16 bytes") {
			t.Fatalf("--max-bytes should cap the indented payload, got: %s", stderr.String())
		}
		if stdout.String() != "{\n  \"ok\"\n" {
			t.Fatalf("unexpected truncated stdout: %q", stdout.String())
		}
	})
}

// A cap smaller than the payload's first rune keeps no bytes. `truncated` still
// says so, and the excerpt is present-and-empty rather than absent — a missing
// key reads as a different kind of answer.
func TestMaxBytesKeepsAnEmptyExcerptPresent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// The payload opens with a two-byte rune, so a one-byte cap can keep nothing.
	a := callApp(t, `{"content":[{"type":"text","text":"über"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--format", "json", "--max-bytes", "1", "search_aws"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		Truncated bool    `json:"truncated"`
		Excerpt   *string `json:"result_excerpt"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, stdout.String())
	}
	if !doc.Truncated {
		t.Fatalf("expected truncated=true, got: %s", stdout.String())
	}
	if doc.Excerpt == nil || *doc.Excerpt != "" {
		t.Fatalf("expected a present, empty excerpt, got %v", doc.Excerpt)
	}
}

// One invalid byte anywhere before the cut used to walk the excerpt back to
// empty — truncateBytes shortened while the whole prefix failed utf8.Valid, so
// a --raw payload or an unrecognised envelope, neither of which is laundered to
// U+FFFD, lost its excerpt entirely and took quadratic time doing it.
func TestTruncateKeepsThePrefixAroundInvalidUTF8(t *testing.T) {
	payload := append([]byte{0xff}, bytes.Repeat([]byte("a"), 1000)...)
	got := truncateBytes(payload, 100)
	if len(got) != 100 {
		t.Fatalf("an invalid byte before the cut must not shorten the excerpt, got %d bytes", len(got))
	}
	if !bytes.Equal(got, payload[:100]) {
		t.Fatalf("the excerpt should be the payload's own prefix, got %q", got)
	}
}

// exit_code is in the failure document because the audit found 11 rejected calls
// that read as successes: a following pipeline command replaced BMCP's exit
// status with its own, and nothing in the output disagreed.
func TestErrorDocumentNamesTheCommandAndCarriesTheExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--format", "json", "search_aws", "--nonsense", "x"}); code != exitValidation {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		OK       bool   `json:"ok"`
		Command  string `json:"command"`
		Error    string `json:"error"`
		Message  string `json:"message"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
		t.Fatalf("stderr is not a single JSON document: %v\n%s", err, stderr.String())
	}
	if doc.OK || doc.Error != "tool_validation_failed" || doc.ExitCode != exitValidation {
		t.Fatalf("unexpected error document: %+v", doc)
	}
	if doc.Command != "call" {
		t.Fatalf("a failed tool call should report the call command, got %q", doc.Command)
	}
	if stdout.Len() != 0 {
		t.Fatalf("a failure must not write to stdout, got %q", stdout.String())
	}
}

// describe had no machine form at all, so an agent that wanted a schema had to
// parse indented prose or call `list --schemas` and filter it. The schema is
// unconditional here: describe is the command asked when a payload is about to
// be written.
func TestDescribeJSONCarriesTheSchemaInTheCatalogRecordShape(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{
		Name:        "tools___search_aws",
		Description: "Search.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`),
	}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	if code := a.run([]string{"--non-interactive", "describe", "search_aws", "--format", "json"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Tool    struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
			InputSchema struct {
				Required []string `json:"required"`
			} `json:"input_schema"`
		} `json:"tool"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if !doc.OK || doc.Command != "describe" {
		t.Fatalf("unexpected envelope: %s", stdout.String())
	}
	if doc.Tool.Name != "tools___search_aws" || doc.Tool.DisplayName != "search_aws" {
		t.Fatalf("unexpected tool identity: %+v", doc.Tool)
	}
	if len(doc.Tool.InputSchema.Required) != 1 || doc.Tool.InputSchema.Required[0] != "query" {
		t.Fatalf("the schema should arrive verbatim, got %+v", doc.Tool.InputSchema)
	}
	// Without --output it is still the indented text a person reads.
	stdout.Reset()
	if code := a.run([]string{"--non-interactive", "describe", "search_aws"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Arguments:") {
		t.Fatalf("the default describe should stay human, got: %s", stdout.String())
	}
}

// Every command answers in the selected format. A command that stayed silent in
// a machine format would leave the caller unable to tell success from a command
// that does not exist.
//
// `want` checks a field only that command's document carries, so a command whose
// body was gutted down to ok/command still fails here.
func TestEveryCommandAnswersInTheSelectedMachineFormat(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want func(*testing.T, map[string]any)
	}{
		{name: "version", args: []string{"version"}, want: func(t *testing.T, doc map[string]any) {
			if doc["version"] == "" || doc["version"] == nil {
				t.Fatalf("version document should carry the version: %v", doc)
			}
		}},
		{name: "sync", args: []string{"sync"}, want: func(t *testing.T, doc map[string]any) {
			if doc["count"] != float64(1) || doc["tools_path"] == nil {
				t.Fatalf("sync document should carry the catalog size and path: %v", doc)
			}
		}},
		{name: "doctor", args: []string{"doctor"}, want: func(t *testing.T, doc map[string]any) {
			if doc["checks"] == nil || doc["mode"] == nil {
				t.Fatalf("doctor document should carry checks and mode: %v", doc)
			}
			// exit_code, for the reason the failure document carries it — doctor is
			// the command most often piped into jq.
			if doc["exit_code"] != float64(0) {
				t.Fatalf("a passing doctor should report exit_code 0: %v", doc)
			}
		}},
		{name: "list", args: []string{"list"}, want: func(t *testing.T, doc map[string]any) {
			if doc["count"] != float64(1) {
				t.Fatalf("list document should carry a count: %v", doc)
			}
		}},
		{name: "describe", args: []string{"describe", "search_aws"}, want: func(t *testing.T, doc map[string]any) {
			tool, _ := doc["tool"].(map[string]any)
			if tool == nil || tool["input_schema"] == nil {
				t.Fatalf("describe document should carry the schema: %v", doc)
			}
		}},
		{name: "call", args: []string{"search_aws"}, want: func(t *testing.T, doc map[string]any) {
			if doc["tool"] != "tools___search_aws" || doc["result_bytes"] == nil {
				t.Fatalf("call document should identify the tool and its size: %v", doc)
			}
		}},
		{name: "install", args: []string{"install", "claude-code"}, want: func(t *testing.T, doc map[string]any) {
			if doc["scope"] != "user" {
				t.Fatalf("install document should carry the scope: %v", doc)
			}
			files, _ := doc["files"].([]any)
			if len(files) == 0 {
				t.Fatalf("install document should list the files it wrote: %v", doc)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A directory of its own: `sync` refreshes project-scope instruction
			// files in the working directory, and the package directory is where the
			// test binary runs. Adding a CLAUDE.md there would otherwise make this
			// test rewrite a tracked file.
			t.Chdir(t.TempDir())
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			args := append([]string{"--non-interactive", "--format", "json"}, tc.args...)
			if code := a.run(args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			var doc map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
				t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
			}
			if doc["ok"] != true || doc["command"] != tc.name {
				t.Fatalf("expected an ok %q document, got: %s", tc.name, stdout.String())
			}
			tc.want(t, doc)
			if stderr.Len() != 0 {
				t.Fatalf("a machine format must leave stderr empty, got: %s", stderr.String())
			}
		})
	}
}

// init reports its own document and exactly one: it calls the sync path, which
// has a document of its own to emit and must not.
func TestInitAnswersWithOneDocumentAndASanitizedURL(t *testing.T) {
	t.Chdir(t.TempDir())
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BMCP_HOME", filepath.Join(home, ".bmcp"))
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient:  &fakeMCP{tools: []tool{{Name: "tools___search_aws", Description: "Search."}}},
		credentials: staticCreds(),
		// Interactive, to pin that a machine format declines to prompt rather than
		// blocking on a question the caller cannot see.
		interactive: func() bool { return true },
	}
	if code := a.run([]string{"--format", "json", "init", "--url", "https://user:secret@example.invalid/mcp"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		OK         bool   `json:"ok"`
		Command    string `json:"command"`
		ConfigPath string `json:"config_path"`
		URL        string `json:"url"`
	}
	// Two documents — init's and the sync it triggers — fail this parse.
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout should be exactly one document: %v\n%s", err, stdout.String())
	}
	if !doc.OK || doc.Command != "init" || doc.ConfigPath == "" {
		t.Fatalf("unexpected document: %s", stdout.String())
	}
	if strings.Contains(doc.URL, "secret") {
		t.Fatalf("the URL must be sanitized before it reaches the document: %q", doc.URL)
	}
}

// The schema-change refusal is the one failure carrying structured detail, and
// the shape #40 will extend with retryability.
func TestSchemaChangeRefusalIsAStructuredFailureDocument(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	// A stale cache holding the old schema, against a server serving a new one:
	// the call syncs, sees the hash move, and refuses rather than calling with
	// arguments the agent chose from the schema it read.
	old := []tool{{
		Name: "tools___search_aws", Description: "Search.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
	}}
	old[0].SchemaHash = schemaHash(old[0].InputSchema)
	if err := writeCache(filepath.Join(borisHome, "tools.json"), &toolCache{
		Version: 1, URL: "http://localhost:8787/mcp", Tools: old,
		LastSync: time.Now().Add(-defaultTTL - time.Hour),
	}); err != nil {
		t.Fatalf("writeCache: %v", err)
	}
	fresh := []tool{{
		Name: "tools___search_aws", Description: "Search.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"cypher":{"type":"string"}}}`),
	}}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient:  &fakeMCP{tools: fresh, callResult: []byte(`{"content":[{"type":"text","text":"{}"}]}`)},
		credentials: staticCreds(),
	}
	// The `call` form, not `bmcp <tool>`: cmdDynamic resolves the name against the
	// catalog first and syncs while doing it, so by the time runCall compares
	// LastSync the advance has already been consumed and the guard cannot fire.
	// That is #17, which this test deliberately does not try to fix — it pins the
	// shape of the refusal on the path that still reaches it.
	if code := a.run([]string{"--non-interactive", "--format", "json", "call", "search_aws", "{}"}); code != exitSync {
		t.Fatalf("exit code %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	var doc struct {
		OK       bool                `json:"ok"`
		Command  string              `json:"command"`
		Error    string              `json:"error"`
		ExitCode int                 `json:"exit_code"`
		Tool     string              `json:"tool"`
		Changes  []map[string]string `json:"changes"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
		t.Fatalf("stderr is not a single JSON document: %v\n%s", err, stderr.String())
	}
	if doc.OK || doc.Error != "tool_schema_changed" || doc.ExitCode != exitSync {
		t.Fatalf("unexpected error document: %+v", doc)
	}
	if doc.Tool != "tools___search_aws" || len(doc.Changes) == 0 {
		t.Fatalf("the refusal should name the tool and what changed: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("the tool was not called, so stdout must be empty: %q", stdout.String())
	}
}

// A failure document is one line in both machine formats — the one place the
// output does not follow --output. --json used to mean errors and nothing else,
// so every pre-existing --json caller is an error-document caller, and indenting
// under --output json would break `tail -1` and `read -r line` for all of them.
func TestFailureDocumentsAreAlwaysOneLine(t *testing.T) {
	for _, format := range []string{"json", "ndjson"} {
		t.Run(format, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run([]string{"--format", format, "search_aws", "--nonsense", "x"}); code != exitValidation {
				t.Fatalf("exit code %d", code)
			}
			// The message itself is multi-line; it has to survive as one JSON string.
			if lines := strings.Count(strings.TrimSuffix(stderr.String(), "\n"), "\n"); lines != 0 {
				t.Fatalf("a failure document must be one line, got %d newlines:\n%s", lines, stderr.String())
			}
			var doc struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
				t.Fatalf("unmarshal: %v\n%s", err, stderr.String())
			}
			if !strings.Contains(doc.Message, "\n") {
				t.Fatalf("the multi-line message should survive into the JSON string: %q", doc.Message)
			}
		})
	}
}

// The failure document names the command even when the failure happens before
// dispatch, and reports whichever exit code bmcp is about to exit with.
func TestFailureDocumentsNameTheCommandAndCodeBeforeDispatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantCmd  string
		wantErr  string
		wantCode int
	}{
		{name: "unknown flag", args: []string{"--format", "json", "list", "--bogus"},
			wantCmd: "list", wantErr: "invalid_flags", wantCode: exitGeneric},
		{name: "bad max-bytes", args: []string{"--format", "json", "list", "--max-bytes", "0"},
			wantCmd: "list", wantErr: "invalid_max_bytes", wantCode: exitValidation},
		{name: "usage", args: []string{"--format", "json", "describe"},
			wantCmd: "describe", wantErr: "usage", wantCode: exitValidation},
		// Globally positioned, which is the ordering the docs give for --max-bytes —
		// so the command has to be named before the global flags are validated, or
		// the document that reports the bad value cannot say where it happened.
		{name: "global max-bytes on a tool call", args: []string{"--format", "json", "--max-bytes", "0", "search_aws"},
			wantCmd: "call", wantErr: "invalid_max_bytes", wantCode: exitValidation},
		{name: "global max-bytes on a command", args: []string{"--format", "json", "--max-bytes", "0", "list"},
			wantCmd: "list", wantErr: "invalid_max_bytes", wantCode: exitValidation},
		// No command at all. A bare machine-format invocation is an unfinished
		// command line, not a request for help, so it fails rather than writing
		// usage prose into a parser.
		{name: "no command", args: []string{"--format", "json"},
			wantCmd: "", wantErr: "usage", wantCode: exitValidation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(tc.args); code != tc.wantCode {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			var doc struct {
				OK       bool   `json:"ok"`
				Command  string `json:"command"`
				Error    string `json:"error"`
				ExitCode int    `json:"exit_code"`
			}
			if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
				t.Fatalf("stderr is not a single JSON document: %v\n%s", err, stderr.String())
			}
			if doc.OK || doc.Error != tc.wantErr || doc.ExitCode != tc.wantCode {
				t.Fatalf("unexpected error document: %+v", doc)
			}
			if doc.Command != tc.wantCmd {
				t.Fatalf("expected command %q, got %q", tc.wantCmd, doc.Command)
			}
			if stdout.Len() != 0 {
				t.Fatalf("a failure must not write to stdout, got %q", stdout.String())
			}
		})
	}
}

// A format named anywhere on the line is the format the failure is reported in.
// parseFlags used to return on the first unknown flag, so `bmcp list --bogus
// --output json` failed as prose while `bmcp list --output json --bogus` failed
// as a document — the same invocation answering differently on flag order alone.
func TestFailureFormatDoesNotDependOnFlagOrder(t *testing.T) {
	for _, args := range [][]string{
		{"list", "--bogus", "--format", "json"},
		{"list", "--format", "json", "--bogus"},
		{"--bogus", "--format", "json", "list"},
		{"--format", "json", "--bogus", "list"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(append([]string{"--non-interactive"}, args...)); code != exitGeneric {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			var doc struct {
				OK      bool   `json:"ok"`
				Error   string `json:"error"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
				t.Fatalf("stderr should be a document whatever the flag order: %v\n%s", err, stderr.String())
			}
			// The first error is the one reported, not whichever the scan ended on.
			if doc.OK || doc.Error != "invalid_flags" || !strings.Contains(doc.Message, "--bogus") {
				t.Fatalf("unexpected error document: %+v", doc)
			}
		})
	}
}

// A caller who has not successfully named a machine format is not owed one. The
// fallback used to be ndjson, so a typo in --output was answered with a JSON
// document instead of the sentence explaining the typo.
func TestRejectedOutputValueIsReportedInProse(t *testing.T) {
	for _, args := range [][]string{
		{"list", "--output", "huamn"},
		{"--output=", "list"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(append([]string{"--non-interactive"}, args...)); code != exitValidation {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if strings.HasPrefix(strings.TrimSpace(stderr.String()), "{") {
				t.Fatalf("a bad --output must not be reported as a document: %s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "Supported values") {
				t.Fatalf("stderr should list the accepted values, got: %s", stderr.String())
			}
		})
	}
}

// The compatibility boundary, stated as the outputs a caller on an older release
// already parses. Installed binaries self-update, so every one of these reaches
// every machine automatically on its next `bmcp doctor` — none of them may move.
func TestLegacyFlagsKeepTheirExactOutput(t *testing.T) {
	t.Run("json leaves a tool call payload bare", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		a := callApp(t, `{"content":[{"type":"text","text":"{\"hits\":1}"}]}`, &stdout, &stderr)
		if code := a.run([]string{"--json", "search_aws"}); code != 0 {
			t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
		}
		// The payload itself, not an envelope around it. `jq .hits` still works.
		if stdout.String() != "{\"hits\":1}\n" {
			t.Fatalf("--json must not envelope a successful call, got %q", stdout.String())
		}
	})
	t.Run("json error shape gains no fields", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
		if code := a.run([]string{"--json", "search_aws", "--nonsense", "x"}); code != exitValidation {
			t.Fatalf("exit code %d", code)
		}
		var doc map[string]any
		if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, stderr.String())
		}
		// Exactly the three keys --json has always emitted. `command` and
		// `exit_code` belong to the contract document and must not leak here: a
		// consumer asserting on the key set would break on its next auto-update.
		if len(doc) != 3 || doc["ok"] != false || doc["error"] == nil || doc["message"] == nil {
			t.Fatalf("the legacy error shape must not gain fields: %v", doc)
		}
	})
	t.Run("output json on list is still ndjson", func(t *testing.T) {
		var plain, aliased, stderr bytes.Buffer
		a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &plain, &stderr)
		if code := a.run([]string{"--non-interactive", "list"}); code != 0 {
			t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
		}
		a.stdout = &aliased
		if code := a.run([]string{"--non-interactive", "list", "--output", "json"}); code != 0 {
			t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
		}
		if aliased.String() != plain.String() {
			t.Fatalf("--output json is still an alias for ndjson:\n got: %q\nwant: %q", aliased.String(), plain.String())
		}
	})
	t.Run("doctor json report gains no fields", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
		if code := a.run([]string{"--non-interactive", "doctor", "--json"}); code != 0 {
			t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, stdout.String())
		}
		for _, key := range []string{"command", "exit_code"} {
			if _, present := doc[key]; present {
				t.Fatalf("the legacy doctor report must not gain %q: %v", key, doc)
			}
		}
		if doc["ok"] == nil || doc["checks"] == nil || doc["mode"] == nil {
			t.Fatalf("the legacy doctor report lost a field: %v", doc)
		}
	})
	t.Run("schema change refusal keeps its own json shape", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
		old := []tool{{
			Name: "tools___search_aws", Description: "Search.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
		}}
		old[0].SchemaHash = schemaHash(old[0].InputSchema)
		if err := writeCache(filepath.Join(borisHome, "tools.json"), &toolCache{
			Version: 1, URL: "http://localhost:8787/mcp", Tools: old,
			LastSync: time.Now().Add(-defaultTTL - time.Hour),
		}); err != nil {
			t.Fatalf("writeCache: %v", err)
		}
		var stdout, stderr bytes.Buffer
		a := &app{
			stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
			httpClient: &fakeMCP{tools: []tool{{
				Name: "tools___search_aws", Description: "Search.",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"cypher":{"type":"string"}}}`),
			}}, callResult: []byte(`{"content":[{"type":"text","text":"{}"}]}`)},
			credentials: staticCreds(),
		}
		if code := a.run([]string{"--non-interactive", "--json", "call", "search_aws", "{}"}); code != exitSync {
			t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
		}
		// The last line, because in legacy mode "Syncing tools..." shares stderr with
		// the document — which is the plumbing the contract exists to remove, and
		// which stays exactly as it was for a caller that has not opted in.
		lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
		var doc map[string]any
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &doc); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, stderr.String())
		}
		// tool and changes, and no message — the shape this one failure has always
		// had under --json, which is not the shape fail() produces.
		if doc["error"] != "tool_schema_changed" || doc["tool"] == nil || doc["changes"] == nil {
			t.Fatalf("the legacy refusal shape changed: %v", doc)
		}
	})
}

// --format human is a selection too. It asks for prose, so the legacy --json
// must not answer with its JSON report — "machine format" alone does not cover
// this, since human is not one.
func TestFormatHumanSupersedesLegacyJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--non-interactive", "--json", "--format", "human", "doctor"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), `"checks"`) {
		t.Fatalf("--format human must suppress the legacy JSON report, got: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "config") {
		t.Fatalf("expected human check rows, got: %s", stdout.String())
	}
	// And a failure under --format human is prose, not the legacy error document.
	stdout.Reset()
	stderr.Reset()
	if code := a.run([]string{"--non-interactive", "--json", "--format", "human", "describe"}); code != exitValidation {
		t.Fatalf("exit code %d", code)
	}
	if strings.HasPrefix(strings.TrimSpace(stderr.String()), "{") {
		t.Fatalf("--format human must render failures as prose, got: %s", stderr.String())
	}
}

// The legacy doctor report is frozen down to its bytes, not just its key set.
// It has always been HTML-escaped, because it was marshalled with
// json.MarshalIndent; encodeMachineDoc turns escaping off, so routing the legacy
// path through it would have changed the output of any machine whose config path
// or URL contains &, < or >.
func TestLegacyDoctorReportKeepsItsHTMLEscaping(t *testing.T) {
	home := t.TempDir()
	// A directory the escaping is observable in. The config path goes into the
	// report verbatim.
	borisHome := filepath.Join(home, "a&b")
	t.Setenv("HOME", home)
	t.Setenv("BMCP_HOME", borisHome)
	if err := os.MkdirAll(borisHome, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(borisHome, "config.toml"), []byte("url = \"http://localhost:8787/mcp\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("BMCP_AUTO_UPDATE", "0")
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	a.run([]string{"--non-interactive", "doctor", "--json"})
	if !strings.Contains(stdout.String(), `a\u0026b`) {
		t.Fatalf("the legacy report must stay HTML-escaped, got: %s", stdout.String())
	}
	// The contract report is the one that turns escaping off, so grepping raw
	// output for what a tool actually said works there.
	stdout.Reset()
	a.run([]string{"--non-interactive", "doctor", "--format", "json"})
	if !strings.Contains(stdout.String(), "a&b") {
		t.Fatalf("the contract report should not escape, got: %s", stdout.String())
	}
}

// The self-update path has always been silent under the legacy --json: every one
// of those sites sat behind `if !flags.jsonOut`. Routing them through prose()
// alone would have started showing update notices to every `doctor --json`
// caller on their next automatic update.
func TestLegacyJSONStillSilencesUpdateProse(t *testing.T) {
	var stderr bytes.Buffer
	a := &app{stdout: &bytes.Buffer{}, stderr: &stderr, now: time.Now}
	st := &updateState{Current: "1.0.0", Target: "2.0.0", Available: true, Action: "bmcp update"}
	a.nudge(globalFlags{jsonOut: true}, st)
	a.warnUpdate(globalFlags{jsonOut: true}, "Could not update bmcp automatically: %v", errors.New("boom"))
	if stderr.Len() != 0 {
		t.Fatalf("--json must silence the update path, got: %s", stderr.String())
	}
	// Recorded even so, because a --format document has a field to carry it.
	if len(a.warnings) != 1 {
		t.Fatalf("the warning should still be recorded for a machine document, got %v", a.warnings)
	}
	// Without --json it is prose, as it always was.
	stderr.Reset()
	a.nudge(globalFlags{}, st)
	if !strings.Contains(stderr.String(), "bmcp 2.0.0 is available") {
		t.Fatalf("a plain invocation should still be nudged, got: %s", stderr.String())
	}
}

// A --format anywhere the parser would legitimately have looked decides how a
// failure is reported, even one raised before the parser got there — parsing
// stops at the first unknown flag, which is what every legacy caller sees and
// must keep seeing.
func TestFormatIsFoundWhereverItSitsOnTheLine(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		document bool
	}{
		{args: []string{"list", "--format", "json", "--bogus"}, document: true},
		{args: []string{"list", "--bogus", "--format", "json"}, document: true},
		{args: []string{"--bogus", "list", "--format", "json"}, document: true},
		{args: []string{"--format", "json", "--bogus", "list"}, document: true},
		{args: []string{"--format=json", "--bogus", "list"}, document: true},
		{args: []string{"--max-bytes", "0", "list", "--format", "json"}, document: true},
		// Legacy, and it must stay prose: continuing the scan past the unknown flag
		// is what would have turned this into a document.
		{args: []string{"list", "--bogus", "--json"}, document: false},
		{args: []string{"list", "--bogus"}, document: false},
		// An invalid --format selects nothing, so the complaint about it is prose.
		{args: []string{"list", "--bogus", "--format", "bogus"}, document: false},
		// After a tool name everything belongs to the tool, so the scan stops there.
		{args: []string{"--bogus", "search_aws", "--format", "json"}, document: false},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(append([]string{"--non-interactive"}, tc.args...)); code == 0 {
				t.Fatalf("expected a failure, stderr: %s", stderr.String())
			}
			isDoc := strings.HasPrefix(strings.TrimSpace(stderr.String()), "{")
			if isDoc != tc.document {
				t.Fatalf("expected document=%v, got stderr: %s", tc.document, stderr.String())
			}
		})
	}
}

// --format supersedes the legacy flags wherever both are given, and neither
// legacy flag selects a format on its own. That is the compatibility boundary:
// a caller keeps its old output until it spells --format.
func TestFormatSupersedesTheLegacyFlags(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		contract bool
	}{
		// --json alone: legacy. describe had no machine form before --format, so
		// prose is the correct answer here.
		{name: "json alone stays legacy", args: []string{"--json", "describe", "search_aws"}, contract: false},
		// --output alone: legacy, and describe never read it at all.
		{name: "output alone stays legacy", args: []string{"--output", "json", "describe", "search_aws"}, contract: false},
		// --format wins whichever side it is written on.
		{name: "format after json", args: []string{"--json", "--format", "json", "describe", "search_aws"}, contract: true},
		{name: "format before json", args: []string{"--format", "json", "--json", "describe", "search_aws"}, contract: true},
		{name: "format beats output", args: []string{"--output", "human", "--format", "json", "describe", "search_aws"}, contract: true},
		{name: "format beats output reversed", args: []string{"--format", "json", "--output", "human", "describe", "search_aws"}, contract: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(append([]string{"--non-interactive"}, tc.args...)); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			var doc struct {
				Command string `json:"command"`
			}
			gotContract := json.Unmarshal(stdout.Bytes(), &doc) == nil && doc.Command == "describe"
			if gotContract != tc.contract {
				t.Fatalf("expected contract=%v, got stdout: %s", tc.contract, stdout.String())
			}
		})
	}
}

// Prose is suppressed only when the contract was selected. Every legacy caller
// keeps the stderr it has always had, which is what makes this release safe to
// apply unattended on a self-updating binary.
func TestContractSuppressesProseOnlyWhenSelected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		quiet bool
	}{
		{name: "legacy list", args: []string{"list"}, quiet: false},
		{name: "legacy json list", args: []string{"--json", "list"}, quiet: false},
		{name: "legacy output json list", args: []string{"--output", "json", "list"}, quiet: false},
		{name: "contract ndjson", args: []string{"--format", "ndjson", "list"}, quiet: true},
		{name: "contract json", args: []string{"--format", "json", "list"}, quiet: true},
		// --verbose puts the prose back for a human debugging a contract run, so it
		// is the one combination that must not be merged with 2>&1.
		{name: "contract verbose", args: []string{"--format", "ndjson", "--verbose", "list"}, quiet: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
			if code := a.run(append([]string{"--non-interactive"}, tc.args...)); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if quiet := stderr.Len() == 0; quiet != tc.quiet {
				t.Fatalf("expected quiet=%v, got stderr: %q", tc.quiet, stderr.String())
			}
		})
	}
}

// `bmcp <tool> --help` is the documented alias for that tool's schema, so it
// answers with describe's document rather than prose on stdout.
func TestToolHelpAnswersWithTheDescribeDocument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := callApp(t, `{"content":[{"type":"text","text":"{}"}]}`, &stdout, &stderr)
	if code := a.run([]string{"--format", "json", "search_aws", "--help"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var doc struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Tool    struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"input_schema"`
		} `json:"tool"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not a single JSON document: %v\n%s", err, stdout.String())
	}
	if !doc.OK || doc.Command != "describe" || doc.Tool.Name != "tools___search_aws" {
		t.Fatalf("unexpected document: %s", stdout.String())
	}
	if len(doc.Tool.InputSchema) == 0 {
		t.Fatalf("the schema is the thing being asked for: %s", stdout.String())
	}
	// Without a machine format it is still the indented text a person reads.
	stdout.Reset()
	if code := a.run([]string{"search_aws", "--help"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Arguments:") {
		t.Fatalf("the default should stay human, got: %s", stdout.String())
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

// jq is not a bmcp dependency and may not be installed on the machine reading
// these instructions, so the template must never route an agent through it.
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

// The change everything else here rests on: 71% of observed bmcp invocations
// were piped into head/tail, and the cut leaves no marker, so a partial answer
// reads exactly like a complete one. The instructions must state the
// prohibition outright and keep pointing at the two in-band completeness
// checks, `count` and `has_more`. Asserted positively on the shortest
// distinctive phrases: a !Contains check on the phrasings this replaced would
// be self-nullifying, since the same commit deleted them.
func TestGeneratedInstructionsForbidShorteningOutput(t *testing.T) {
	cache := &toolCache{LastSync: time.Now(), Tools: []tool{{Name: "tools___search_aws", Description: "Find infrastructure context."}}}
	got := borisInstructionsMarkdown(cache)
	for _, want := range []string{
		"**Never shorten `bmcp` output to a fixed number of lines, bytes, or records.**",
		"leaves no marker",
		"`bmcp --max-bytes <n>`",
		"`truncated`",
		"`has_more`",
		"`count`",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("instructions should carry %q: %s", want, got)
		}
	}
}

// The live catalog has three tools with a nested `scope` object. Describe walked
// only the top level, so `scope` rendered with no fields at all and the only
// shape guidance was the `{"Key":"value"}` placeholder — which Validate accepts,
// because it checks an object argument for being a map and nothing more. `Key`
// then reached the server as a filter key that does not exist.
func TestDescribeRendersNestedObjectFields(t *testing.T) {
	tl := tool{
		Name: "tools___search_infrastructure_by_description",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"required":["query"],
			"properties":{
				"query":{"type":"string","description":"What to look for"},
				"scope":{"type":"object","description":"Exact-match filters","properties":{
					"account_id":{"type":"string","description":"12-digit AWS account ID"},
					"region":{"type":"string"},
					"type":{"type":"string"}
				}}
			}
		}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	got := out.String()

	// Indented under scope, not flush with the top-level arguments: the nesting is
	// the part that says these are fields *of* scope rather than more arguments.
	for _, want := range []string{
		"  scope (object, optional) - Exact-match filters\n",
		"    account_id (string, optional) - 12-digit AWS account ID\n",
		"    region (string, optional)\n",
		"    type (string, optional)\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("describe should render %q, got:\n%s", want, got)
		}
	}
	// Both examples must name a field the schema declares. This is the half that
	// stops the garbage shipping: an agent copying the example now sends a real key.
	if !strings.Contains(got, `--scope '{"account_id":"value"}'`) {
		t.Fatalf("subcommand example should name a real field, got:\n%s", got)
	}
	if !strings.Contains(got, `"scope":{"account_id":"value"}`) {
		t.Fatalf("JSON example should name a real field, got:\n%s", got)
	}
	if strings.Contains(got, `"Key"`) {
		t.Fatalf("no example may still offer the Key placeholder, got:\n%s", got)
	}
}

// An object with no declared fields is the `filters` case: the shape lives in the
// description prose, and there is no real key to name. The placeholder stays,
// because inventing one would be worse than admitting there is nothing to say.
func TestDescribeKeepsPlaceholderForFieldlessObject(t *testing.T) {
	tl := tool{
		Name:        "tools___search",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"filters":{"type":"object","description":"See above"}}}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	got := out.String()
	if !strings.Contains(got, `--filters '{"Key":"value"}'`) {
		t.Fatalf("fieldless object should keep the placeholder, got:\n%s", got)
	}
	// The JSON example keeps `{}` rather than the placeholder: it sends nothing,
	// which beats sending a key the server does not know.
	if !strings.Contains(got, `'{"filters":{}}'`) {
		t.Fatalf("JSON example should send an empty object, got:\n%s", got)
	}
}

func TestDescribeRendersArrayItemFieldsAndPrefersRequiredInExamples(t *testing.T) {
	tl := tool{
		Name: "tools___tag_resources",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"tags":{"type":"array","items":{"type":"object","required":["key"],"properties":{
					"key":{"type":"string"},"value":{"type":"string"}
				}}},
				"names":{"type":"array","items":{"type":"string"}},
				"scope":{"type":"object","required":["region"],"properties":{
					"account_id":{"type":"string"},"region":{"type":"string"}
				}}
			}
		}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	got := out.String()
	// "array of object" rather than "array": it is what attributes the indented
	// fields to the items instead of to the array.
	for _, want := range []string{
		"  tags (array of object, optional)\n",
		"    key (string, required)\n",
		"    value (string, optional)\n",
		"  names (array of string, optional)\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("describe should render %q, got:\n%s", want, got)
		}
	}
	// region, not the alphabetically-first account_id: an example built from a
	// required field is a payload the server can accept as written.
	if !strings.Contains(got, `--scope '{"region":"value"}'`) {
		t.Fatalf("object example should prefer a required field, got:\n%s", got)
	}
}

// Every rendered example has to be valid JSON, because the point of an example is
// that it can be copied. A property with no recognisable type renders as a
// placeholder, and a bare `...` was survivable only while it could appear at the
// top level alone — nested inside an object or array it makes the whole example
// unparseable, so the CLI rejects its own printed example. Enum-only and `anyOf`
// sub-fields (what Pydantic emits) are exactly that case.
func TestDescribeExamplesAreAlwaysValidJSON(t *testing.T) {
	tl := tool{
		Name: "tools___q",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"untyped":{"description":"no type at all"},
				"scope":{"type":"object","required":["kind"],"properties":{"kind":{"enum":["a","b"]}}},
				"rows":{"type":"array","items":{"anyOf":[{"type":"string"}]}}
			}
		}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	got := out.String()

	// The JSON-call line, parsed as the payload `bmcp call` would receive.
	_, payload, ok := strings.Cut(got, "bmcp call q '")
	if !ok {
		t.Fatalf("could not find the JSON call example in:\n%s", got)
	}
	payload, _, _ = strings.Cut(payload, "'\n")
	var decoded map[string]any
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("the JSON call example must parse: %v\ngot: %s", err, payload)
	}
	// And the subcommand line: every object/array flag value must parse too, since
	// ParseFlags decodes them.
	if err := tl.Validate(decoded); err != nil {
		t.Fatalf("the example payload must also pass validation: %v", err)
	}
	for _, frag := range []string{`--scope '`, `--rows '`} {
		_, rest, found := strings.Cut(got, frag)
		if !found {
			t.Fatalf("missing %s in:\n%s", frag, got)
		}
		value, _, _ := strings.Cut(rest, "'")
		var v any
		if err := json.Unmarshal([]byte(value), &v); err != nil {
			t.Fatalf("flag example %s%s' must parse: %v", frag, value, err)
		}
	}
}

// An example must satisfy the schema, not merely parse. One required field named
// out of two is a payload the server rejects for a missing key, and a type
// placeholder in a field constrained to an enum is rejected for a bad value —
// both leave the caller with an example that cannot be used as printed.
func TestDescribeExamplesSatisfyTheSchemaTheyCameFrom(t *testing.T) {
	tl := tool{
		Name: "tools___q",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"scope":{"type":"object","required":["account_id","region"],"properties":{
					"account_id":{"type":"string"},
					"region":{"type":"string"},
					"note":{"type":"string"}
				}},
				"mode":{"type":"object","required":["kind"],"properties":{
					"kind":{"enum":["fast","thorough"]}
				}},
				"pinned":{"type":"object","required":["v"],"properties":{
					"v":{"const":7}
				}}
			}
		}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	got := out.String()
	for _, want := range []string{
		// Both required fields, and not the optional one.
		`--scope '{"account_id":"value","region":"value"}'`,
		// A value the enum actually allows.
		`--mode '{"kind":"fast"}'`,
		// const wins over the declared type.
		`--pinned '{"v":7}'`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("example should be %s, got:\n%s", want, got)
		}
	}
}

// The declared type decides which keyword describes the shape: JSON Schema reads
// `items` for an array and `properties` for an object. A schema carrying both used
// to print the array's `properties` under a heading taken from its `items`, so the
// fields shown belonged to neither.
func TestDescribeFollowsItemsForADeclaredArray(t *testing.T) {
	tl := tool{
		Name: "tools___t",
		InputSchema: json.RawMessage(`{"type":"object","properties":{
			"rows":{"type":"array","properties":{"wrong":{"type":"string"}},
			        "items":{"type":"object","properties":{"right":{"type":"string"}}}}
		}}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	got := out.String()
	if !strings.Contains(got, "  rows (array of object, optional)\n") {
		t.Fatalf("heading should describe the items, got:\n%s", got)
	}
	if !strings.Contains(got, "    right (string, optional)\n") {
		t.Fatalf("an array's fields come from items, got:\n%s", got)
	}
	if strings.Contains(got, "wrong") {
		t.Fatalf("properties must not be read off a declared array, got:\n%s", got)
	}
}

// An items schema with fields but no declared type is an object by construction.
// Labelling it a bare "array" while indenting its fields underneath is the exact
// ambiguity the "array of object" spelling exists to remove.
func TestDescribeNamesArrayItemsThatDeclareNoType(t *testing.T) {
	tl := tool{
		Name: "tools___tag",
		InputSchema: json.RawMessage(`{"type":"object","properties":{
			"tags":{"type":"array","items":{"properties":{"key":{"type":"string"}}}}
		}}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	if got := out.String(); !strings.Contains(got, "  tags (array of object, optional)\n") {
		t.Fatalf("an items schema with properties should be named as such, got:\n%s", got)
	}
}

// Nesting deeper than one level is rendered rather than truncated. Recursion is
// safe here because the tree comes from an unmarshalled schema — nothing resolves
// $ref, so a cycle is not representable.
func TestDescribeRendersDeeplyNestedFields(t *testing.T) {
	tl := tool{
		Name:        "tools___q",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"a":{"type":"object","properties":{"b":{"type":"object","properties":{"c":{"type":"string"}}}}}}}`),
	}
	var out bytes.Buffer
	tl.Describe(&out)
	got := out.String()
	for _, want := range []string{"  a (object,", "    b (object,", "      c (string,"} {
		if !strings.Contains(got, want) {
			t.Fatalf("describe should render %q, got:\n%s", want, got)
		}
	}
	// The example follows the nesting too, rather than bottoming out at `{}`.
	if !strings.Contains(got, `'{"a":{"b":{"c":"value"}}}'`) {
		t.Fatalf("example should follow the nesting, got:\n%s", got)
	}
}

// Version discovery used to require the exact `bmcp version` subcommand, so an
// agent reaching for the conventional spelling got "unknown global flag" and
// exit 1 — which reads as a broken CLI rather than a wrong spelling.
func TestVersionFlagsPrintVersionWithoutConfig(t *testing.T) {
	// No config and no catalog: the version cannot depend on either.
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	for _, args := range [][]string{
		{"--version"},
		{"-V"},
		{"--non-interactive", "--version"},
		// After `--` the flag cannot fire, because `--` stops flag interpretation.
		// The command-table aliases are what keep these working.
		{"--", "--version"},
		{"--", "-V"},
		// help wins, and the post-command and with-arguments forms are errors —
		// both asserted separately below.
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: failingDoer{},
			}
			if code := a.run(args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.HasPrefix(stdout.String(), "bmcp ") {
				t.Fatalf("version should go to stdout, got stdout %q stderr %q", stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("--version must not print usage: %s", stdout.String())
			}
			if strings.Contains(stderr.String(), "unknown") {
				t.Fatalf("stderr should not report an unknown flag, got: %s", stderr.String())
			}
		})
	}
}

// Ordering, which the table above cannot express: help is the broader question,
// so it answers first, and it held that position before --version existed.
func TestHelpWinsOverVersion(t *testing.T) {
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	for _, args := range [][]string{{"--help", "--version"}, {"--version", "--help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now, httpClient: failingDoer{}}
			if code := a.run(args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("help should win, got: %s", stdout.String())
			}
		})
	}
}

// --version must not silently swallow a command or its arguments. `bmcp update
// --to 0.7.0 --version` reporting success while updating nothing is the exact trap
// that made the update flag `--to` rather than `--version`, and before this change
// each of these was a hard error. Rejecting them keeps that true.
func TestVersionFlagRefusesToSwallowACommand(t *testing.T) {
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	for _, tc := range []struct {
		args []string
		code int
	}{
		// Post-command: parseFlags accepts --version in the global scope only, so
		// these are flag errors. `install` is rawArgs and rejects it itself.
		{[]string{"doctor", "--version"}, exitGeneric},
		{[]string{"list", "-V"}, exitGeneric},
		{[]string{"update", "--to", "0.7.0", "--version"}, exitGeneric},
		{[]string{"update", "--version", "0.7.0"}, exitGeneric},
		{[]string{"install", "--version"}, exitValidation},
		// Global position, but with a command or tool still to run.
		{[]string{"--version", "doctor"}, exitValidation},
		{[]string{"-V", "some_tool", "--arg", "x"}, exitValidation},
		// Through the command aliases, which reach cmdVersion with their arguments
		// intact and so are not covered by run()'s guard on the flag.
		{[]string{"--", "--version", "doctor"}, exitValidation},
		{[]string{"--", "-V", "doctor"}, exitValidation},
		{[]string{"version", "garbage"}, exitValidation},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now, httpClient: failingDoer{}}
			if code := a.run(tc.args); code != tc.code {
				t.Fatalf("exit code %d, want %d, stderr: %s", code, tc.code, stderr.String())
			}
			if strings.HasPrefix(stdout.String(), "bmcp ") {
				t.Fatalf("must not report the version and abandon the command, got: %q", stdout.String())
			}
		})
	}
}

// Same guarantee TestHelpNeverReachesTheNetwork pins for help: a release build is
// needed for it to mean anything, because under `go test` inspectUpdate
// short-circuits as a source build before any request is built.
func TestVersionFlagNeverReachesTheNetwork(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	for _, args := range [][]string{{"--version"}, {"-V"}, {"--", "--version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// github is nil, so any GitHub request becomes an error and is counted.
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
				t.Fatalf("%v made %d GitHub requests; reporting the version must not check for updates", args, m.githubRequests)
			}
			if m.listCalls != 0 {
				t.Fatalf("%v made %d tools/list calls; the version must not need the catalog", args, m.listCalls)
			}
		})
	}
	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("reporting the version may not replace the binary, got %q", got)
	}
}

// A mistyped command used to fall through to dynamic tool resolution, which loads
// config, can sync, and on an unconfigured interactive machine runs the whole
// first-run setup — so a typo was answered with a prompt for a URL.
func TestMistypedCommandIsCorrectedFromLocalStateAlone(t *testing.T) {
	cases := []struct{ typo, want string }{
		{"doctr", "bmcp doctor"},
		{"lst", "bmcp list"},
		{"instal", "bmcp install"},
		{"describ", "bmcp describe"},
	}
	for _, tc := range cases {
		t.Run(tc.typo, func(t *testing.T) {
			// No config, no catalog, and interactive: the pre-fix path would have
			// prompted here rather than answering.
			t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
			m := &fakeMCP{}
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: m,
				credentials: func(context.Context, effectiveConfig) (aws.Credentials, string, error) {
					t.Fatal("a typo must not load credentials")
					return aws.Credentials{}, "", nil
				},
				interactive: func() bool { return true },
			}
			if code := a.run([]string{tc.typo}); code != exitValidation {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Did you mean the command: "+tc.want+"?") {
				t.Fatalf("should name the nearest command, got: %s", stderr.String())
			}
			// The recovery routes are named whether or not a suggestion was found.
			if !strings.Contains(stderr.String(), "`bmcp list` for the current tool catalog") {
				t.Fatalf("should name the recovery routes, got: %s", stderr.String())
			}
			if m.listCalls != 0 {
				t.Fatalf("a typo made %d tools/list calls", m.listCalls)
			}
			// stderr, not stdout: cmdInit writes its prompts to stderr, so the same
			// assertion against stdout could never have fired.
			if strings.Contains(stderr.String(), "BORIS MCP URL") {
				t.Fatalf("a typo must not start first-run setup, got: %s", stderr.String())
			}
		})
	}
}

// The safety property behind the short-circuit above. Command names are short, so
// a real tool name can land within an edit of one; when it does, the catalog wins
// and the call goes through.
//
// The fixture is asserted to be a near miss rather than described as one. It was
// `sync_status` first, which is seven edits from `sync` — so nearestCommand
// returned "", the guard never fired, and the test proved nothing while its
// comment claimed it pinned the mechanism. A fixture precondition is the only
// thing that stops that recurring.
func TestToolNamedLikeACommandStillReachesTheServer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{
		Name:        "tools___syncs",
		Description: "One edit from the sync command.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`),
	}})
	if near := nearestCommand("syncs"); near != "sync" {
		t.Fatalf("fixture must be a near miss for a command, got nearestCommand(%q) = %q", "syncs", near)
	}
	m := &fakeMCP{
		tools:      []tool{{Name: "tools___syncs"}},
		callResult: []byte(`{"content":[{"type":"text","text":"{\"ok\":true}"}]}`),
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"--non-interactive", "syncs", "--q", "x"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `{"ok":true}`) {
		t.Fatalf("the tool should have been called, got stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "Did you mean the command") {
		t.Fatalf("a real tool must not be corrected to a command: %s", stderr.String())
	}
}

// The bar for answering locally: a stale catalog must not be allowed to refuse a
// name, because the server grows tools and a new one whose name reads like a typo
// would otherwise be refused locally and never synced for. Here the cache is past
// its TTL and does not list the tool, and the sync that follows finds it.
func TestStaleCatalogSyncsRatherThanCorrectingARealTool(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___already_known"}})
	if near := nearestCommand("syncs"); near != "sync" {
		t.Fatalf("fixture must be a near miss for a command, got %q", near)
	}
	m := &fakeMCP{
		tools:      []tool{{Name: "tools___already_known"}, {Name: "tools___syncs"}},
		callResult: []byte(`{"content":[{"type":"text","text":"{\"ok\":true}"}]}`),
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		// Past the TTL, so the cache on disk is not what a tool call would use.
		now:        func() time.Time { return time.Now().Add(defaultTTL + time.Hour) },
		httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"--non-interactive", "syncs"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `{"ok":true}`) {
		t.Fatalf("a tool absent from a stale cache must still be reachable, got stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

// The remaining cost of the guard, stated so a future change cannot widen it
// quietly: with no config there is nothing to sync with, so a real tool that reads
// like a typo is refused from the spelling alone. That is the deliberate trade —
// a typo must not open the first-run prompt — and the message names the way out.
func TestToolNamedLikeACommandIsRefusedWithoutConfig(t *testing.T) {
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	m := &fakeMCP{tools: []tool{{Name: "tools___syncs"}}}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"--non-interactive", "syncs"}); code != exitValidation {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if m.listCalls != 0 {
		t.Fatalf("made %d tools/list calls; the point is that it does not sync", m.listCalls)
	}
	if !strings.Contains(stderr.String(), "`bmcp list` for the current tool catalog") {
		t.Fatalf("should name the way out, got: %s", stderr.String())
	}
}

// Both near misses at once, which is the shape the separate labels exist for and
// which no other test produces — TestMistypedCommandIsCorrectedFromLocalStateAlone
// runs with no catalog, so it only ever sees the command half.
func TestMistypedCommandNamesBothNearMisses(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___docto"}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{},
		credentials: func(context.Context, effectiveConfig) (aws.Credentials, string, error) {
			t.Fatal("a typo must not load credentials")
			return aws.Credentials{}, "", nil
		},
	}
	if code := a.run([]string{"--non-interactive", "doctr"}); code != exitValidation {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	for _, want := range []string{
		"Did you mean the tool: docto?",
		"Did you mean the command: bmcp doctor?",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("should report %q, got: %s", want, stderr.String())
		}
	}
}

// The recovery line is unconditional. A token close to nothing gets no suggestion,
// and that is exactly the caller with the least idea what to do next — it used to
// be the only one told nothing at all.
func TestUnknownNameWithNoSuggestionStillNamesARecovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws_memory"}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{tools: []tool{{Name: "tools___search_aws_memory"}}},
		credentials: staticCreds(),
	}
	if code := a.run([]string{"--non-interactive", "describe", "totally_unrelated"}); code != exitValidation {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "Did you mean") {
		t.Fatalf("fixture must be far from everything for this test to mean anything: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "`bmcp list` for the current tool catalog") {
		t.Fatalf("an unknown name with no suggestion should still name a next step, got: %s", stderr.String())
	}
}

// unknown_command is a new failure name, and machine consumers read the envelope
// rather than the prose. The multi-line message has to survive as one JSON string
// rather than breaking the document into unparseable lines.
func TestUnknownCommandJSONErrorIsParseableOnStderr(t *testing.T) {
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now, httpClient: &fakeMCP{}}
	if code := a.run([]string{"--json", "doctr"}); code != exitValidation {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Fatalf("an error must not write to stdout, got %q", stdout.String())
	}
	var env struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr.String())), &env); err != nil {
		t.Fatalf("stderr should be one parseable document: %v (got %q)", err, stderr.String())
	}
	if env.OK || env.Error != "unknown_command" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	if !strings.Contains(env.Message, "Did you mean the command: bmcp doctor?") {
		t.Fatalf("the suggestion should survive into the JSON message, got %q", env.Message)
	}
}

// The suggestion rules, which nothing else pins. Flat edit distance failed in both
// directions: short command names swallowed unrelated tokens, and truncations —
// the most natural way to get a command name wrong — lost to them.
func TestNearestCommandRules(t *testing.T) {
	for _, tc := range []struct{ typed, want string }{
		// Truncations resolve by prefix, however many edits away they are.
		{"doc", "doctor"},
		{"desc", "describe"},
		{"ver", "version"},
		{"inst", "install"},
		{"tool", "list"}, // through the `tools` alias
		// Ordinary misspellings resolve by distance.
		{"doctr", "doctor"},
		{"lst", "list"},
		{"instal", "install"},
		{"describ", "describe"},
		{"upgrade", "update"},
		{"uninstall", "install"},
		// Transpositions. Two adjacent characters swapped is one of the commonest
		// ways to mistype a word, and it costs two plain Levenshtein edits — so
		// under the tight limit short command names need, every one of these fell
		// through to the first-run prompt that #38 is about. editDistance counts a
		// swap as one.
		{"lsit", "list"},
		{"snyc", "sync"},
		{"inti", "init"},
		{"clal", "call"},
		{"doctro", "doctor"},
		// Plausible tool names must NOT be captured: every one of these is within
		// three edits of a four-letter command, and `init` and `sync` both have
		// side effects, so a confident wrong answer is worse than none.
		{"cost", ""},
		{"logs", ""},
		{"info", ""},
		{"cells", ""},
		{"hosts", ""},
		{"index", ""},
		{"sync_x", ""},
		{"run", ""},
		{"aws", ""},
	} {
		t.Run(tc.typed, func(t *testing.T) {
			if got := nearestCommand(tc.typed); got != tc.want {
				t.Fatalf("nearestCommand(%q) = %q, want %q", tc.typed, got, tc.want)
			}
		})
	}
}

// The shared threshold, untouched by the command rules above: it still serves
// --flag and tool-name suggestions, where the candidates are long enough for three
// edits to be a good bet. The refactor rewrote `dist <= 3` on a sentinel of 99 as a
// sentinel of 4 with `d < dist`, and nothing would have caught a one-off shift.
func TestNearestSuggestionThreshold(t *testing.T) {
	for _, tc := range []struct{ typed, want string }{
		{"doctor", "doctor"}, // 0
		{"doctr", "doctor"},  // 1
		{"docr", "doctor"},   // 2
		{"dor", "doctor"},    // 3 — the last distance that still suggests
		{"do", ""},           // 4 — one too far
	} {
		t.Run(tc.typed, func(t *testing.T) {
			if got := nearest(tc.typed, []string{"doctor"}); got != tc.want {
				t.Fatalf("nearest(%q) = %q, want %q (distance %d)", tc.typed, got, tc.want, editDistance(tc.typed, "doctor"))
			}
		})
	}
}

// The determinism nearestToolName's comment claims. Two names equally distant from
// the input must resolve the same way regardless of the order the catalog lists
// them in, or `bmcp describe` prints a different suggestion after every sync.
func TestNearestToolNameDoesNotDependOnCatalogOrder(t *testing.T) {
	forward := &toolCache{Tools: []tool{{Name: "tools___aaa"}, {Name: "tools___bbb"}}}
	reversed := &toolCache{Tools: []tool{{Name: "tools___bbb"}, {Name: "tools___aaa"}}}
	if editDistance("ccc", "aaa") != editDistance("ccc", "bbb") {
		t.Fatalf("fixture must be a tie for the test to mean anything")
	}
	if got, want := nearestToolName(forward, "ccc"), nearestToolName(reversed, "ccc"); got != want {
		t.Fatalf("catalog order changed the suggestion: %q vs %q", got, want)
	}
	if got := nearestToolName(forward, "ccc"); got != "aaa" {
		t.Fatalf("a tie should resolve to the alphabetically first name, got %q", got)
	}
}

// The claim in flags.go that a tool's own `version` argument is unaffected. The
// global scope stops at the first non-flag token, so `--version` after a tool name
// belongs to tool.ParseFlags; if it ever leaked back the call would turn into
// `bmcp version` and the tool would silently never run.
func TestToolVersionArgumentIsNotStolenByTheGlobalFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{
		Name:        "tools___deploy",
		Description: "Has its own version argument.",
		InputSchema: json.RawMessage(`{"type":"object","required":["version"],"properties":{"version":{"type":"string"}}}`),
	}})
	for _, args := range [][]string{
		{"--non-interactive", "deploy", "--version", "1.2.3"},
		{"--non-interactive", "deploy", "--version=1.2.3"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			m := &fakeMCP{
				tools:      []tool{{Name: "tools___deploy"}},
				callResult: []byte(`{"content":[{"type":"text","text":"{\"deployed\":true}"}]}`),
			}
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: m, credentials: staticCreds(),
			}
			if code := a.run(args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), `{"deployed":true}`) {
				t.Fatalf("the tool should have run, got stdout %q stderr %q", stdout.String(), stderr.String())
			}
			if strings.HasPrefix(stdout.String(), "bmcp ") {
				t.Fatalf("the global --version stole the tool's argument: %q", stdout.String())
			}
		})
	}
}

// `tools` was the most common wrong first token in the audit. An alias answers it
// in one invocation; a suggestion would still have cost the failed one.
func TestToolsIsAnAliasForList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	if code := a.run([]string{"--non-interactive", "tools"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	var record toolRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &record); err != nil {
		t.Fatalf("`bmcp tools` should emit the list records: %v (stdout %q)", err, stdout.String())
	}
	if record.DisplayName != "search_aws" {
		t.Fatalf("unexpected record: %#v", record)
	}
}

// resolveTool used to report only that a name was unknown, leaving the caller to
// re-derive the catalog the lookup had just searched.
func TestUnknownToolNamesTheNearestTool(t *testing.T) {
	cache := &toolCache{Tools: []tool{
		{Name: "tools___search_aws_memory"},
		{Name: "tools___list_aws_resources"},
	}}
	_, err := resolveTool(cache, "search_aws_memry")
	if err == nil || !strings.Contains(err.Error(), "Did you mean the tool: search_aws_memory?") {
		t.Fatalf("expected a nearest-tool suggestion, got: %v", err)
	}
	// Nothing close enough is left unsuggested rather than answered with the least
	// bad match in the catalog.
	// The full namespaced spelling is matched too. It is what a copy out of the
	// catalog gives, and the `tools___` prefix alone puts it past the threshold if
	// only display names are compared — so a typo in it used to get no suggestion.
	// The answer is still the short spelling, which also resolves.
	if _, err := resolveTool(cache, "tools___search_aws_memry"); err == nil ||
		!strings.Contains(err.Error(), "Did you mean the tool: search_aws_memory?") {
		t.Fatalf("a typo in the full name should still be suggestable, got: %v", err)
	}
	_, err = resolveTool(cache, "totally_different_name")
	if err == nil || !strings.Contains(err.Error(), "Unknown command or tool") {
		t.Fatalf("expected an unknown-tool error, got: %v", err)
	}
	if strings.Contains(err.Error(), "Did you mean") {
		t.Fatalf("a distant name should get no suggestion, got: %v", err)
	}
	// A nil cache is the no-catalog case, and must not panic reaching for one.
	if _, err := resolveTool(nil, "anything"); err == nil {
		t.Fatalf("expected an error for a nil cache")
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

// The point of --schemas: one local invocation answers both "which tools exist"
// and "how do I call them". Agents made 144 describe calls across 54 sessions to
// get the second answer a tool at a time.
func TestListWithSchemasCarriesEverySchemaInOneInvocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	tools := []tool{
		{
			Name:        "tools___search_aws",
			Description: "Search.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`),
		},
		{
			Name:        "tools___list_resources",
			Description: "List.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"resource_type":{"type":"string"}}}`),
		},
	}
	setupInstallCatalog(t, home, tools)
	var stdout, stderr bytes.Buffer
	m := &fakeMCP{tools: tools}
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
	}
	if code := a.run([]string{"list", "--schemas"}); code != 0 {
		t.Fatalf("list exit %d, stderr: %s", code, stderr.String())
	}
	// Local: the catalog is fresh, so this costs no round trip either.
	if m.listCalls != 0 {
		t.Fatalf("a fresh catalog must be served from disk, got %d tools/list calls", m.listCalls)
	}

	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != len(tools) {
		t.Fatalf("expected one record per tool, got %d lines:\n%s", len(lines), stdout.String())
	}
	byName := map[string]map[string]any{}
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("record is not valid JSON: %v\n%s", err, line)
		}
		byName[record["name"].(string)] = record
	}
	schema, ok := byName["tools___search_aws"]["input_schema"].(map[string]any)
	if !ok {
		t.Fatalf("expected an input_schema object, got: %v", byName["tools___search_aws"]["input_schema"])
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok || props["query"] == nil {
		t.Fatalf("the schema should carry its properties, got: %v", schema)
	}
	if req, _ := schema["required"].([]any); len(req) != 1 || req[0] != "query" {
		t.Fatalf("the schema should carry its required list, got: %v", schema["required"])
	}
	// The fields a caller could already rely on stay where they were.
	if byName["tools___list_resources"]["display_name"] != "list_resources" {
		t.Fatalf("--schemas must not disturb the existing record shape: %v", byName["tools___list_resources"])
	}
}

// writeCache stores the catalog with MarshalIndent, which re-indents the
// embedded raw schema, so the bytes on disk contain newlines. One record would
// then span as many lines as its schema has fields, and `head` would split
// records: the single guarantee NDJSON makes here.
//
// It holds because encoding/json compacts a RawMessage as it encodes it, so
// there is deliberately no compaction step in writeToolRecords to point at. This
// pins the property rather than an implementation of it — it is what would fail
// if the records were ever assembled by hand, or the schema carried through some
// type that is not a RawMessage.
func TestListWithSchemasStaysOneRecordPerLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	nested := json.RawMessage(`{"type":"object","properties":{"scope":{"type":"object","properties":{"account_id":{"type":"string"},"region":{"type":"string"}}}}}`)
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search.", InputSchema: nested}})

	// Precondition: the cache really did land on disk indented, or this test
	// would pass against a fixture that never had the problem.
	raw, err := os.ReadFile(filepath.Join(home, ".bmcp", "tools.json"))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if !strings.Contains(string(raw), "\"account_id\": {") {
		t.Fatalf("fixture precondition: expected an indented schema on disk, got:\n%s", raw)
	}

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{}, credentials: staticCreds(),
	}
	if code := a.run([]string{"list", "--schemas"}); code != 0 {
		t.Fatalf("list exit %d, stderr: %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("one tool must render as one line, got %d:\n%s", len(lines), stdout.String())
	}
	// Every line independently parseable is what lets a caller truncate safely.
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("record is not valid JSON: %v\n%s", err, lines[0])
	}
	if record["input_schema"] == nil {
		t.Fatalf("expected the schema to survive compaction: %s", lines[0])
	}
}

// The default is unchanged. A caller asking which tools exist should not pay for
// schemas it will not read — on the live catalog they more than double the
// output.
func TestListWithoutSchemasIsUnchanged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	tools := []tool{{
		Name:        "tools___search_aws",
		Description: "Search.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
	}}
	setupInstallCatalog(t, home, tools)
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{}, credentials: staticCreds(),
	}
	if code := a.run([]string{"list"}); code != 0 {
		t.Fatalf("list exit %d, stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "input_schema") {
		t.Fatalf("plain list must not carry schemas: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"display_name":"search_aws"`) {
		t.Fatalf("plain list should still carry the record: %s", stdout.String())
	}
}

// --schemas in the human view is describe for every tool. Rejecting the
// combination would be a usage papercut for the one caller least able to guess
// which half of it was wrong.
func TestListWithSchemasInHumanOutputDescribesEveryTool(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	tools := []tool{
		{
			Name:        "tools___search_aws",
			Description: "Search.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"What to search for"}},"required":["query"]}`),
		},
		{
			Name:        "tools___list_resources",
			Description: "List.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"resource_type":{"type":"string"}}}`),
		},
	}
	setupInstallCatalog(t, home, tools)
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{}, credentials: staticCreds(),
	}
	if code := a.run([]string{"list", "--schemas", "--output", "human"}); code != 0 {
		t.Fatalf("list exit %d, stderr: %s", code, stderr.String())
	}
	for _, want := range []string{
		"search_aws",
		"query (string, required) - What to search for",
		"list_resources",
		"resource_type (string, optional)",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("expected %q in the human view, got:\n%s", want, stdout.String())
		}
	}
}

// --schemas is list's alone. Admitting it everywhere would make `bmcp <tool>
// --schemas` a tool argument named schemas on some future catalog and silently
// nothing on this one.
func TestSchemasFlagIsScopedToList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{}, credentials: staticCreds(),
	}
	if code := a.run([]string{"doctor", "--schemas"}); code == 0 {
		t.Fatalf("--schemas must not be accepted by doctor, stdout:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown flag for command: --schemas") {
		t.Fatalf("expected a flag error naming --schemas, got: %s", stderr.String())
	}
}
