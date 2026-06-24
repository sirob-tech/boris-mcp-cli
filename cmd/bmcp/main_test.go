package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
}

func (m *fakeMCP) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
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
		toolsOut := make([]map[string]any, 0, len(m.tools))
		for _, t := range m.tools {
			toolsOut = append(toolsOut, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": json.RawMessage(nonEmptySchema(t.InputSchema)),
			})
		}
		result, _ := json.Marshal(map[string]any{"tools": toolsOut})
		env, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "result": json.RawMessage(result)})
		return respond(string(env))
	case "tools/call":
		env, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 3, "result": json.RawMessage(m.callResult)})
		return respond(string(env))
	}
	return respond(`{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"unexpected"}}`)
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

func TestRenderToolListWrapsDescriptions(t *testing.T) {
	var out bytes.Buffer
	renderToolList(&out, []tool{
		{
			Name:        "tools___graph_query",
			Description: "Execute read-only Cypher queries against the Memgraph graph database to explore infrastructure relationships.",
		},
		{
			Name:        "x_amz_bedrock_agentcore_search",
			Description: "A special tool that returns a trimmed down list of tools given a context. Use this tool only when there are many tools available and you want to get a subset that matches the provided context.",
		},
	})
	got := out.String()
	if !strings.Contains(got, "graph_query") {
		t.Fatalf("missing first tool: %s", got)
	}
	if strings.Contains(got, "tools___graph_query") {
		t.Fatalf("list should use shortened display names, got:\n%s", got)
	}
	if !hasIndentedContinuation(got) {
		t.Fatalf("expected wrapped continuation indentation, got:\n%s", got)
	}
	if strings.Contains(got, "Execute read-only Cypher queries against the Memgraph graph database to explore infrastructure relationships.") {
		t.Fatalf("description should be wrapped, got:\n%s", got)
	}
}

func TestRenderToolListPutsVeryLongNamesOnOwnLine(t *testing.T) {
	var out bytes.Buffer
	renderToolList(&out, []tool{
		{
			Name:        "tools___this_name_is_far_too_long_for_the_table_column",
			Description: "Search for relevant context before making changes.",
		},
	})
	got := out.String()
	if !strings.HasPrefix(got, "this_name_is_far_too_long_for_the_table_column\n  Search for relevant context") {
		t.Fatalf("long name should be on its own line, got:\n%s", got)
	}
}

func TestDisplayToolNameStripsNamespacePrefix(t *testing.T) {
	if got := displayToolName("tools___graph_query"); got != "graph_query" {
		t.Fatalf("displayToolName mismatch: %q", got)
	}
	if got := displayToolName("graph_query"); got != "graph_query" {
		t.Fatalf("displayToolName should leave plain names alone: %q", got)
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

func TestWriteFileWithBackupKeepsOnlyLatestBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "BORIS.md")
	oldBackup := path + ".bak-20260607T000000Z"
	if err := os.WriteFile(path, []byte("v1\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if err := os.WriteFile(oldBackup, []byte("older\n"), 0o600); err != nil {
		t.Fatalf("write old backup: %v", err)
	}
	result := writeFileWithBackup(path, []byte("v2\n"))
	if !result.Changed || result.Backup == "" {
		t.Fatalf("expected changed file with backup, got: %#v", result)
	}
	backups, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	if len(backups) != 1 || backups[0] != result.Backup {
		t.Fatalf("expected only latest backup %q, got %#v", result.Backup, backups)
	}
	if _, err := os.Stat(oldBackup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old backup should be pruned, stat err: %v", err)
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
			if name == "claude" || name == "codex" || name == "cursor" || name == "kiro-cli" {
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
		filepath.Join(home, ".cursor", "rules", "boris.mdc"),
		filepath.Join(home, ".kiro", "steering", "boris.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected install path %s: %v", path, err)
		}
	}
	if strings.Count(stderr.String(), "Install BORIS instructions for") != 4 {
		t.Fatalf("expected separate prompts for four harnesses, got: %s", stderr.String())
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

func hasIndentedContinuation(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "          ") && strings.TrimSpace(line) != "" && !strings.Contains(line, "graph_query") && !strings.Contains(line, "x_amz_bedrock_agentcore_search") {
			return true
		}
	}
	return false
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
