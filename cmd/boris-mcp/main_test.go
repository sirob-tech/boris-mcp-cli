package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
	t.Setenv("BORIS_MCP_HOME", home)
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"init", "--url", "http://localhost:8787/mcp", "--no-sync"})
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
	t.Setenv("BORIS_MCP_HOME", home)
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader("\n\n"), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"init", "--url", "http://localhost:8787/mcp", "--no-sync"})
	if code != 0 {
		t.Fatalf("init exit code %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "AWS profile (optional, blank uses AWS defaults)") {
		t.Fatalf("prompt should explain optional profile, got: %s", stderr.String())
	}
}

func TestMissingConfigNonInteractiveFailsFast(t *testing.T) {
	t.Setenv("BORIS_MCP_HOME", t.TempDir())
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	code := a.run([]string{"--non-interactive", "list"})
	if code != exitConfig {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "boris-mcp init --url <url>") {
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
	t.Setenv("BORIS_MCP_HOME", home)
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
	if !strings.Contains(stdout.String(), "boris-mcp call search_aws") {
		t.Fatalf("help should use alias in call example, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "boris-mcp search_aws --query") {
		t.Fatalf("help should use alias in subcommand example, got:\n%s", stdout.String())
	}
}

func TestDescribeUsesDisplayAlias(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BORIS_MCP_HOME", home)
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
	if !strings.Contains(stdout.String(), "boris-mcp call search_aws") {
		t.Fatalf("describe should use alias examples, got:\n%s", stdout.String())
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
	got, err := parseToolFlags(tl, []string{
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

func TestValidateInputErrors(t *testing.T) {
	tl := tool{
		Name: "tools___deploy_service",
		InputSchema: json.RawMessage(`{
			"type":"object",
			"required":["service"],
			"properties":{"service":{"type":"string"},"environment":{"type":"string"}}
		}`),
	}
	err := validateInput(tl, map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "Missing required argument: service") {
		t.Fatalf("missing required error mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), "boris-mcp call deploy_service") {
		t.Fatalf("missing required example should use display alias: %v", err)
	}
	err = validateInput(tl, map[string]any{"service": "api", "enviroment": "prod"})
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

func TestSchemaDiff(t *testing.T) {
	oldTool := tool{
		Name:        "deploy_service",
		InputSchema: json.RawMessage(`{"type":"object","required":["environment"],"properties":{"environment":{"type":"string"},"replicas":{"type":"integer"}}}`),
	}
	newTool := tool{
		Name:        "deploy_service",
		InputSchema: json.RawMessage(`{"type":"object","required":["target_environment"],"properties":{"target_environment":{"type":"string"},"replicas":{"type":"number"}}}`),
	}
	diff := schemaDiff(oldTool, newTool)
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
