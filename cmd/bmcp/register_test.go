package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readServers(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatalf("config is not JSON: %v", err)
	}
	servers, _ := config["mcpServers"].(map[string]any)
	return servers
}

func TestRegisterKeepsEveryOtherKeyAndServer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claude_desktop_config.json")
	existing := `{"preferences":{"theme":"dark"},"mcpServers":{"other":{"command":"/bin/other"}}}`
	if err := os.WriteFile(path, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, wrote := registerMCPServer(path, "/usr/local/bin/bmcp"); !wrote {
		t.Fatal("expected a write")
	}
	servers := readServers(t, path)
	if _, kept := servers["other"]; !kept {
		t.Errorf("another server was dropped: %v", servers)
	}
	boris, _ := servers[mcpServerName].(map[string]any)
	if boris["command"] != "/usr/local/bin/bmcp" {
		t.Errorf("command = %v", boris["command"])
	}
	raw, _ := os.ReadFile(path)
	var config map[string]any
	_ = json.Unmarshal(raw, &config)
	if _, kept := config["preferences"]; !kept {
		t.Errorf("unrelated keys were dropped: %s", raw)
	}
}

func TestRegisterIsQuietWhenAlreadyCorrect(t *testing.T) {
	// Rewriting a correct file on every doctor would rotate a backup generation
	// each session for no change at all.
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if _, wrote := registerMCPServer(path, "/usr/local/bin/bmcp"); !wrote {
		t.Fatal("first call should write")
	}
	before, _ := os.ReadFile(path)
	if _, wrote := registerMCPServer(path, "/usr/local/bin/bmcp"); wrote {
		t.Error("second call must write nothing")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Errorf("file changed on a no-op refresh")
	}
}

func TestRegisterFollowsAMovedBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	registerMCPServer(path, "/old/bin/bmcp")
	if _, wrote := registerMCPServer(path, "/new/bin/bmcp"); !wrote {
		t.Fatal("a moved binary must be corrected")
	}
	if readServers(t, path)[mcpServerName].(map[string]any)["command"] != "/new/bin/bmcp" {
		t.Error("entry still points at the old path")
	}
}

func TestRegisterRefusesWhatItCannotSafelyRewrite(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"mcpServers": {trailing garbage`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, wrote := registerMCPServer(broken, "/usr/local/bin/bmcp"); wrote {
		t.Error("a hand-edited file we cannot parse must be left alone")
	}
	raw, _ := os.ReadFile(broken)
	if string(raw) != `{"mcpServers": {trailing garbage` {
		t.Errorf("the unparseable file was modified: %s", raw)
	}

	// A client that is not installed has no config directory to write into.
	missing := filepath.Join(dir, "nope", "mcp.json")
	if _, wrote := registerMCPServer(missing, "/usr/local/bin/bmcp"); wrote {
		t.Error("must not create a config directory for an absent client")
	}
}

func TestMCPConfigPathOnlyCoversClientsThatRender(t *testing.T) {
	home := "/home/x"
	for _, name := range []string{"codex", "opencode", "kiro"} {
		if p := mcpConfigPath(name, home); p != "" {
			t.Errorf("%s draws no widget, should not be registered: %s", name, p)
		}
	}
	if mcpConfigPath("cursor", home) != filepath.Join(home, ".cursor", "mcp.json") {
		t.Errorf("cursor path = %s", mcpConfigPath("cursor", home))
	}
	if got := mcpConfigPath("claude-code", home); got == "" {
		t.Error("claude-code must register with the desktop app")
	} else if filepath.Base(got) != "claude_desktop_config.json" {
		t.Errorf("claude-code must use the desktop config, got %s", got)
	}
}
