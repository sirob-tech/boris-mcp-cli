package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// Registering bmcp as a client's own MCP server is what makes the graph picture
// appear: only the process that spawns `bmcp serve` can negotiate MCP Apps and
// mount the widget, so a server the client did not start can never draw one.
//
// Only the two clients that render a widget are registered. The rest reach the
// same tools through the CLI and would gain nothing from an entry, while each
// wants a different config format to be parsed and rewritten without losing the
// servers already in it.
const mcpServerName = "boris"

// mcpConfigPath names the file a client reads its MCP servers from, or "" for a
// client this does not register.
func mcpConfigPath(harnessName, home string) string {
	if home == "" {
		return ""
	}
	switch harnessName {
	case "claude-code":
		// The desktop app's config, not the CLI's: a server in ~/.claude.json is
		// spawned by the CLI, which does not implement the extension.
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
		}
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json")
	}
	return ""
}

// registerMCPServer points a client's `boris` entry at this binary, leaving
// every other key and server in the file untouched. It reports whether it wrote.
func registerMCPServer(path, executable string) (installFileResult, bool) {
	if path == "" || executable == "" {
		return installFileResult{}, false
	}
	// The client's own config directory standing in for "this client is
	// installed". Creating it would be installing a config for a client that may
	// not be here.
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		return installFileResult{}, false
	}

	config := map[string]json.RawMessage{}
	if raw, err := os.ReadFile(path); err == nil && len(raw) > 0 {
		// Hand-edited and unparseable is not ours to repair, and rewriting it
		// would drop whatever servers the user has.
		if json.Unmarshal(raw, &config) != nil {
			return installFileResult{}, false
		}
	}
	servers := map[string]json.RawMessage{}
	if raw, ok := config["mcpServers"]; ok {
		if json.Unmarshal(raw, &servers) != nil {
			return installFileResult{}, false
		}
	}
	if currentRegistration(servers[mcpServerName]) == executable {
		return installFileResult{}, false
	}

	entry, err := json.Marshal(map[string]any{"command": executable, "args": []string{"serve"}})
	if err != nil {
		return installFileResult{}, false
	}
	servers[mcpServerName] = entry
	encoded, err := json.Marshal(servers)
	if err != nil {
		return installFileResult{}, false
	}
	config["mcpServers"] = encoded
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return installFileResult{}, false
	}
	return writeFileWithBackup(path, append(content, '\n')), true
}

// currentRegistration reports the command an existing entry already points at,
// so a correct one is left alone rather than reformatting the whole file on
// every refresh — and rotating a backup generation each time.
func currentRegistration(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var entry struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if json.Unmarshal(raw, &entry) != nil {
		return ""
	}
	if len(entry.Args) != 1 || entry.Args[0] != "serve" {
		return ""
	}
	return entry.Command
}
