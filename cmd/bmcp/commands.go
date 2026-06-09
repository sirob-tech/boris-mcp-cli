package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type command struct {
	names   []string
	rawArgs bool
	run     func(*app, globalFlags, []string) int
}

var commands = []command{
	{names: []string{"help", "-h", "--help"}, rawArgs: true, run: (*app).cmdHelp},
	{names: []string{"version"}, rawArgs: true, run: (*app).cmdVersion},
	{names: []string{"init"}, run: (*app).cmdInit},
	{names: []string{"sync"}, run: (*app).cmdSync},
	{names: []string{"doctor"}, run: (*app).cmdDoctor},
	{names: []string{"list", "ls"}, run: (*app).cmdList},
	{names: []string{"describe", "d"}, run: (*app).cmdDescribe},
	{names: []string{"call"}, run: (*app).cmdCall},
	{names: []string{"install"}, rawArgs: true, run: (*app).cmdInstall},
}

func lookupCommand(name string) (command, bool) {
	for _, c := range commands {
		for _, n := range c.names {
			if n == name {
				return c, true
			}
		}
	}
	return command{}, false
}

func (a *app) run(args []string) int {
	flags, rest, err := parseGlobalFlags(args)
	if err != nil {
		return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
	}
	if len(rest) == 0 {
		usage(a.stdout)
		return 0
	}
	name, cmdArgs := rest[0], rest[1:]
	if c, ok := lookupCommand(name); ok {
		if !c.rawArgs {
			flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs)
			if err != nil {
				return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
			}
		}
		return c.run(a, flags, cmdArgs)
	}
	return a.cmdDynamic(flags, name, cmdArgs)
}

func (a *app) cmdInit(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp init [--url <url>] [--profile <profile>]")
	}
	cfg, exists, err := a.loadEffective(flags, false)
	if err != nil {
		return a.fail(flags, exitConfig, "config_invalid", err.Error())
	}
	if !exists {
		cfg = defaultEffective(flags)
	}

	interactive := a.isInteractive() && !cfg.NonInteractive
	var reader *bufio.Reader
	fileCfg, _ := readConfig(cfg.ConfigPath)
	if interactive {
		reader = bufio.NewReader(a.stdin)
		fmt.Fprintf(a.stderr, "BORIS MCP URL")
		if cfg.URL != "" {
			fmt.Fprintf(a.stderr, " [%s]", sanitizeURL(cfg.URL))
		}
		fmt.Fprint(a.stderr, ": ")
		if line, err := reader.ReadString('\n'); err == nil {
			if v := strings.TrimSpace(line); v != "" {
				flags.url = v
				cfg.URL = v
			}
		}
		fmt.Fprintf(a.stderr, "AWS profile (optional, blank uses AWS defaults)")
		if cfg.Profile != "" {
			fmt.Fprintf(a.stderr, " [%s]", cfg.Profile)
		}
		fmt.Fprint(a.stderr, ": ")
		if line, err := reader.ReadString('\n'); err == nil {
			if v := strings.TrimSpace(line); v != "" {
				flags.profile = v
				cfg.Profile = v
			}
		}
	} else if !exists && flags.url == "" {
		return a.fail(flags, exitConfig, "not_configured", "BORIS MCP is not configured.\nRun interactively: bmcp init\nOr non-interactively: bmcp init --url <url>")
	}

	if flags.url != "" {
		fileCfg.URL = flags.url
	}
	if flags.profile != "" {
		fileCfg.AWSProfile = flags.profile
	}
	if flags.region != "" {
		fileCfg.Region = flags.region
	}
	if flags.service != "" {
		fileCfg.Service = flags.service
	}
	if !exists {
		applyDefaults(&fileCfg)
	}
	if err := validateURL(fileCfg.URL, flags.allowHTTP); err != nil {
		return a.fail(flags, exitConfig, "url_invalid", err.Error())
	}
	if err := os.MkdirAll(cfg.Home, 0o700); err != nil {
		return a.fail(flags, exitConfig, "config_write_failed", err.Error())
	}
	oldURL := ""
	if exists {
		old, _ := readConfig(cfg.ConfigPath)
		oldURL = old.URL
	}
	if err := writeConfig(cfg.ConfigPath, fileCfg); err != nil {
		return a.fail(flags, exitConfig, "config_write_failed", err.Error())
	}
	fmt.Fprintf(a.stderr, "Saved config: %s\nRun `bmcp init` again to change it.\n", cfg.ConfigPath)
	if oldURL != "" && oldURL != fileCfg.URL {
		_ = os.Remove(cfg.ToolsPath)
	}
	refreshInstructions := !interactive
	if code := a.cmdSyncWithRefresh(flags, refreshInstructions); code != 0 {
		return code
	}
	if interactive && reader != nil {
		a.promptInstallDetectedHarnesses(reader, flags)
	}
	return 0
}

func (a *app) cmdHelp(flags globalFlags, args []string) int {
	usage(a.stdout)
	return 0
}

func (a *app) cmdVersion(flags globalFlags, args []string) int {
	fmt.Fprintf(a.stdout, "bmcp %s\ncommit: %s\nbuilt: %s\n", version, buildCommit, buildDate)
	return 0
}

func (a *app) cmdSync(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp sync")
	}
	return a.cmdSyncWithRefresh(flags, true)
}

func (a *app) cmdSyncWithRefresh(flags globalFlags, refreshInstructions bool) int {
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	cache, err := a.syncTools(context.Background(), cfg)
	if err != nil {
		code := exitSync
		if isAuthErr(err) {
			code = exitAuth
		}
		return a.fail(flags, code, errorName(err), err.Error())
	}
	fmt.Fprintf(a.stderr, "Synced %d tools to %s\n", len(cache.Tools), cfg.ToolsPath)
	if refreshInstructions {
		for _, result := range refreshExistingInstructions(cache) {
			printRefreshResult(a.stderr, result)
		}
	}
	return 0
}

func (a *app) cmdList(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp list")
	}
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		return a.fail(flags, exitSync, "sync_failed", err.Error())
	}
	fmt.Fprintf(a.stdout, "%d tools synced %s\n", len(cache.Tools), cache.LastSync.UTC().Format(time.RFC3339))
	renderToolList(a.stdout, cache.Tools)
	return 0
}

func (a *app) cmdDescribe(flags globalFlags, args []string) int {
	if len(args) != 1 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp describe <tool>")
	}
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		return a.fail(flags, exitSync, "sync_failed", err.Error())
	}
	t, err := resolveTool(cache, args[0])
	if err != nil {
		return a.fail(flags, exitValidation, "tool_not_found", err.Error())
	}
	t.Describe(a.stdout)
	return 0
}

func (a *app) cmdCall(flags globalFlags, args []string) int {
	if len(args) < 1 || len(args) > 2 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp call <tool> ['{\"arg\":\"value\"}']")
	}
	payload := ""
	if len(args) == 2 {
		payload = args[1]
	}
	return a.runCall(flags, args[0], payload, true)
}

func (a *app) runCall(flags globalFlags, name string, payload string, readStdin bool) int {
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	oldCache, _ := readCache(cfg.ToolsPath)
	cache, err := a.cacheForCatalog(flags, cfg, false)
	if err != nil {
		code := exitSync
		if isAuthErr(err) {
			code = exitAuth
		}
		return a.fail(flags, code, errorName(err), err.Error())
	}
	t, err := resolveTool(cache, name)
	if err != nil {
		return a.fail(flags, exitSync, "tool_not_found", fmt.Sprintf("%s\nThe tool was not called.", err.Error()))
	}
	if oldCache != nil && cache.LastSync.After(oldCache.LastSync) {
		if oldTool, err := resolveTool(oldCache, name); err == nil {
			if newTool, ok := findTool(cache, oldTool.Name); ok && oldTool.SchemaHash != newTool.SchemaHash {
				return a.failSchemaChanged(flags, oldTool, newTool)
			}
		}
	}
	if payload == "" && readStdin && shouldReadPayloadFromStdin(a.stdin) {
		data, err := io.ReadAll(a.stdin)
		if err != nil {
			return a.fail(flags, exitValidation, "stdin_read_failed", err.Error())
		}
		payload = strings.TrimSpace(string(data))
	}
	if payload == "" {
		payload = "{}"
	}
	var input map[string]any
	if err := json.Unmarshal([]byte(payload), &input); err != nil {
		return a.fail(flags, exitValidation, "invalid_json", fmt.Sprintf("Invalid JSON payload: %v", err))
	}
	if err := t.Validate(input); err != nil {
		return a.fail(flags, exitValidation, "tool_validation_failed", err.Error())
	}
	fmt.Fprintf(a.stderr, "Calling %s...\n", displayToolName(t.Name))
	result, err := a.callTool(context.Background(), cfg, t.Name, input)
	if err != nil {
		code := exitSync
		if isAuthErr(err) {
			code = exitAuth
		}
		if errors.Is(err, errUpstream) {
			code = exitUpstream
		}
		return a.fail(flags, code, errorName(err), err.Error())
	}
	if !flags.raw {
		result = unwrapMCPTextEnvelope(result)
	}
	if flags.pretty {
		var pretty bytes.Buffer
		if json.Indent(&pretty, result, "", "  ") == nil {
			result = pretty.Bytes()
		}
	}
	a.stdout.Write(result)
	if len(result) == 0 || result[len(result)-1] != '\n' {
		fmt.Fprintln(a.stdout)
	}
	return 0
}

func (a *app) cmdDynamic(flags globalFlags, name string, args []string) int {
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		return a.fail(flags, exitSync, "sync_failed", err.Error())
	}
	t, err := resolveTool(cache, name)
	if err != nil {
		return a.fail(flags, exitValidation, "unknown_command", err.Error())
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		t.Describe(a.stdout)
		return 0
	}
	input, err := t.ParseFlags(args)
	if err != nil {
		return a.fail(flags, exitValidation, "tool_validation_failed", err.Error())
	}
	body, _ := json.Marshal(input)
	return a.runCall(flags, t.Name, string(body), false)
}

func (a *app) cmdDoctor(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp doctor")
	}
	cfg, exists, err := a.loadEffective(flags, false)
	checks := []map[string]any{}
	add := func(name string, ok bool, msg string) {
		checks = append(checks, map[string]any{"name": name, "ok": ok, "message": msg})
		if flags.jsonOut {
			return
		}
		state := "ok"
		if !ok {
			state = "fail"
		}
		fmt.Fprintf(a.stdout, "%-18s %s  %s\n", name, state, msg)
	}
	if err != nil {
		add("config", false, err.Error())
	} else if !exists {
		add("config", false, "missing")
	} else {
		add("config", true, cfg.ConfigPath)
		add("url", validateURL(cfg.URL, flags.allowHTTP) == nil, sanitizeURL(cfg.URL))
		if cache, err := readCache(cfg.ToolsPath); err == nil {
			add("cache", true, fmt.Sprintf("%d tools, age %s", len(cache.Tools), a.now().Sub(cache.LastSync).Round(time.Second)))
		} else {
			add("cache", false, "missing or unreadable")
		}
		_, _, authErr := a.loadCredentials(context.Background(), cfg)
		add("auth", authErr == nil, messageOrOK(authErr))
		if authErr == nil {
			cache, syncErr := a.syncTools(context.Background(), cfg)
			add("remote", syncErr == nil, messageOrOK(syncErr))
			if syncErr == nil {
				add("tools", true, fmt.Sprintf("%d tools synced", len(cache.Tools)))
			}
		}
	}
	if flags.jsonOut {
		out, _ := json.MarshalIndent(map[string]any{"ok": allChecksOK(checks), "checks": checks}, "", "  ")
		fmt.Fprintln(a.stderr, string(out))
	}
	if !allChecksOK(checks) {
		return exitGeneric
	}
	return 0
}

func (a *app) cmdInstall(flags globalFlags, args []string) int {
	scope := "user"
	var harnesses []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--scope":
			if i+1 >= len(args) {
				return a.fail(flags, exitValidation, "usage", "--scope requires a value: user or project")
			}
			i++
			scope = args[i]
		case strings.HasPrefix(arg, "--scope="):
			scope = strings.TrimPrefix(arg, "--scope=")
		case strings.HasPrefix(arg, "-"):
			return a.fail(flags, exitValidation, "usage", "unknown install flag: "+arg)
		default:
			harnesses = append(harnesses, arg)
		}
	}
	if scope != "user" && scope != "project" {
		return a.fail(flags, exitValidation, "usage", "--scope must be user or project")
	}
	if len(harnesses) == 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp install <claude-code|codex|cursor|all> [--scope user|project]")
	}
	if len(harnesses) == 1 && harnesses[0] == "all" {
		harnesses = []string{"claude-code", "codex", "cursor"}
	}
	for _, harness := range harnesses {
		result, err := a.installHarnessWithCatalog(flags, harness, scope)
		if err != nil {
			return a.fail(flags, exitValidation, "install_failed", err.Error())
		}
		printInstallResult(a.stderr, result)
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  bmcp init [--url <url>] [--profile <profile>]
  bmcp install <claude-code|codex|cursor|all> [--scope user|project]
  bmcp sync
  bmcp doctor
  bmcp list|ls
  bmcp describe|d <tool>
  bmcp call <tool> ['{"arg":"value"}']
  bmcp <exact_tool_name> --arg value
  bmcp version

Global flags:
  --url, -u <url>              Override BORIS MCP URL
  --profile, -p <profile>      Override AWS profile
  --region <region>            Override SigV4 region
  --service <service>          Override SigV4 service
  --json                       Emit structured errors
  --pretty                     Pretty-print successful tool JSON
  --raw                        Emit raw MCP tool envelopes
  --non-interactive            Disable prompts and SSO login
  --verbose                    Emit diagnostics to stderr
`)
}

func (a *app) fail(flags globalFlags, code int, name, msg string) int {
	if flags.jsonOut {
		out, _ := json.Marshal(map[string]any{"ok": false, "error": name, "message": msg})
		fmt.Fprintln(a.stderr, string(out))
	} else {
		fmt.Fprintln(a.stderr, msg)
	}
	return code
}

func (a *app) failSchemaChanged(flags globalFlags, oldTool, newTool tool) int {
	changes := oldTool.Diff(newTool)
	if flags.jsonOut {
		out, _ := json.Marshal(map[string]any{"ok": false, "error": "tool_schema_changed", "tool": newTool.Name, "changes": changes})
		fmt.Fprintln(a.stderr, string(out))
	} else {
		fmt.Fprintf(a.stderr, "Tool schema changed: %s\n", newTool.Name)
		for _, c := range changes {
			fmt.Fprintf(a.stderr, "- %s\n", c["message"])
		}
		fmt.Fprintln(a.stderr, "\nThe tool was not called. Retry with the updated arguments.")
	}
	return exitSync
}

func shouldReadPayloadFromStdin(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return true
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == 0
}

func messageOrOK(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func allChecksOK(checks []map[string]any) bool {
	for _, c := range checks {
		if ok, _ := c["ok"].(bool); !ok {
			return false
		}
	}
	return len(checks) > 0
}
