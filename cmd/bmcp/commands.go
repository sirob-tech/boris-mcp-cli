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
	// autoUpdate marks the commands that may check for and apply an update.
	// Tool calls are deliberately excluded: they must never pay for a network
	// round trip, let alone a binary swap.
	autoUpdate bool
	// ownsUpdateFlags admits --check/--to/--rollback for this command only.
	ownsUpdateFlags bool
	run             func(*app, globalFlags, []string) int
}

// The auto-update hook hangs off this table rather than off the command
// functions themselves, which is what makes "tool calls never update" true.
// cmdInit is also reachable from requireConfig, so a first-run `bmcp list`
// would otherwise trigger an update through the first-run setup path; and
// cmdInit calls cmdSyncWithRefresh, so hooking that shared function would fire
// twice for every init. Dispatch is the only place that sees the difference.
var commands = []command{
	{names: []string{"help", "-h", "--help"}, rawArgs: true, run: (*app).cmdHelp},
	{names: []string{"version"}, rawArgs: true, run: (*app).cmdVersion},
	{names: []string{"init"}, autoUpdate: true, run: (*app).cmdInit},
	{names: []string{"sync"}, autoUpdate: true, run: (*app).cmdSync},
	{names: []string{"doctor"}, autoUpdate: true, run: (*app).cmdDoctor},
	{names: []string{"update"}, ownsUpdateFlags: true, run: (*app).cmdUpdate},
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
	// Validated here rather than in parseFlags: run() collapses every parse
	// error to exitGeneric, and an unsupported --output is a usage error. Checked
	// before the bare-usage path too, so a bad value never exits 0. rawArgs
	// commands still receive their own arguments unparsed, by design.
	if flags.output, err = normalizeOutputFormat(flags.output); err != nil {
		return a.fail(flags, exitValidation, "invalid_output", err.Error())
	}
	if len(rest) == 0 {
		usage(a.stdout)
		return 0
	}
	name, cmdArgs := rest[0], rest[1:]
	c, known := lookupCommand(name)
	if known && !c.rawArgs {
		scope := scopePostCommand
		if c.ownsUpdateFlags {
			scope = scopeUpdate
		}
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs, scope)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		if flags.output, err = normalizeOutputFormat(flags.output); err != nil {
			return a.fail(flags, exitValidation, "invalid_output", err.Error())
		}
	}
	if known {
		if c.autoUpdate {
			a.maybeAutoUpdate(flags)
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
	// Without this line, "bmcp broke" reports after a self-update arrive with no
	// way to tell which version replaced which, or when.
	if path, err := a.resolveExecutable(); err == nil {
		if receipt, err := readInstallReceipt(path); err == nil && len(receipt.Updates) > 0 {
			last := receipt.Updates[len(receipt.Updates)-1]
			fmt.Fprintf(a.stdout, "updated: %s -> %s at %s\n", last.From, last.To, last.At)
		}
	}
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

// cmdList writes machine-readable records to stdout and everything else to
// stderr: callers pipe it through head/grep, so one truncated line must still
// be a complete, parseable record.
func (a *app) cmdList(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp list [--output ndjson|json|human]")
	}
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		return a.fail(flags, exitSync, "sync_failed", err.Error())
	}
	if cache.LastSync.IsZero() {
		fmt.Fprintf(a.stderr, "%d tools\n", len(cache.Tools))
	} else {
		fmt.Fprintf(a.stderr, "%d tools synced %s\n", len(cache.Tools), cache.LastSync.UTC().Format(time.RFC3339))
	}
	if flags.output == outputHuman {
		err = renderToolList(a.stdout, cache.Tools)
	} else {
		err = writeToolRecords(a.stdout, cache.Tools, cache.LastSync)
	}
	if err != nil {
		return a.fail(flags, exitGeneric, "output_failed", err.Error())
	}
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
	// The update state is reported outside `checks` on purpose. add() feeds
	// allChecksOK, which drives the exit code, so routing it through there
	// would let a GitHub outage make doctor exit 1 — and BORIS.md tells agents
	// to read a failing doctor as "BORIS is broken" and stop.
	st := a.update
	// The one update failure that must reach the exit code. A GitHub outage is
	// not a BORIS outage, but "the swap left no working binary at this path" is
	// not something to report as an informational row and exit 0 on.
	if st != nil && errors.Is(st.Err, errUpdateCorrupted) {
		add("update", false, st.Err.Error())
	}
	if flags.jsonOut {
		payload := map[string]any{"ok": allChecksOK(checks), "checks": checks}
		if st != nil {
			payload["update"] = st.updateJSON()
		}
		out, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Fprintln(a.stderr, string(out))
	} else if st != nil {
		fmt.Fprintf(a.stdout, "%-18s %s  %s\n", "version", "ok", a.updateSummary(st))
	}
	if !allChecksOK(checks) {
		return exitGeneric
	}
	return 0
}

func (a *app) updateSummary(st *updateState) string {
	switch {
	case st.Kind == installSource:
		return fmt.Sprintf("%s (built from source)", st.Current)
	case st.Applied:
		return fmt.Sprintf("updated %s -> %s, active next run", st.Current, st.Target)
	case st.Err != nil && st.Stage == updateStageApply:
		return fmt.Sprintf("%s (update failed: %v)", st.Current, st.Err)
	case st.Err != nil:
		return fmt.Sprintf("%s (update check failed: %v)", st.Current, st.Err)
	case !st.Checked:
		return st.Current
	case st.Available:
		return fmt.Sprintf("%s, %s available (run: %s)", st.Current, st.Target, st.Action)
	default:
		return fmt.Sprintf("%s (latest)", st.Current)
	}
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
		return a.fail(flags, exitValidation, "usage", "usage: bmcp install <claude-code|codex|opencode|cursor|kiro|all> [--scope user|project]")
	}
	if len(harnesses) == 1 && harnesses[0] == "all" {
		harnesses = []string{"claude-code", "codex", "opencode", "cursor", "kiro"}
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
  bmcp install <claude-code|codex|opencode|cursor|kiro|all> [--scope user|project]
  bmcp sync
  bmcp doctor
  bmcp list|ls [--output ndjson|json|human]
  bmcp describe|d <tool>
  bmcp call <tool> ['{"arg":"value"}']
  bmcp <exact_tool_name> --arg value
  bmcp update [--check] [--to <version>] [--rollback]
  bmcp version

Flags for bmcp update:
  --check                      Report whether an update is available, apply nothing
  --to <version>               Update to this exact version, downgrading if needed
  --rollback                   Restore the binary the last update replaced

Global flags:
  --no-auto-update             Do not update automatically during this command
  --url, -u <url>              Override BORIS MCP URL
  --profile, -p <profile>      Override AWS profile
  --region <region>            Override SigV4 region
  --service <service>          Override SigV4 service
  --output <ndjson|json|human> Format for bmcp list (default ndjson)
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
