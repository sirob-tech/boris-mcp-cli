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
	// scope admits the flags belonging to this command alone — --check/--to/
	// --rollback for update, --deep for doctor. The zero value is
	// scopePostCommand, which is what every other command wants.
	scope flagScope
	run   func(*app, globalFlags, []string) int
}

// The auto-update hook hangs off this table rather than off the command
// functions themselves, which is what makes "tool calls never update" true.
// cmdInit is also reachable from requireConfig, so a first-run `bmcp list`
// would otherwise trigger an update through the first-run setup path; and
// cmdInit calls cmdSyncWithRefresh, so hooking that shared function would fire
// twice for every init. Dispatch is the only place that sees the difference.
var commands = []command{
	// The `-h`/`--help` aliases cover exactly one position that globalFlags.help
	// cannot: after `--`, where parseFlags stops interpreting flags and hands the
	// token on as a command name. Without them `bmcp -- --help` falls through to
	// cmdDynamic and is treated as an unknown *tool*, which costs a credential
	// load and a sync round trip before failing. Every other position is served
	// by the flag, because parseGlobalFlags rejects unknown `-`-prefixed tokens
	// before dispatch and so would never see these names.
	{names: []string{"help", "-h", "--help"}, rawArgs: true, run: (*app).cmdHelp},
	// The `--version`/`-V` aliases cover the same one position the help aliases
	// do: after `--`, where parseFlags stops interpreting flags and hands the token
	// on as a command name. Without them `bmcp -- --version` reaches cmdDynamic and
	// is answered with a suggestion to run `bmcp version` — which is what it
	// already said.
	{names: []string{"version", "--version", "-V"}, rawArgs: true, run: (*app).cmdVersion},
	{names: []string{"init"}, autoUpdate: true, run: (*app).cmdInit},
	{names: []string{"sync"}, autoUpdate: true, run: (*app).cmdSync},
	{names: []string{"doctor"}, autoUpdate: true, scope: scopeDoctor, run: (*app).cmdDoctor},
	{names: []string{"update"}, scope: scopeUpdate, run: (*app).cmdUpdate},
	// `tools` is here because it is what agents typed. It was the single most
	// common wrong first token in the transcript audit, ahead of every
	// near-miss spelling a suggestion could have caught, and a suggestion still
	// costs the round trip an alias does not. It shadows a remote tool literally
	// named `tools`, which the namespace prefix (`tools___<name>`) makes an
	// implausible name for a tool inside it.
	{names: []string{"list", "ls", "tools"}, scope: scopeList, run: (*app).cmdList},
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

// commandNames lists one spelling per command — names[0] — which is what keeps
// the flag-shaped aliases (`-h`, `--help`) and the single-letter ones (`d`) out
// of suggestions. Suggesting `bmcp -h` to someone who mistyped a command name
// would answer a question they did not ask.
func commandNames() []string {
	out := make([]string, 0, len(commands))
	for _, c := range commands {
		out = append(out, c.names[0])
	}
	return out
}

// nearestCommand answers with a command name only where the guess is a good one.
// Plain edit distance is not good enough here, and it fails in both directions.
//
// Command names are short, so `sync`, `init`, `call` and `list` become attractors
// that swallow any three-to-five character token: at a flat threshold of 3, `info`
// meant `init` and `cost` meant `list`. Both of those point at commands with side
// effects — `init` rewrites config and `sync` rewrites installed instruction files
// — so a confidently wrong suggestion can talk a caller into one.
//
// In the other direction, truncation costs one edit per dropped character, so the
// most natural abbreviations lost to unrelated short names: `desc` was answered
// with `help` while being an unambiguous prefix of `describe`, which already has
// `d` as an alias.
func nearestCommand(name string) string {
	// Prefix affinity first. A token that prefixes exactly one command is not a
	// guess at all, however many edits away it is. Aliases count and map back to
	// the canonical name, so `tool` resolves through `tools` to `list`.
	if prefixed := commandsWithPrefix(name); len(prefixed) == 1 {
		return prefixed[0]
	}
	// Then distance, scaled to the length of what it is matching against. One edit
	// on a four-letter command is already a quarter of it.
	best, bestDist := "", 0
	for _, candidate := range commandNames() {
		limit := 3
		if len(candidate) <= 4 {
			limit = 1
		}
		d := editDistance(name, candidate)
		if d <= limit && (best == "" || d < bestDist) {
			best, bestDist = candidate, d
		}
	}
	return best
}

// commandsWithPrefix returns the canonical name of every command that name is a
// prefix of, by any of its spellings. An empty name prefixes everything and so
// identifies nothing.
func commandsWithPrefix(name string) []string {
	if name == "" {
		return nil
	}
	var out []string
	for _, c := range commands {
		for _, n := range c.names {
			if strings.HasPrefix(n, name) {
				out = append(out, c.names[0])
				break
			}
		}
	}
	return out
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
	// Checked after --output on purpose, so `bmcp --output bogus --help` still
	// reports the bad value rather than exiting 0 on the usage path.
	if flags.help {
		return a.cmdHelp(flags, nil)
	}
	// After help, so `bmcp --help --version` answers the broader question, and
	// before the bare-usage path, so `bmcp -V` is not answered with usage.
	if flags.version {
		// Only as the whole request. `bmcp --version <tool> --arg x` would otherwise
		// report the version and silently never call the tool, which is the same
		// trap that made the update flag `--to` rather than `--version`.
		if len(rest) > 0 {
			return a.fail(flags, exitValidation, "usage", fmt.Sprintf(
				"--version reports the installed version and takes no arguments; got %q.\nTo update to a specific version: bmcp update --to <version>", rest[0]))
		}
		return a.cmdVersion(flags, nil)
	}
	if len(rest) == 0 {
		usage(a.stdout)
		return 0
	}
	name, cmdArgs := rest[0], rest[1:]
	c, known := lookupCommand(name)
	if known && !c.rawArgs {
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs, c.scope)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		if flags.output, err = normalizeOutputFormat(flags.output); err != nil {
			return a.fail(flags, exitValidation, "invalid_output", err.Error())
		}
		// Before maybeAutoUpdate below: asking a command for help must not cost a
		// network round trip, let alone a binary swap. There is no version check
		// here on purpose — parseFlags accepts --version in the global scope only,
		// so after a command name it is a flag error.
		if flags.help {
			return a.cmdHelp(flags, nil)
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

// hasHelpArg spots --help/-h in the argument list of a rawArgs command, which
// parseFlags never gets to inspect.
func hasHelpArg(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func (a *app) cmdVersion(flags globalFlags, args []string) int {
	// version is rawArgs, so parseFlags never sees its arguments and cannot set
	// flags.help for it — same reason install handles these two tokens itself.
	if hasHelpArg(args) {
		usage(a.stdout)
		return 0
	}
	// Rejected rather than ignored. run() guards the flag form, but the command
	// aliases reach here with their arguments intact, so `bmcp -- --version doctor`
	// and `bmcp version garbage` would otherwise report the version and exit 0
	// having silently dropped what was actually asked for.
	if len(args) > 0 {
		return a.fail(flags, exitValidation, "usage", fmt.Sprintf(
			"bmcp version takes no arguments; got %q.\nTo update to a specific version: bmcp update --to <version>", args[0]))
	}
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
		// True: a human typed `bmcp sync` in a directory they chose.
		a.refreshInstructions(cache, true)
	}
	return 0
}

// refreshSummary is what a refresh did, in the form doctor --json reports. The
// exit code deliberately ignores a failed refresh, so without this a fleet
// watching `ok` would never learn that its agents are reading a months-stale
// tool list — which is issue #25 again, one layer up.
type refreshSummary struct {
	Refreshed int `json:"refreshed"`
	Failed    int `json:"failed"`
}

// refreshInstructions rewrites installed instruction files so the tool catalog
// they embed matches the one this run just fetched. Every caller has already
// synced, so the cache is the newest catalog available.
//
// Output goes to stderr and nothing here reaches an exit code. This runs inside
// doctor, and BORIS.md tells agents to read a failing doctor as "BORIS is
// broken" and stop using it — an unwritable ~/.claude is not that.
func (a *app) refreshInstructions(cache *toolCache, includeProject bool) refreshSummary {
	var summary refreshSummary
	for _, result := range refreshExistingInstructions(cache, includeProject) {
		for _, file := range result.Files {
			switch {
			case file.Path == "":
				summary.Failed++
			case file.Changed:
				summary.Refreshed++
			}
		}
		printRefreshResult(a.stderr, result)
	}
	return summary
}

// cmdList writes machine-readable records to stdout and everything else to
// stderr: callers pipe it through head/grep, so one truncated line must still
// be a complete, parseable record.
func (a *app) cmdList(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp list [--schemas] [--output ndjson|json|human]")
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
		// --schemas in the human view is `describe` for every tool, which is what
		// the flag means in the machine view too. Rejecting the combination would
		// be a usage papercut for the one caller — a person — least able to guess
		// which half of it was wrong.
		if flags.listSchemas {
			err = renderToolListWithSchemas(a.stdout, cache.Tools)
		} else {
			err = renderToolList(a.stdout, cache.Tools)
		}
	} else {
		err = writeToolRecords(a.stdout, cache.Tools, cache.LastSync, flags.listSchemas)
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
	// A mistyped command is answered from local state alone. Everything below can
	// load credentials, sync the catalog, and — through requireConfig on an
	// unconfigured interactive machine — run the whole first-run setup, none of
	// which a typo should cost, and the last of which turns a typo into a prompt.
	//
	// The bar for answering locally is that the answer cannot differ from the one
	// the normal path would give: either the catalog on disk is already the catalog
	// a tool call would use, or there is no config, so no sync could produce a
	// better one. Without that bar a stale cache made real tools unreachable — the
	// server grows tools, and any new one whose name reads like a typo would be
	// refused locally and never synced for.
	if near := nearestCommand(name); near != "" {
		cfg, configured, cfgErr := a.loadEffective(flags, false)
		disk, diskErr := readCache(cfg.ToolsPath)
		if cfgErr != nil || !configured || a.catalogIsFresh(cfg, disk, diskErr) {
			if _, err := resolveTool(disk, name); err != nil {
				var unknown *unknownToolError
				if errors.As(err, &unknown) {
					err = unknown.withCommand(near)
				}
				return a.fail(flags, exitValidation, "unknown_command", err.Error())
			}
		}
	}
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
		// Reached whenever the check above declined to answer locally: a stale or
		// absent catalog, or a name nowhere near a command. resolveTool speaks only
		// for the catalog, so the command table's answer is added here.
		var unknown *unknownToolError
		if errors.As(err, &unknown) {
			if near := nearestCommand(name); near != "" {
				err = unknown.withCommand(near)
			}
		}
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

// cmdDoctor answers "can this machine call BORIS right now".
//
// The generated instructions require it before the first BORIS call of every
// agent session, which makes it the latency and authentication gate on all BMCP
// usage. It used to load AWS credentials and sync the catalog every time: a
// 3.55s median and an 11s maximum in the audited sessions, and three outright
// failures where an expired SSO session met a sandbox that could not reach
// device authorization — a diagnostic command failing closed on work the first
// real tool call would have done anyway.
//
// So the routine answer now comes from local state alone, and the network half
// runs only when local state cannot give it: no cache, an unreadable one, one
// belonging to another server, or one past its TTL. `--deep` asks for it
// unconditionally, which is what to reach for when a call has already failed on
// auth or connectivity and the question is who is at fault.
//
// What this deliberately does not fix is #17. failSchemaChanged fires when a
// tool call observes LastSync advance, and the escalation above syncs on exactly
// the condition that would otherwise have made the tool call sync — a stale
// cache — so doctor still consumes the signal first and the guard still cannot
// fire in a session that ran doctor. Restoring it needs a baseline of what the
// agent last read, not of when the cache was last written.
func (a *app) cmdDoctor(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp doctor [--deep]")
	}
	cfg, exists, err := a.loadEffective(flags, false)
	checks := []map[string]any{}
	// nil when no refresh was attempted — no config, or no readable catalog to
	// render from — which is a different state from "attempted and wrote nothing".
	var instructions *refreshSummary
	deep := false
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
		disk, diskErr := readCache(cfg.ToolsPath)
		deep = flags.doctorDeep || !a.catalogIsFresh(cfg, disk, diskErr)
		if deep {
			_, _, authErr := a.loadCredentials(context.Background(), cfg)
			add("auth", authErr == nil, messageOrOK(authErr))
			if authErr == nil {
				synced, syncErr := a.syncTools(context.Background(), cfg)
				add("remote", syncErr == nil, messageOrOK(syncErr))
				if syncErr == nil {
					add("tools", true, fmt.Sprintf("%d tools synced", len(synced.Tools)))
					disk, diskErr = synced, nil
				}
			}
		}
		// Reported last, and from the state this run ends in rather than the one it
		// started in. Emitting it before the escalation meant a machine whose cache
		// was missing was told "cache fail" and exited 1 having just successfully
		// rebuilt it — and BORIS.md tells agents to read a failing doctor as "BORIS
		// is broken" and stop using it.
		if diskErr != nil {
			add("cache", false, "missing or unreadable")
		} else {
			add("cache", true, a.cacheStatus(cfg, disk))
			// Refreshed from whatever catalog this run ended with, synced or not.
			//
			// The catalog in tools.json is not the catalog agents read. They read the
			// tool list embedded in the instruction files, and only `bmcp sync`
			// rewrote those — while BORIS.md tells agents to run `bmcp doctor`. So a
			// tool added, renamed or removed stayed invisible to every agent
			// indefinitely, and the names they did see could point at tools the
			// server no longer serves.
			//
			// Doing it on the local path too is what keeps that per-session cadence
			// after this command stopped syncing. It cannot carry a change the server
			// made — nothing local can — but it does carry every change that has
			// already reached this machine: a catalog some earlier tool call synced,
			// a template the last self-update changed, and a file whose previous
			// refresh failed. Those are most of what went stale, and they cost
			// nothing to fix. Server drift is bounded by sync_ttl instead of by the
			// session, which is the price of not authenticating every session.
			//
			// It is free to repeat because renderInstructionToolList is a pure
			// function of the catalog: an unchanged one renders byte-identical and
			// writeFileWithBackup declines to write it at all.
			//
			// User scope only. doctor runs unattended from whatever directory an
			// agent is working in, and a project-scope file is claimed by filename
			// alone — see refreshExistingInstructions.
			summary := a.refreshInstructions(disk, false)
			instructions = &summary
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
		// mode says which question was answered, because the two produce different
		// check sets and a consumer that finds no `auth` row should be able to tell
		// "not checked" from "checked and gone".
		payload := map[string]any{"ok": allChecksOK(checks), "checks": checks, "mode": doctorMode(deep)}
		if st != nil {
			payload["update"] = st.updateJSON()
		}
		if instructions != nil {
			payload["instructions"] = instructions
		}
		out, _ := json.MarshalIndent(payload, "", "  ")
		// stdout, matching the convention cmdList follows: machine-readable output
		// on stdout, prose on stderr. This document used to share stderr with
		// syncTools' "Syncing tools...", so the stream was not a parseable JSON
		// document and every consumer had to scan for the first `{`.
		fmt.Fprintln(a.stdout, string(out))
	} else if st != nil {
		fmt.Fprintf(a.stdout, "%-18s %s  %s\n", "version", "ok", a.updateSummary(st))
	}
	if !allChecksOK(checks) {
		return exitGeneric
	}
	return 0
}

func doctorMode(deep bool) string {
	if deep {
		return "deep"
	}
	return "local"
}

// cacheStatus describes the catalog on disk, and when it is not the one a tool
// call would use, why not. "age 200h" is not an answer on its own: whether that
// is stale depends on sync_ttl, and a cache can also be unusable at any age
// because it belongs to another server. Each branch mirrors one conjunct of
// catalogIsFresh, so a reader is never told to look at something that is fine.
func (a *app) cacheStatus(cfg effectiveConfig, cache *toolCache) string {
	msg := fmt.Sprintf("%d %s, age %s", len(cache.Tools), pluralize(len(cache.Tools), "tool"),
		a.now().Sub(cache.LastSync).Round(time.Second))
	switch {
	case cache.URL != cfg.URL:
		return msg + ", synced from a different URL"
	case cfg.SyncTTL == 0:
		return msg + ", sync_ttl is 0 so it is never reused"
	case a.now().Sub(cache.LastSync) > cfg.SyncTTL:
		return fmt.Sprintf("%s, older than sync_ttl %s", msg, cfg.SyncTTL)
	}
	return msg
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
	// Same reason as cmdVersion: install is rawArgs, so flags.help is never set
	// for it. Checked before the argument loop so that --help wins over any other
	// usage error in the same command line.
	if hasHelpArg(args) {
		usage(a.stdout)
		return 0
	}
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
  bmcp doctor [--deep]
  bmcp list|ls|tools [--schemas] [--output ndjson|json|human]
  bmcp describe|d <tool>
  bmcp call <tool> ['{"arg":"value"}']
  bmcp <exact_tool_name> --arg value
  bmcp update [--check] [--to <version>] [--rollback]
  bmcp version

Flags for bmcp list:
  --schemas                    Include each tool's input schema, so the catalog
                               and every schema arrive in one invocation

Flags for bmcp doctor:
  --deep                       Also check credentials, the server and the live
                               catalog. Without it doctor answers from local
                               state when the cached catalog is fresh

Flags for bmcp update:
  --check                      Report whether an update is available, apply nothing
  --to <version>               Update to this exact version, downgrading if needed
  --rollback                   Restore the binary the last update replaced

Global flags:
  --help, -h                   Show this help. As the only argument after a tool
                               name, shows that tool's schema instead
  --version, -V                Show the installed version, same as bmcp version.
                               Takes no arguments and no command
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
