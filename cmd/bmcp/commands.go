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
	// Before the error check and before validation: parsing stops at the first
	// unknown flag, so a --format later on the line was never seen, and the
	// failure would otherwise be rendered in whichever format the mistake's
	// position happened to leave selected. See formatForReport.
	if !flags.formatSet {
		if f := formatForReport(args); f != "" {
			flags.format, flags.formatSet = f, true
		}
	}
	// Named before the global flags are validated, so that a failure raised there —
	// a bad --output, a bad --max-bytes, both of which the documented ordering puts
	// ahead of the command — still says which command it happened in. An
	// unrecognised name is a tool call, which is what dispatch will decide below.
	if len(rest) > 0 {
		if c, known := lookupCommand(rest[0]); known {
			flags.command = c.names[0]
		} else {
			flags.command = "call"
		}
	}
	if err != nil {
		return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
	}
	// Validated here rather than in parseFlags: run() collapses every parse
	// error to exitGeneric, and an unsupported --output is a usage error. Checked
	// before the bare-usage path too, so a bad value never exits 0. rawArgs
	// commands still receive their own arguments unparsed, by design.
	if code, ok := a.validateOutputFlags(&flags); !ok {
		return code
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
		// A machine format gets a failure document rather than usage prose. `--help`
		// is an explicit request for the human text and keeps it in every format, but
		// an empty command line is not a request — it is an invocation that did not
		// finish being built, and `bmcp --format json $ARGS | jq` with an empty $ARGS
		// otherwise exits 0 having written 2.8KB of English to the parser.
		if flags.machine() {
			return a.fail(flags, exitValidation, "usage", "bmcp needs a command.\nRun `bmcp --help` for the list, or `bmcp list` for the tool catalog.")
		}
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
		if code, ok := a.validateOutputFlags(&flags); !ok {
			return code
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
		a.selectFormat(&flags)
		if c.autoUpdate {
			a.maybeAutoUpdate(flags)
		}
		return c.run(a, flags, cmdArgs)
	}
	// An unrecognised name is a tool call, so it answers in the format a tool call
	// answers in — and it is the one dispatch path with no table entry to read a
	// default from.
	flags.command = "call"
	a.selectFormat(&flags)
	return a.cmdDynamic(flags, name, cmdArgs)
}

// validateOutputFlags checks the two value-taking flags that describe the output
// rather than the work. Both are validated in run() rather than in parseFlags,
// which maps every error it raises to exitGeneric — a bad value for either is a
// usage error and exits 5.
func (a *app) validateOutputFlags(flags *globalFlags) (int, bool) {
	var err error
	// --format first: it is the one that decides how this very report is rendered,
	// so a bad --output alongside a good --format still answers in the contract.
	if flags.formatSet {
		if flags.format, err = normalizeContractFormat(flags.format); err != nil {
			return a.fail(*flags, exitValidation, "invalid_format", err.Error()), false
		}
	}
	if flags.outputSet {
		if flags.output, err = normalizeOutputFormat(flags.output); err != nil {
			return a.fail(*flags, exitValidation, "invalid_output", err.Error()), false
		}
	}
	if flags.maxBytesSet {
		if flags.maxBytes, err = parseMaxBytes(flags.maxBytesRaw); err != nil {
			return a.fail(*flags, exitValidation, "invalid_max_bytes", err.Error()), false
		}
	}
	return 0, true
}

// selectOutput resolves the format for the dispatched command and silences
// progress prose whenever that format is a machine one.
//
// Suppressing rather than redirecting is the point: stderr was already the prose
// channel, and agents merged it into stdout anyway to keep hold of errors. One
// line of prose in a merged NDJSON stream is an unparseable record, which is
// what the audit measured. --verbose puts the prose back for a human debugging a
// machine-mode invocation.
// There is no per-command default to resolve: --format always names a value, and
// validateOutputFlags has already rejected any spelling that does not.
func (a *app) selectFormat(flags *globalFlags) {
	// No --format means no contract: every command keeps its legacy output, and
	// nothing here is silenced. That is the whole compatibility story — a fleet of
	// self-updating binaries sees no change until a caller opts in by spelling
	// --format.
	if !flags.formatSet {
		return
	}
	a.machine = machineFormat(flags.format)
	a.quiet = a.machine && !flags.verbose
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

	// A machine format is never interactive. Asking a question through a channel
	// this invocation has promised to keep free of prose would block on an answer
	// to a prompt the caller cannot see.
	interactive := a.isInteractive() && !cfg.NonInteractive && !flags.machine()
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
	fmt.Fprintf(a.prose(), "Saved config: %s\nRun `bmcp init` again to change it.\n", cfg.ConfigPath)
	if oldURL != "" && oldURL != fileCfg.URL {
		_ = os.Remove(cfg.ToolsPath)
	}
	refreshInstructions := !interactive
	if code := a.cmdSyncWithRefresh(flags, refreshInstructions, false); code != 0 {
		return code
	}
	if interactive && reader != nil {
		a.promptInstallDetectedHarnesses(reader, flags)
	}
	if flags.machine() {
		if err := encodeMachineDoc(a.stdout, flags.contract(), initDoc{
			OK: true, Command: "init", ConfigPath: cfg.ConfigPath, URL: sanitizeURL(fileCfg.URL), Warnings: a.warnings,
		}); err != nil {
			return a.fail(flags, exitGeneric, "output_failed", err.Error())
		}
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
	// Without the update trail, "bmcp broke" reports after a self-update arrive
	// with no way to tell which version replaced which, or when.
	var updated *updatedFrom
	if path, err := a.resolveExecutable(); err == nil {
		if receipt, err := readInstallReceipt(path); err == nil && len(receipt.Updates) > 0 {
			last := receipt.Updates[len(receipt.Updates)-1]
			updated = &updatedFrom{From: last.From, To: last.To, At: last.At}
		}
	}
	if flags.machine() {
		if err := encodeMachineDoc(a.stdout, flags.contract(), versionDoc{
			OK: true, Command: "version", Version: version, Commit: buildCommit, Built: buildDate, Updated: updated,
		}); err != nil {
			return a.fail(flags, exitGeneric, "output_failed", err.Error())
		}
		return 0
	}
	fmt.Fprintf(a.stdout, "bmcp %s\ncommit: %s\nbuilt: %s\n", version, buildCommit, buildDate)
	if updated != nil {
		fmt.Fprintf(a.stdout, "updated: %s -> %s at %s\n", updated.From, updated.To, updated.At)
	}
	return 0
}

func (a *app) cmdSync(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp sync")
	}
	return a.cmdSyncWithRefresh(flags, true, true)
}

// report is false when init calls this, because the contract allows a machine
// invocation exactly one document on stdout and init emits its own. It is not a
// synonym for refreshInstructions: init refreshes in its non-interactive form
// and still reports as init.
func (a *app) cmdSyncWithRefresh(flags globalFlags, refreshInstructions, report bool) int {
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
	fmt.Fprintf(a.prose(), "Synced %d tools to %s\n", len(cache.Tools), cfg.ToolsPath)
	var instructions *refreshSummary
	if refreshInstructions {
		// True: a human typed `bmcp sync` in a directory they chose.
		summary := a.refreshInstructions(cache, true)
		instructions = &summary
	}
	if report && flags.machine() {
		if err := encodeMachineDoc(a.stdout, flags.contract(), syncDoc{
			OK: true, Command: "sync", Count: len(cache.Tools), ToolsPath: cfg.ToolsPath, Instructions: instructions, Warnings: a.warnings,
		}); err != nil {
			return a.fail(flags, exitGeneric, "output_failed", err.Error())
		}
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
// Output goes through a.prose() and nothing here reaches an exit code. This runs inside
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
		printRefreshResult(a.prose(), result)
	}
	return summary
}

// cmdList writes machine-readable records to stdout and everything else to
// stderr, which makes stdout a line-oriented stream: every line is one
// complete, parseable record on its own.
//
// ndjson stays a stream of bare records rather than becoming an enveloped
// document because that is what keeps it line-oriented: `grep` matches whole
// records, `while read -r line` handles them one at a time, and a consumer can
// parse incrementally instead of buffering the catalog. --format json is the
// enveloped form, and it is the one to reach for when completeness matters: it
// carries `count`, which a bare stream cannot report about itself.
func (a *app) cmdList(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp list [--schemas] [--format human|json|ndjson]")
	}
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		return a.fail(flags, exitSync, "sync_failed", err.Error())
	}
	stamp := ""
	if !cache.LastSync.IsZero() {
		stamp = cache.LastSync.UTC().Format(time.RFC3339)
	}
	if stamp == "" {
		fmt.Fprintf(a.prose(), "%d tools\n", len(cache.Tools))
	} else {
		fmt.Fprintf(a.prose(), "%d tools synced %s\n", len(cache.Tools), stamp)
	}
	// The legacy --output when no --format was given, and the contract when one
	// was. `list` is the only command that ever read --output, so it is the only
	// one carrying both — and `json` still means `ndjson` on that side, because
	// changing it there is exactly the silent break --format exists to avoid.
	format := flags.contract()
	if format == "" {
		// normalizeOutputFormat already collapsed `json` to `ndjson`, so this is
		// only ever ndjson or human.
		format = flags.output
	}
	switch format {
	case outputHuman:
		// --schemas in the human view is `describe` for every tool, which is what
		// the flag means in the machine view too. Rejecting the combination would
		// be a usage papercut for the one caller — a person — least able to guess
		// which half of it was wrong.
		if flags.listSchemas {
			err = renderToolListWithSchemas(a.stdout, cache.Tools)
		} else {
			err = renderToolList(a.stdout, cache.Tools)
		}
	case outputJSON:
		// Tools is never nil, so an empty catalog is `"tools":[]` rather than
		// `"tools":null` — a consumer ranging over it should not have to special-case
		// the empty case that this command exits 0 on.
		records := make([]toolRecord, 0, len(cache.Tools))
		for _, t := range cache.Tools {
			records = append(records, newToolRecord(t, stamp, flags.listSchemas))
		}
		err = encodeMachineDoc(a.stdout, format, listDoc{
			OK: true, Command: "list", Count: len(records), LastSync: stamp, Tools: records, Warnings: a.warnings,
		})
	default:
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
	return a.describeTool(flags, t, cache)
}

// describeTool answers "what are this tool's inputs" in the selected format.
//
// Shared with cmdDynamic, which answers `bmcp <tool> --help` with the same
// document. That path used to print the human rendering whatever the format,
// so a machine caller asking a documented question got prose on stdout and no
// document at all.
func (a *app) describeTool(flags globalFlags, t tool, cache *toolCache) int {
	if !flags.machine() {
		t.Describe(a.stdout)
		return 0
	}
	stamp := ""
	if cache != nil && !cache.LastSync.IsZero() {
		stamp = cache.LastSync.UTC().Format(time.RFC3339)
	}
	// Schema always included. `describe` is the command asked when the caller is
	// about to write a payload, so the machine form withholding the schema would
	// leave it answering a question nobody asks it.
	if err := encodeMachineDoc(a.stdout, flags.contract(), describeDoc{
		OK: true, Command: "describe", Tool: newToolRecord(t, stamp, true), Warnings: a.warnings,
	}); err != nil {
		return a.fail(flags, exitGeneric, "output_failed", err.Error())
	}
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
	fmt.Fprintf(a.prose(), "Calling %s...\n", displayToolName(t.Name))
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
	if flags.machine() {
		// --pretty is not consulted here. The json document is already indented and
		// the ndjson one must stay on one line, so honouring it could only corrupt
		// the format the caller explicitly selected.
		if err := encodeMachineDoc(a.stdout, flags.contract(), newCallDoc(t.Name, result, flags.maxBytes, a.warnings)); err != nil {
			return a.fail(flags, exitGeneric, "output_failed", err.Error())
		}
		return 0
	}
	if flags.pretty {
		var pretty bytes.Buffer
		if json.Indent(&pretty, result, "", "  ") == nil {
			result = pretty.Bytes()
		}
	}
	// Truncation after --pretty, so --max-bytes caps what is actually written
	// rather than what would have been written before reformatting.
	full := len(result)
	result = truncateBytes(result, flags.maxBytes)
	// Checked, like every machine path checks encodeMachineDoc: a payload cut
	// short by a full disk must not exit 0, which is the rule cmdList already
	// follows for the catalog.
	if _, err := a.stdout.Write(result); err != nil {
		return a.fail(flags, exitGeneric, "output_failed", err.Error())
	}
	if len(result) == 0 || result[len(result)-1] != '\n' {
		fmt.Fprintln(a.stdout)
	}
	if len(result) != full {
		// The only signal a human format has for it. A clipped JSON payload does not
		// parse, and this line is the difference between that and a server that
		// returned something malformed.
		fmt.Fprintf(a.prose(), "Truncated to %d of %d bytes by --max-bytes; the payload above is incomplete.\n", len(result), full)
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
		return a.describeTool(flags, t, cache)
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
		// Both the contract and the legacy --json answer with a document, so neither
		// prints the human rows.
		if flags.machine() || flags.legacyJSON() {
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
	if flags.machine() || flags.legacyJSON() {
		// mode says which question was answered, because the two produce different
		// check sets and a consumer that finds no `auth` row should be able to tell
		// "not checked" from "checked and gone".
		payload := map[string]any{"ok": allChecksOK(checks), "checks": checks, "mode": doctorMode(deep)}
		if flags.machine() {
			// command and exit_code only under the contract. The legacy --json report
			// keeps the exact key set it has always had, because every consumer of it
			// takes the next release automatically.
			//
			// exit_code is here for the reason the failure document carries it: a
			// pipeline that replaced bmcp's status with its own leaves this the only
			// place the real one survives. Doctor is the command most often piped into
			// jq, and the one whose report is a success document even when ok is false.
			code := 0
			if !allChecksOK(checks) {
				code = exitGeneric
			}
			payload["command"], payload["exit_code"] = "doctor", code
		}
		if st != nil {
			payload["update"] = st.updateJSON()
		}
		if instructions != nil {
			payload["instructions"] = instructions
		}
		// stdout, like every other success document. This one used to share stderr
		// with syncTools' "Syncing tools...", so the stream was not a parseable JSON
		// document and every consumer had to scan for the first `{`; under the
		// contract prose is suppressed outright, so neither stream needs scanning.
		//
		if format := flags.contract(); format != "" {
			if err := encodeMachineDoc(a.stdout, format, payload); err != nil {
				return a.fail(flags, exitGeneric, "output_failed", err.Error())
			}
		} else {
			// json.MarshalIndent, not encodeMachineDoc: the legacy report has always
			// been HTML-escaped, and encodeMachineDoc turns that off. A config path
			// containing & would otherwise come back with different bytes than the
			// release before it, which is exactly what freezing this path forbids.
			out, _ := json.MarshalIndent(payload, "", "  ")
			fmt.Fprintln(a.stdout, string(out))
		}
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
	doc := installDoc{OK: true, Command: "install", Scope: scope, Harnesses: []harnessDoc{}, Files: []installedDoc{}}
	for _, harness := range harnesses {
		result, err := a.installHarnessWithCatalog(flags, harness, scope)
		if err != nil {
			return a.fail(flags, exitValidation, "install_failed", err.Error())
		}
		printInstallResult(a.prose(), result)
		doc.Harnesses = append(doc.Harnesses, harnessDoc{Harness: result.Harness, Scope: result.Scope})
		for _, file := range result.Files {
			// An empty path is how installHarness reports a file it could not write.
			// printInstallResult says so in prose and the exit code ignores it, so the
			// machine form has to carry it or a partial install reads as a whole one.
			doc.Files = append(doc.Files, installedDoc{
				Harness: result.Harness, Path: file.Path, Backup: file.Backup,
				Changed: file.Changed, Failed: file.Path == "",
			})
		}
	}
	if flags.machine() {
		doc.Warnings = a.warnings
		if err := encodeMachineDoc(a.stdout, flags.contract(), doc); err != nil {
			return a.fail(flags, exitGeneric, "output_failed", err.Error())
		}
	}
	return 0
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  bmcp init [--url <url>] [--profile <profile>]
  bmcp install <claude-code|codex|opencode|cursor|kiro|all> [--scope user|project]
  bmcp sync
  bmcp doctor [--deep]
  bmcp list|ls|tools [--schemas] [--format human|json|ndjson]
  bmcp describe|d <tool>
  bmcp call <tool> ['{"arg":"value"}']
  bmcp [--format json] [--max-bytes <n>] <exact_tool_name> --arg value
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
  --format <human|json|ndjson> Answer under the machine-output contract. json is
                               one document per invocation; ndjson is one object
                               per line (one tool record per line for list);
                               human is prose. stdout then carries that and
                               nothing else, progress prose is suppressed so
                               merging the streams stays safe, and no prompt is
                               ever shown. Without it every command keeps the
                               output it had before this flag existed
  --max-bytes <n>              Cap a tool result at n bytes. Under --format the
                               document reports the full size and marks itself
                               truncated, so reach for this rather than cutting
                               bmcp output to a fixed number of lines
  --pretty                     Pretty-print successful tool JSON. Not consulted
                               under --format, whose json is already indented
  --raw                        Emit raw MCP tool envelopes
  --non-interactive            Disable prompts and SSO login
  --verbose                    Emit diagnostics to stderr

Deprecated, superseded by --format wherever both are given:
  --output <ndjson|json|human> Format for bmcp list only (json means ndjson)
  --json                       Structured errors, and doctor's JSON report
`)
}

// fail is the one failure path. Every command routes through it, so the machine
// error shape is the same whatever went wrong and wherever it went wrong.
//
// stderr in every format, unlike the success documents. A shell expects errors
// there, and nothing is gained by moving them: prose is suppressed in a machine
// format, so a caller that merges the streams sees exactly one JSON document
// either way and reads `ok` to tell which it got.
func (a *app) fail(flags globalFlags, code int, name, msg string) int {
	return a.failDoc(flags, code, errorDoc{Command: flags.command, Error: name, Message: msg, ExitCode: code}, msg, nil)
}

// failDoc reports a failure carrying more than a message. prose is what the
// human format prints; doc is what the machine formats emit.
//
// Three renderings, because there are three callers to keep faith with. Under
// the contract it is the full document; under the legacy --json it is the shape
// that flag has always produced, unchanged to the byte; otherwise it is prose.
func (a *app) failDoc(flags globalFlags, code int, doc errorDoc, prose string, legacy map[string]any) int {
	switch {
	case flags.machine():
		// One line, whichever machine format was selected — the only place the
		// contract does not follow --format. A failure document is a thing to log
		// and grep, so `tail -1`, `read -r line` and `grep '^{'` all have to keep
		// working on it.
		if err := encodeMachineDoc(a.stderr, outputNDJSON, doc); err != nil {
			// Nothing left to report it with — the error channel is the thing that
			// failed. The exit code still carries the original failure.
			fmt.Fprintln(a.stderr, prose)
		}
	case flags.legacyJSON():
		// The legacy shape, deliberately not the new one: no command, no exit_code.
		// Anything added here would reach every existing --json caller on their next
		// automatic update, which is the whole reason the contract got a flag of its
		// own. legacy carries the one failure that always had a shape of its own.
		if legacy == nil {
			legacy = map[string]any{"ok": false, "error": doc.Error, "message": doc.Message}
		}
		out, _ := json.Marshal(legacy)
		fmt.Fprintln(a.stderr, string(out))
	default:
		fmt.Fprintln(a.stderr, prose)
	}
	return code
}

func (a *app) failSchemaChanged(flags globalFlags, oldTool, newTool tool) int {
	changes := oldTool.Diff(newTool)
	var prose strings.Builder
	fmt.Fprintf(&prose, "Tool schema changed: %s\n", newTool.Name)
	for _, c := range changes {
		fmt.Fprintf(&prose, "- %s\n", c["message"])
	}
	prose.WriteString("\nThe tool was not called. Retry with the updated arguments.")
	return a.failDoc(flags, exitSync, errorDoc{
		Command: flags.command,
		Error:   "tool_schema_changed",
		Message: prose.String(),
		// exitSync rather than the code the caller would infer: the refusal is a
		// catalog-state failure, and a caller that lost the exit status through a
		// pipeline reads it from here.
		ExitCode: exitSync,
		Tool:     newTool.Name,
		Changes:  changes,
	}, prose.String(), map[string]any{
		// Byte-for-byte what --json produced before the contract existed.
		"ok": false, "error": "tool_schema_changed", "tool": newTool.Name, "changes": changes,
	})
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
