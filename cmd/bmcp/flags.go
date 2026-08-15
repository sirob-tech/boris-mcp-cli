package main

import (
	"fmt"
	"strings"
)

type globalFlags struct {
	url     string
	profile string
	region  string
	service string
	// format is the machine-output contract selector, --format. Empty means the
	// caller did not ask for the contract, and every command then keeps exactly the
	// output it had before the contract existed. run() resolves it once dispatch
	// knows the command, so everything downstream reads one field. See output.go.
	//
	// It is a new spelling rather than a new meaning for --output because installed
	// binaries self-update: reusing --output would have silently changed
	// `bmcp list --output json` from a record stream to a document on every machine
	// in the fleet, with no version gate able to express "do not apply unattended".
	format string
	// formatSet distinguishes an explicit --format from an absent one, which the
	// value alone cannot: `--format=` is a usage error and has to stay one, so
	// empty cannot double as "unset".
	formatSet bool
	// output is the legacy --output flag, read by `bmcp list` alone and frozen at
	// the behaviour it had before --format: ndjson (the default), json as an alias
	// for it, and human. Deprecated in favour of --format, which supersedes it
	// wherever both are given.
	output string
	// outputSet distinguishes an explicit --output from an absent one, for the same
	// reason formatSet exists.
	outputSet bool
	// jsonOut is the legacy --json flag, frozen at its old meaning: structured
	// errors, and doctor's report as a JSON document. Deprecated in favour of
	// --format json, which supersedes it. It is not a format selector — it never
	// changed any command's successful output except doctor's.
	jsonOut bool
	// command is the canonical name of the command being run, carried into the
	// machine error document so a failure says what failed.
	command string
	// maxBytesRaw is the unparsed --max-bytes value, and maxBytesSet marks it as
	// given — `--max-bytes=` is a usage error, so empty cannot double as "unset",
	// exactly as with output/outputSet. Parsed in run() rather than in parseFlags
	// for the same reason --output is validated there: parseFlags maps every error
	// it raises to exitGeneric, and a bad value is a validation error.
	maxBytesRaw    string
	maxBytesSet    bool
	maxBytes       int
	pretty         bool
	raw            bool
	nonInteractive bool
	verbose        bool
	allowHTTP      bool
	noAutoUpdate   bool
	updateCheck    bool
	updateRollback bool
	// help is a flag as well as a command alias, because neither form covers
	// every position. The flag serves `bmcp --help` and `bmcp doctor --help`; an
	// alias cannot, since parseGlobalFlags rejects unknown `-`-prefixed tokens
	// before dispatch sees the name. The alias serves `bmcp -- --help`, which the
	// flag cannot, since `--` stops flag interpretation. See the commands table.
	help bool
	// version is a flag as well as a command, for the same reason help is one: it
	// is the spelling reached for first. Rejecting `--version` and `-V` cost a
	// failed invocation before `bmcp version` was found, and the failure looked
	// like a broken CLI rather than a wrong spelling.
	//
	// -V, not -v: -v is unbound here, but it conventionally means verbose, and
	// this CLI already has --verbose for that.
	version bool
	// updateTo is `--to`, not `--version`: `version` is already a command, and a
	// `--version` flag that meant "update target" next to a `--version` flag that
	// means "print the version" is the same trap this file already sprang once
	// with help.
	updateTo string
	// doctorDeep asks doctor for the checks that need the network: credentials,
	// the server, and the live catalog. Without it doctor answers from local
	// state alone whenever that state is trustworthy — see cmdDoctor.
	doctorDeep bool
	// listSchemas adds each tool's input schema to `bmcp list`, so the catalog and
	// every schema in it arrive in one local invocation instead of a list followed
	// by a describe per tool.
	listSchemas bool
}

// normalizeContractFormat resolves --format to a canonical value. The three are
// distinct: human is prose, json is one document per invocation, and ndjson is
// one object per line.
//
// It runs once per flag-parsing scope, so it is handed its own previous value on
// the second pass: every canonical value must stay an accepted spelling.
func normalizeContractFormat(v string) (string, error) {
	switch v {
	case outputNDJSON, outputJSON, outputHuman:
		return v, nil
	default:
		// human, not the rejected value. Callers assign the result before reporting
		// the error, so whatever comes back here is the format the complaint about
		// --format is rendered in, and a caller who has not successfully named a
		// machine format is not owed one.
		return outputHuman, fmt.Errorf("invalid --format value: %q\nSupported values: human, json, ndjson", v)
	}
}

// normalizeOutputFormat resolves the legacy --output. `json` is an alias for
// `ndjson` here, because `list` is the only command that reads this flag and its
// records are JSON — just one object per line. That alias is frozen: --format is
// where json and ndjson became different things.
func normalizeOutputFormat(v string) (string, error) {
	switch v {
	case outputNDJSON, outputJSON:
		return outputNDJSON, nil
	case outputHuman:
		return outputHuman, nil
	default:
		return outputNDJSON, fmt.Errorf("invalid --output value: %q\nSupported values: ndjson (default), json, human", v)
	}
}

// contract is the resolved --format, or "" when the caller did not select one
// and the command keeps its legacy output.
//
// Defensive about being asked before run() resolves one: failures raised during
// flag parsing reach fail() with whatever was parsed so far, which may be a value
// that never reached normalizeContractFormat — and a report about a bad --format
// must not itself be rendered by it.
func (f globalFlags) contract() string {
	switch f.format {
	case outputJSON, outputNDJSON, outputHuman:
		return f.format
	}
	return ""
}

// legacyJSON reports whether the deprecated --json is in force. It is not, once
// --format has selected a contract — including --format human, which asks for
// prose and must not be answered with the legacy JSON report.
func (f globalFlags) legacyJSON() bool {
	return f.jsonOut && f.contract() == ""
}

// machine reports whether this invocation answers under the machine half of the
// contract. The legacy --json is deliberately not part of it: it never selected a
// format, and treating it as one is the break --format exists to avoid.
func (f globalFlags) machine() bool {
	return machineFormat(f.contract())
}

type flagScope int

// scopePostCommand is the zero value so that the commands table can name a scope
// per command and leave it out for the ordinary ones, which is what every
// non-rawArgs command wants.
const (
	scopePostCommand flagScope = iota
	scopeGlobal
	// scopeUpdate is scopePostCommand plus the flags only `bmcp update` accepts.
	// They are scoped rather than shared because every non-rawArgs command runs
	// through the same switch: admitting --to/--check/--rollback everywhere
	// turned `bmcp call <tool> --to x` from a flag error that did nothing into a
	// real call against the live server, and let `--to` swallow the tool name.
	scopeUpdate
	// scopeDoctor is scopePostCommand plus `--deep`, scoped for the same reason.
	// `--deep` reads as "try harder", so admitting it everywhere would invite
	// `bmcp <tool> --deep` — which is a tool argument named deep on some future
	// catalog, and silently nothing on this one.
	scopeDoctor
	// scopeList is scopePostCommand plus `--schemas`.
	scopeList
)

func parseGlobalFlags(args []string) (globalFlags, []string, error) {
	// --output keeps its seeded default because `list` still reads it when no
	// --format is given, and seeding it here means an empty value can only come
	// from an explicit `--output=`, which is a usage error. --format is seeded
	// empty on purpose: empty means "no contract selected", and formatSet is what
	// marks the explicit `--format=`.
	return parseFlags(globalFlags{output: outputNDJSON}, args, scopeGlobal)
}

func parsePostCommandFlags(flags globalFlags, args []string, scope flagScope) (globalFlags, []string, error) {
	return parseFlags(flags, args, scope)
}

func parseFlags(flags globalFlags, args []string, scope flagScope) (globalFlags, []string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			if scope == scopeGlobal {
				rest = append(rest, args[i:]...)
				break
			}
			rest = append(rest, arg)
			continue
		}
		next := func(name string) (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", name)
			}
			i++
			return args[i], nil
		}
		switch {
		// Accepted in every scope, so help works before or after a command name.
		// It only fires when --help precedes the command, though, since the global
		// scope hands everything from the first non-flag token onward to the
		// command. `bmcp <tool> --help` therefore still reaches cmdDynamic, which
		// answers it with that tool's schema instead of this usage text.
		case arg == "--help" || arg == "-h":
			flags.help = true
		// Global scope only, unlike --help. After a command name it would have to
		// either report the version and abandon the command — `bmcp update --to X
		// --version` reporting success while updating nothing — or be ignored. Both
		// are worse than the flag error it already was, and rejecting it is also
		// what `git status --version` and `docker ps --version` do. `install` is
		// rawArgs and rejects it too, so the answer stays consistent.
		//
		// A tool's own --version argument is unaffected: the global scope stops at
		// the first non-flag token, so `bmcp <tool> --version x` is parsed by
		// tool.ParseFlags and never reaches here.
		case (arg == "--version" || arg == "-V") && scope == scopeGlobal:
			flags.version = true
		// Legacy, and deliberately not wired to --format. It means structured errors
		// and doctor's JSON report, exactly as it always did; --format is where the
		// contract lives. Making this an alias would have changed successful output
		// for every caller already passing it, on a binary that self-updates.
		case arg == "--json":
			flags.jsonOut = true
		case arg == "--pretty":
			flags.pretty = true
		case arg == "--raw":
			flags.raw = true
		case arg == "--non-interactive":
			flags.nonInteractive = true
		case arg == "--verbose":
			flags.verbose = true
		case arg == "--allow-http":
			flags.allowHTTP = true
		// Global: it suppresses the auto-update that doctor, sync and init run,
		// so it has to be accepted wherever those are invoked.
		case arg == "--no-auto-update":
			flags.noAutoUpdate = true
		case arg == "--deep" && scope == scopeDoctor:
			flags.doctorDeep = true
		case arg == "--schemas" && scope == scopeList:
			flags.listSchemas = true
		case arg == "--check" && scope == scopeUpdate:
			flags.updateCheck = true
		case arg == "--rollback" && scope == scopeUpdate:
			flags.updateRollback = true
		case arg == "--to" && scope == scopeUpdate:
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.updateTo = v
		case strings.HasPrefix(arg, "--to=") && scope == scopeUpdate:
			flags.updateTo = strings.TrimPrefix(arg, "--to=")
		case arg == "--url" || arg == "-u":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.url = v
		case strings.HasPrefix(arg, "--url="):
			flags.url = strings.TrimPrefix(arg, "--url=")
		case arg == "--profile" || arg == "-p":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.profile = v
		case strings.HasPrefix(arg, "--profile="):
			flags.profile = strings.TrimPrefix(arg, "--profile=")
		case arg == "--region":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.region = v
		case strings.HasPrefix(arg, "--region="):
			flags.region = strings.TrimPrefix(arg, "--region=")
		case arg == "--service":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.service = v
		case strings.HasPrefix(arg, "--service="):
			flags.service = strings.TrimPrefix(arg, "--service=")
		case arg == "--format":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.format, flags.formatSet = v, true
		case strings.HasPrefix(arg, "--format="):
			flags.format, flags.formatSet = strings.TrimPrefix(arg, "--format="), true
		case arg == "--output":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.output, flags.outputSet = v, true
		case strings.HasPrefix(arg, "--output="):
			flags.output, flags.outputSet = strings.TrimPrefix(arg, "--output="), true
		// Accepted in every scope, like --pretty and --raw, because it describes the
		// result rather than the command. In the `bmcp <tool> --arg value` form it
		// has to precede the tool name: everything after it is parsed as that tool's
		// arguments, which is also where a tool of its own named max-bytes would be
		// answered rather than shadowed.
		case arg == "--max-bytes":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.maxBytesRaw, flags.maxBytesSet = v, true
		case strings.HasPrefix(arg, "--max-bytes="):
			flags.maxBytesRaw, flags.maxBytesSet = strings.TrimPrefix(arg, "--max-bytes="), true
		default:
			if scope == scopeGlobal {
				return flags, nil, fmt.Errorf("unknown global flag: %s", arg)
			}
			return flags, nil, fmt.Errorf("unknown flag for command: %s", arg)
		}
	}
	return flags, rest, nil
}

// valueTakingFlags are the flags whose value is the next token, which
// formatForReport has to step over rather than mistake for a command name. The
// `--flag=value` spellings need no entry.
var valueTakingFlags = map[string]bool{
	"--url": true, "-u": true, "--profile": true, "-p": true,
	"--region": true, "--service": true, "--output": true,
	"--max-bytes": true, "--to": true,
}

// formatForReport finds a valid --format anywhere the parser would legitimately
// have looked, so that a failure raised before it got there is still reported in
// the format the caller asked for.
//
// Parsing stops at the first unknown flag, which is what every legacy caller
// already sees and must keep seeing. Without this scan the rendering of a failure
// depended on where --format sat relative to the mistake, and on which side of
// the command name it fell: `bmcp list --format json --bogus` answered with a
// document while `bmcp list --bogus --format json` answered with prose.
//
// It looks for --format and nothing else. A scan that also honoured --output or
// --json would change what those flags do, which is the one thing this release
// must not do. The scan stops at a tool name for the same reason the parser does:
// everything after it belongs to the tool.
func formatForReport(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return ""
		}
		if !strings.HasPrefix(arg, "-") {
			if c, known := lookupCommand(arg); !known || c.rawArgs {
				return ""
			}
			continue
		}
		var v string
		switch {
		case arg == "--format" && i+1 < len(args):
			v = args[i+1]
		case strings.HasPrefix(arg, "--format="):
			v = strings.TrimPrefix(arg, "--format=")
		default:
			// A value-taking flag's value is not a command name, and treating it as
			// one ended the scan early: `--max-bytes 0 list --format json` stopped at
			// the 0 and reported its own complaint in prose.
			if valueTakingFlags[arg] {
				i++
			}
			continue
		}
		// An invalid value selects nothing: the complaint about it must not be
		// rendered by it.
		if f, err := normalizeContractFormat(v); err == nil {
			return f
		}
		return ""
	}
	return ""
}
