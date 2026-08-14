package main

import (
	"fmt"
	"strings"
)

type globalFlags struct {
	url            string
	profile        string
	region         string
	service        string
	output         string
	jsonOut        bool
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
}

const (
	outputNDJSON = "ndjson"
	outputHuman  = "human"
)

// normalizeOutputFormat resolves --output to a canonical value. `json` is
// accepted as an alias because the records are JSON — just one object per line.
//
// It runs once per flag-parsing scope, so it is handed its own previous output
// on the second pass: every canonical value must stay an accepted spelling.
func normalizeOutputFormat(v string) (string, error) {
	switch v {
	case outputNDJSON, "json":
		return outputNDJSON, nil
	case outputHuman:
		return outputHuman, nil
	default:
		// Never return the rejected value: callers assign the result before
		// reporting the error, and flags should not carry an invalid format.
		return outputNDJSON, fmt.Errorf("invalid --output value: %q\nSupported values: ndjson (default), json, human", v)
	}
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
)

func parseGlobalFlags(args []string) (globalFlags, []string, error) {
	// Seeding the default here means an empty output value can only come from an
	// explicit `--output=`, which is a usage error rather than a silent default.
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
		case arg == "--output":
			v, err := next(arg)
			if err != nil {
				return flags, nil, err
			}
			flags.output = v
		case strings.HasPrefix(arg, "--output="):
			flags.output = strings.TrimPrefix(arg, "--output=")
		default:
			if scope == scopeGlobal {
				return flags, nil, fmt.Errorf("unknown global flag: %s", arg)
			}
			return flags, nil, fmt.Errorf("unknown flag for command: %s", arg)
		}
	}
	return flags, rest, nil
}
