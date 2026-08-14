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
	// help is a flag rather than a command alias so that it works in both
	// positions an agent reaches for: `bmcp --help` and `bmcp doctor --help`.
	// As an alias it could only ever serve the first, because parseGlobalFlags
	// rejects unknown `-`-prefixed tokens before dispatch ever sees the name.
	help bool
	// updateTo is `--to`, not `--version`: `version` is already a command, and a
	// `--version` flag next to a `version` command is the same trap this file
	// already sprang once with help.
	updateTo string
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

const (
	scopeGlobal flagScope = iota
	scopePostCommand
	// scopeUpdate is scopePostCommand plus the flags only `bmcp update` accepts.
	// They are scoped rather than shared because every non-rawArgs command runs
	// through the same switch: admitting --to/--check/--rollback everywhere
	// turned `bmcp call <tool> --to x` from a flag error that did nothing into a
	// real call against the live server, and let `--to` swallow the tool name.
	scopeUpdate
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
		// Accepted in every scope: help must not depend on where the user put it.
		// Note this only fires when --help precedes the command name, since the
		// global scope hands everything from the first non-flag token onward to
		// the command. `bmcp <tool> --help` therefore still reaches cmdDynamic,
		// which answers it with that tool's schema instead of this usage text.
		case arg == "--help" || arg == "-h":
			flags.help = true
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
