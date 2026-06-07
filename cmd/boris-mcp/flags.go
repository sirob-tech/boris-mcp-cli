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
	jsonOut        bool
	pretty         bool
	raw            bool
	nonInteractive bool
	verbose        bool
	allowHTTP      bool
}

type flagScope int

const (
	scopeGlobal flagScope = iota
	scopePostCommand
)

func parseGlobalFlags(args []string) (globalFlags, []string, error) {
	return parseFlags(globalFlags{}, args, scopeGlobal)
}

func parsePostCommandFlags(flags globalFlags, args []string) (globalFlags, []string, error) {
	return parseFlags(flags, args, scopePostCommand)
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
		default:
			if scope == scopeGlobal {
				return flags, nil, fmt.Errorf("unknown global flag: %s", arg)
			}
			return flags, nil, fmt.Errorf("unknown flag for command: %s", arg)
		}
	}
	return flags, rest, nil
}
