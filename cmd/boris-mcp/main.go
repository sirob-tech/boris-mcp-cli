package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

const (
	version        = "0.1.0"
	defaultTTL     = 168 * time.Hour
	defaultConnect = 30 * time.Second
	defaultSync    = 60 * time.Second
	defaultCall    = 10 * time.Minute

	exitGeneric    = 1
	exitConfig     = 2
	exitAuth       = 3
	exitSync       = 4
	exitValidation = 5
	exitUpstream   = 6
)

var (
	buildCommit = "unknown"
	buildDate   = "unknown"
)

type app struct {
	stdin         io.Reader
	stdout        io.Writer
	stderr        io.Writer
	now           func() time.Time
	syncToolsFunc func(context.Context, effectiveConfig) (*toolCache, error)
	callToolFunc  func(context.Context, effectiveConfig, string, map[string]any) ([]byte, error)
	lookPath      func(string) (string, error)
	interactive   func() bool
}

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

type configFile struct {
	URL            string
	AWSProfile     string
	Region         string
	Service        string
	SyncTTL        time.Duration
	ConnectTimeout time.Duration
	SyncTimeout    time.Duration
	CallTimeout    time.Duration
}

type effectiveConfig struct {
	Home           string
	ConfigPath     string
	ToolsPath      string
	URL            string
	Profile        string
	Region         string
	Service        string
	SyncTTL        time.Duration
	ConnectTimeout time.Duration
	SyncTimeout    time.Duration
	CallTimeout    time.Duration
	NonInteractive bool
}

type serverInfo struct {
	Name            string `json:"name,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	Instructions    string `json:"instructions,omitempty"`
}

type toolCache struct {
	Version  int        `json:"version"`
	URL      string     `json:"url"`
	LastSync time.Time  `json:"last_sync"`
	Server   serverInfo `json:"server"`
	Tools    []tool     `json:"tools"`
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	SchemaHash  string          `json:"schema_hash"`
}

type mcpClient struct {
	httpClient *http.Client
	url        string
	region     string
	service    string
	creds      aws.Credentials
	sessionID  string
	verbose    bool
	stderr     io.Writer
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc,omitempty"`
	ID      any             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int             `json:"code,omitempty"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type schemaObject struct {
	Type       any                       `json:"type,omitempty"`
	Properties map[string]schemaProperty `json:"properties,omitempty"`
	Required   []string                  `json:"required,omitempty"`
}

type schemaProperty struct {
	Type        any                       `json:"type,omitempty"`
	Description string                    `json:"description,omitempty"`
	Items       *schemaProperty           `json:"items,omitempty"`
	Properties  map[string]schemaProperty `json:"properties,omitempty"`
}

func main() {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
	os.Exit(a.run(os.Args[1:]))
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

	cmd := rest[0]
	cmdArgs := rest[1:]
	switch cmd {
	case "help", "-h", "--help":
		usage(a.stdout)
		return 0
	case "version":
		fmt.Fprintf(a.stdout, "boris-mcp %s\ncommit: %s\nbuilt: %s\n", version, buildCommit, buildDate)
		return 0
	case "init":
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		return a.cmdInit(flags, cmdArgs)
	case "sync":
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		if len(cmdArgs) != 0 {
			return a.fail(flags, exitValidation, "usage", "usage: boris-mcp sync")
		}
		return a.cmdSync(flags)
	case "doctor":
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		if len(cmdArgs) != 0 {
			return a.fail(flags, exitValidation, "usage", "usage: boris-mcp doctor")
		}
		return a.cmdDoctor(flags)
	case "list", "ls":
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		if len(cmdArgs) != 0 {
			return a.fail(flags, exitValidation, "usage", "usage: boris-mcp list")
		}
		return a.cmdList(flags)
	case "describe", "d":
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		if len(cmdArgs) != 1 {
			return a.fail(flags, exitValidation, "usage", "usage: boris-mcp describe <tool>")
		}
		return a.cmdDescribe(flags, cmdArgs[0])
	case "call":
		flags, cmdArgs, err = parsePostCommandFlags(flags, cmdArgs)
		if err != nil {
			return a.fail(flags, exitGeneric, "invalid_flags", err.Error())
		}
		if len(cmdArgs) < 1 || len(cmdArgs) > 2 {
			return a.fail(flags, exitValidation, "usage", "usage: boris-mcp call <tool> ['{\"arg\":\"value\"}']")
		}
		payload := ""
		if len(cmdArgs) == 2 {
			payload = cmdArgs[1]
		}
		return a.cmdCall(flags, cmdArgs[0], payload, true)
	case "install":
		return a.cmdInstall(flags, cmdArgs)
	default:
		return a.cmdDynamic(flags, cmd, cmdArgs)
	}
}

func parseGlobalFlags(args []string) (globalFlags, []string, error) {
	var flags globalFlags
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			rest = append(rest, args[i:]...)
			break
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
			return flags, nil, fmt.Errorf("unknown global flag: %s", arg)
		}
	}
	return flags, rest, nil
}

func parsePostCommandFlags(flags globalFlags, args []string) (globalFlags, []string, error) {
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
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
			return flags, nil, fmt.Errorf("unknown flag for command: %s", arg)
		}
	}
	return flags, rest, nil
}

func (a *app) cmdInit(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: boris-mcp init [--url <url>] [--profile <profile>]")
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
		return a.fail(flags, exitConfig, "not_configured", "BORIS MCP is not configured.\nRun interactively: boris-mcp init\nOr non-interactively: boris-mcp init --url <url>")
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
	fmt.Fprintf(a.stderr, "Saved config: %s\nRun `boris-mcp init` again to change it.\n", cfg.ConfigPath)
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

func (a *app) cmdSync(flags globalFlags) int {
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

func (a *app) cmdList(flags globalFlags) int {
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

func (a *app) cmdDescribe(flags globalFlags, name string) int {
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
		return a.fail(flags, exitValidation, "tool_not_found", err.Error())
	}
	describeTool(a.stdout, t)
	return 0
}

func (a *app) cmdCall(flags globalFlags, name string, payload string, readStdin bool) int {
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
	if err := validateInput(t, input); err != nil {
		return a.fail(flags, exitValidation, "tool_validation_failed", err.Error())
	}
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
		describeTool(a.stdout, t)
		return 0
	}
	input, err := parseToolFlags(t, args)
	if err != nil {
		return a.fail(flags, exitValidation, "tool_validation_failed", err.Error())
	}
	body, _ := json.Marshal(input)
	return a.cmdCall(flags, t.Name, string(body), false)
}

func (a *app) cmdDoctor(flags globalFlags) int {
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
		_, _, authErr := a.awsCredentials(context.Background(), cfg)
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

type installFileResult struct {
	Path    string
	Backup  string
	Changed bool
}

type installResult struct {
	Harness string
	Scope   string
	Files   []installFileResult
}

func (a *app) promptInstallDetectedHarnesses(reader *bufio.Reader, flags globalFlags) {
	for _, harness := range a.detectHarnesses() {
		if !promptYesNo(reader, a.stderr, fmt.Sprintf("Install BORIS instructions for %s? [Y/n]: ", harnessDisplayName(harness)), true) {
			continue
		}
		result, err := a.installHarnessWithCatalog(flags, harness, "user")
		if err != nil {
			fmt.Fprintf(a.stderr, "Could not install %s instructions: %s\n", harnessDisplayName(harness), err)
			continue
		}
		printInstallResult(a.stderr, result)
	}
}

func (a *app) detectHarnesses() []string {
	known := []struct {
		name string
		bin  string
		dir  string
	}{
		{name: "claude-code", bin: "claude", dir: ".claude"},
		{name: "codex", bin: "codex", dir: ".codex"},
		{name: "cursor", bin: "cursor", dir: ".cursor"},
	}
	var detected []string
	for _, h := range known {
		if a.hasCommand(h.bin) || userDirExists(h.dir) {
			detected = append(detected, h.name)
		}
	}
	return detected
}

func (a *app) hasCommand(name string) bool {
	lookPath := a.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	_, err := lookPath(name)
	return err == nil
}

func userDirExists(name string) bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	info, err := os.Stat(filepath.Join(home, name))
	return err == nil && info.IsDir()
}

func promptYesNo(reader *bufio.Reader, w io.Writer, question string, defaultYes bool) bool {
	fmt.Fprint(w, question)
	line, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "" {
		return defaultYes
	}
	return answer == "y" || answer == "yes"
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
		return a.fail(flags, exitValidation, "usage", "usage: boris-mcp install <claude-code|codex|cursor|all> [--scope user|project]")
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

func (a *app) installHarnessWithCatalog(flags globalFlags, harness, scope string) (installResult, error) {
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return installResult{}, err
	}
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		return installResult{}, err
	}
	return a.installHarness(harness, scope, cache)
}

func (a *app) installHarness(harness, scope string, cache *toolCache) (installResult, error) {
	switch harness {
	case "claude", "claude-code":
		return installClaudeCode(scope, cache)
	case "codex":
		return installCodex(scope, cache)
	case "cursor":
		return installCursor(scope, cache)
	default:
		return installResult{}, fmt.Errorf("unknown harness: %s", harness)
	}
}

func installClaudeCode(scope string, cache *toolCache) (installResult, error) {
	base, err := installBase(scope, ".claude")
	if err != nil {
		return installResult{}, err
	}
	refFile := "CLAUDE.md"
	instructionPath := filepath.Join(base, "BORIS.md")
	result := installResult{Harness: "claude-code", Scope: scope}
	result.Files = append(result.Files, writeInstructionFile(instructionPath, borisInstructionsMarkdown(cache)))
	result.Files = append(result.Files, appendInstructionRef(filepath.Join(base, refFile), "@BORIS.md"))
	return result, firstInstallErr(result.Files)
}

func installCodex(scope string, cache *toolCache) (installResult, error) {
	base, err := installBase(scope, ".codex")
	if err != nil {
		return installResult{}, err
	}
	result := installResult{Harness: "codex", Scope: scope}
	result.Files = append(result.Files, writeInstructionFile(filepath.Join(base, "BORIS.md"), borisInstructionsMarkdown(cache)))
	result.Files = append(result.Files, appendInstructionRef(filepath.Join(base, "AGENTS.md"), "@BORIS.md"))
	return result, firstInstallErr(result.Files)
}

func installCursor(scope string, cache *toolCache) (installResult, error) {
	base, err := installBase(scope, ".cursor")
	if err != nil {
		return installResult{}, err
	}
	result := installResult{Harness: "cursor", Scope: scope}
	result.Files = append(result.Files, writeInstructionFile(filepath.Join(base, "rules", "boris.mdc"), borisCursorRule(cache)))
	return result, firstInstallErr(result.Files)
}

func installBase(scope, userSubdir string) (string, error) {
	if scope == "project" {
		return os.Getwd()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, userSubdir), nil
}

func firstInstallErr(results []installFileResult) error {
	for _, r := range results {
		if r.Path == "" {
			return errors.New("install failed")
		}
	}
	return nil
}

func writeInstructionFile(path, content string) installFileResult {
	return writeFileWithBackup(path, []byte(ensureTrailingNewline(content)))
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func appendInstructionRef(path, ref string) installFileResult {
	old, err := os.ReadFile(path)
	if err == nil {
		for _, line := range strings.Split(string(old), "\n") {
			if strings.TrimSpace(line) == ref {
				return installFileResult{Path: path, Changed: false}
			}
		}
		content := string(old)
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += ref + "\n"
		return writeFileWithBackup(path, []byte(content))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return installFileResult{}
	}
	return writeFileWithBackup(path, []byte(ref+"\n"))
}

func writeFileWithBackup(path string, content []byte) installFileResult {
	result := installFileResult{Path: path}
	old, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(old, content) {
			return result
		}
		backup := backupPath(path)
		if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
			return installFileResult{}
		}
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return installFileResult{}
		}
		pruneOldBackups(path, backup)
		result.Backup = backup
	} else if !errors.Is(err, os.ErrNotExist) {
		return installFileResult{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return installFileResult{}
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return installFileResult{}
	}
	result.Changed = true
	return result
}

func backupPath(path string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	return fmt.Sprintf("%s.bak-%s", path, stamp)
}

func pruneOldBackups(path, keep string) {
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		return
	}
	for _, match := range matches {
		if match == keep {
			continue
		}
		_ = os.Remove(match)
	}
}

func printInstallResult(w io.Writer, result installResult) {
	fmt.Fprintf(w, "Installed BORIS instructions for %s (%s scope):\n", harnessDisplayName(result.Harness), result.Scope)
	for _, file := range result.Files {
		if file.Changed {
			fmt.Fprintf(w, "  wrote %s\n", file.Path)
			if file.Backup != "" {
				fmt.Fprintf(w, "  backup %s\n", file.Backup)
			}
		} else {
			fmt.Fprintf(w, "  unchanged %s\n", file.Path)
		}
	}
}

func printRefreshResult(w io.Writer, result installResult) {
	changed := false
	for _, file := range result.Files {
		changed = changed || file.Changed
	}
	if !changed {
		return
	}
	fmt.Fprintf(w, "Refreshed BORIS instructions for %s (%s scope):\n", harnessDisplayName(result.Harness), result.Scope)
	for _, file := range result.Files {
		if !file.Changed {
			continue
		}
		fmt.Fprintf(w, "  wrote %s\n", file.Path)
		if file.Backup != "" {
			fmt.Fprintf(w, "  backup %s\n", file.Backup)
		}
	}
}

func refreshExistingInstructions(cache *toolCache) []installResult {
	var results []installResult
	home, _ := os.UserHomeDir()
	if home != "" {
		refresh := []struct {
			harness string
			path    string
			content string
		}{
			{harness: "claude-code", path: filepath.Join(home, ".claude", "BORIS.md"), content: borisInstructionsMarkdown(cache)},
			{harness: "codex", path: filepath.Join(home, ".codex", "BORIS.md"), content: borisInstructionsMarkdown(cache)},
			{harness: "cursor", path: filepath.Join(home, ".cursor", "rules", "boris.mdc"), content: borisCursorRule(cache)},
		}
		for _, item := range refresh {
			if fileExists(item.path) {
				results = append(results, installResult{Harness: item.harness, Scope: "user", Files: []installFileResult{writeInstructionFile(item.path, item.content)}})
			}
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		projectBORIS := filepath.Join(cwd, "BORIS.md")
		if fileExists(projectBORIS) {
			results = append(results, installResult{Harness: "claude-code/codex", Scope: "project", Files: []installFileResult{writeInstructionFile(projectBORIS, borisInstructionsMarkdown(cache))}})
		}
		projectCursor := filepath.Join(cwd, ".cursor", "rules", "boris.mdc")
		if fileExists(projectCursor) {
			results = append(results, installResult{Harness: "cursor", Scope: "project", Files: []installFileResult{writeInstructionFile(projectCursor, borisCursorRule(cache))}})
		}
	}
	return results
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func harnessDisplayName(harness string) string {
	switch harness {
	case "claude", "claude-code":
		return "Claude Code"
	case "codex":
		return "Codex"
	case "cursor":
		return "Cursor"
	case "claude-code/codex":
		return "Claude Code/Codex"
	default:
		return harness
	}
}

func borisInstructionsMarkdown(cache *toolCache) string {
	return `# BORIS MCP Infrastructure Context

Use the local ` + "`boris-mcp`" + ` CLI when a task needs live context about infrastructure, deployed resources, repository/code relationships, dependencies, topology, or prior decisions and memory. Do not use it for general cloud or programming knowledge when the answer does not depend on this environment.

Before the first BORIS call in a session, run:

` + "```bash" + `
boris-mcp doctor
` + "```" + `

If ` + "`doctor`" + ` fails on config, tell the user to run ` + "`boris-mcp init`" + `. The BORIS MCP server requires AWS credentials for any account in the AWS Organization; if auth is unavailable, use the normal environment credential workflow available in this harness or explain the credential requirement to the user.

Useful commands:

- ` + "`boris-mcp list`" + `: list available remote tools.
- ` + "`boris-mcp describe <tool>`" + `: show tool schema and examples.
- ` + "`boris-mcp <tool> --arg value`" + `: call a tool with CLI flags.
- ` + "`boris-mcp call <tool> '{\"arg\":\"value\"}'`" + `: call a tool with JSON.
- ` + "`boris-mcp --pretty <tool> ...`" + `: pretty-print JSON output when the tool returns JSON.
- ` + "`boris-mcp --raw <tool> ...`" + `: show the original MCP tool envelope for debugging.

Tools available when these instructions were generated:

` + renderInstructionToolList(cache) + `

To refresh this tool list after BORIS changes, run:

` + "```bash" + `
boris-mcp sync
` + "```" + `

` + "`boris-mcp sync`" + ` refreshes the local tool cache and updates any existing BORIS instruction files it finds.

BORIS unwraps MCP text envelopes internally, so normal tool calls print the useful payload directly. Summarize the relevant facts and mention if the tool returned an error.`
}

func renderInstructionToolList(cache *toolCache) string {
	if cache == nil || len(cache.Tools) == 0 {
		return "- No tools were available in the local BORIS cache. Run `boris-mcp sync`, then reinstall or sync instructions."
	}
	var b strings.Builder
	if !cache.LastSync.IsZero() {
		fmt.Fprintf(&b, "_Synced: %s_\n\n", cache.LastSync.UTC().Format(time.RFC3339))
	}
	for _, t := range cache.Tools {
		desc := normalizeWhitespace(t.Description)
		if desc == "" {
			fmt.Fprintf(&b, "- `%s`\n", displayToolName(t.Name))
			continue
		}
		fmt.Fprintf(&b, "- `%s`: %s\n", displayToolName(t.Name), desc)
	}
	return strings.TrimRight(b.String(), "\n")
}

func borisCursorRule(cache *toolCache) string {
	return `---
description: Use BORIS for infrastructure, code, dependency, and memory context
alwaysApply: true
---

` + borisInstructionsMarkdown(cache)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  boris-mcp init [--url <url>] [--profile <profile>]
  boris-mcp install <claude-code|codex|cursor|all> [--scope user|project]
  boris-mcp sync
  boris-mcp doctor
  boris-mcp list|ls
  boris-mcp describe|d <tool>
  boris-mcp call <tool> ['{"arg":"value"}']
  boris-mcp <exact_tool_name> --arg value
  boris-mcp version

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
	changes := schemaDiff(oldTool, newTool)
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

func defaultEffective(flags globalFlags) effectiveConfig {
	home := os.Getenv("BORIS_MCP_HOME")
	if home == "" {
		if userHome, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(userHome, ".boris-mcp")
		}
	}
	return effectiveConfig{
		Home: home, ConfigPath: filepath.Join(home, "config.toml"), ToolsPath: filepath.Join(home, "tools.json"),
		URL: flags.url, Profile: flags.profile, Region: flags.region, Service: flags.service,
		SyncTTL: defaultTTL, ConnectTimeout: defaultConnect, SyncTimeout: defaultSync, CallTimeout: defaultCall,
		NonInteractive: flags.nonInteractive || truthy(os.Getenv("BORIS_MCP_NON_INTERACTIVE")),
	}
}

func (a *app) loadEffective(flags globalFlags, require bool) (effectiveConfig, bool, error) {
	cfg := defaultEffective(flags)
	fileCfg, err := readConfig(cfg.ConfigPath)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return cfg, false, err
	}
	if require && !exists {
		return cfg, false, errors.New("BORIS MCP is not configured.\nRun interactively: boris-mcp init\nOr non-interactively: boris-mcp init --url <url>")
	}
	if !exists {
		applyDefaults(&fileCfg)
	}
	if flags.url == "" {
		cfg.URL = firstNonEmpty(os.Getenv("BORIS_MCP_URL"), fileCfg.URL)
	}
	if flags.profile == "" {
		cfg.Profile = firstNonEmpty(os.Getenv("BORIS_MCP_PROFILE"), os.Getenv("AWS_PROFILE"), fileCfg.AWSProfile)
	}
	if flags.region == "" {
		cfg.Region = firstNonEmpty(os.Getenv("BORIS_MCP_REGION"), fileCfg.Region)
	}
	if flags.service == "" {
		cfg.Service = firstNonEmpty(os.Getenv("BORIS_MCP_SERVICE"), fileCfg.Service)
	}
	cfg.SyncTTL = durationFromEnv("BORIS_MCP_SYNC_TTL", fileCfg.SyncTTL)
	cfg.ConnectTimeout = durationFromEnv("BORIS_MCP_CONNECT_TIMEOUT", fileCfg.ConnectTimeout)
	cfg.SyncTimeout = durationFromEnv("BORIS_MCP_SYNC_TIMEOUT", fileCfg.SyncTimeout)
	cfg.CallTimeout = durationFromEnv("BORIS_MCP_CALL_TIMEOUT", fileCfg.CallTimeout)
	if cfg.Service == "" {
		cfg.Service = "bedrock-agentcore"
	}
	if cfg.Region == "" {
		cfg.Region = inferRegion(cfg.URL)
	}
	return cfg, exists, nil
}

func (a *app) requireConfig(flags globalFlags) (effectiveConfig, bool, error) {
	cfg, exists, err := a.loadEffective(flags, false)
	if err != nil {
		return cfg, exists, err
	}
	if !exists {
		if a.isInteractive() && !cfg.NonInteractive {
			if code := a.cmdInit(flags, nil); code != 0 {
				return cfg, false, errors.New("first-run setup failed")
			}
			cfg, exists, err = a.loadEffective(flags, false)
			if err != nil {
				return cfg, exists, err
			}
		} else {
			return cfg, false, errors.New("BORIS MCP is not configured.\nRun interactively: boris-mcp init\nOr non-interactively: boris-mcp init --url <url>")
		}
	}
	if cfg.URL == "" {
		return cfg, exists, errors.New("BORIS MCP is not configured.\nRun interactively: boris-mcp init\nOr non-interactively: boris-mcp init --url <url>")
	}
	if err := validateURL(cfg.URL, flags.allowHTTP); err != nil {
		return cfg, exists, err
	}
	return cfg, exists, nil
}

func readConfig(path string) (configFile, error) {
	var cfg configFile
	var syncTTLSet, connectTimeoutSet, syncTimeoutSet, callTimeoutSet bool
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch key {
		case "url":
			cfg.URL = val
		case "aws_profile":
			cfg.AWSProfile = val
		case "region":
			cfg.Region = val
		case "service":
			cfg.Service = val
		case "sync_ttl":
			if d, err := time.ParseDuration(val); err == nil {
				cfg.SyncTTL = d
				syncTTLSet = true
			}
		case "connect_timeout":
			if d, err := time.ParseDuration(val); err == nil {
				cfg.ConnectTimeout = d
				connectTimeoutSet = true
			}
		case "sync_timeout":
			if d, err := time.ParseDuration(val); err == nil {
				cfg.SyncTimeout = d
				syncTimeoutSet = true
			}
		case "call_timeout":
			if d, err := time.ParseDuration(val); err == nil {
				cfg.CallTimeout = d
				callTimeoutSet = true
			}
		}
	}
	applyDefaultsWithPresence(&cfg, syncTTLSet, connectTimeoutSet, syncTimeoutSet, callTimeoutSet)
	return cfg, nil
}

func writeConfig(path string, cfg configFile) error {
	var b strings.Builder
	writeKV := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%s = %q\n", k, v)
		}
	}
	writeKV("url", cfg.URL)
	writeKV("aws_profile", cfg.AWSProfile)
	writeKV("region", cfg.Region)
	writeKV("service", cfg.Service)
	fmt.Fprintf(&b, "sync_ttl = %q\n", cfg.SyncTTL.String())
	fmt.Fprintf(&b, "connect_timeout = %q\n", cfg.ConnectTimeout.String())
	fmt.Fprintf(&b, "sync_timeout = %q\n", cfg.SyncTimeout.String())
	fmt.Fprintf(&b, "call_timeout = %q\n", cfg.CallTimeout.String())
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func applyDefaults(cfg *configFile) {
	applyDefaultsWithPresence(cfg, false, false, false, false)
}

func applyDefaultsWithPresence(cfg *configFile, syncTTLSet, connectTimeoutSet, syncTimeoutSet, callTimeoutSet bool) {
	if !syncTTLSet && cfg.SyncTTL == 0 {
		cfg.SyncTTL = defaultTTL
	}
	if !connectTimeoutSet && cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = defaultConnect
	}
	if !syncTimeoutSet && cfg.SyncTimeout == 0 {
		cfg.SyncTimeout = defaultSync
	}
	if !callTimeoutSet && cfg.CallTimeout == 0 {
		cfg.CallTimeout = defaultCall
	}
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

func (a *app) cacheForCatalog(flags globalFlags, cfg effectiveConfig, allowStale bool) (*toolCache, error) {
	cache, cacheErr := readCache(cfg.ToolsPath)
	due := cacheErr != nil || cache.URL != cfg.URL || cfg.SyncTTL == 0 || a.now().Sub(cache.LastSync) > cfg.SyncTTL
	if due {
		newCache, err := a.syncTools(context.Background(), cfg)
		if err != nil {
			if allowStale && cacheErr == nil {
				fmt.Fprintf(a.stderr, "Warning: sync failed, using stale cache: %s\n", err)
				return cache, nil
			}
			return nil, err
		}
		return newCache, nil
	}
	return cache, nil
}

func readCache(path string) (*toolCache, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c toolCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func writeCache(path string, cache *toolCache) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func (a *app) syncTools(ctx context.Context, cfg effectiveConfig) (*toolCache, error) {
	if a.syncToolsFunc != nil {
		return a.syncToolsFunc(ctx, cfg)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.SyncTimeout)
	defer cancel()
	client, err := a.newMCPClient(ctx, cfg, cfg.SyncTimeout)
	if err != nil {
		return nil, err
	}
	server, err := client.initialize(ctx)
	if err != nil {
		return nil, err
	}
	tools, err := client.listTools(ctx)
	if err != nil {
		return nil, err
	}
	for i := range tools {
		tools[i].SchemaHash = schemaHash(tools[i].InputSchema)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	cache := &toolCache{Version: 1, URL: cfg.URL, LastSync: a.now().UTC(), Server: server, Tools: tools}
	if err := writeCache(cfg.ToolsPath, cache); err != nil {
		return nil, err
	}
	return cache, nil
}

func (a *app) callTool(ctx context.Context, cfg effectiveConfig, name string, input map[string]any) ([]byte, error) {
	if a.callToolFunc != nil {
		return a.callToolFunc(ctx, cfg, name, input)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.CallTimeout)
	defer cancel()
	client, err := a.newMCPClient(ctx, cfg, cfg.CallTimeout)
	if err != nil {
		return nil, err
	}
	if _, err := client.initialize(ctx); err != nil {
		return nil, err
	}
	return client.callTool(ctx, name, input)
}

func (a *app) awsCredentials(ctx context.Context, cfg effectiveConfig) (aws.Credentials, string, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Credentials{}, "", authError{err}
	}
	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err == nil {
		return creds, awsCfg.Region, nil
	}
	if cfg.Profile != "" && !cfg.NonInteractive && looksLikeSSO(err) && isInteractive() {
		fmt.Fprintf(a.stderr, "AWS SSO credentials for profile %s are expired or missing. Running aws sso login --profile %s\n", cfg.Profile, cfg.Profile)
		cmd := exec.CommandContext(ctx, "aws", "sso", "login", "--profile", cfg.Profile)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if runErr := cmd.Run(); runErr != nil {
			return aws.Credentials{}, "", authError{fmt.Errorf("aws sso login failed: %w", runErr)}
		}
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Credentials{}, "", authError{err}
		}
		creds, err = awsCfg.Credentials.Retrieve(ctx)
	}
	if err != nil {
		if cfg.Profile != "" && looksLikeSSO(err) {
			return aws.Credentials{}, "", authError{fmt.Errorf("AWS SSO credentials unavailable. Run: aws sso login --profile %s", cfg.Profile)}
		}
		return aws.Credentials{}, "", authError{err}
	}
	return creds, awsCfg.Region, nil
}

func (a *app) newMCPClient(ctx context.Context, cfg effectiveConfig, timeout time.Duration) (*mcpClient, error) {
	creds, sdkRegion, err := a.awsCredentials(ctx, cfg)
	if err != nil {
		return nil, err
	}
	region := firstNonEmpty(cfg.Region, sdkRegion)
	if region == "" {
		return nil, errors.New("AWS region could not be inferred; set --region, BORIS_MCP_REGION, or an AWS profile/default region")
	}
	return &mcpClient{
		httpClient: &http.Client{Timeout: timeout},
		url:        cfg.URL, region: region, service: cfg.Service, creds: creds,
		verbose: cfg.NonInteractive, stderr: a.stderr,
	}, nil
}

func (c *mcpClient) initialize(ctx context.Context) (serverInfo, error) {
	params := json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"boris-mcp","version":"0.1.0"}}`)
	body, err := c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: params}, true)
	if err != nil {
		return serverInfo{}, err
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	_ = json.Unmarshal(body, &result)
	_, _ = c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", Method: "notifications/initialized"}, false)
	return serverInfo{Name: result.ServerInfo.Name, ProtocolVersion: result.ProtocolVersion, Instructions: result.Instructions}, nil
}

func (c *mcpClient) listTools(ctx context.Context) ([]tool, error) {
	body, err := c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list"}, true)
	if err != nil {
		return nil, err
	}
	var result struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	tools := make([]tool, 0, len(result.Tools))
	for _, t := range result.Tools {
		tools = append(tools, tool{Name: t.Name, Description: t.Description, InputSchema: nonEmptySchema(t.InputSchema)})
	}
	return tools, nil
}

var errUpstream = errors.New("upstream tool failure")

func (c *mcpClient) callTool(ctx context.Context, name string, input map[string]any) ([]byte, error) {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": input})
	body, err := c.rpc(ctx, jsonRPCRequest{JSONRPC: "2.0", ID: 3, Method: "tools/call", Params: params}, true)
	if err != nil {
		return nil, err
	}
	var maybe struct {
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(body, &maybe) == nil && maybe.IsError {
		return nil, fmt.Errorf("%w: %s", errUpstream, string(body))
	}
	return body, nil
}

func (c *mcpClient) rpc(ctx context.Context, rpcReq jsonRPCRequest, expectResponse bool) (json.RawMessage, error) {
	body, err := json.Marshal(rpcReq)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if err := v4.NewSigner().SignHTTP(ctx, c.creds, req, hex.EncodeToString(sum[:]), c.service, c.region, time.Now().UTC()); err != nil {
		return nil, authError{err}
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionID = sid
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remote MCP HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if !expectResponse {
		return nil, nil
	}
	payload := normalizeMCPResponse(resp.Header.Get("Content-Type"), respBody)
	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(payload, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid MCP response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("MCP error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, nil
}

func (c *mcpClient) newRequest(ctx context.Context, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	return req, nil
}

func normalizeMCPResponse(contentType string, body []byte) []byte {
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return body
	}
	var last []byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			last = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if len(last) == 0 {
		return body
	}
	return last
}

func unwrapMCPTextEnvelope(raw []byte) []byte {
	var envelope struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return raw
	}
	for _, item := range envelope.Content {
		if item.Type == "text" && item.Text != "" {
			return []byte(item.Text)
		}
	}
	return raw
}

type authError struct{ error }

func isAuthErr(err error) bool {
	var ae authError
	return errors.As(err, &ae)
}

func errorName(err error) string {
	if isAuthErr(err) {
		return "auth_failure"
	}
	if errors.Is(err, errUpstream) {
		return "upstream_tool_failure"
	}
	return "failure"
}

func validateURL(raw string, allowHTTP bool) error {
	if raw == "" {
		return errors.New("BORIS MCP URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid URL: %s", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || allowHTTP) {
		return nil
	}
	return errors.New("https:// is required, except http://localhost and http://127.0.0.1")
}

func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func inferRegion(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parts := strings.Split(u.Hostname(), ".")
	for i, part := range parts {
		if part == "amazonaws" && i > 0 {
			return parts[i-1]
		}
	}
	for _, part := range parts {
		if strings.HasPrefix(part, "us-") || strings.HasPrefix(part, "eu-") || strings.HasPrefix(part, "ap-") || strings.HasPrefix(part, "sa-") || strings.HasPrefix(part, "ca-") || strings.HasPrefix(part, "af-") || strings.HasPrefix(part, "me-") {
			return part
		}
	}
	return ""
}

func schemaHash(raw json.RawMessage) string {
	var v any
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	_ = json.Unmarshal(raw, &v)
	canonical := canonicalJSON(v)
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalJSON(v any) string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.WriteString(canonicalJSON(x[k]))
		}
		b.WriteByte('}')
		return b.String()
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(canonicalJSON(item))
		}
		b.WriteByte(']')
		return b.String()
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func nonEmptySchema(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return raw
}

func parseSchema(t tool) schemaObject {
	var s schemaObject
	_ = json.Unmarshal(nonEmptySchema(t.InputSchema), &s)
	if s.Properties == nil {
		s.Properties = map[string]schemaProperty{}
	}
	return s
}

func validateInput(t tool, input map[string]any) error {
	s := parseSchema(t)
	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
		if _, ok := input[r]; !ok {
			return fmt.Errorf("Missing required argument: %s\nExpected type: %s\nExample: boris-mcp call %s '{\"%s\":...}'", r, typeName(s.Properties[r].Type), displayToolName(t.Name), r)
		}
	}
	for name, val := range input {
		prop, ok := s.Properties[name]
		if !ok && len(s.Properties) > 0 {
			return fmt.Errorf("Unknown argument: --%s\n%sThe tool was not called.", name, suggestion(name, propertyNames(s.Properties)))
		}
		if ok && !valueMatchesType(val, prop) {
			return fmt.Errorf("Invalid argument: %s expected %s", name, typeName(prop.Type))
		}
	}
	return nil
}

func parseToolFlags(t tool, args []string) (map[string]any, error) {
	s := parseSchema(t)
	input := map[string]any{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("unexpected positional argument: %s", arg)
		}
		raw := strings.TrimPrefix(arg, "--")
		name, value, hasValue := strings.Cut(raw, "=")
		prop, known := s.Properties[name]
		if !known && len(s.Properties) > 0 {
			return nil, fmt.Errorf("Unknown argument: --%s\n%sThe tool was not called.", name, suggestion(name, propertyNames(s.Properties)))
		}
		if !hasValue {
			if typeName(prop.Type) == "boolean" {
				value = "true"
				hasValue = true
			} else {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("--%s requires a value", name)
				}
				i++
				value = args[i]
			}
		}
		parsed, err := parseFlagValue(value, prop)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", name, err)
		}
		if typeName(prop.Type) == "array" {
			input[name] = appendValue(input[name], parsed)
		} else {
			input[name] = parsed
		}
	}
	if err := validateInput(t, input); err != nil {
		return nil, err
	}
	return input, nil
}

func parseFlagValue(raw string, prop schemaProperty) (any, error) {
	switch typeName(prop.Type) {
	case "boolean":
		return strconv.ParseBool(raw)
	case "integer":
		return strconv.ParseInt(raw, 10, 64)
	case "number":
		return strconv.ParseFloat(raw, 64)
	case "array":
		if strings.HasPrefix(strings.TrimSpace(raw), "[") {
			var v any
			if err := json.Unmarshal([]byte(raw), &v); err != nil {
				return nil, err
			}
			return v, nil
		}
		if prop.Items != nil {
			return parseFlagValue(raw, *prop.Items)
		}
		return raw, nil
	case "object":
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		if strings.HasPrefix(strings.TrimSpace(raw), "{") || strings.HasPrefix(strings.TrimSpace(raw), "[") {
			var v any
			if json.Unmarshal([]byte(raw), &v) == nil {
				return v, nil
			}
		}
		return raw, nil
	}
}

func appendValue(existing any, parsed any) []any {
	var out []any
	if arr, ok := existing.([]any); ok {
		out = arr
	}
	if parsedArr, ok := parsed.([]any); ok {
		return append(out, parsedArr...)
	}
	return append(out, parsed)
}

func valueMatchesType(val any, prop schemaProperty) bool {
	switch typeName(prop.Type) {
	case "", "any":
		return true
	case "string":
		_, ok := val.(string)
		return ok
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "integer":
		switch val.(type) {
		case int, int64, float64:
			f, _ := toFloat(val)
			return f == float64(int64(f))
		default:
			return false
		}
	case "number":
		_, ok := toFloat(val)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	case "object":
		_, ok := val.(map[string]any)
		return ok
	default:
		return true
	}
}

func typeName(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		if len(x) > 0 {
			if s, ok := x[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func describeTool(w io.Writer, t tool) {
	s := parseSchema(t)
	fmt.Fprintf(w, "%s\n", displayToolName(t.Name))
	if t.Description != "" {
		fmt.Fprintf(w, "%s\n", t.Description)
	}
	fmt.Fprintln(w, "\nArguments:")
	if len(s.Properties) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		req := map[string]bool{}
		for _, r := range s.Required {
			req[r] = true
		}
		names := propertyNames(s.Properties)
		for _, name := range names {
			marker := "optional"
			if req[name] {
				marker = "required"
			}
			p := s.Properties[name]
			desc := p.Description
			if desc != "" {
				desc = " - " + desc
			}
			fmt.Fprintf(w, "  %s (%s, %s)%s\n", name, typeName(p.Type), marker, desc)
		}
	}
	displayName := displayToolName(t.Name)
	fmt.Fprintf(w, "\nJSON call:\n  boris-mcp call %s '{%s}'\n", displayName, exampleJSONArgs(s))
	fmt.Fprintf(w, "\nSubcommand:\n  boris-mcp %s%s\n", displayName, exampleFlags(s))
}

func renderToolList(w io.Writer, tools []tool) {
	const nameWidth = 34
	const descWidth = 88
	for _, t := range tools {
		desc := normalizeWhitespace(t.Description)
		name := displayToolName(t.Name)
		if desc == "" {
			fmt.Fprintf(w, "%s\n", name)
			continue
		}
		lines := wrapText(desc, descWidth)
		if len(name) <= nameWidth {
			fmt.Fprintf(w, "%-*s %s\n", nameWidth, name, lines[0])
			for _, line := range lines[1:] {
				fmt.Fprintf(w, "%-*s %s\n", nameWidth, "", line)
			}
			continue
		}
		fmt.Fprintf(w, "%s\n", name)
		for _, line := range lines {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

func displayToolName(name string) string {
	if _, suffix, ok := strings.Cut(name, "___"); ok {
		return suffix
	}
	return name
}

func schemaDiff(oldTool, newTool tool) []map[string]string {
	oldS, newS := parseSchema(oldTool), parseSchema(newTool)
	oldReq, newReq := set(oldS.Required), set(newS.Required)
	var changes []map[string]string
	for name := range oldReq {
		if !newReq[name] {
			changes = append(changes, map[string]string{"kind": "removed_required_arg", "name": name, "message": "removed required arg: " + name})
		}
	}
	for name := range newReq {
		if !oldReq[name] {
			changes = append(changes, map[string]string{"kind": "added_required_arg", "name": name, "message": "added required arg: " + name})
		}
	}
	for name, oldProp := range oldS.Properties {
		if newProp, ok := newS.Properties[name]; ok && typeName(oldProp.Type) != typeName(newProp.Type) {
			changes = append(changes, map[string]string{"kind": "changed_type", "name": name, "message": fmt.Sprintf("changed type: %s %s -> %s", name, typeName(oldProp.Type), typeName(newProp.Type))})
		}
	}
	if len(changes) == 0 {
		changes = append(changes, map[string]string{"kind": "schema_hash_changed", "name": newTool.Name, "message": "input schema hash changed"})
	}
	return changes
}

func findTool(cache *toolCache, name string) (tool, bool) {
	if cache == nil {
		return tool{}, false
	}
	for _, t := range cache.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return tool{}, false
}

func resolveTool(cache *toolCache, name string) (tool, error) {
	if t, ok := findTool(cache, name); ok {
		return t, nil
	}
	if cache == nil {
		return tool{}, fmt.Errorf("Unknown command or tool: %s", name)
	}
	var matches []tool
	for _, t := range cache.Tools {
		if displayToolName(t.Name) == name {
			matches = append(matches, t)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		fullNames := make([]string, 0, len(matches))
		for _, t := range matches {
			fullNames = append(fullNames, t.Name)
		}
		sort.Strings(fullNames)
		return tool{}, fmt.Errorf("Ambiguous tool alias: %s\nUse the full tool name: %s", name, strings.Join(fullNames, ", "))
	}
	return tool{}, fmt.Errorf("Unknown command or tool: %s", name)
}

func propertyNames(props map[string]schemaProperty) []string {
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func suggestion(name string, candidates []string) string {
	best, dist := "", 99
	for _, c := range candidates {
		if d := levenshtein(name, c); d < dist {
			best, dist = c, d
		}
	}
	if best != "" && dist <= 3 {
		return fmt.Sprintf("Did you mean: --%s?\n", best)
	}
	return ""
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func set(vals []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range vals {
		m[v] = true
	}
	return m
}

func exampleJSONArgs(s schemaObject) string {
	parts := []string{}
	for _, name := range propertyNames(s.Properties) {
		parts = append(parts, fmt.Sprintf("%q:%s", name, exampleValue(s.Properties[name])))
	}
	return strings.Join(parts, ",")
}

func exampleFlags(s schemaObject) string {
	parts := []string{}
	for _, name := range propertyNames(s.Properties) {
		parts = append(parts, fmt.Sprintf(" --%s %s", name, exampleValue(s.Properties[name])))
	}
	return strings.Join(parts, "")
}

func exampleValue(p schemaProperty) string {
	switch typeName(p.Type) {
	case "string":
		return `"value"`
	case "boolean":
		return "true"
	case "integer":
		return "1"
	case "number":
		return "1.0"
	case "array":
		return "[]"
	case "object":
		return "{}"
	default:
		return "..."
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	var current strings.Builder
	for _, word := range words {
		if current.Len() == 0 {
			current.WriteString(word)
			continue
		}
		if current.Len()+1+len(word) <= width {
			current.WriteByte(' ')
			current.WriteString(word)
			continue
		}
		lines = append(lines, current.String())
		current.Reset()
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (a *app) isInteractive() bool {
	if a.interactive != nil {
		return a.interactive()
	}
	return isInteractive()
}

func isInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func looksLikeSSO(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "sso") || strings.Contains(s, "token") || strings.Contains(s, "expired")
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

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	default:
		return 0, false
	}
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}
