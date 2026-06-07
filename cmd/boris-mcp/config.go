package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
