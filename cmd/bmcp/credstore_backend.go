package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

type backendName string

const (
	backendAuto          backendName = "auto"
	backendKeychain      backendName = "keychain"
	backendSecretService backendName = "secret-service"
	backendFile          backendName = "file"
	backendAWSCLICache   backendName = "aws-cli-cache"
)

// backendSource says where the backend setting came from. Only the flag
// matters to a remedy: a backend named by flag has to be named again in the
// command a message hands back, or the retry runs against another store.
type backendSource string

const (
	backendSourceDefault backendSource = ""
	backendSourceFlag    backendSource = "--backend"
	backendSourceEnv     backendSource = "BMCP_BACKEND"
	backendSourceFile    backendSource = "backend in config.toml"
)

func parseBackendName(v string) (backendName, error) {
	switch b := backendName(v); b {
	case backendAuto, backendKeychain, backendSecretService, backendFile, backendAWSCLICache:
		return b, nil
	}
	return "", fmt.Errorf("invalid backend %q\nSupported values: auto, keychain, secret-service, file, aws-cli-cache", v)
}

// resolvedBackend is the store this run uses. Auto is decided anew on every
// run, so it is never persisted.
type resolvedBackend struct {
	Name     backendName
	Source   backendSource
	FromFlag bool
	// Auto marks a backend auto picked, so doctor can say why.
	Auto bool
}

// secretServiceState is the outcome of a probe that shows no UI.
type secretServiceState int

const (
	ssAvailable secretServiceState = iota
	ssNoBus
	ssNotOwned
	ssLocked
	ssError
)

type secretServiceStatus struct {
	State secretServiceState
	Err   error
}

// backendEnv is what auto resolution depends on, injectable for tests.
type backendEnv struct {
	GOOS    string
	AllowUI bool
	Probe   func(context.Context) secretServiceStatus
}

func defaultBackendEnv(allowUI bool) backendEnv {
	return backendEnv{GOOS: runtime.GOOS, AllowUI: allowUI, Probe: probeSecretService}
}

const secretServiceProbeTimeout = 3 * time.Second

var secretServiceUnlockHint = "unlock the login keyring (for example by logging in to the desktop session), or pass --backend aws-cli-cache to use the plaintext AWS CLI cache instead"

// resolveBackend turns the configured setting into the backend this run uses.
//
// On Linux auto fails closed: only a missing session bus or an unowned
// org.freedesktop.secrets name falls back to the plaintext CLI cache. Anything
// else — locked, denied, timed out — is an error, never a silent downgrade.
func resolveBackend(ctx context.Context, name backendName, source backendSource, env backendEnv) (resolvedBackend, error) {
	out := resolvedBackend{Name: name, Source: source, FromFlag: source == backendSourceFlag}
	if name == "" {
		out.Name = backendAuto
	}
	switch out.Name {
	case backendAuto:
		out.Auto = true
		switch env.GOOS {
		case "darwin":
			out.Name = backendKeychain
			return out, nil
		case "linux":
			st := runProbe(ctx, env)
			switch st.State {
			case ssNoBus, ssNotOwned:
				out.Name = backendAWSCLICache
				return out, nil
			case ssAvailable:
				out.Name = backendSecretService
				return out, nil
			case ssLocked:
				if env.AllowUI {
					out.Name = backendSecretService
					return out, nil
				}
			}
			out.Name = backendSecretService
			return out, secretServiceLocked(st)
		default:
			out.Name = backendAWSCLICache
			return out, nil
		}
	case backendKeychain:
		if env.GOOS != "darwin" {
			return out, errors.New("the keychain backend is macOS only; use --backend secret-service, file or aws-cli-cache")
		}
	case backendSecretService:
		if env.GOOS != "linux" {
			return out, errors.New("the secret-service backend is Linux only; use --backend keychain, file or aws-cli-cache")
		}
		st := runProbe(ctx, env)
		switch st.State {
		case ssAvailable:
		case ssNoBus, ssNotOwned:
			return out, fmt.Errorf("the secret-service backend is unavailable: %s; use --backend aws-cli-cache or file", describeProbe(st))
		case ssLocked:
			if !env.AllowUI {
				return out, secretServiceLocked(st)
			}
		default:
			return out, secretServiceLocked(st)
		}
	case backendFile, backendAWSCLICache:
	default:
		_, err := parseBackendName(string(out.Name))
		return out, err
	}
	return out, nil
}

func runProbe(ctx context.Context, env backendEnv) secretServiceStatus {
	if env.Probe == nil {
		return secretServiceStatus{State: ssNoBus}
	}
	ctx, cancel := context.WithTimeout(ctx, secretServiceProbeTimeout)
	defer cancel()
	return env.Probe(ctx)
}

func describeProbe(st secretServiceStatus) string {
	switch st.State {
	case ssNoBus:
		return "no D-Bus session bus"
	case ssNotOwned:
		return "nothing owns org.freedesktop.secrets on the session bus"
	case ssLocked:
		return "the Secret Service collection is locked"
	case ssAvailable:
		return "available"
	}
	if st.Err != nil {
		return "Secret Service did not answer: " + st.Err.Error()
	}
	return "Secret Service did not answer"
}

func secretServiceLocked(st secretServiceStatus) error {
	return &storeLockedError{Backend: backendSecretService, Reason: describeProbe(st), Hint: secretServiceUnlockHint, Err: st.Err}
}

// chooseBackendSetting applies flag > BMCP_BACKEND > config.toml > auto. The
// value is validated later, by effectiveConfig.backend, so a typo fails the
// commands that open a store and not, say, `bmcp version`.
func chooseBackendSetting(flagValue, envValue, fileValue string) (string, backendSource) {
	switch {
	case flagValue != "":
		return flagValue, backendSourceFlag
	case envValue != "":
		return envValue, backendSourceEnv
	case fileValue != "":
		return fileValue, backendSourceFile
	}
	return "", backendSourceDefault
}

// backend validates the configured backend; an empty setting means auto.
func (c effectiveConfig) backend() (backendName, backendSource, error) {
	if c.BackendRaw == "" {
		return backendAuto, c.BackendSource, nil
	}
	name, err := parseBackendName(c.BackendRaw)
	if err != nil {
		return "", c.BackendSource, fmt.Errorf("%s: %w", c.BackendSource, err)
	}
	return name, c.BackendSource, nil
}

const (
	ssoFlowAuto       = ""
	ssoFlowPKCE       = "pkce"
	ssoFlowDeviceCode = "device-code"
)

// ssoFlow resolves BMCP_SSO_DEVICE_CODE > sso_flow in config.toml. Auto leaves
// the choice to the login, which also switches to device code over SSH and for
// `bmcp login --device-code`.
func (c effectiveConfig) ssoFlow() (string, error) {
	if raw := strings.TrimSpace(c.SSODeviceCodeEnv); raw != "" {
		v, ok := parseStrictBool(raw)
		if !ok {
			return ssoFlowAuto, fmt.Errorf("BMCP_SSO_DEVICE_CODE: %q is not a boolean (use true or false)", raw)
		}
		if v {
			return ssoFlowDeviceCode, nil
		}
		return ssoFlowPKCE, nil
	}
	switch c.SSOFlowFile {
	case ssoFlowAuto, ssoFlowPKCE, ssoFlowDeviceCode:
		return c.SSOFlowFile, nil
	}
	return ssoFlowAuto, fmt.Errorf("sso_flow in config.toml: invalid value %q\nSupported values: pkce, device-code", c.SSOFlowFile)
}
