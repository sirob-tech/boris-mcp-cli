package main

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// credStore holds what bmcp's own SSO provider persists: one token record per
// SSO session, and role credentials minted from that session. Every backend
// stores the same JSON records, so a record means the same thing wherever it
// lives.
//
// Reads, writes and deletes return errStoreItemNotFound only from reads; a
// delete of something absent succeeds. A store that cannot be opened without UI
// it was not allowed to show returns a *storeLockedError, never "not found".
type credStore interface {
	Backend() backendName
	ReadToken(sessionKey string) (ssoTokenRecord, error)
	WriteToken(sessionKey string, rec ssoTokenRecord) error
	DeleteToken(sessionKey string) error
	ReadRoleCreds(sessionKey, credKey string) (roleCredsRecord, error)
	WriteRoleCreds(sessionKey, credKey string, rec roleCredsRecord) error
	DeleteRoleCreds(sessionKey, credKey string) error
	// DeleteSessionRoleCreds removes every role credential minted from one SSO
	// session, which is what `bmcp clear` needs and what a new login invalidates.
	DeleteSessionRoleCreds(sessionKey string) error
	// ClearAll removes every item bmcp owns in this backend. sessionKeys only
	// matters to aws-cli-cache, whose token files are shared with the AWS CLI
	// and so cannot be told apart from the CLI's own: only those keys are deleted.
	ClearAll(sessionKeys []string) error
}

// storeOptions is fixed per invocation. AllowUI follows the prompt policy:
// machine formats, --non-interactive, serve and doctor open stores without it.
type storeOptions struct {
	AllowUI bool
	// Passphrase is the file backend's prompt; nil means none can be shown.
	Passphrase func(prompt string) (string, error)
}

var errStoreItemNotFound = errors.New("credential store: item not found")

// errStoreItemCorrupt is an item that was read but does not parse, e.g. the AWS
// CLI's non-atomic write caught halfway. Readers treat it as absent.
var errStoreItemCorrupt = errors.New("credential store: item is not readable")

// classifyStoreRead puts a token read failure in decision 12's order: absent or
// unparseable is errStoreItemNotFound, a store bmcp may not read is
// store_locked, and anything else is a store error, never "log in".
func classifyStoreRead(backend backendName, err error) error {
	var locked *storeLockedError
	switch {
	case err == nil, errors.As(err, &locked):
		return err
	case errors.Is(err, errStoreItemNotFound), errors.Is(err, errStoreItemCorrupt):
		return errStoreItemNotFound
	case errors.Is(err, fs.ErrPermission):
		return &storeLockedError{Backend: backend, Reason: "permission denied reading the stored token",
			Hint: "check that bmcp's credential files belong to this user", Err: err}
	}
	return fmt.Errorf("reading the %s credential store: %w", backend, err)
}

// storeLockedError means the store exists but could not be read or written
// without UI this invocation may not show, or was refused. Kept apart from
// errStoreItemNotFound because the remedies differ: a missing token wants a
// login, a locked store wants approval.
type storeLockedError struct {
	Backend backendName
	Reason  string
	// Hint is backend-specific and complete on its own, e.g. naming the
	// environment variable the file backend reads.
	Hint string
	Err  error
}

func (e *storeLockedError) Error() string {
	msg := fmt.Sprintf("credential store needs approval (%s): %s", e.Backend, e.Reason)
	if e.Hint != "" {
		msg += "; " + e.Hint
	}
	return msg
}

func (e *storeLockedError) Unwrap() error { return e.Err }

// Remedy is the one command a locked store's message names. A typed file
// passphrase does not carry into the next process, so that backend names the
// variable instead of a login.
func (e *storeLockedError) Remedy(profile string, backend resolvedBackend) string {
	if e.Backend == backendFile {
		return "set BMCP_FILE_PASSPHRASE in the environment of the process that runs bmcp"
	}
	cmd := "bmcp"
	if profile != "" {
		cmd += " --profile " + profile
	}
	if backend.FromFlag {
		cmd += " --backend " + string(backend.Name)
	}
	return "credential store needs approval: run " + cmd + " login"
}

const (
	errNameStoreLocked          = "store_locked"
	errNameLoginInProgress      = "sso_login_in_progress"
	defaultSSORegistrationScope = "sso:account:access"
)

// ssoTokenRecord is the AWS CLI's cache file shape, field for field, so the
// aws-cli-cache backend stays readable by the CLI and the SDK. bmcp's additions
// carry a bmcp prefix: the CLI ignores fields it does not know, and drops them
// when it rewrites the file, which reads here as a generation change.
type ssoTokenRecord struct {
	StartURL              string
	Region                string
	AccessToken           string
	ExpiresAt             time.Time
	ClientID              string
	ClientSecret          string
	RegistrationExpiresAt time.Time
	RefreshToken          string
	Scopes                []string
	Generation            string
}

type ssoTokenJSON struct {
	StartURL              string   `json:"startUrl,omitempty"`
	Region                string   `json:"region,omitempty"`
	AccessToken           string   `json:"accessToken"`
	ExpiresAt             string   `json:"expiresAt"`
	ClientID              string   `json:"clientId,omitempty"`
	ClientSecret          string   `json:"clientSecret,omitempty"`
	RegistrationExpiresAt string   `json:"registrationExpiresAt,omitempty"`
	RefreshToken          string   `json:"refreshToken,omitempty"`
	Scopes                []string `json:"bmcpScopes,omitempty"`
	Generation            string   `json:"bmcpGeneration,omitempty"`
}

func (r ssoTokenRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(ssoTokenJSON{
		StartURL: r.StartURL, Region: r.Region, AccessToken: r.AccessToken,
		ExpiresAt: formatCacheTime(r.ExpiresAt), ClientID: r.ClientID, ClientSecret: r.ClientSecret,
		RegistrationExpiresAt: formatCacheTime(r.RegistrationExpiresAt), RefreshToken: r.RefreshToken,
		Scopes: r.Scopes, Generation: r.Generation,
	})
}

func (r *ssoTokenRecord) UnmarshalJSON(b []byte) error {
	var j ssoTokenJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	exp, err := parseCacheTime(j.ExpiresAt)
	if err != nil {
		return fmt.Errorf("expiresAt: %w", err)
	}
	// A bad registration expiry only costs the refresh, so it does not make the
	// access token unreadable.
	regExp, _ := parseCacheTime(j.RegistrationExpiresAt)
	*r = ssoTokenRecord{
		StartURL: j.StartURL, Region: j.Region, AccessToken: j.AccessToken, ExpiresAt: exp,
		ClientID: j.ClientID, ClientSecret: j.ClientSecret, RegistrationExpiresAt: regExp,
		RefreshToken: j.RefreshToken, Scopes: j.Scopes, Generation: j.Generation,
	}
	return nil
}

// matchesSession reports whether a stored token belongs to the session the
// current config describes; a token for another start URL, region or scope set
// counts as no token. No recorded scopes means a token the CLI wrote, which
// bmcp cannot second-guess.
func (r ssoTokenRecord) matchesSession(startURL, region string, scopes []string) bool {
	if r.StartURL != startURL || r.Region != region {
		return false
	}
	if len(r.Scopes) == 0 {
		return true
	}
	if len(scopes) == 0 {
		scopes = []string{defaultSSORegistrationScope}
	}
	return sameStringSet(r.Scopes, scopes)
}

// roleCredsRecord is a cached sso:GetRoleCredentials or AssumeRole result,
// stamped with the token generation it was minted under.
type roleCredsRecord struct {
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	Expiration      time.Time `json:"expiration"`
	Generation      string    `json:"generation"`
}

// usable reports whether cached role credentials may still be handed out: before
// their STS expiry, and only while the token they came from is the current one.
func (r roleCredsRecord) usable(tokenGeneration string, now time.Time, margin time.Duration) bool {
	return r.AccessKeyID != "" && r.Generation != "" && r.Generation == tokenGeneration &&
		now.Add(margin).Before(r.Expiration)
}

func formatCacheTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// parseCacheTime accepts what the CLI and the SDK have written over the years:
// RFC 3339 with or without fractional seconds, and the old "UTC" suffix form.
func parseCacheTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05UTC", "2006-01-02T15:04:05Z0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised time %q", s)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// ssoSessionStoreKey is the SDK's and the CLI's cache key: sha1 hex of the
// sso_session name for the current profile form, of the start URL for the
// legacy one. Matching it is what keeps aws-cli-cache shared with the CLI; the
// other backends and the lock files reuse it so one session has one name.
func ssoSessionStoreKey(sessionName, startURL string) string {
	key := startURL
	if sessionName != "" {
		key = sessionName
	}
	sum := sha1.Sum([]byte(key))
	return hex.EncodeToString(sum[:])
}

// roleCacheKeyInput is everything that decides which role credentials a chain
// yields. Any field that changes the credentials must be here, or two profiles
// would share a cache entry they should not.
type roleCacheKeyInput struct {
	SSOSession string         `json:"ssoSession"`
	StartURL   string         `json:"startUrl"`
	SSORegion  string         `json:"ssoRegion"`
	AccountID  string         `json:"accountId"`
	RoleName   string         `json:"roleName"`
	Hops       []roleCacheHop `json:"hops"`
}

type roleCacheHop struct {
	RoleARN         string `json:"roleArn"`
	ExternalID      string `json:"externalId"`
	RoleSessionName string `json:"roleSessionName"`
	DurationSeconds int    `json:"durationSeconds"`
}

// roleCacheKey hashes the canonical JSON of the input; struct field order
// fixes the encoding, and the hop order is the chain order.
func roleCacheKey(in roleCacheKeyInput) string {
	if in.Hops == nil {
		in.Hops = []roleCacheHop{}
	}
	b, _ := json.Marshal(in)
	sum := sha256.Sum256(append([]byte("bmcp-role-creds-v1\n"), b...))
	return hex.EncodeToString(sum[:])
}

// newGeneration stamps a token write that changes which token is current:
// login and refresh-token rotation.
func newGeneration() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on supported platforms; a time-based value
		// still differs from the previous generation, which is all it must do.
		return fmt.Sprintf("t%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// bmcpConfigDir and bmcpCacheDir follow XDG on every platform, including
// macOS, so the paths in docs and error messages are the same everywhere.
func bmcpConfigDir() (string, error) {
	if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "bmcp"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "bmcp"), nil
}

func bmcpCacheDir() (string, error) {
	if d := os.Getenv("XDG_CACHE_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "bmcp"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "bmcp"), nil
}

// writeSecretFileAtomic always lands 0600, unlike writeFileAtomic, which keeps
// an existing file's mode: a credential file someone loosened must not stay
// loose across a rewrite.
func writeSecretFileAtomic(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, tmp, err := createTempFile(filepath.Dir(path), "."+filepath.Base(path), 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// validStoreKey keeps keys usable as file names and keychain accounts; every
// key bmcp derives is lowercase hex.
func validStoreKey(k string) error {
	if k == "" || strings.Trim(k, "0123456789abcdef") != "" {
		return fmt.Errorf("invalid credential store key %q", k)
	}
	return nil
}

// openCredStore builds the store for an already-resolved backend.
func openCredStore(b resolvedBackend, opts storeOptions) (credStore, error) {
	switch b.Name {
	case backendAWSCLICache:
		return newAWSCLICacheStore()
	case backendFile:
		return newFileStore(opts)
	case backendKeychain:
		return newKeychainStore(keychainService, opts)
	case backendSecretService:
		return newSecretServiceStore(secretServiceApplication, opts)
	}
	return nil, fmt.Errorf("unknown credential store backend %q", b.Name)
}

const (
	keychainService          = "bmcp"
	secretServiceApplication = "bmcp"
)
