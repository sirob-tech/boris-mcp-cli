package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
)

// isolateCredStoreEnv points every directory a store or lock could touch at
// temp dirs, and clears the variables that would pick a backend or supply a
// passphrase, so no test reads or writes the developer's own ~/.aws or ~/.config.
func isolateCredStoreEnv(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "xdg-cache"))
	for _, name := range []string{"BMCP_BACKEND", "BMCP_FILE_PASSPHRASE", "BMCP_SSO_DEVICE_CODE"} {
		t.Setenv(name, "")
	}
	return home
}

// platformContractStores lets build-tagged test files add backends that only
// exist on one platform, such as the keychain.
var platformContractStores = map[string]func(t *testing.T) credStore{}

func contractStores() map[string]func(t *testing.T) credStore {
	m := map[string]func(t *testing.T) credStore{
		"aws-cli-cache": func(t *testing.T) credStore {
			s, err := newAWSCLICacheStore()
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		"file": func(t *testing.T) credStore {
			t.Setenv("BMCP_FILE_PASSPHRASE", "correct horse battery staple")
			s, err := newFileStore(storeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	}
	for k, v := range platformContractStores {
		m[k] = v
	}
	return m
}

func sampleToken(gen string) ssoTokenRecord {
	return ssoTokenRecord{
		StartURL: "https://example.awsapps.com/start", Region: "us-east-1",
		AccessToken: "access-" + gen, ExpiresAt: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		ClientID: "client-id", ClientSecret: "client-secret",
		RegistrationExpiresAt: time.Date(2030, 3, 1, 0, 0, 0, 0, time.UTC),
		RefreshToken:          "refresh-" + gen, Scopes: []string{"sso:account:access"}, Generation: gen,
	}
}

func sampleRoleCreds(gen, akid string) roleCredsRecord {
	return roleCredsRecord{AccessKeyID: akid, SecretAccessKey: "secret", SessionToken: "session",
		Expiration: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), Generation: gen}
}

func TestCredStoreContract(t *testing.T) {
	for name, open := range contractStores() {
		t.Run(name, func(t *testing.T) {
			isolateCredStoreEnv(t)
			s := open(t)
			sessA := ssoSessionStoreKey("session-a", "")
			sessB := ssoSessionStoreKey("", "https://b.example.com/start")
			credA1 := roleCacheKey(roleCacheKeyInput{SSOSession: "session-a", AccountID: "111111111111", RoleName: "R1"})
			credA2 := roleCacheKey(roleCacheKeyInput{SSOSession: "session-a", AccountID: "111111111111", RoleName: "R2"})
			credB := roleCacheKey(roleCacheKeyInput{StartURL: "https://b.example.com/start", AccountID: "1", RoleName: "R"})

			if _, err := s.ReadToken(sessA); !errors.Is(err, errStoreItemNotFound) {
				t.Fatalf("missing token: want not found, got %v", err)
			}
			if _, err := s.ReadRoleCreds(sessA, credA1); !errors.Is(err, errStoreItemNotFound) {
				t.Fatalf("missing role creds: want not found, got %v", err)
			}
			if err := s.DeleteToken(sessA); err != nil {
				t.Fatalf("deleting an absent token must succeed: %v", err)
			}

			want := sampleToken("g1")
			if err := s.WriteToken(sessA, want); err != nil {
				t.Fatalf("WriteToken: %v", err)
			}
			got, err := s.ReadToken(sessA)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("token round trip:\n got %#v (%v)\nwant %#v", got, err, want)
			}
			want2 := sampleToken("g2")
			if err := s.WriteToken(sessA, want2); err != nil {
				t.Fatalf("overwrite: %v", err)
			}
			if got, _ := s.ReadToken(sessA); got.Generation != "g2" {
				t.Fatalf("overwrite did not take: %#v", got)
			}
			if err := s.WriteToken(sessB, sampleToken("gb")); err != nil {
				t.Fatal(err)
			}

			for _, c := range []struct{ sess, cred, akid string }{{sessA, credA1, "AKIA1"}, {sessA, credA2, "AKIA2"}, {sessB, credB, "AKIAB"}} {
				if err := s.WriteRoleCreds(c.sess, c.cred, sampleRoleCreds("g2", c.akid)); err != nil {
					t.Fatalf("WriteRoleCreds: %v", err)
				}
			}
			rc, err := s.ReadRoleCreds(sessA, credA1)
			if err != nil || !reflect.DeepEqual(rc, sampleRoleCreds("g2", "AKIA1")) {
				t.Fatalf("role creds round trip: %#v %v", rc, err)
			}
			if err := s.DeleteRoleCreds(sessA, credA2); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ReadRoleCreds(sessA, credA2); !errors.Is(err, errStoreItemNotFound) {
				t.Fatalf("deleted role creds still readable: %v", err)
			}
			if err := s.DeleteSessionRoleCreds(sessA); err != nil {
				t.Fatal(err)
			}
			if _, err := s.ReadRoleCreds(sessA, credA1); !errors.Is(err, errStoreItemNotFound) {
				t.Fatalf("session role creds survived DeleteSessionRoleCreds: %v", err)
			}
			if _, err := s.ReadRoleCreds(sessB, credB); err != nil {
				t.Fatalf("another session's role creds were removed: %v", err)
			}
			if _, err := s.ReadToken(sessA); err != nil {
				t.Fatalf("DeleteSessionRoleCreds removed the token: %v", err)
			}

			if err := s.ClearAll([]string{sessA, sessB}); err != nil {
				t.Fatalf("ClearAll: %v", err)
			}
			for _, k := range []string{sessA, sessB} {
				if _, err := s.ReadToken(k); !errors.Is(err, errStoreItemNotFound) {
					t.Fatalf("token %s survived ClearAll: %v", k, err)
				}
			}
			if _, err := s.ReadRoleCreds(sessB, credB); !errors.Is(err, errStoreItemNotFound) {
				t.Fatalf("role creds survived ClearAll: %v", err)
			}

			if err := s.WriteToken("not/a/key", want); err == nil {
				t.Fatal("a key that is not lowercase hex must be refused")
			}
		})
	}
}

// The aws-cli-cache backend is only worth having if the CLI and the SDK read
// what it writes, from where they look.
func TestAWSCLICacheIsCLICompatible(t *testing.T) {
	isolateCredStoreEnv(t)
	s, err := newAWSCLICacheStore()
	if err != nil {
		t.Fatal(err)
	}
	key := ssoSessionStoreKey("my-sso", "https://ignored.example.com/start")
	if err := s.WriteToken(key, sampleToken("g1")); err != nil {
		t.Fatal(err)
	}
	sdkPath, err := ssocreds.StandardCachedTokenFilepath("my-sso")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sdkPath)
	if err != nil {
		t.Fatalf("token not at the SDK's path %s: %v", sdkPath, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode %v, want 0600", info.Mode().Perm())
	}
	legacy, _ := ssocreds.StandardCachedTokenFilepath("https://example.awsapps.com/start")
	if filepath.Base(legacy) != ssoSessionStoreKey("", "https://example.awsapps.com/start")+".json" {
		t.Fatalf("legacy key differs from the SDK's: %s", legacy)
	}

	raw, _ := os.ReadFile(sdkPath)
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"startUrl", "region", "accessToken", "expiresAt", "clientId", "clientSecret", "registrationExpiresAt", "refreshToken"} {
		if _, ok := fields[f]; !ok {
			t.Errorf("CLI field %s missing from %s", f, raw)
		}
	}
	if fields["expiresAt"] != "2030-01-02T03:04:05Z" {
		t.Errorf("expiresAt = %v, want the CLI's UTC RFC 3339 form", fields["expiresAt"])
	}

	// A file the CLI wrote, without bmcp's fields, still reads.
	cli := `{"startUrl":"https://example.awsapps.com/start","region":"us-east-1","accessToken":"tok","expiresAt":"2030-01-01T00:00:00UTC"}`
	if err := os.WriteFile(sdkPath, []byte(cli), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadToken(key)
	if err != nil || got.AccessToken != "tok" || got.Generation != "" || got.ExpiresAt.Year() != 2030 {
		t.Fatalf("CLI-written token: %#v %v", got, err)
	}

	// Role creds live in bmcp's own cache dir, 0600, never next to the CLI's files.
	if err := s.WriteRoleCreds(key, roleCacheKey(roleCacheKeyInput{}), sampleRoleCreds("g1", "AKIA")); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(os.Getenv("XDG_CACHE_HOME"), "bmcp", "creds", key, "*.json"))
	if len(matches) != 1 {
		t.Fatalf("role creds files: %v", matches)
	}
	if info, _ := os.Stat(matches[0]); info.Mode().Perm() != 0o600 {
		t.Fatalf("role creds mode %v", info.Mode().Perm())
	}
	// A loosened file is tightened on rewrite rather than kept.
	os.Chmod(sdkPath, 0o644)
	if err := s.WriteToken(key, sampleToken("g2")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(sdkPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("rewrite kept mode %v", info.Mode().Perm())
	}
}

func TestFileStoreNeedsAPassphraseWithoutUI(t *testing.T) {
	isolateCredStoreEnv(t)
	t.Setenv("BMCP_FILE_PASSPHRASE", "pw")
	w, _ := newFileStore(storeOptions{})
	key := ssoSessionStoreKey("s", "")
	if err := w.WriteToken(key, sampleToken("g1")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BMCP_FILE_PASSPHRASE", "")

	prompted := false
	prompt := func(string) (string, error) { prompted = true; return "pw", nil }
	s, _ := newFileStore(storeOptions{AllowUI: false, Passphrase: prompt})
	_, err := s.ReadToken(key)
	var locked *storeLockedError
	if !errors.As(err, &locked) || errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("no-UI read without BMCP_FILE_PASSPHRASE: want storeLockedError, got %v", err)
	}
	if prompted {
		t.Fatal("prompted although UI was not allowed")
	}
	if !strings.Contains(err.Error(), "BMCP_FILE_PASSPHRASE") || !strings.Contains(locked.Remedy("p", resolvedBackend{}), "BMCP_FILE_PASSPHRASE") {
		t.Fatalf("error and remedy must name BMCP_FILE_PASSPHRASE: %v", err)
	}
	// A missing item is still "not found": the passphrase is only needed to decrypt.
	if _, err := s.ReadToken(ssoSessionStoreKey("other", "")); !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("missing item without passphrase: %v", err)
	}

	s, _ = newFileStore(storeOptions{AllowUI: true, Passphrase: prompt})
	if got, err := s.ReadToken(key); err != nil || got.AccessToken != "access-g1" || !prompted {
		t.Fatalf("UI read: %#v %v prompted=%v", got, err, prompted)
	}

	s, _ = newFileStore(storeOptions{AllowUI: true, Passphrase: func(string) (string, error) { return "wrong", nil }})
	if _, err := s.ReadToken(key); !errors.As(err, &locked) {
		t.Fatalf("wrong passphrase: want storeLockedError, got %v", err)
	}
	// Deleting needs no passphrase, which is how a lost one is recovered from.
	if err := s.ClearAll(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadToken(key); !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("after ClearAll: %v", err)
	}
}

func TestFileStoreEncryptsWithAVersionHeader(t *testing.T) {
	isolateCredStoreEnv(t)
	t.Setenv("BMCP_FILE_PASSPHRASE", "pw")
	s, _ := newFileStore(storeOptions{})
	key := ssoSessionStoreKey("s", "")
	if err := s.WriteToken(key, sampleToken("g1")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "bmcp", "keys", "token-"+key+".age")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(fileStoreHeader)) {
		t.Fatalf("missing version header: %q", raw[:20])
	}
	for _, secret := range []string{"access-g1", "refresh-g1", "client-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("plaintext %q in the encrypted file", secret)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("bmcp-credstore-v9\nxxx"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadToken(key); err == nil || errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("unknown format must be an error of its own, got %v", err)
	}
}

func TestStoreKeys(t *testing.T) {
	if ssoSessionStoreKey("sess", "https://x") != ssoSessionStoreKey("sess", "https://y") {
		t.Fatal("a named session must key on its name alone")
	}
	if ssoSessionStoreKey("", "https://x") == ssoSessionStoreKey("", "https://y") {
		t.Fatal("legacy profiles must key on the start URL")
	}
	base := roleCacheKeyInput{SSOSession: "s", StartURL: "u", SSORegion: "r", AccountID: "a", RoleName: "n",
		Hops: []roleCacheHop{{RoleARN: "arn1", ExternalID: "e", RoleSessionName: "rs", DurationSeconds: 900}}}
	if roleCacheKey(base) != roleCacheKey(base) {
		t.Fatal("key is not deterministic")
	}
	variants := []func(*roleCacheKeyInput){
		func(i *roleCacheKeyInput) { i.SSOSession = "s2" },
		func(i *roleCacheKeyInput) { i.StartURL = "u2" },
		func(i *roleCacheKeyInput) { i.SSORegion = "r2" },
		func(i *roleCacheKeyInput) { i.AccountID = "a2" },
		func(i *roleCacheKeyInput) { i.RoleName = "n2" },
		func(i *roleCacheKeyInput) { i.Hops = nil },
		func(i *roleCacheKeyInput) { i.Hops = append(i.Hops, roleCacheHop{RoleARN: "arn2"}) },
		func(i *roleCacheKeyInput) {
			i.Hops = []roleCacheHop{{RoleARN: "arnX", ExternalID: "e", RoleSessionName: "rs", DurationSeconds: 900}}
		},
		func(i *roleCacheKeyInput) {
			i.Hops = []roleCacheHop{{RoleARN: "arn1", ExternalID: "x", RoleSessionName: "rs", DurationSeconds: 900}}
		},
		func(i *roleCacheKeyInput) {
			i.Hops = []roleCacheHop{{RoleARN: "arn1", ExternalID: "e", RoleSessionName: "x", DurationSeconds: 900}}
		},
		func(i *roleCacheKeyInput) {
			i.Hops = []roleCacheHop{{RoleARN: "arn1", ExternalID: "e", RoleSessionName: "rs", DurationSeconds: 901}}
		},
	}
	for i, mutate := range variants {
		v := base
		v.Hops = append([]roleCacheHop(nil), base.Hops...)
		mutate(&v)
		if roleCacheKey(v) == roleCacheKey(base) {
			t.Errorf("variant %d shares the base key", i)
		}
	}
}

func TestTokenAndRoleCredValidity(t *testing.T) {
	tok := sampleToken("g1")
	if !tok.matchesSession(tok.StartURL, tok.Region, nil) {
		t.Fatal("default scopes must match sso:account:access")
	}
	if tok.matchesSession("https://other", tok.Region, nil) || tok.matchesSession(tok.StartURL, "eu-west-1", nil) {
		t.Fatal("start URL and region must match")
	}
	if tok.matchesSession(tok.StartURL, tok.Region, []string{"other:scope"}) {
		t.Fatal("scopes must match")
	}
	cli := tok
	cli.Scopes = nil
	if !cli.matchesSession(tok.StartURL, tok.Region, []string{"other:scope"}) {
		t.Fatal("a token without recorded scopes (written by the CLI) must not be rejected on scopes")
	}

	now := time.Date(2029, 12, 31, 23, 0, 0, 0, time.UTC)
	rc := sampleRoleCreds("g1", "AKIA")
	if !rc.usable("g1", now, 5*time.Minute) {
		t.Fatal("fresh creds of the current generation must be usable")
	}
	if rc.usable("g2", now, 5*time.Minute) {
		t.Fatal("a generation change must invalidate role creds")
	}
	if rc.usable("g1", rc.Expiration.Add(-time.Minute), 5*time.Minute) {
		t.Fatal("creds inside the expiry margin must not be usable")
	}
	if (roleCredsRecord{AccessKeyID: "A", Expiration: rc.Expiration}).usable("", now, 0) {
		t.Fatal("creds with no generation must never be usable")
	}
}

func TestStoreLockedRemedyNamesTheBackendOnlyWhenFlagged(t *testing.T) {
	e := &storeLockedError{Backend: backendKeychain, Reason: "r"}
	if got := e.Remedy("dev", resolvedBackend{Name: backendKeychain, Source: backendSourceEnv}); got != "credential store needs approval: run bmcp --profile dev login" {
		t.Fatalf("got %q", got)
	}
	if got := e.Remedy("dev", resolvedBackend{Name: backendKeychain, Source: backendSourceFlag, FromFlag: true}); got != "credential store needs approval: run bmcp --profile dev --backend keychain login" {
		t.Fatalf("got %q", got)
	}
}

func TestBackendSettingPrecedence(t *testing.T) {
	isolateCredStoreEnv(t)
	t.Setenv("BMCP_HOME", t.TempDir())
	cfgPath := filepath.Join(os.Getenv("BMCP_HOME"), "config.toml")
	if err := writeConfig(cfgPath, configFile{URL: "https://example.com/mcp", Backend: "file", SSOFlow: "device-code"}); err != nil {
		t.Fatal(err)
	}
	a := &app{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	load := func(flags globalFlags) effectiveConfig {
		cfg, _, err := a.loadEffective(flags, false)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	check := func(cfg effectiveConfig, wantName backendName, wantSrc backendSource) {
		t.Helper()
		name, src, err := cfg.backend()
		if err != nil || name != wantName || src != wantSrc {
			t.Fatalf("backend = %q from %q (%v), want %q from %q", name, src, err, wantName, wantSrc)
		}
	}
	check(load(globalFlags{}), backendFile, backendSourceFile)
	t.Setenv("BMCP_BACKEND", "aws-cli-cache")
	check(load(globalFlags{}), backendAWSCLICache, backendSourceEnv)
	check(load(globalFlags{backend: "keychain"}), backendKeychain, backendSourceFlag)

	t.Setenv("BMCP_BACKEND", "bogus")
	if _, src, err := load(globalFlags{}).backend(); err == nil || src != backendSourceEnv || !strings.Contains(err.Error(), "BMCP_BACKEND") {
		t.Fatalf("invalid env value: src %q err %v", src, err)
	}
	t.Setenv("BMCP_BACKEND", "")
	os.Remove(cfgPath)
	check(load(globalFlags{}), backendAuto, backendSourceDefault)
}

func TestSSOFlowSetting(t *testing.T) {
	for _, c := range []struct {
		env, file, want string
		wantErr         bool
	}{
		{"", "", ssoFlowAuto, false},
		{"", "device-code", ssoFlowDeviceCode, false},
		{"", "pkce", ssoFlowPKCE, false},
		{"1", "pkce", ssoFlowDeviceCode, false},
		{"0", "device-code", ssoFlowPKCE, false},
		{"maybe", "", ssoFlowAuto, true},
		{"", "browser", ssoFlowAuto, true},
	} {
		got, err := effectiveConfig{SSODeviceCodeEnv: c.env, SSOFlowFile: c.file}.ssoFlow()
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("env %q file %q: got %q, %v", c.env, c.file, got, err)
		}
	}
}

func TestBackendFlagParsing(t *testing.T) {
	f, rest, err := parseGlobalFlags([]string{"--backend", "file", "list"})
	if err != nil || f.backend != "file" || len(rest) != 1 {
		t.Fatalf("got %#v %v %v", f.backend, rest, err)
	}
	f, _, err = parseGlobalFlags([]string{"--backend=aws-cli-cache", "list"})
	if err != nil || f.backend != "aws-cli-cache" {
		t.Fatalf("got %q %v", f.backend, err)
	}
	if _, _, err := parseGlobalFlags([]string{"--backend=", "list"}); err == nil {
		t.Fatal("--backend= must be a usage error, not unset")
	}
	if got := formatForReport([]string{"--backend", "file", "list", "--format", "json"}); got != outputJSON {
		t.Fatalf("formatForReport must step over --backend's value, got %q", got)
	}
}

func TestResolveBackend(t *testing.T) {
	probe := func(st secretServiceState) func(context.Context) secretServiceStatus {
		return func(context.Context) secretServiceStatus {
			return secretServiceStatus{State: st, Err: errors.New("boom")}
		}
	}
	ctx := context.Background()
	var locked *storeLockedError
	for _, c := range []struct {
		name    string
		backend backendName
		env     backendEnv
		want    backendName
		locked  bool
		failErr bool
	}{
		{"darwin auto", backendAuto, backendEnv{GOOS: "darwin"}, backendKeychain, false, false},
		{"linux no bus", backendAuto, backendEnv{GOOS: "linux", Probe: probe(ssNoBus)}, backendAWSCLICache, false, false},
		{"linux not owned", backendAuto, backendEnv{GOOS: "linux", Probe: probe(ssNotOwned)}, backendAWSCLICache, false, false},
		{"linux available", backendAuto, backendEnv{GOOS: "linux", Probe: probe(ssAvailable)}, backendSecretService, false, false},
		{"linux locked no UI", backendAuto, backendEnv{GOOS: "linux", Probe: probe(ssLocked)}, backendSecretService, true, true},
		{"linux locked with UI", backendAuto, backendEnv{GOOS: "linux", AllowUI: true, Probe: probe(ssLocked)}, backendSecretService, false, false},
		{"linux D-Bus error", backendAuto, backendEnv{GOOS: "linux", AllowUI: true, Probe: probe(ssError)}, backendSecretService, true, true},
		{"keychain on linux", backendKeychain, backendEnv{GOOS: "linux"}, backendKeychain, false, true},
		{"secret-service on darwin", backendSecretService, backendEnv{GOOS: "darwin"}, backendSecretService, false, true},
		{"secret-service unreachable", backendSecretService, backendEnv{GOOS: "linux", Probe: probe(ssNoBus)}, backendSecretService, false, true},
		{"secret-service locked", backendSecretService, backendEnv{GOOS: "linux", Probe: probe(ssLocked)}, backendSecretService, true, true},
		{"file anywhere", backendFile, backendEnv{GOOS: "linux", Probe: probe(ssError)}, backendFile, false, false},
		{"cli cache anywhere", backendAWSCLICache, backendEnv{GOOS: "darwin"}, backendAWSCLICache, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveBackend(ctx, c.backend, backendSourceEnv, c.env)
			if got.Name != c.want {
				t.Errorf("backend %q, want %q", got.Name, c.want)
			}
			if (err != nil) != c.failErr {
				t.Fatalf("err = %v, want failure %v", err, c.failErr)
			}
			if errors.As(err, &locked) != c.locked {
				t.Fatalf("store-locked = %v, want %v (%v)", !c.locked, c.locked, err)
			}
			if c.locked && !strings.Contains(err.Error(), "--backend aws-cli-cache") {
				t.Fatalf("locked Secret Service must name the plaintext alternative: %v", err)
			}
		})
	}
	got, _ := resolveBackend(ctx, backendFile, backendSourceFlag, backendEnv{GOOS: "linux"})
	if !got.FromFlag {
		t.Fatal("a backend named by flag must be marked FromFlag")
	}
}
