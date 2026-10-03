package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ssoCommandEnv is a configured machine whose profile is the SSO fixture, with
// a fresh catalog, the fake IAM Identity Center and a fake BORIS server.
func ssoCommandEnv(t *testing.T) (*fakeIdentityCenter, *fakeMCP, func(stdout, stderr *bytes.Buffer) *app) {
	t.Helper()
	f := loginTestEnv(t)
	t.Chdir(t.TempDir())
	tools := []tool{{Name: "tools___search_aws", Description: "Search."}}
	borisHome := setupInstallCatalog(t, os.Getenv("HOME"), tools)
	cfgPath := filepath.Join(borisHome, "config.toml")
	fileCfg, err := readConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	fileCfg.AWSProfile = "sso-only"
	if err := writeConfig(cfgPath, fileCfg); err != nil {
		t.Fatal(err)
	}
	server := &fakeMCP{tools: tools, callResult: []byte(`{"nodes":[]}`)}
	return f, server, func(stdout, stderr *bytes.Buffer) *app {
		a := loginTestApp(t, f, stdout, stderr)
		a.httpClient = server
		return a
	}
}

// promptCounter is the file backend's passphrase prompt, counting every time a
// run was allowed to show one.
type promptCounter struct {
	mu sync.Mutex
	n  int
}

func (p *promptCounter) prompt(string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	return "test-passphrase", nil
}

func (p *promptCounter) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

// useFileBackend selects the encrypted file store with no passphrase in the
// environment, so any read needs the prompt.
func useFileBackend(t *testing.T) *promptCounter {
	t.Helper()
	t.Setenv("BMCP_BACKEND", "file")
	t.Setenv("BMCP_FILE_PASSPHRASE", "")
	return &promptCounter{}
}

// seedFileToken stores a token the fake honours in the encrypted file store.
func seedFileToken(t *testing.T, f *fakeIdentityCenter) {
	t.Helper()
	rec := f.seedToken(t, 8*time.Hour, "gen-1")
	store, err := newFileStore(storeOptions{AllowUI: true, Passphrase: func(string) (string, error) { return "test-passphrase", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteToken(fixtureSessionKey(), rec); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ssoCachePath(t, fixtureStartURL)); err != nil {
		t.Fatal(err)
	}
}

func roleCredFiles(t *testing.T) int {
	t.Helper()
	dir, err := bmcpCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	filepath.WalkDir(filepath.Join(dir, "creds"), func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func TestClearRemovesTheProfilesSessionAndSaysTheAWSCLIIsLoggedOut(t *testing.T) {
	f, _, newApp := ssoCommandEnv(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run([]string{"--format", "json", "tools___search_aws"}); code != 0 {
		t.Fatalf("call exit %d: %s", code, stderr.String())
	}
	if roleCredFiles(t) == 0 {
		t.Fatal("the call cached no role credentials, so clear has nothing to prove")
	}
	stdout.Reset()
	if code := newApp(&stdout, &stderr).run([]string{"clear"}); code != 0 {
		t.Fatalf("clear exit %d: %s", code, stderr.String())
	}
	for _, want := range []string{
		"Cleared AWS SSO session " + fixtureStartURL + " (profile sso-only) from the aws-cli-cache (plaintext) credential store",
		"also logs the AWS CLI out of those sessions",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout %q should contain %q", stdout.String(), want)
		}
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("the token survived clear")
	}
	if n := roleCredFiles(t); n != 0 {
		t.Fatalf("%d role credential files survived clear", n)
	}
}

func TestClearAllInAMachineFormat(t *testing.T) {
	f, _, newApp := ssoCommandEnv(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run([]string{"--format", "json", "tools___search_aws"}); code != 0 {
		t.Fatalf("call exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	if code := newApp(&stdout, &stderr).run([]string{"--format", "json", "clear", "--all"}); code != 0 {
		t.Fatalf("clear exit %d: %s", code, stderr.String())
	}
	var doc clearDoc
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not one document (%v): %s", err, stdout.String())
	}
	if !doc.OK || !doc.All || doc.Backend != "aws-cli-cache" || !doc.LoggedOutAWSCLI ||
		len(doc.Sessions) != 1 || doc.Sessions[0] != fixtureStartURL {
		t.Fatalf("document %+v", doc)
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("the token survived clear --all")
	}
	dir, _ := bmcpCacheDir()
	if dirExists(filepath.Join(dir, "creds")) {
		t.Fatal("the role credential directory survived clear --all")
	}
}

func TestClearAllDuringABrowserLoginDiscardsItsResult(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.gate()
	login := startSSOHelper(t, "interactive", 10*time.Minute)
	waitForLoginMarker(t)
	if _, err := authTestApp().ssoClearAll(authTestContext(t), ssoTestConfig("sso-only"), false); err != nil {
		t.Fatal(err)
	}
	f.release()
	if out := login.result(t); !strings.Contains(out["error"], "discarded") {
		t.Fatalf("login %v should report its discarded result", out)
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("a login raced by clear --all saved its token")
	}
}

func TestClearRefusesWhatIsNotAnSSOProfile(t *testing.T) {
	_, _, newApp := ssoCommandEnv(t)
	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run([]string{"--profile", "has-static", "clear"}); code != exitValidation {
		t.Fatalf("exit %d; stderr %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "bmcp clear --all") {
		t.Fatalf("the refusal should name the alternatives: %s", stderr.String())
	}
}

// Deleting needs no passphrase, so a machine-format clear of the file store
// succeeds without one, and without asking for one.
func TestClearNeverPromptsInAMachineFormat(t *testing.T) {
	f, _, newApp := ssoCommandEnv(t)
	prompts := useFileBackend(t)
	seedFileToken(t, f)
	var stdout, stderr bytes.Buffer
	a := newApp(&stdout, &stderr)
	a.passphrasePrompt = prompts.prompt
	if code := a.run([]string{"--format", "json", "clear"}); code != 0 {
		t.Fatalf("exit %d; stderr %s", code, stderr.String())
	}
	if prompts.count() != 0 {
		t.Fatal("a machine-format clear prompted")
	}
	keys, _ := bmcpConfigDir()
	if _, err := os.Stat(filepath.Join(keys, "keys", "token-"+fixtureSessionKey()+".age")); !os.IsNotExist(err) {
		t.Fatalf("the encrypted token survived clear: %v", err)
	}
}

func TestDoctorReportsTheStoreWithoutTheNetwork(t *testing.T) {
	f, server, newApp := ssoCommandEnv(t)
	rec := f.seedToken(t, 8*time.Hour, "gen-1")
	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit %d:\n%s%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{
		"backend            ok  aws-cli-cache (plaintext, from BMCP_BACKEND)",
		"sso token          ok  aws-cli-cache, readable, expires " + formatExpiry(rec.ExpiresAt) + ", refreshable: yes",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor should print %q, got:\n%s", want, stdout.String())
		}
	}
	if strings.Contains(stdout.String(), "aws cli token") {
		t.Fatalf("on aws-cli-cache the CLI token is the store, not a leftover:\n%s", stdout.String())
	}
	if _, _, roleCalls, _ := f.counts(); roleCalls != 0 || server.listCalls != 0 {
		t.Fatal("a fresh-catalog doctor reached the network")
	}
}

func TestDoctorNotesALeftoverAWSCLIToken(t *testing.T) {
	_, _, newApp := ssoCommandEnv(t)
	t.Setenv("BMCP_BACKEND", "file")
	t.Setenv("BMCP_FILE_PASSPHRASE", "test-passphrase")
	writeSSOToken(t, fixtureStartURL, time.Now().Add(time.Hour))
	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run([]string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit %d:\n%s", code, stdout.String())
	}
	for _, want := range []string{
		"sso token          ok  file, readable, no token for session " + fixtureStartURL,
		"aws cli token      ok  a plaintext AWS CLI token for session " + fixtureStartURL + " is at " + ssoCachePath(t, fixtureStartURL),
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("doctor should print %q, got:\n%s", want, stdout.String())
		}
	}
}

func TestDoctorFailsOnABackendNoCallCouldUse(t *testing.T) {
	_, _, newApp := ssoCommandEnv(t)
	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run([]string{"--backend", "bogus", "doctor"}); code != exitGeneric {
		t.Fatalf("doctor exit %d:\n%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "backend            fail  credential store: --backend: invalid backend") {
		t.Fatalf("got:\n%s", stdout.String())
	}
}

// Doctor never prompts and never exits 3, on every path: shallow, a stale
// catalog, and --deep. A locked store is a non-failing row locally, and the
// auth row's own failure when it blocks the remote check.
func TestDoctorOnALockedStoreNeverPrompts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		stale bool
		code  int
	}{
		{name: "shallow", args: []string{"doctor"}, code: 0},
		{name: "stale catalog", args: []string{"doctor"}, stale: true, code: exitGeneric},
		{name: "deep", args: []string{"doctor", "--deep"}, code: exitGeneric},
		{name: "deep, json", args: []string{"--format", "json", "doctor", "--deep"}, code: exitGeneric},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, newApp := ssoCommandEnv(t)
			prompts := useFileBackend(t)
			seedFileToken(t, f)
			if tc.stale {
				path := filepath.Join(os.Getenv("BMCP_HOME"), "tools.json")
				cache, err := readCache(path)
				if err != nil {
					t.Fatal(err)
				}
				cache.LastSync = time.Now().Add(-233 * time.Hour)
				if err := writeCache(path, cache); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			a := newApp(&stdout, &stderr)
			a.interactive = func() bool { return true }
			a.passphrasePrompt = prompts.prompt
			if code := a.run(tc.args); code != tc.code {
				t.Fatalf("doctor exit %d, want %d:\n%s%s", code, tc.code, stdout.String(), stderr.String())
			}
			if prompts.count() != 0 {
				t.Fatal("doctor prompted for the store passphrase")
			}
			out := stdout.String()
			if !strings.Contains(out, "not inspected (file store needs BMCP_FILE_PASSPHRASE)") {
				t.Fatalf("the store row is missing:\n%s", out)
			}
			if tc.code != 0 && (!strings.Contains(out, "store_locked: set BMCP_FILE_PASSPHRASE") ||
				strings.Contains(out, "If the AWS SSO session")) {
				t.Fatalf("the auth row should name store_locked and its own remedy only:\n%s", out)
			}
		})
	}
}

// The store prompt follows the implicit-login gate: a machine format,
// --non-interactive and serve never show one; a human-format interactive call
// may; and `bmcp login` may even with nothing at the terminal, as it may open
// a browser.
func TestStorePromptGate(t *testing.T) {
	for _, tc := range []struct {
		name        string
		args        []string
		interactive bool
		code        int
		prompts     bool
	}{
		{name: "machine format", args: []string{"--format", "json", "tools___search_aws"}, interactive: true, code: exitAuth},
		{name: "--non-interactive", args: []string{"--non-interactive", "tools___search_aws"}, interactive: true, code: exitAuth},
		{name: "human interactive call", args: []string{"tools___search_aws"}, interactive: true, code: 0, prompts: true},
		{name: "login with stdin closed", args: []string{"login"}, interactive: false, code: 0, prompts: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, newApp := ssoCommandEnv(t)
			prompts := useFileBackend(t)
			seedFileToken(t, f)
			var stdout, stderr bytes.Buffer
			a := newApp(&stdout, &stderr)
			a.interactive = func() bool { return tc.interactive }
			a.passphrasePrompt = prompts.prompt
			if code := a.run(tc.args); code != tc.code {
				t.Fatalf("exit %d, want %d; stderr %s", code, tc.code, stderr.String())
			}
			if got := prompts.count() > 0; got != tc.prompts {
				t.Fatalf("prompted %v, want %v", got, tc.prompts)
			}
			if tc.code == exitAuth && !strings.Contains(stderr.String(), "BMCP_FILE_PASSPHRASE") {
				t.Fatalf("the refusal should name the passphrase variable: %s", stderr.String())
			}
		})
	}
}

// serve reads the store without UI on every tools/call, not once at startup:
// a passphrase made available mid-session is seen by the next call.
func TestServeReadsTheStorePerCallAndNeverPrompts(t *testing.T) {
	f, _, newApp := ssoCommandEnv(t)
	prompts := useFileBackend(t)
	seedFileToken(t, f)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var stderr bytes.Buffer
	a := newApp(&bytes.Buffer{}, &stderr)
	a.stdin, a.stdout = inR, outW
	a.interactive = func() bool { return true }
	a.passphrasePrompt = prompts.prompt
	done := make(chan int, 1)
	go func() { done <- a.run([]string{"serve"}); outW.Close() }()
	replies := bufio.NewScanner(outR)
	exchange := func(frame string) map[string]any {
		t.Helper()
		if _, err := io.WriteString(inW, frame+"\n"); err != nil {
			t.Fatal(err)
		}
		if !replies.Scan() {
			t.Fatalf("serve closed without answering; stderr %s", stderr.String())
		}
		var reply map[string]any
		if err := json.Unmarshal(replies.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	exchange(initPlainRPC)
	first := resultOf(t, exchange(callFrame(1, "tools___search_aws", `{}`)))
	if first["isError"] != true || !strings.Contains(firstText(first), "BMCP_FILE_PASSPHRASE") {
		t.Fatalf("first call %v should fail on the locked store", first)
	}
	t.Setenv("BMCP_FILE_PASSPHRASE", "test-passphrase")
	second := resultOf(t, exchange(callFrame(2, "tools___search_aws", `{}`)))
	if second["isError"] == true {
		t.Fatalf("second call %v should have read the store", second)
	}
	inW.Close()
	if code := <-done; code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	if prompts.count() != 0 {
		t.Fatal("serve prompted for the store passphrase")
	}
}

func firstText(result map[string]any) string {
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return ""
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	return text
}

// A gateway 401 drops the cached role credentials that signed the request, so
// the next call re-mints; the SSO token is kept and no login is prescribed.
func TestGatewayRejectionEvictsTheCachedRoleCredentials(t *testing.T) {
	f, server, newApp := ssoCommandEnv(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	call := []string{"--format", "json", "tools___search_aws"}
	var stdout, stderr bytes.Buffer
	if code := newApp(&stdout, &stderr).run(call); code != 0 {
		t.Fatalf("call exit %d: %s", code, stderr.String())
	}
	if roleCredFiles(t) != 1 {
		t.Fatalf("%d role credential files cached, want 1", roleCredFiles(t))
	}
	server.mu.Lock()
	server.statusByMethod = map[string]int{"tools/call": 401}
	server.mu.Unlock()
	stderr.Reset()
	if code := newApp(&stdout, &stderr).run(call); code != exitAuth {
		t.Fatalf("rejected call exit %d: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "login") {
		t.Fatalf("a gateway rejection must not prescribe a login: %s", stderr.String())
	}
	if n := roleCredFiles(t); n != 0 {
		t.Fatalf("%d role credential files survived the rejection", n)
	}
	if _, ok := readStoredToken(t); !ok {
		t.Fatal("a gateway rejection touched the SSO token")
	}
	_, _, before, _ := f.counts()
	server.mu.Lock()
	server.statusByMethod = nil
	server.mu.Unlock()
	if code := newApp(&stdout, &stderr).run(call); code != 0 {
		t.Fatalf("call after rejection exit %d: %s", code, stderr.String())
	}
	if _, _, after, _ := f.counts(); after != before+1 {
		t.Fatalf("role credential calls %d -> %d; the next call should re-mint once", before, after)
	}
}

func TestHelpAndCommandTableCarryLoginAndClear(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	for _, want := range []string{"bmcp login [--device-code]", "bmcp clear [--all]", "--device-code", "Flags for bmcp clear:"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("usage should carry %q", want)
		}
	}
	c, ok := lookupCommand("clear")
	if !ok || c.autoUpdate || c.scope != scopeClear {
		t.Fatalf("clear: %+v %v", c, ok)
	}
	if c, _ := lookupCommand("login"); c.scope != scopeLogin {
		t.Fatal("login does not admit --device-code")
	}
	// Scoped: --all and --device-code are flag errors anywhere else.
	if _, _, err := parsePostCommandFlags(globalFlags{}, []string{"--all"}, scopeLogin); err == nil {
		t.Fatal("--all was accepted by login")
	}
	if _, _, err := parsePostCommandFlags(globalFlags{}, []string{"--device-code"}, scopePostCommand); err == nil {
		t.Fatal("--device-code was accepted outside login")
	}
}

func TestInitPersistsTheBackend(t *testing.T) {
	f, _, newApp := ssoCommandEnv(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	var stdout, stderr bytes.Buffer
	a := newApp(&stdout, &stderr)
	a.interactive = func() bool { return false }
	if code := a.run([]string{"--backend", "aws-cli-cache", "--url", "http://localhost:8787/mcp", "init"}); code != 0 {
		t.Fatalf("init exit %d: %s", code, stderr.String())
	}
	cfg, err := readConfig(filepath.Join(os.Getenv("BMCP_HOME"), "config.toml"))
	if err != nil || cfg.Backend != "aws-cli-cache" {
		t.Fatalf("config %+v %v", cfg, err)
	}
}

func TestClearOnALockedStoreNamesTheStoreLockedRemedy(t *testing.T) {
	f, _, newApp := ssoCommandEnv(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	var stdout, stderr bytes.Buffer
	a := newApp(&stdout, &stderr)
	useScriptedStore(a, &scriptedStore{deleteErr: &storeLockedError{Backend: backendKeychain, Reason: "user interaction is not allowed"}})
	if code := a.run([]string{"clear"}); code != exitAuth {
		t.Fatalf("exit %d; stderr %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "credential store needs approval: run bmcp --profile sso-only login") {
		t.Fatalf("clear should name the store_locked remedy: %s", stderr.String())
	}
}
