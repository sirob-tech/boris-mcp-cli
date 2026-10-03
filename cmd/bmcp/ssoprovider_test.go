package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// storedSSOTokenExpiry reads the token bmcp would use for profile, through the
// same prompt-free probe doctor uses, and fails when there is none.
func storedSSOTokenExpiry(t *testing.T, profile string) (time.Time, error) {
	t.Helper()
	st := authTestApp().ssoStoreStatus(authTestContext(t), ssoTestConfig(profile))
	switch {
	case st.Err != nil:
		return time.Time{}, st.Err
	case st.Locked != nil:
		return time.Time{}, st.Locked
	case !st.HasToken:
		return time.Time{}, errors.New("no usable SSO token in the store")
	}
	return st.ExpiresAt, nil
}

func ssoTestConfig(profile string) effectiveConfig {
	return effectiveConfig{Profile: profile, ProfileSource: profileSourceFlag, Region: "us-east-1"}
}

// ssoTestApp may log in: human format, someone at the terminal, and the fake
// browser in place of the real one.
func ssoTestApp(f *fakeIdentityCenter) *app {
	a := authTestApp()
	a.machine = false
	a.interactive = func() bool { return true }
	a.openURL = f.browser
	return a
}

func loginBudget(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func readStoredToken(t *testing.T) (ssoTokenRecord, bool) {
	t.Helper()
	rec, err := testSSOStore(t).ReadToken(fixtureSessionKey())
	if errors.Is(err, errStoreItemNotFound) {
		return rec, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return rec, true
}

func TestPKCELoginSavesARefreshableToken(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	a := ssoTestApp(f)
	creds, _, err := a.awsCredentials(loginBudget(t), ssoTestConfig("sso-only"))
	if err != nil {
		t.Fatalf("login and retrieval should succeed: %v", err)
	}
	if !strings.HasPrefix(creds.AccessKeyID, "ASIA-SSO-ExampleRole-") {
		t.Fatalf("credentials %q did not come from GetRoleCredentials", creds.AccessKeyID)
	}
	f.mu.Lock()
	reg := f.registrations[0]
	f.mu.Unlock()
	want := map[string]any{
		"clientName": "bmcp", "clientType": "public",
		"scopes":       []any{"sso:account:access"},
		"grantTypes":   []any{"authorization_code", "refresh_token"},
		"redirectUris": []any{"http://127.0.0.1/oauth/callback"},
		"issuerUrl":    fixtureStartURL,
	}
	if !reflect.DeepEqual(reg, want) {
		t.Fatalf("RegisterClient got %v, want %v", reg, want)
	}
	tok, ok := readStoredToken(t)
	if !ok || tok.RefreshToken == "" || tok.Generation == "" || tok.ClientSecret == "" {
		t.Fatalf("the login should store a refreshable, stamped token, got %+v", tok)
	}
	out := a.stderr.(*bytes.Buffer).String()
	if !strings.Contains(out, f.srv.URL+"/authorize?") || !strings.Contains(out, "code_challenge_method=S256") {
		t.Fatalf("the authorize URL should be printed, got: %s", out)
	}
	if strings.Contains(out, "authcode-") {
		t.Fatalf("the callback code reached the output: %s", out)
	}
}

func TestPKCECallbackChecksStateAndTakesOnlyTheFirstAnswer(t *testing.T) {
	srv, err := newSSOCallbackServer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer srv.shutdown()
	get := func(q url.Values) int {
		resp, err := http.Get(srv.redirectURI() + "?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get(url.Values{"state": {"forged"}, "code": {"stolen"}}); code != http.StatusBadRequest {
		t.Fatalf("wrong state answered %d, want 400", code)
	}
	if code := get(url.Values{"code": {"stolen"}}); code != http.StatusBadRequest {
		t.Fatalf("missing state answered %d, want 400", code)
	}
	select {
	case r := <-srv.results:
		t.Fatalf("a forged callback ended the login: %+v", r)
	default:
	}
	if code := get(url.Values{"state": {srv.state}, "code": {"real"}}); code != http.StatusOK {
		t.Fatalf("valid callback answered %d", code)
	}
	get(url.Values{"state": {srv.state}, "code": {"reload"}})
	if r := <-srv.results; r.code != "real" || r.err != nil {
		t.Fatalf("result %+v, want the first valid code", r)
	}
}

func TestPKCEErrorCallbackFailsTheLogin(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.authorizeErr = "access_denied"
	_, _, err := ssoTestApp(f).awsCredentials(loginBudget(t), ssoTestConfig("sso-only"))
	if err == nil || !strings.Contains(err.Error(), "SSO login failed") || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("error %v should report the refused login", err)
	}
	if strings.Contains(err.Error(), f.errorBody) {
		t.Fatalf("the error description from the browser reached the message: %v", err)
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("a refused login stored a token")
	}
}

func TestPKCELoginEndsWithItsContext(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	l := &ssoLoginer{oidc: fakeOIDCClient(t), sess: ssoSession{Profile: "p", StartURL: fixtureStartURL, Region: "us-east-1"},
		out: io.Discard, openURL: func(string) error { return nil }, now: time.Now, sleep: sleepCtx}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := l.login(ctx, false)
	if err == nil || !strings.Contains(err.Error(), "not approved in time") {
		t.Fatalf("error %v, want a timeout", err)
	}
	if regs, _, _, _ := f.counts(); regs != 1 {
		t.Fatalf("registrations %d, want 1", regs)
	}
}

func TestDeviceCodeLoginPollsThroughPendingAndSlowDown(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.deviceSteps = []string{"AuthorizationPendingException", "SlowDownException", "AuthorizationPendingException"}
	var out bytes.Buffer
	var waits []time.Duration
	l := &ssoLoginer{oidc: fakeOIDCClient(t), sess: ssoSession{Profile: "sso-only", StartURL: fixtureStartURL, Region: "us-east-1"},
		out: &out, openURL: func(string) error { return nil }, now: time.Now,
		sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}
	rec, err := l.login(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if rec.AccessToken == "" || rec.RefreshToken == "" {
		t.Fatalf("token %+v", rec)
	}
	if want := []time.Duration{time.Second, time.Second, 6 * time.Second, 6 * time.Second}; !reflect.DeepEqual(waits, want) {
		t.Fatalf("poll waits %v, want %v (slow_down adds five seconds for good)", waits, want)
	}
	f.mu.Lock()
	reg := f.registrations[0]
	f.mu.Unlock()
	if _, ok := reg["grantTypes"]; ok {
		t.Fatalf("device-code registration should not restrict grant types: %v", reg)
	}
	if !strings.Contains(out.String(), "ABCD-EFGH") || strings.Contains(out.String(), fakeDeviceCode) {
		t.Fatalf("the user code should be shown and the device code never: %s", out.String())
	}
}

// IAM Identity Center answers the poll that outlives the device code with
// InvalidGrantException; only one that arrives early means something else.
func TestDeviceCodeLoginReportsAnExpiredCodeAsATimeout(t *testing.T) {
	start := time.Now()
	for _, tc := range []struct {
		name, step string
		elapsed    time.Duration
		want       string
	}{
		{"expired token", "ExpiredTokenException", time.Minute, "the device login was not approved in time"},
		{"invalid grant at expiry", "InvalidGrantException", 600 * time.Second, "the device login was not approved in time"},
		{"invalid grant early", "InvalidGrantException", time.Minute, "the device login was denied or the code is no longer valid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			f := newFakeIdentityCenter(t)
			f.deviceSteps = []string{"AuthorizationPendingException", tc.step}
			calls := 0
			now := func() time.Time {
				calls++
				if calls == 1 {
					return start
				}
				return start.Add(tc.elapsed)
			}
			l := &ssoLoginer{oidc: fakeOIDCClient(t), sess: ssoSession{Profile: "p", StartURL: fixtureStartURL, Region: "us-east-1"},
				out: io.Discard, openURL: func(string) error { return nil }, now: now,
				sleep: func(context.Context, time.Duration) error { return nil }}
			_, err := l.login(context.Background(), true)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("error %v, want it to start with %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.step) || strings.Contains(err.Error(), f.errorBody) {
				t.Fatalf("error %v should name the type and withhold the message", err)
			}
		})
	}
}

func TestSSOFlowChoice(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      map[string]string
		cfg      effectiveConfig
		explicit bool
		device   bool
	}{
		{name: "default is PKCE"},
		{name: "SSH session", env: map[string]string{"SSH_CONNECTION": "1 2 3 4"}, device: true},
		{name: "SSH tty", env: map[string]string{"SSH_TTY": "/dev/pts/1"}, device: true},
		{name: "explicit flag", explicit: true, device: true},
		{name: "env asks", cfg: effectiveConfig{SSODeviceCodeEnv: "1"}, device: true},
		{name: "config asks", cfg: effectiveConfig{SSOFlowFile: "device-code"}, device: true},
		{name: "pkce outranks SSH", env: map[string]string{"SSH_CLIENT": "x"}, cfg: effectiveConfig{SSODeviceCodeEnv: "false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
				t.Setenv(v, tc.env[v])
			}
			got, _, err := ssoFlowChoice(tc.cfg, tc.explicit)
			if err != nil || got != tc.device {
				t.Fatalf("device=%v err=%v, want %v", got, err, tc.device)
			}
		})
	}
}

func TestRegistrationScopesComeFromTheSSOSession(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[profile scoped]
sso_session = scoped-session
sso_account_id = 123456789012
sso_role_name = ExampleRole

[sso-session scoped-session]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access, codewhisperer:completions
`)
	chain, err := resolveSSOChain(authTestContext(t), "scoped")
	if err != nil || chain == nil {
		t.Fatalf("chain %v, err %v", chain, err)
	}
	if want := []string{"sso:account:access", "codewhisperer:completions"}; !reflect.DeepEqual(chain.Leaf.scopes(), want) {
		t.Fatalf("scopes %v, want %v", chain.Leaf.scopes(), want)
	}
	if chain.Leaf.Name != "scoped-session" {
		t.Fatalf("session %q", chain.Leaf.Name)
	}
}

func TestRefreshRenewsTheTokenAndRotationBumpsTheGeneration(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(fmt.Sprintf("rotate=%v", rotate), func(t *testing.T) {
			isolateAWSEnv(t)
			f := newFakeIdentityCenter(t)
			f.rotate = rotate
			seeded := f.seedToken(t, 5*time.Minute, "gen-1")
			if _, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only")); err != nil {
				t.Fatal(err)
			}
			if _, _, _, g := f.counts(); g[grantRefreshToken] != 1 {
				t.Fatalf("refresh grants %d, want 1", g[grantRefreshToken])
			}
			tok, _ := readStoredToken(t)
			if tok.AccessToken == seeded.AccessToken || !tok.ExpiresAt.After(time.Now().Add(time.Hour)) {
				t.Fatalf("the refreshed token was not saved: %+v", tok)
			}
			if rotated := tok.RefreshToken != seeded.RefreshToken; rotated != rotate {
				t.Fatalf("refresh token rotated=%v, want %v", rotated, rotate)
			}
			if changed := tok.Generation != "gen-1"; changed != rotate {
				t.Fatalf("generation changed=%v, want %v", changed, rotate)
			}
		})
	}
}

func TestRejectedRefreshOfAnExpiredTokenDeletesIt(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.refreshErr = "InvalidGrantException"
	f.seedToken(t, -time.Minute, "gen-1")
	_, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only"))
	if err == nil || !strings.Contains(err.Error(), "run: bmcp --profile sso-only login") {
		t.Fatalf("error %v should name bmcp login", err)
	}
	if errorName(err) != "auth_failure" {
		t.Fatalf("name %q", errorName(err))
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("a token whose refresh was rejected is still stored, so bmcp login would short-circuit on it")
	}
	if regs, _, _, _ := f.counts(); regs != 0 {
		t.Fatal("a machine-format run started a login")
	}
}

func TestTransientRefreshFailureKeepsTheToken(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.refreshErr, f.refreshStatus = "InternalServerException", 500
	seeded := f.seedToken(t, -time.Minute, "gen-1")
	if _, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only")); err == nil {
		t.Fatal("an expired token with a failing refresh cannot produce credentials")
	}
	tok, ok := readStoredToken(t)
	if !ok || tok.RefreshToken != seeded.RefreshToken {
		t.Fatalf("a transient failure dropped the refresh token: %+v", tok)
	}
}

func TestFailedRefreshKeepsUsingAStillValidAccessToken(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.refreshErr = "InvalidGrantException"
	seeded := f.seedToken(t, 5*time.Minute, "gen-1")
	if _, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only")); err != nil {
		t.Fatalf("the access token still works: %v", err)
	}
	if tok, ok := readStoredToken(t); !ok || tok.AccessToken != seeded.AccessToken {
		t.Fatal("the still-valid token was dropped")
	}
}

func TestUnauthorizedRoleCredentialsRefreshOnceThenDropTheToken(t *testing.T) {
	t.Run("refresh repairs it", func(t *testing.T) {
		isolateAWSEnv(t)
		f := newFakeIdentityCenter(t)
		seeded := f.seedToken(t, 8*time.Hour, "gen-1")
		f.rejectAccess[seeded.AccessToken] = true
		if _, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only")); err != nil {
			t.Fatal(err)
		}
		if _, _, calls, g := f.counts(); g[grantRefreshToken] != 1 || calls != 2 {
			t.Fatalf("refreshes %d role calls %d, want 1 and 2", g[grantRefreshToken], calls)
		}
	})
	t.Run("rejected refresh drops it", func(t *testing.T) {
		isolateAWSEnv(t)
		f := newFakeIdentityCenter(t)
		seeded := f.seedToken(t, 8*time.Hour, "gen-1")
		f.rejectAccess[seeded.AccessToken] = true
		f.refreshErr = "InvalidGrantException"
		_, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only"))
		if err == nil || !strings.Contains(err.Error(), "UnauthorizedException") {
			t.Fatalf("error %v", err)
		}
		if _, ok := readStoredToken(t); ok {
			t.Fatal("an unexpired but rejected token survived, so bmcp login would short-circuit on it")
		}
	})
}

func TestRoleCredentialCacheIsKeyedPerRole(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[profile sso-other]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = OtherRole
region = us-east-1
`)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	get := func(profile string) string {
		creds, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig(profile))
		if err != nil {
			t.Fatal(err)
		}
		return creds.AccessKeyID
	}
	first := get("sso-only")
	if again := get("sso-only"); again != first {
		t.Fatalf("second call minted %q instead of reusing %q", again, first)
	}
	other := get("sso-other")
	if !strings.HasPrefix(other, "ASIA-SSO-OtherRole-") {
		t.Fatalf("a profile sharing the session got %q, another role's credentials", other)
	}
	if _, _, calls, _ := f.counts(); calls != 2 {
		t.Fatalf("role calls %d, want 2", calls)
	}
}

func TestANewLoginRetiresCachedRoleCredentials(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	a := ssoTestApp(f)
	before, _, err := a.awsCredentials(authTestContext(t), ssoTestConfig("sso-only"))
	if err != nil {
		t.Fatal(err)
	}
	// An expired, unrefreshable token: the explicit login has to really log in.
	tok, _ := readStoredToken(t)
	tok.ExpiresAt, tok.RefreshToken = time.Now().Add(-time.Minute), ""
	if err := testSSOStore(t).WriteToken(fixtureSessionKey(), tok); err != nil {
		t.Fatal(err)
	}
	res, err := a.ssoLogin(loginBudget(t), ssoTestConfig("sso-only"), "sso-only", false)
	if err != nil || res.AlreadyValid || res.Refreshed {
		t.Fatalf("login %+v, %v", res, err)
	}
	after, _, err := a.awsCredentials(authTestContext(t), ssoTestConfig("sso-only"))
	if err != nil {
		t.Fatal(err)
	}
	if after.AccessKeyID == before.AccessKeyID {
		t.Fatal("role credentials minted under the previous login were reused")
	}
}

func TestChainWalkerAssumesEveryHopAboveTheSSOLeaf(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[profile hop1]
role_arn = arn:aws:iam::111111111111:role/HopOne
source_profile = sso-only
external_id = ext-1
role_session_name = bmcp-hop
duration_seconds = 3600
region = us-east-1

[profile hop2]
role_arn = arn:aws:iam::222222222222:role/HopTwo
source_profile = hop1
region = us-east-1
`)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	creds, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("hop2"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	calls, signers := f.stsCalls, f.stsSigners
	f.mu.Unlock()
	if len(calls) != 2 || creds.AccessKeyID != "ASIA-HOP-2" {
		t.Fatalf("STS calls %d, credentials %q; want 2 and the second hop's", len(calls), creds.AccessKeyID)
	}
	first := calls[0]
	if first.Get("RoleArn") != "arn:aws:iam::111111111111:role/HopOne" || first.Get("ExternalId") != "ext-1" ||
		first.Get("RoleSessionName") != "bmcp-hop" || first.Get("DurationSeconds") != "3600" {
		t.Fatalf("first hop sent %v", first)
	}
	if calls[1].Get("RoleArn") != "arn:aws:iam::222222222222:role/HopTwo" {
		t.Fatalf("second hop sent %v", calls[1])
	}
	if !strings.HasPrefix(signers[0], "ASIA-SSO-ExampleRole-") || signers[1] != "ASIA-HOP-1" {
		t.Fatalf("hops signed with %v; each must use the credentials below it", signers)
	}
	// The final credentials are cached: no further STS or SSO calls.
	again, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("hop2"))
	if err != nil || again.AccessKeyID != "ASIA-HOP-2" {
		t.Fatalf("cached chain credentials %q, %v", again.AccessKeyID, err)
	}
	// A one-hop chain reuses the cached leaf rather than minting again.
	one, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("hop1"))
	if err != nil || one.AccessKeyID != "ASIA-HOP-3" {
		t.Fatalf("one-hop chain %q, %v", one.AccessKeyID, err)
	}
	if _, _, roleCalls, _ := f.counts(); roleCalls != 1 {
		t.Fatalf("role calls %d, want 1", roleCalls)
	}
}

func TestMFASerialInAnSSOChainIsRefusedBeforeSTS(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[profile mfa-hop]
role_arn = arn:aws:iam::111111111111:role/Mfa
source_profile = sso-only
mfa_serial = arn:aws:iam::111111111111:mfa/me
region = us-east-1
`)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	_, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("mfa-hop"))
	want := "profile mfa-hop requires an MFA code (mfa_serial), which bmcp does not support; use a profile without mfa_serial"
	if err == nil || err.Error() != want {
		t.Fatalf("error %v, want %q", err, want)
	}
	if _, _, roleCalls, _ := f.counts(); roleCalls != 0 || len(f.stsCalls) != 0 {
		t.Fatal("the refusal came after a network call")
	}
}

func TestANonSSOLeafIsLeftToTheSDK(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[profile static-hop]
role_arn = arn:aws:iam::111111111111:role/FromStatic
source_profile = has-static
region = eu-west-1
`)
	f := newFakeIdentityCenter(t)
	a := authTestApp()
	ctx, slot := withSSOIssuedSlot(authTestContext(t))
	creds, _, err := a.awsCredentials(ctx, ssoTestConfig("static-hop"))
	if err != nil {
		t.Fatal(err)
	}
	if iss := slot.take(); creds.AccessKeyID != "ASIA-HOP-1" || iss != nil {
		t.Fatalf("credentials %q, issued %v: the SDK should have assumed the role", creds.AccessKeyID, iss)
	}
	if f.stsSigners[0] != profileKey {
		t.Fatalf("signed with %q, want the static leaf's key", f.stsSigners[0])
	}
	if chain, _ := resolveSSOChain(authTestContext(t), "static-hop"); chain != nil {
		t.Fatal("a static leaf was claimed as SSO")
	}
}

// Identity Center echoes request fields in its errors, and the requests carry
// tokens and client secrets. Only type, status and request id may pass.
func TestSSOErrorsNeverCarryResponseBodies(t *testing.T) {
	secrets := `{"accessToken":"SECRET-AT-1","refreshToken":"SECRET-RT-1","clientSecret":"SECRET-CS-1"}`
	for _, tc := range []struct {
		name  string
		setup func(f *fakeIdentityCenter)
		login bool
	}{
		{name: "registration", setup: func(f *fakeIdentityCenter) { f.registerErr = "InvalidClientMetadataException" }, login: true},
		{name: "refresh", setup: func(f *fakeIdentityCenter) {
			f.refreshErr, f.refreshStatus = "InternalServerException", 500
			f.seedToken(f.t, -time.Minute, "gen-1")
		}},
		{name: "role credentials", setup: func(f *fakeIdentityCenter) {
			f.roleErr, f.roleStatus = "TooManyRequestsException", 429
			f.seedToken(f.t, 8*time.Hour, "gen-1")
		}},
		{name: "unreadable success", setup: func(f *fakeIdentityCenter) {
			f.roleRawBody = `{"roleCredentials":` + secrets
			f.seedToken(f.t, 8*time.Hour, "gen-1")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			f := newFakeIdentityCenter(t)
			f.errorBody = secrets
			tc.setup(f)
			a := authTestApp()
			if tc.login {
				a = ssoTestApp(f)
			}
			_, _, err := a.awsCredentials(loginBudget(t), ssoTestConfig("sso-only"))
			if err == nil {
				t.Fatal("expected a failure")
			}
			out := err.Error() + a.stderr.(*bytes.Buffer).String()
			for _, s := range []string{"SECRET-AT-1", "SECRET-RT-1", "SECRET-CS-1", "seeded-refresh", "seeded-client-secret"} {
				if strings.Contains(out, s) {
					t.Fatalf("%q reached the output: %s", s, out)
				}
			}
			if !strings.Contains(err.Error(), "IAM Identity Center") {
				t.Fatalf("the failure should still say what failed: %v", err)
			}
		})
	}
}

func TestALockedStoreIsStoreLockedBeforeAnythingAboutTheToken(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("BMCP_BACKEND", "file")
	newFakeIdentityCenter(t)
	// A token file exists, so a reader that skipped the store would find one.
	if err := os.MkdirAll(os.Getenv("XDG_CONFIG_HOME")+"/bmcp/keys", 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(os.Getenv("XDG_CONFIG_HOME")+"/bmcp/keys/token-"+fixtureSessionKey()+".age", []byte(fileStoreHeader+"x"), 0o600)
	_, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only"))
	if err == nil || errorName(err) != errNameStoreLocked || !isCredentialFailure(err) {
		t.Fatalf("error %v named %q, want %s with exit 3", err, errorName(err), errNameStoreLocked)
	}
	if !strings.Contains(err.Error(), "BMCP_FILE_PASSPHRASE") || strings.Contains(err.Error(), "If the AWS SSO session") {
		t.Fatalf("a locked store should name its own remedy only: %v", err)
	}
}

func TestStoreLockedRemedyNamesTheProfileAndAFlaggedBackend(t *testing.T) {
	isolateAWSEnv(t)
	locked := &storeLockedError{Backend: backendKeychain, Reason: "user interaction is not allowed"}
	err := authTestApp().ssoFailure(ssoTestConfig("prod"), "prod", resolvedBackend{Name: backendKeychain, FromFlag: true}, locked)
	if !strings.HasPrefix(err.Error(), "credential store needs approval: run bmcp --profile prod --backend keychain login") {
		t.Fatalf("message %q", err.Error())
	}
	if errorName(err) != errNameStoreLocked {
		t.Fatalf("name %q", errorName(err))
	}
}

func TestGatewayRejectionEvictsOnlyTheRejectedCredentials(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	a := authTestApp()
	ctx, slot := withSSOIssuedSlot(authTestContext(t))
	if _, _, err := a.awsCredentials(ctx, ssoTestConfig("sso-only")); err != nil {
		t.Fatal(err)
	}
	iss := slot.take()
	if err := evictRejectedSSOCreds(authTestContext(t), iss); err != nil {
		t.Fatal(err)
	}
	if _, err := testSSOStore(t).ReadRoleCreds(iss.sessionKey, iss.credKey); !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("rejected credentials still cached: %v", err)
	}
	if _, ok := readStoredToken(t); !ok {
		t.Fatal("a gateway rejection touched the SSO token")
	}
	// A newer entry saved meanwhile by another process survives a late eviction.
	newer := iss.rec
	newer.AccessKeyID = "ASIA-NEWER"
	if err := testSSOStore(t).WriteRoleCreds(iss.sessionKey, iss.credKey, newer); err != nil {
		t.Fatal(err)
	}
	if err := evictRejectedSSOCreds(authTestContext(t), iss); err != nil {
		t.Fatal(err)
	}
	if got, err := testSSOStore(t).ReadRoleCreds(iss.sessionKey, iss.credKey); err != nil || got.AccessKeyID != "ASIA-NEWER" {
		t.Fatalf("a late eviction removed newer credentials: %+v %v", got, err)
	}
}

// serve runs requests concurrently in one process: a late rejection of an
// earlier request must not evict what a later request signed with.
func TestGatewayRejectionEvictsOnlyWhatThatRequestSignedWith(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	a := authTestApp()
	ctxA, slotA := withSSOIssuedSlot(authTestContext(t))
	if _, _, err := a.awsCredentials(ctxA, ssoTestConfig("sso-only")); err != nil {
		t.Fatal(err)
	}
	issA := slotA.take()
	newer := issA.rec
	newer.AccessKeyID = "ASIA-NEWER"
	if err := testSSOStore(t).WriteRoleCreds(issA.sessionKey, issA.credKey, newer); err != nil {
		t.Fatal(err)
	}
	ctxB, slotB := withSSOIssuedSlot(authTestContext(t))
	if creds, _, err := a.awsCredentials(ctxB, ssoTestConfig("sso-only")); err != nil || creds.AccessKeyID != "ASIA-NEWER" {
		t.Fatalf("request B: %q %v", creds.AccessKeyID, err)
	}
	if err := evictRejectedSSOCreds(authTestContext(t), issA); err != nil {
		t.Fatal(err)
	}
	if got, err := testSSOStore(t).ReadRoleCreds(issA.sessionKey, issA.credKey); err != nil || got.AccessKeyID != "ASIA-NEWER" {
		t.Fatalf("request A's rejection evicted request B's credentials: %+v %v", got, err)
	}
	if err := evictRejectedSSOCreds(authTestContext(t), slotB.take()); err != nil {
		t.Fatal(err)
	}
	if _, err := testSSOStore(t).ReadRoleCreds(issA.sessionKey, issA.credKey); !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("request B's rejection kept its credentials: %v", err)
	}
}

func TestStoreStatusProbe(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	seeded := f.seedToken(t, 2*time.Hour, "gen-1")
	st := authTestApp().ssoStoreStatus(authTestContext(t), ssoTestConfig("sso-only"))
	if st.Err != nil || st.Locked != nil || !st.HasToken || !st.Refreshable || !st.ExpiresAt.Equal(seeded.ExpiresAt.Truncate(time.Second)) {
		t.Fatalf("status %+v", st)
	}
	if st.Backend.Name != backendAWSCLICache || st.Session != fixtureStartURL || st.Profile != "sso-only" {
		t.Fatalf("status %+v", st)
	}
	if st := authTestApp().ssoStoreStatus(authTestContext(t), ssoTestConfig("has-static")); st.Profile != "" {
		t.Fatalf("a static profile reported an SSO status: %+v", st)
	}
}

func TestExplicitLoginShortCircuitsOnlyWhenItCan(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		isolateAWSEnv(t)
		f := newFakeIdentityCenter(t)
		f.seedToken(t, 8*time.Hour, "gen-1")
		res, err := ssoTestApp(f).ssoLogin(loginBudget(t), ssoTestConfig("sso-only"), "sso-only", false)
		if err != nil || !res.AlreadyValid {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("refreshable", func(t *testing.T) {
		isolateAWSEnv(t)
		f := newFakeIdentityCenter(t)
		f.seedToken(t, -time.Minute, "gen-1")
		res, err := ssoTestApp(f).ssoLogin(loginBudget(t), ssoTestConfig("sso-only"), "sso-only", false)
		if err != nil || !res.Refreshed {
			t.Fatalf("%+v %v", res, err)
		}
		if regs, _, _, _ := f.counts(); regs != 0 {
			t.Fatal("a refreshable token opened a browser")
		}
	})
	t.Run("expired and refresh rejected", func(t *testing.T) {
		isolateAWSEnv(t)
		f := newFakeIdentityCenter(t)
		f.refreshErr = "InvalidGrantException"
		f.seedToken(t, -time.Minute, "gen-1")
		a := ssoTestApp(f)
		res, err := a.ssoLogin(loginBudget(t), ssoTestConfig("sso-only"), "sso-only", false)
		if err != nil || res.AlreadyValid || res.Refreshed || !res.Refreshable {
			t.Fatalf("%+v %v", res, err)
		}
		if !strings.Contains(a.stderr.(*bytes.Buffer).String(), "A browser opens on this machine, and bmcp blocks until the login is approved") {
			t.Fatalf("the login was not announced: %s", a.stderr.(*bytes.Buffer).String())
		}
	})
	t.Run("device code announces a browser anywhere", func(t *testing.T) {
		isolateAWSEnv(t)
		f := newFakeIdentityCenter(t)
		a := ssoTestApp(f)
		if _, err := a.ssoLogin(loginBudget(t), ssoTestConfig("sso-only"), "sso-only", true); err != nil {
			t.Fatal(err)
		}
		got := a.stderr.(*bytes.Buffer).String()
		if !strings.Contains(got, "Approve the login in a browser on any machine, and bmcp blocks until the login is approved") ||
			strings.Contains(got, "on this machine") {
			t.Fatalf("device-code announcement: %s", got)
		}
	})
}

func TestClearRemovesTheSessionAndClearAllEverything(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	a := authTestApp()
	ctx, slot := withSSOIssuedSlot(authTestContext(t))
	if _, _, err := a.awsCredentials(ctx, ssoTestConfig("sso-only")); err != nil {
		t.Fatal(err)
	}
	iss := slot.take()
	out, err := a.ssoClear(authTestContext(t), ssoTestConfig("sso-only"), "sso-only", false)
	if err != nil || !out.SharedWithAWSCLI || len(out.Sessions) != 1 {
		t.Fatalf("%+v %v", out, err)
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("token survived clear")
	}
	if _, err := testSSOStore(t).ReadRoleCreds(iss.sessionKey, iss.credKey); !errors.Is(err, errStoreItemNotFound) {
		t.Fatal("role credentials survived clear")
	}

	f.seedToken(t, 8*time.Hour, "gen-2")
	if _, _, err := a.awsCredentials(authTestContext(t), ssoTestConfig("sso-only")); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ssoClearAll(authTestContext(t), ssoTestConfig("sso-only"), false); err != nil {
		t.Fatal(err)
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("token survived clear --all")
	}
	if dir, _ := bmcpCacheDir(); dirExists(dir + "/creds") {
		t.Fatal("role-credential directory survived clear --all")
	}
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// --- Multi-process: the lock and the login marker are between processes. ---

const ssoHelperEnv = "BMCP_SSO_TEST_HELPER"

// TestSSOHelperProcess is not a test: it is the body of the subprocesses the
// tests below start, selected by ssoHelperEnv. It prints one JSON line.
func TestSSOHelperProcess(t *testing.T) {
	mode := os.Getenv(ssoHelperEnv)
	if mode == "" {
		return
	}
	budget, _ := time.ParseDuration(os.Getenv("BMCP_SSO_TEST_BUDGET"))
	a := &app{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard, now: time.Now}
	a.machine = mode == "machine"
	a.interactive = func() bool { return mode == "interactive" }
	a.openURL = func(u string) error {
		go func() {
			if resp, err := http.Get(u); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	creds, _, err := a.awsCredentials(ctx, ssoTestConfig("sso-only"))
	out := map[string]string{"akid": creds.AccessKeyID}
	if err != nil {
		out["error"], out["name"] = err.Error(), errorName(err)
	}
	json.NewEncoder(os.Stdout).Encode(out)
	os.Exit(0)
}

type ssoHelper struct {
	cmd *exec.Cmd
	out bytes.Buffer
}

func startSSOHelper(t *testing.T, mode string, budget time.Duration) *ssoHelper {
	t.Helper()
	h := &ssoHelper{cmd: exec.Command(os.Args[0], "-test.run=^TestSSOHelperProcess$")}
	h.cmd.Env = append(os.Environ(), ssoHelperEnv+"="+mode, "BMCP_SSO_TEST_BUDGET="+budget.String())
	h.cmd.Stdout, h.cmd.Stderr = &h.out, os.Stderr
	if err := h.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if h.cmd.ProcessState == nil {
			h.cmd.Process.Kill()
			h.cmd.Wait()
		}
	})
	return h
}

func (h *ssoHelper) result(t *testing.T) map[string]string {
	t.Helper()
	if err := h.cmd.Wait(); err != nil {
		t.Fatalf("helper: %v; output %s", err, h.out.String())
	}
	var out map[string]string
	if err := json.Unmarshal(h.out.Bytes(), &out); err != nil {
		t.Fatalf("helper output %q: %v", h.out.String(), err)
	}
	return out
}

func waitForLoginMarker(t *testing.T) *loginMarker {
	t.Helper()
	locks, err := newCredLocks()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if m, _ := locks.PeekLoginMarker(fixtureSessionKey(), time.Now()); m != nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no login marker appeared")
	return nil
}

func TestParallelRetrievalsStartOneBrowserLogin(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.mu.Lock()
	f.authorizeWait = 2 * time.Second
	f.mu.Unlock()
	var helpers []*ssoHelper
	for i := 0; i < 4; i++ {
		helpers = append(helpers, startSSOHelper(t, "interactive", 10*time.Minute))
	}
	for i, h := range helpers {
		if out := h.result(t); out["error"] != "" || !strings.HasPrefix(out["akid"], "ASIA-SSO-") {
			t.Fatalf("helper %d: %v", i, out)
		}
	}
	if regs, authorizes, _, _ := f.counts(); regs != 1 || authorizes != 1 {
		t.Fatalf("registrations %d, browser tabs %d; want one login for four processes", regs, authorizes)
	}
}

func TestAShortBudgetWaiterGetsLoginInProgress(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.gate()
	login := startSSOHelper(t, "interactive", 10*time.Minute)
	m := waitForLoginMarker(t)
	waiter := startSSOHelper(t, "machine", 90*time.Second).result(t)
	if waiter["name"] != errNameLoginInProgress || !strings.Contains(waiter["error"], "pid "+strconv.Itoa(m.PID)) ||
		!strings.Contains(waiter["error"], "profile sso-only") {
		t.Fatalf("waiter %v", waiter)
	}
	f.release()
	if out := login.result(t); out["error"] != "" {
		t.Fatalf("login %v", out)
	}
}

func TestConcurrentRefreshesRedeemTheRefreshTokenOnce(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.mu.Lock()
	f.rotate, f.refreshDelay = true, 300*time.Millisecond
	f.mu.Unlock()
	f.seedToken(t, 5*time.Minute, "gen-1")
	var helpers []*ssoHelper
	for i := 0; i < 3; i++ {
		helpers = append(helpers, startSSOHelper(t, "machine", time.Minute))
	}
	for i, h := range helpers {
		if out := h.result(t); out["error"] != "" {
			t.Fatalf("helper %d: %v", i, out)
		}
	}
	if _, _, _, g := f.counts(); g[grantRefreshToken] != 1 {
		t.Fatalf("refresh grants %d, want 1: a single-use refresh token was redeemed twice", g[grantRefreshToken])
	}
}

func TestARefreshQueuedBehindClearDoesNotRestoreTheToken(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 5*time.Minute, "gen-1")
	locks, err := newCredLocks()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := locks.lockSession(authTestContext(t), fixtureSessionKey())
	if err != nil {
		t.Fatal(err)
	}
	h := startSSOHelper(t, "machine", time.Minute)
	time.Sleep(time.Second)
	if err := lock.clearSession(testSSOStore(t)); err != nil {
		t.Fatal(err)
	}
	lock.Unlock()
	h.result(t)
	if _, _, _, g := f.counts(); g[grantRefreshToken] != 0 {
		t.Fatal("a refresh ran after clear")
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("clear was undone")
	}
}

func TestClearDuringABrowserLoginDiscardsItsResult(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.gate()
	login := startSSOHelper(t, "interactive", 10*time.Minute)
	waitForLoginMarker(t)
	if _, err := authTestApp().ssoClear(authTestContext(t), ssoTestConfig("sso-only"), "sso-only", false); err != nil {
		t.Fatal(err)
	}
	f.release()
	out := login.result(t)
	if !strings.Contains(out["error"], "discarded") {
		t.Fatalf("login %v should report its discarded result", out)
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("a login raced by clear saved its token")
	}
}

// scriptedStore wraps a real store and fails chosen operations, putting it in
// states no real backend reaches on demand. ops records the mutation order.
type scriptedStore struct {
	credStore
	mu sync.Mutex
	// tokenReadErrFrom fails every token read from that read on (1-based).
	tokenReadErrFrom int
	tokenReadErr     error
	tokenReads       int
	deleteErr        error
	ops              []string
}

func (s *scriptedStore) ReadToken(key string) (ssoTokenRecord, error) {
	s.mu.Lock()
	s.tokenReads++
	fail := s.tokenReadErrFrom > 0 && s.tokenReads >= s.tokenReadErrFrom
	s.mu.Unlock()
	if fail {
		return ssoTokenRecord{}, s.tokenReadErr
	}
	return s.credStore.ReadToken(key)
}

func (s *scriptedStore) record(op string) {
	s.mu.Lock()
	s.ops = append(s.ops, op)
	s.mu.Unlock()
}

func (s *scriptedStore) WriteToken(key string, rec ssoTokenRecord) error {
	s.record("write-token")
	return s.credStore.WriteToken(key, rec)
}

func (s *scriptedStore) DeleteToken(key string) error {
	s.record("delete-token")
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.credStore.DeleteToken(key)
}

func (s *scriptedStore) DeleteSessionRoleCreds(key string) error {
	s.record("delete-role-creds")
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.credStore.DeleteSessionRoleCreds(key)
}

func useScriptedStore(a *app, s *scriptedStore) {
	a.openStore = func(b resolvedBackend, o storeOptions) (credStore, error) {
		inner, err := openCredStore(b, o)
		s.credStore = inner
		return s, err
	}
}

func TestPKCECallbackListenerIsClosedBeforeTheCodeIsRedeemed(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	if _, _, err := ssoTestApp(f).awsCredentials(loginBudget(t), ssoTestConfig("sso-only")); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	open := f.callbackOpenAtExchange
	f.mu.Unlock()
	if open {
		t.Fatal("the callback listener still accepted connections while the code was redeemed")
	}
}

// With no profile named and no environment credentials, the SDK reads
// "default"; an SSO default must go through bmcp's store, not the CLI cache.
func TestAnSSODefaultProfileResolvesNatively(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[default]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = ExampleRole
region = us-east-1
`)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	cfg := effectiveConfig{Region: "us-east-1"}
	ctx, slot := withSSOIssuedSlot(authTestContext(t))
	creds, _, err := authTestApp().awsCredentials(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if iss := slot.take(); iss == nil || !strings.HasPrefix(creds.AccessKeyID, "ASIA-SSO-") {
		t.Fatalf("credentials %q, issued %v: the default SSO profile bypassed the native path", creds.AccessKeyID, iss)
	}
	if st := authTestApp().ssoStoreStatus(authTestContext(t), cfg); st.Profile != "default" || !st.HasToken {
		t.Fatalf("doctor should report the default profile's store: %+v", st)
	}
	setEnvCredentials(t)
	if p := authTestApp().ssoProfileFor(authTestContext(t), cfg); p != "" {
		t.Fatalf("environment credentials outrank the default profile, got %q", p)
	}
}

// Decision 12: an unreadable store is store_locked, never "no token, log in".
func TestAnUnreadableTokenFileIsStoreLockedNotALogin(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file")
	}
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "gen-1")
	home, _ := os.UserHomeDir()
	path := home + "/.aws/sso/cache/" + fixtureSessionKey() + ".json"
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	_, _, err := ssoTestApp(f).awsCredentials(loginBudget(t), ssoTestConfig("sso-only"))
	if errorName(err) != errNameStoreLocked {
		t.Fatalf("error %v named %q, want %s", err, errorName(err), errNameStoreLocked)
	}
	if regs, _, _, _ := f.counts(); regs != 0 {
		t.Fatal("an unreadable store started a browser login")
	}
}

// Decision 8's fallback is for a failed refresh, not for a store that turned
// unreadable under the lock.
func TestALockedStoreDuringRefreshIsNotMaskedByTheOldToken(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 10*time.Minute, "gen-1")
	a := authTestApp()
	useScriptedStore(a, &scriptedStore{tokenReadErrFrom: 2,
		tokenReadErr: &storeLockedError{Backend: backendKeychain, Reason: "user interaction is not allowed"}})
	_, _, err := a.awsCredentials(authTestContext(t), ssoTestConfig("sso-only"))
	if errorName(err) != errNameStoreLocked {
		t.Fatalf("error %v named %q, want %s", err, errorName(err), errNameStoreLocked)
	}
}

// The AWS CLI writes tokens with no bmcp generation; one is stamped on first
// use so role credentials minted from it can be cached.
func TestACLIWrittenTokenIsStampedSoRoleCredentialsCache(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.seedToken(t, 8*time.Hour, "")
	for i := 0; i < 2; i++ {
		if _, _, err := authTestApp().awsCredentials(authTestContext(t), ssoTestConfig("sso-only")); err != nil {
			t.Fatal(err)
		}
	}
	if tok, _ := readStoredToken(t); tok.Generation == "" {
		t.Fatal("the CLI-written token was not stamped")
	}
	if _, _, roleCalls, _ := f.counts(); roleCalls != 1 {
		t.Fatalf("GetRoleCredentials ran %d times; the second call should have used the cache", roleCalls)
	}
}

// A lock-free reader that sees the new token must not find role credentials
// the old one minted, so they go before the token is written.
func TestANewTokenDropsRoleCredentialsBeforeItIsWritten(t *testing.T) {
	isolateAWSEnv(t)
	locks, err := newCredLocks()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := locks.lockSession(authTestContext(t), fixtureSessionKey())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	s := &scriptedStore{credStore: testSSOStore(t)}
	if _, err := lock.saveNewToken(s, sampleToken("")); err != nil {
		t.Fatal(err)
	}
	if err := lock.clearSession(s); err != nil {
		t.Fatal(err)
	}
	want := []string{"delete-role-creds", "write-token", "delete-role-creds", "delete-token"}
	if !reflect.DeepEqual(s.ops, want) {
		t.Fatalf("store operations %v, want %v", s.ops, want)
	}
}

// A marker that cannot be read may hide a `bmcp clear`, so the login fails
// closed rather than saving a token clear meant to discard.
func TestAnUnreadableLoginMarkerDiscardsTheLogin(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.gate()
	login := startSSOHelper(t, "interactive", 10*time.Minute)
	waitForLoginMarker(t)
	locks, _ := newCredLocks()
	path := locks.markerPath(fixtureSessionKey())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	f.release()
	if out := login.result(t); !strings.Contains(out["error"], "could not confirm") {
		t.Fatalf("login %v should fail closed on an unreadable marker", out)
	}
	if _, ok := readStoredToken(t); ok {
		t.Fatal("a login that could not read its marker saved its token")
	}
}

// A login that cannot re-take the lock still removes its marker, or every
// other process reports sso_login_in_progress for up to 15 minutes.
func TestALoginThatCannotRelockStillRemovesItsMarker(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a 0000 file")
	}
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.gate()
	login := startSSOHelper(t, "interactive", 10*time.Minute)
	waitForLoginMarker(t)
	locks, _ := newCredLocks()
	global := locks.dir + "/global.lock"
	if err := os.Chmod(global, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(global, 0o600) })
	f.release()
	if out := login.result(t); out["error"] != "" {
		t.Fatalf("login %v: an approved login should still serve this call", out)
	}
	if _, err := os.Stat(locks.markerPath(fixtureSessionKey())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the login marker survived: %v", err)
	}
}

func TestExplicitLoginReportsAFailedRefreshOfAStillValidToken(t *testing.T) {
	isolateAWSEnv(t)
	f := newFakeIdentityCenter(t)
	f.refreshErr, f.refreshStatus = "InternalServerException", 500
	f.seedToken(t, 10*time.Minute, "gen-1")
	res, err := ssoTestApp(f).ssoLogin(loginBudget(t), ssoTestConfig("sso-only"), "sso-only", false)
	if err != nil || !res.AlreadyValid || res.RefreshErr == nil {
		t.Fatalf("%+v %v: want an already-valid session with its refresh failure", res, err)
	}
	if regs, _, _, _ := f.counts(); regs != 0 {
		t.Fatal("a still-valid token opened a browser")
	}
}
