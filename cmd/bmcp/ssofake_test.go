package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
)

// fakeIdentityCenter is IAM Identity Center's OIDC and portal APIs plus STS
// AssumeRole, on one httptest server the SDK clients reach through the
// standard AWS_ENDPOINT_URL_* variables. Subprocess tests share it over HTTP,
// so every counter here counts across processes.
type fakeIdentityCenter struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	registrations []map[string]any
	authorizes    int
	grants        map[string]int
	roleCalls     int
	stsCalls      []url.Values
	stsSigners    []string

	accessTTL     time.Duration
	issueRefresh  bool
	rotate        bool
	refreshErr    string
	refreshStatus int
	refreshDelay  time.Duration
	deviceSteps   []string
	authorizeErr  string
	authorizeWait time.Duration
	authorizeGate chan struct{}
	registerErr   string
	roleErr       string
	roleStatus    int
	roleRawBody   string
	rejectAccess  map[string]bool
	// callbackOpenAtExchange records a PKCE callback listener still accepting
	// connections when its code was redeemed.
	callbackOpenAtExchange bool
	// errorBody rides on every error response, so a test can plant secrets in
	// what the service says and look for them in what bmcp says.
	errorBody string

	seq       int
	access    map[string]bool
	refresh   map[string]bool
	challenge map[string]string
}

const fakeDeviceCode = "device-code-secret-value"

func newFakeIdentityCenter(t *testing.T) *fakeIdentityCenter {
	t.Helper()
	f := &fakeIdentityCenter{
		t: t, accessTTL: 8 * time.Hour, issueRefresh: true, refreshStatus: 400, roleStatus: 400,
		grants: map[string]int{}, rejectAccess: map[string]bool{},
		access: map[string]bool{}, refresh: map[string]bool{}, challenge: map[string]string{},
		errorBody: "the request was refused",
	}
	f.srv = httptest.NewServer(f)
	t.Cleanup(func() {
		f.release()
		f.srv.Close()
	})
	for _, name := range []string{"AWS_ENDPOINT_URL_SSO_OIDC", "AWS_ENDPOINT_URL_SSO", "AWS_ENDPOINT_URL_STS"} {
		t.Setenv(name, f.srv.URL)
	}
	return f
}

// gate makes /authorize wait until release, so a test can act while a browser
// login is in flight.
func (f *fakeIdentityCenter) gate() {
	f.mu.Lock()
	f.authorizeGate = make(chan struct{})
	f.mu.Unlock()
}

func (f *fakeIdentityCenter) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.authorizeGate != nil {
		close(f.authorizeGate)
		f.authorizeGate = nil
	}
}

// browser is the operator's browser: it follows the authorize URL, whose
// redirect lands on bmcp's loopback callback.
func (f *fakeIdentityCenter) browser(u string) error {
	go func() {
		resp, err := http.Get(u)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	return nil
}

func (f *fakeIdentityCenter) counts() (registrations, authorizes, roleCalls int, grants map[string]int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := map[string]int{}
	for k, v := range f.grants {
		g[k] = v
	}
	return len(f.registrations), f.authorizes, f.roleCalls, g
}

// seedToken stores a token this fake will honour, as a login would have.
func (f *fakeIdentityCenter) seedToken(t *testing.T, expiresIn time.Duration, generation string) ssoTokenRecord {
	t.Helper()
	f.mu.Lock()
	f.seq++
	at, rt := fmt.Sprintf("seeded-access-%d", f.seq), fmt.Sprintf("seeded-refresh-%d", f.seq)
	f.access[at], f.refresh[rt] = true, true
	f.mu.Unlock()
	rec := ssoTokenRecord{
		StartURL: fixtureStartURL, Region: "us-east-1", AccessToken: at,
		ExpiresAt: time.Now().Add(expiresIn).UTC(), ClientID: "seeded-client", ClientSecret: "seeded-client-secret",
		RegistrationExpiresAt: time.Now().Add(90 * 24 * time.Hour).UTC(), RefreshToken: rt,
		Scopes: []string{defaultSSORegistrationScope}, Generation: generation,
	}
	if err := testSSOStore(t).WriteToken(fixtureSessionKey(), rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func fixtureSessionKey() string { return ssoSessionStoreKey("", fixtureStartURL) }

func testSSOStore(t *testing.T) credStore {
	t.Helper()
	s, err := newAWSCLICacheStore()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fakeIdentityCenter) fail(w http.ResponseWriter, status int, typ string) {
	w.Header().Set("X-Amzn-ErrorType", typ)
	w.Header().Set("X-Amzn-Requestid", "req-fake-1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(map[string]string{"error": "refused", "error_description": f.errorBody, "message": f.errorBody})
	w.Write(b)
}

func (f *fakeIdentityCenter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/client/register":
		f.register(w, body)
	case r.URL.Path == "/authorize":
		f.authorize(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/device_authorization":
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"deviceCode":%q,"userCode":"ABCD-EFGH","verificationUri":"%s/device","verificationUriComplete":"%s/device?user_code=ABCD-EFGH","expiresIn":600,"interval":1}`,
			fakeDeviceCode, f.srv.URL, f.srv.URL)
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		f.token(w, body)
	case r.Method == http.MethodGet && r.URL.Path == "/federation/credentials":
		f.roleCredentials(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/":
		f.assumeRole(w, r, body)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIdentityCenter) register(w http.ResponseWriter, body []byte) {
	var in map[string]any
	json.Unmarshal(body, &in)
	f.mu.Lock()
	f.registrations = append(f.registrations, in)
	n, errType := len(f.registrations), f.registerErr
	f.mu.Unlock()
	if errType != "" {
		f.fail(w, 400, errType)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"clientId":"client-%d","clientSecret":"client-secret-%d","clientIdIssuedAt":%d,"clientSecretExpiresAt":%d}`,
		n, n, time.Now().Unix(), time.Now().Add(90*24*time.Hour).Unix())
}

func (f *fakeIdentityCenter) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	f.authorizes++
	f.seq++
	code := fmt.Sprintf("authcode-%d", f.seq)
	f.challenge[code] = q.Get("code_challenge") + " " + q.Get("redirect_uri")
	gate, wait, errCode := f.authorizeGate, f.authorizeWait, f.authorizeErr
	f.mu.Unlock()
	time.Sleep(wait)
	if gate != nil {
		select {
		case <-gate:
		case <-time.After(60 * time.Second):
		}
	}
	back := url.Values{"state": {q.Get("state")}}
	if errCode != "" {
		back.Set("error", errCode)
		back.Set("error_description", f.errorBody)
	} else {
		back.Set("code", code)
	}
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+back.Encode(), http.StatusFound)
}

func (f *fakeIdentityCenter) token(w http.ResponseWriter, body []byte) {
	var in struct {
		GrantType, Code, CodeVerifier, RedirectURI, RefreshToken, DeviceCode string
	}
	var raw map[string]string
	json.Unmarshal(body, &raw)
	in.GrantType, in.Code, in.CodeVerifier = raw["grantType"], raw["code"], raw["codeVerifier"]
	in.RedirectURI, in.RefreshToken, in.DeviceCode = raw["redirectUri"], raw["refreshToken"], raw["deviceCode"]

	if in.GrantType == grantAuthCode {
		if u, err := url.Parse(in.RedirectURI); err == nil {
			if c, err := net.DialTimeout("tcp", u.Host, time.Second); err == nil {
				c.Close()
				f.mu.Lock()
				f.callbackOpenAtExchange = true
				f.mu.Unlock()
			}
		}
	}
	f.mu.Lock()
	f.grants[in.GrantType]++
	delay := time.Duration(0)
	if in.GrantType == grantRefreshToken {
		delay = f.refreshDelay
	}
	f.mu.Unlock()
	time.Sleep(delay)

	f.mu.Lock()
	defer f.mu.Unlock()
	switch in.GrantType {
	case grantAuthCode:
		sum := sha256.Sum256([]byte(in.CodeVerifier))
		want := base64.RawURLEncoding.EncodeToString(sum[:]) + " " + in.RedirectURI
		if f.challenge[in.Code] != want {
			f.fail(w, 400, "InvalidGrantException")
			return
		}
		delete(f.challenge, in.Code)
	case grantDeviceCode:
		if in.DeviceCode != fakeDeviceCode {
			f.fail(w, 400, "InvalidGrantException")
			return
		}
		if len(f.deviceSteps) > 0 {
			step := f.deviceSteps[0]
			f.deviceSteps = f.deviceSteps[1:]
			f.fail(w, 400, step)
			return
		}
	case grantRefreshToken:
		if f.refreshErr != "" {
			f.fail(w, f.refreshStatus, f.refreshErr)
			return
		}
		if !f.refresh[in.RefreshToken] {
			f.fail(w, 400, "InvalidGrantException")
			return
		}
		if f.rotate {
			delete(f.refresh, in.RefreshToken)
		} else {
			f.issueLocked(w, in.RefreshToken)
			return
		}
	default:
		f.fail(w, 400, "UnsupportedGrantTypeException")
		return
	}
	f.issueLocked(w, "")
}

func (f *fakeIdentityCenter) issueLocked(w http.ResponseWriter, keepRefresh string) {
	f.seq++
	at := fmt.Sprintf("access-%d", f.seq)
	f.access[at] = true
	out := map[string]any{"accessToken": at, "expiresIn": int(f.accessTTL / time.Second), "tokenType": "Bearer"}
	switch {
	case keepRefresh != "":
	case f.issueRefresh:
		rt := fmt.Sprintf("refresh-%d", f.seq)
		f.refresh[rt] = true
		out["refreshToken"] = rt
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (f *fakeIdentityCenter) roleCredentials(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Amz-Sso_bearer_token")
	f.mu.Lock()
	f.roleCalls++
	f.seq++
	n, ok := f.seq, f.access[tok] && !f.rejectAccess[tok]
	errType, status, raw := f.roleErr, f.roleStatus, f.roleRawBody
	f.mu.Unlock()
	switch {
	case raw != "":
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, raw)
		return
	case errType != "":
		f.fail(w, status, errType)
		return
	case !ok:
		f.fail(w, 401, "UnauthorizedException")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"roleCredentials":{"accessKeyId":"ASIA-SSO-%s-%d","secretAccessKey":"sso-secret","sessionToken":"sso-session","expiration":%d}}`,
		r.URL.Query().Get("role_name"), n, time.Now().Add(time.Hour).UnixMilli())
}

func (f *fakeIdentityCenter) assumeRole(w http.ResponseWriter, r *http.Request, body []byte) {
	form, _ := url.ParseQuery(string(body))
	signer := ""
	if _, after, ok := strings.Cut(r.Header.Get("Authorization"), "Credential="); ok {
		signer, _, _ = strings.Cut(after, "/")
	}
	f.mu.Lock()
	f.stsCalls = append(f.stsCalls, form)
	f.stsSigners = append(f.stsSigners, signer)
	n := len(f.stsCalls)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>ASIA-HOP-%d</AccessKeyId><SecretAccessKey>hop-secret</SecretAccessKey><SessionToken>hop-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/x/y</Arn><AssumedRoleId>AROA:y</AssumedRoleId></AssumedRoleUser></AssumeRoleResult><ResponseMetadata><RequestId>sts-req</RequestId></ResponseMetadata></AssumeRoleResponse>`,
		n, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
}

// fakeOIDCClient is an OIDC client the way bmcp builds one, aimed at the fake.
func fakeOIDCClient(t *testing.T) *ssooidc.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	return ssooidc.NewFromConfig(cfg)
}
