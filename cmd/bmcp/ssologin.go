package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/aws/smithy-go"
)

// ssoSession is the IAM Identity Center session a leaf profile logs in to,
// plus the account and role it asks for.
type ssoSession struct {
	// Profile is the leaf profile, where the SSO settings live.
	Profile string
	// Name is the sso_session name, empty for the legacy sso_start_url form.
	Name      string
	StartURL  string
	Region    string
	Scopes    []string
	AccountID string
	RoleName  string
}

func (s ssoSession) storeKey() string { return ssoSessionStoreKey(s.Name, s.StartURL) }

// scopes is what a login registers for. sso:account:access by default, so a
// legacy profile gets a refresh token too, which the AWS CLI never asks for.
func (s ssoSession) scopes() []string {
	if len(s.Scopes) > 0 {
		return s.Scopes
	}
	return []string{defaultSSORegistrationScope}
}

const (
	ssoClientName     = "bmcp"
	grantAuthCode     = "authorization_code"
	grantRefreshToken = "refresh_token"
	grantDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	// The registered redirect carries no port: loopback redirects may use any
	// port (RFC 8252 section 7.3), and the listener's is random.
	ssoRedirectURI  = "http://127.0.0.1/oauth/callback"
	ssoCallbackPath = "/oauth/callback"
	// pkceSignInTimeout matches the AWS CLI's own wait for the browser.
	pkceSignInTimeout = 10 * time.Minute
)

// ssoFlowChoice decides between PKCE and device code. Device code is for
// browsers that cannot reach this machine's loopback: SSH sessions, or the
// operator saying so.
func ssoFlowChoice(cfg effectiveConfig, explicitDeviceCode bool) (deviceCode bool, reason string, err error) {
	flow, err := cfg.ssoFlow()
	if err != nil {
		return false, "", err
	}
	switch {
	case explicitDeviceCode:
		return true, "--device-code", nil
	case flow == ssoFlowDeviceCode && strings.TrimSpace(cfg.SSODeviceCodeEnv) != "":
		return true, "BMCP_SSO_DEVICE_CODE", nil
	case flow == ssoFlowDeviceCode:
		return true, "sso_flow in config.toml", nil
	case flow == ssoFlowPKCE:
		// An explicit pkce outranks SSH detection: the operator may forward the port.
		return false, "", nil
	case inSSHSession():
		return true, "an SSH session", nil
	}
	return false, "", nil
}

func inSSHSession() bool {
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}

// ssoLoginer runs one interactive IAM Identity Center login.
type ssoLoginer struct {
	oidc *ssooidc.Client
	sess ssoSession
	// out is where the URL and user code go: bmcp's startup stderr, the
	// descriptor `aws sso login` used to be handed for the same purpose.
	out     io.Writer
	openURL func(string) error
	now     func() time.Time
	// sleep waits between device-code polls; tests replace it.
	sleep func(context.Context, time.Duration) error
}

// login registers a fresh OIDC client and runs the chosen flow. The result
// has no generation: saveNewToken stamps one when it is stored.
func (l *ssoLoginer) login(ctx context.Context, deviceCode bool) (ssoTokenRecord, error) {
	if deviceCode {
		return l.deviceCodeLogin(ctx)
	}
	return l.pkceLogin(ctx)
}

func (l *ssoLoginer) register(ctx context.Context, pkce bool) (*ssooidc.RegisterClientOutput, error) {
	in := &ssooidc.RegisterClientInput{
		ClientName: aws.String(ssoClientName),
		ClientType: aws.String("public"),
		Scopes:     l.sess.scopes(),
	}
	if pkce {
		in.GrantTypes = []string{grantAuthCode, grantRefreshToken}
		in.RedirectUris = []string{ssoRedirectURI}
		in.IssuerUrl = aws.String(l.sess.StartURL)
	}
	out, err := l.oidc.RegisterClient(ctx, in)
	if err != nil {
		return nil, withholdSSOError("RegisterClient", err)
	}
	return out, nil
}

func (l *ssoLoginer) record(reg *ssooidc.RegisterClientOutput, tok *ssooidc.CreateTokenOutput) (ssoTokenRecord, error) {
	if aws.ToString(tok.AccessToken) == "" {
		return ssoTokenRecord{}, errors.New("IAM Identity Center returned no access token")
	}
	rec := ssoTokenRecord{
		StartURL:     l.sess.StartURL,
		Region:       l.sess.Region,
		AccessToken:  aws.ToString(tok.AccessToken),
		ExpiresAt:    l.now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC(),
		ClientID:     aws.ToString(reg.ClientId),
		ClientSecret: aws.ToString(reg.ClientSecret),
		RefreshToken: aws.ToString(tok.RefreshToken),
		Scopes:       l.sess.scopes(),
	}
	if reg.ClientSecretExpiresAt > 0 {
		rec.RegistrationExpiresAt = time.Unix(reg.ClientSecretExpiresAt, 0).UTC()
	}
	return rec, nil
}

// pkceLogin is the authorization code flow with PKCE (RFC 7636), the AWS
// CLI's default since 2.22: one browser click, no code to compare.
func (l *ssoLoginer) pkceLogin(ctx context.Context) (ssoTokenRecord, error) {
	reg, err := l.register(ctx, true)
	if err != nil {
		return ssoTokenRecord{}, err
	}
	verifier, err := randomURLSafe(32)
	if err != nil {
		return ssoTokenRecord{}, err
	}
	challenge := sha256.Sum256([]byte(verifier))
	srv, err := newSSOCallbackServer(ctx)
	if err != nil {
		return ssoTokenRecord{}, err
	}
	defer srv.shutdown()
	authorize, err := l.authorizeURL(ctx)
	if err != nil {
		return ssoTokenRecord{}, err
	}
	redirect := srv.redirectURI()
	authorize.RawQuery = url.Values{
		"client_id":             {aws.ToString(reg.ClientId)},
		"response_type":         {"code"},
		"redirect_uri":          {redirect},
		"state":                 {srv.state},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"scopes":                {strings.Join(l.sess.scopes(), " ")},
	}.Encode()
	fmt.Fprintf(l.out, "Approve the AWS SSO login for profile %s in your browser. If it does not open, visit:\n%s\n", l.sess.Profile, authorize.String())
	l.open(authorize.String())

	wait, cancel := context.WithTimeout(ctx, pkceSignInTimeout)
	defer cancel()
	var res ssoCallbackResult
	select {
	case res = <-srv.results:
	case <-wait.Done():
		return ssoTokenRecord{}, fmt.Errorf("the browser login was not approved in time: %w", wait.Err())
	}
	// Decision 7: the listener goes with the first valid callback, before the
	// code is redeemed, so nothing else can reach it meanwhile.
	srv.shutdown()
	if res.err != nil {
		return ssoTokenRecord{}, res.err
	}
	tok, err := l.oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		GrantType:    aws.String(grantAuthCode),
		Code:         aws.String(res.code),
		CodeVerifier: aws.String(verifier),
		RedirectUri:  aws.String(redirect),
	})
	if err != nil {
		return ssoTokenRecord{}, withholdSSOError("CreateToken", err)
	}
	return l.record(reg, tok)
}

// deviceCodeLogin is RFC 8628: the browser can be on another machine, at the
// cost of the operator comparing a code.
func (l *ssoLoginer) deviceCodeLogin(ctx context.Context) (ssoTokenRecord, error) {
	reg, err := l.register(ctx, false)
	if err != nil {
		return ssoTokenRecord{}, err
	}
	dev, err := l.oidc.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     aws.String(l.sess.StartURL),
	})
	if err != nil {
		return ssoTokenRecord{}, withholdSSOError("StartDeviceAuthorization", err)
	}
	// The user code is meant to be read by the operator; the device code is
	// the secret and is never printed.
	verify := firstNonEmpty(aws.ToString(dev.VerificationUriComplete), aws.ToString(dev.VerificationUri))
	fmt.Fprintf(l.out, "Approve the AWS SSO login for profile %s in a browser. If it does not open, visit:\n%s\nand check that it shows the code: %s\n", l.sess.Profile, verify, aws.ToString(dev.UserCode))
	l.open(verify)

	interval := 5 * time.Second
	if dev.Interval > 0 {
		interval = time.Duration(dev.Interval) * time.Second
	}
	var expiresAt time.Time
	if dev.ExpiresIn > 0 {
		lifetime := time.Duration(dev.ExpiresIn) * time.Second
		expiresAt = l.now().Add(lifetime)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lifetime)
		defer cancel()
	}
	timedOut := errors.New("the device login was not approved in time")
	for {
		if err := l.sleep(ctx, interval); err != nil {
			return ssoTokenRecord{}, fmt.Errorf("%w: %w", timedOut, err)
		}
		tok, err := l.oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    aws.String(grantDeviceCode),
			DeviceCode:   dev.DeviceCode,
		})
		if err == nil {
			return l.record(reg, tok)
		}
		var pending *ssooidctypes.AuthorizationPendingException
		var slow *ssooidctypes.SlowDownException
		var expired *ssooidctypes.ExpiredTokenException
		var invalid *ssooidctypes.InvalidGrantException
		switch {
		case errors.As(err, &pending):
		case errors.As(err, &slow):
			// RFC 8628 section 3.5: every slow_down adds five seconds for good.
			interval += 5 * time.Second
		case ctx.Err() != nil:
			return ssoTokenRecord{}, fmt.Errorf("%w: %w", timedOut, ctx.Err())
		case errors.As(err, &expired):
			return ssoTokenRecord{}, fmt.Errorf("%w: %w", timedOut, withholdSSOError("CreateToken", err))
		case errors.As(err, &invalid):
			// The poll that outlives the code races our own deadline, and IAM
			// Identity Center answers it with invalid_grant, not expired_token.
			if !expiresAt.IsZero() && !l.now().Before(expiresAt.Add(-interval)) {
				return ssoTokenRecord{}, fmt.Errorf("%w: %w", timedOut, withholdSSOError("CreateToken", err))
			}
			return ssoTokenRecord{}, fmt.Errorf("the device login was denied or the code is no longer valid: %w", withholdSSOError("CreateToken", err))
		default:
			return ssoTokenRecord{}, withholdSSOError("CreateToken", err)
		}
	}
}

func (l *ssoLoginer) open(u string) {
	if l.openURL != nil {
		_ = l.openURL(u)
	}
}

// authorizeURL derives /authorize, which is not a modelled operation, from the
// client's resolved endpoint, as the AWS CLI and aws-vault do, so partitions
// and endpoint overrides apply to it too.
func (l *ssoLoginer) authorizeURL(ctx context.Context) (*url.URL, error) {
	o := l.oidc.Options()
	e, err := o.EndpointResolverV2.ResolveEndpoint(ctx, ssooidc.EndpointParameters{
		Region:   aws.String(o.Region),
		Endpoint: o.BaseEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("resolve the IAM Identity Center OIDC endpoint: %w", err)
	}
	if e.URI.Scheme == "" || e.URI.Host == "" {
		return nil, fmt.Errorf("the IAM Identity Center OIDC endpoint %q is not an absolute URL", e.URI.String())
	}
	return e.URI.JoinPath("authorize"), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// openBrowser is best effort: the URL is printed first, so a machine with no
// desktop handler still has a way through. The child gets no bmcp descriptors,
// so it cannot hold a pipe open behind bmcp's back.
func openBrowser(u string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.Command(path, u)
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

type ssoCallbackResult struct {
	code string
	err  error
}

// ssoCallbackServer receives the browser's redirect on a random loopback port.
// Only the first callback carrying the right state counts.
type ssoCallbackServer struct {
	ln       net.Listener
	srv      *http.Server
	state    string
	results  chan ssoCallbackResult
	shutOnce sync.Once
}

func newSSOCallbackServer(ctx context.Context) (*ssoCallbackServer, error) {
	// 127.0.0.1, never a wildcard: the callback carries the authorization code.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for the SSO login callback: %w", err)
	}
	state, err := randomURLSafe(32)
	if err != nil {
		ln.Close()
		return nil, err
	}
	s := &ssoCallbackServer{ln: ln, state: state, results: make(chan ssoCallbackResult, 1)}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 10 * time.Second}
	go s.srv.Serve(ln)
	return s, nil
}

func (s *ssoCallbackServer) redirectURI() string {
	return (&url.URL{Scheme: "http", Host: s.ln.Addr().String(), Path: ssoCallbackPath}).String()
}

func (s *ssoCallbackServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != ssoCallbackPath {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	// A wrong or missing state is a port probe or a forged redirect: refused
	// without ending the login, so it cannot cancel the operator's approval.
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(s.state)) != 1 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	var res ssoCallbackResult
	switch {
	case q.Get("error") != "":
		// The OAuth error code only; the description is free text from the browser.
		res.err = fmt.Errorf("the browser login was not approved: %s", oauthErrorCode(q.Get("error")))
	case q.Get("code") == "":
		res.err = errors.New("the browser login returned no authorization code")
	default:
		res.code = q.Get("code")
	}
	select {
	case s.results <- res:
	default:
		// A reload after the first answer: the login already has its result.
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if res.err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "The AWS SSO login was not approved. See the terminal running bmcp for details. You can close this tab.")
		return
	}
	fmt.Fprintln(w, "The AWS SSO login was approved. bmcp is finishing the login; you can close this tab.")
}

// oauthErrorCode keeps an OAuth error code readable and nothing else, since
// it arrives in a URL anyone on this machine can send.
func oauthErrorCode(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

// shutdown waits briefly so the page answering the callback still reaches
// the browser. Safe to call more than once.
func (s *ssoCallbackServer) shutdown() {
	s.shutOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if s.srv.Shutdown(ctx) != nil {
			s.srv.Close()
		}
	})
}

// ssoServiceError is how an IAM Identity Center failure reaches a message:
// error type, HTTP status and request id. Response bodies and SDK error text
// are withheld, since the services echo request fields, and the requests carry
// tokens and client secrets.
type ssoServiceError struct {
	Op        string
	Type      string
	Status    int
	RequestID string
	err       error
}

func (e *ssoServiceError) Error() string {
	msg := fmt.Sprintf("IAM Identity Center %s failed: %s", e.Op, e.Type)
	var extra []string
	if e.Status != 0 {
		extra = append(extra, fmt.Sprintf("HTTP %d", e.Status))
	}
	if e.RequestID != "" {
		extra = append(extra, "request id "+e.RequestID)
	}
	if len(extra) > 0 {
		msg += " (" + strings.Join(extra, ", ") + ")"
	}
	return msg
}

// Unwrap keeps the typed SDK error reachable for errors.As; nothing renders it.
func (e *ssoServiceError) Unwrap() error { return e.err }

func withholdSSOError(op string, err error) error {
	if err == nil {
		return nil
	}
	out := &ssoServiceError{Op: op, Type: "request failed", err: err}
	var apiErr smithy.APIError
	var respErr *awshttp.ResponseError
	var netErr *net.OpError
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &apiErr):
		out.Type = oauthErrorCode(apiErr.ErrorCode())
	case errors.Is(err, context.DeadlineExceeded):
		out.Type = "timed out"
	case errors.Is(err, context.Canceled):
		out.Type = "cancelled"
	case errors.As(err, &dnsErr):
		// Network errors come from this machine's stack, never from a response.
		out.Type = dnsErr.Error()
	case errors.As(err, &netErr):
		out.Type = netErr.Error()
	}
	if errors.As(err, &respErr) {
		out.Status = respErr.HTTPStatusCode()
		out.RequestID = oauthErrorCode(respErr.ServiceRequestID())
		if out.Type == "request failed" {
			out.Type = "unreadable response"
		}
	}
	return out
}

// isOIDCRejection reports a refresh the service refused for good — a revoked,
// consumed or expired refresh token or registration — as opposed to a
// transient failure that should keep the refresh token for the next attempt.
func isOIDCRejection(err error) bool {
	var (
		accessDenied       *ssooidctypes.AccessDeniedException
		expiredToken       *ssooidctypes.ExpiredTokenException
		invalidClient      *ssooidctypes.InvalidClientException
		invalidGrant       *ssooidctypes.InvalidGrantException
		invalidRequest     *ssooidctypes.InvalidRequestException
		invalidScope       *ssooidctypes.InvalidScopeException
		unauthorizedClient *ssooidctypes.UnauthorizedClientException
		unsupportedGrant   *ssooidctypes.UnsupportedGrantTypeException
	)
	return errors.As(err, &accessDenied) || errors.As(err, &expiredToken) ||
		errors.As(err, &invalidClient) || errors.As(err, &invalidGrant) ||
		errors.As(err, &invalidRequest) || errors.As(err, &invalidScope) ||
		errors.As(err, &unauthorizedClient) || errors.As(err, &unsupportedGrant)
}
