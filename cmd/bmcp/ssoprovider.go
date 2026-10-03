package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"golang.org/x/term"
)

const (
	// ssoRefreshWindow matches the AWS CLI and SDK token providers: refresh
	// early enough that GetRoleCredentials never gets a token with seconds left.
	ssoRefreshWindow = 15 * time.Minute
	// ssoAccessTokenMargin is the least life an access token needs to be used.
	ssoAccessTokenMargin = time.Minute
	// roleCredsMargin keeps cached role credentials from being handed out to
	// sign a request that may be retried after they lapse.
	roleCredsMargin = 5 * time.Minute
)

// loginPollInterval is how often a process waiting on another's browser login
// re-reads the store.
var loginPollInterval = 500 * time.Millisecond

var errSSOTokenGone = errors.New("the AWS SSO token is no longer in the credential store")

// ssoLoginNeededError means there is no usable token and this invocation may
// not open a browser. The caller appends the `bmcp login` remedy.
type ssoLoginNeededError struct{ reason string }

func (e *ssoLoginNeededError) Error() string { return e.reason }

// ssoLoginInProgressError is a waiter that cannot outlast another process's
// browser login. Its own name, so an agent retries rather than logging in.
type ssoLoginInProgressError struct {
	PID     int
	Profile string
}

func (e *ssoLoginInProgressError) Error() string {
	return fmt.Sprintf("another bmcp process (pid %d) is waiting for browser approval for profile %s; retry when it completes", e.PID, e.Profile)
}

// ssoLoginError is a browser login this process ran and that failed.
type ssoLoginError struct{ err error }

func (e *ssoLoginError) Error() string { return "SSO login failed: " + e.err.Error() }
func (e *ssoLoginError) Unwrap() error { return e.err }

var errSSOLoginDiscarded = errors.New("bmcp clear ran while the browser login was waiting for approval, so its result was discarded")

// ssoRefreshError is a refresh that did not produce a token. rejected means
// the refresh token is dead; otherwise the failure was transient and the
// refresh token was kept for the next attempt.
type ssoRefreshError struct {
	rejected bool
	err      error
}

func (e *ssoRefreshError) Error() string {
	return "refreshing the AWS SSO token failed: " + e.err.Error()
}
func (e *ssoRefreshError) Unwrap() error { return e.err }

func isRefreshRejected(err error) bool {
	var r *ssoRefreshError
	return errors.As(err, &r) && r.rejected
}

// remediedError renders its own message and keeps the cause reachable for
// errors.As, so classification still finds a *storeLockedError underneath.
type remediedError struct {
	msg string
	err error
}

func (e *remediedError) Error() string { return e.msg }
func (e *remediedError) Unwrap() error { return e.err }

// issuedRoleCreds remembers which cached entry signed this run's requests, so
// a gateway rejection can evict exactly that entry and nothing newer.
type issuedRoleCreds struct {
	locks      *credLocks
	store      credStore
	sessionKey string
	credKey    string
	rec        roleCredsRecord
}

// ssoSource produces credentials for one SSO chain in one invocation.
type ssoSource struct {
	a       *app
	chain   ssoChain
	store   credStore
	backend resolvedBackend
	locks   *credLocks
	oidc    *ssooidc.Client
	portal  *sso.Client
	awsCfg  aws.Config
	// allowLogin is the implicit-login gate, or true for `bmcp login`.
	allowLogin bool
	deviceCode bool
	// announce is printed on prose before a browser login starts.
	announce string
}

// openSSOStore resolves the backend and opens it. allowUI follows decision 12:
// only a run that may show a browser may show a store prompt.
func (a *app) openSSOStore(ctx context.Context, cfg effectiveConfig, allowUI bool) (credStore, resolvedBackend, error) {
	// A config not built by loadEffective still honours BMCP_BACKEND, so no
	// such caller silently lands on the shared, real keychain.
	if cfg.BackendRaw == "" && cfg.BackendSource == backendSourceDefault {
		if v := strings.TrimSpace(os.Getenv("BMCP_BACKEND")); v != "" {
			cfg.BackendRaw, cfg.BackendSource = v, backendSourceEnv
		}
	}
	name, source, err := cfg.backend()
	if err != nil {
		return nil, resolvedBackend{Source: source}, err
	}
	backend, err := resolveBackend(ctx, name, source, defaultBackendEnv(allowUI))
	if err != nil {
		return nil, backend, err
	}
	opts := storeOptions{AllowUI: allowUI}
	switch {
	case !allowUI:
	case a.passphrasePrompt != nil:
		opts.Passphrase = a.passphrasePrompt
	case a.isInteractive():
		opts.Passphrase = a.promptPassphrase
	}
	open := openCredStore
	if a.openStore != nil {
		open = a.openStore
	}
	store, err := open(backend, opts)
	return store, backend, err
}

// promptPassphrase reads the file backend's passphrase from the startup
// descriptors, never from whatever retrieveCredentials left in os.Stdin.
func (a *app) promptPassphrase(prompt string) (string, error) {
	fmt.Fprint(a.stderr, prompt)
	b, err := term.ReadPassword(int(a.subprocessStdin().Fd()))
	fmt.Fprintln(a.stderr)
	return string(b), err
}

func (a *app) newSSOSource(ctx context.Context, cfg effectiveConfig, chain ssoChain, awsCfg aws.Config, allowUI bool) (*ssoSource, error) {
	store, backend, err := a.openSSOStore(ctx, cfg, allowUI)
	s := &ssoSource{a: a, chain: chain, backend: backend, awsCfg: awsCfg}
	if err != nil {
		return s, err
	}
	locks, err := newCredLocks()
	if err != nil {
		return s, err
	}
	s.store, s.locks = store, locks
	region := chain.Leaf.Region
	s.oidc = ssooidc.NewFromConfig(awsCfg, func(o *ssooidc.Options) {
		o.Region = region
		o.Credentials = aws.AnonymousCredentials{}
	})
	s.portal = sso.NewFromConfig(awsCfg, func(o *sso.Options) {
		o.Region = region
		o.Credentials = aws.AnonymousCredentials{}
	})
	return s, nil
}

func (s *ssoSource) sessionKey() string { return s.chain.Leaf.storeKey() }

func (s *ssoSource) matches(rec ssoTokenRecord) bool {
	return rec.AccessToken != "" && rec.matchesSession(s.chain.Leaf.StartURL, s.chain.Leaf.Region, s.chain.Leaf.scopes())
}

// readToken returns nil, nil when there is no token for this session; a token
// for another start URL, region or scope set counts as none. A locked store is
// an error, and comes before any judgement about the token.
func (s *ssoSource) readToken() (*ssoTokenRecord, error) {
	rec, err := s.store.ReadToken(s.sessionKey())
	if errors.Is(err, errStoreItemNotFound) {
		return nil, nil
	}
	if err != nil {
		var locked *storeLockedError
		if errors.As(err, &locked) {
			return nil, err
		}
		// An unparseable token, e.g. the CLI's non-atomic write caught halfway,
		// is no token.
		return nil, nil
	}
	if !s.matches(rec) {
		return nil, nil
	}
	return &rec, nil
}

func accessUsable(t ssoTokenRecord, now time.Time) bool {
	return t.AccessToken != "" && t.ExpiresAt.After(now.Add(ssoAccessTokenMargin))
}

func refreshable(t ssoTokenRecord, now time.Time) bool {
	return t.RefreshToken != "" && t.ClientID != "" && t.ClientSecret != "" &&
		(t.RegistrationExpiresAt.IsZero() || t.RegistrationExpiresAt.After(now))
}

// credentials is the whole retrieval: cached final credentials, else leaf
// credentials (cached, or minted with a token that may need a refresh or a
// login), then each assume-role hop.
func (s *ssoSource) credentials(ctx context.Context) (aws.Credentials, *issuedRoleCreds, error) {
	tok, err := s.readToken()
	if err != nil {
		return aws.Credentials{}, nil, err
	}
	finalKey := s.chain.cacheKey(len(s.chain.Hops))
	if tok != nil {
		if rec, ok, err := s.cachedRole(finalKey, tok.Generation); err != nil {
			return aws.Credentials{}, nil, err
		} else if ok {
			return rec.credentials(), s.issued(finalKey, rec), nil
		}
	}
	leaf, err := s.leafCredentials(ctx, tok)
	if err != nil {
		return aws.Credentials{}, nil, err
	}
	if len(s.chain.Hops) == 0 {
		return leaf.credentials(), s.issued(finalKey, leaf), nil
	}
	final, err := s.assumeHops(ctx, leaf.credentials())
	if err != nil {
		return aws.Credentials{}, nil, err
	}
	rec := roleCredsRecord{AccessKeyID: final.AccessKeyID, SecretAccessKey: final.SecretAccessKey,
		SessionToken: final.SessionToken, Expiration: final.Expires, Generation: leaf.Generation}
	s.saveRole(ctx, finalKey, rec)
	return rec.credentials(), s.issued(finalKey, rec), nil
}

func (s *ssoSource) issued(credKey string, rec roleCredsRecord) *issuedRoleCreds {
	return &issuedRoleCreds{locks: s.locks, store: s.store, sessionKey: s.sessionKey(), credKey: credKey, rec: rec}
}

func (r roleCredsRecord) credentials() aws.Credentials {
	return aws.Credentials{AccessKeyID: r.AccessKeyID, SecretAccessKey: r.SecretAccessKey,
		SessionToken: r.SessionToken, CanExpire: true, Expires: r.Expiration, Source: "bmcp-sso"}
}

func (s *ssoSource) cachedRole(credKey, generation string) (roleCredsRecord, bool, error) {
	rec, err := s.store.ReadRoleCreds(s.sessionKey(), credKey)
	if err != nil {
		var locked *storeLockedError
		if errors.As(err, &locked) {
			return rec, false, err
		}
		return rec, false, nil
	}
	return rec, rec.usable(generation, s.a.now(), roleCredsMargin), nil
}

// saveRole caches credentials only while the token they came from is still
// current. A failure costs a re-mint next time, never this call.
func (s *ssoSource) saveRole(ctx context.Context, credKey string, rec roleCredsRecord) {
	lock, err := s.locks.lockSession(ctx, s.sessionKey())
	if err != nil {
		s.persistWarning("role credentials", err)
		return
	}
	defer lock.Unlock()
	if _, err := lock.writeRoleCredsIfCurrent(s.store, credKey, rec); err != nil {
		s.persistWarning("role credentials", err)
	}
}

func (s *ssoSource) persistWarning(what string, err error) {
	s.a.warn("bmcp could not save %s to the %s credential store (%v); they are used for this call and saving is retried next time", what, s.backend.Name, err)
}

// leafCredentials mints sso:GetRoleCredentials credentials, or reads them from
// the cache. A 401 gets one refresh; a token rejected after that, or whose
// refresh is rejected, is deleted so the next `bmcp login` really logs in.
func (s *ssoSource) leafCredentials(ctx context.Context, tok *ssoTokenRecord) (roleCredsRecord, error) {
	leafKey := s.chain.cacheKey(0)
	if tok != nil && len(s.chain.Hops) > 0 {
		if rec, ok, err := s.cachedRole(leafKey, tok.Generation); err != nil {
			return rec, err
		} else if ok {
			return rec, nil
		}
	}
	loggedIn, retried := false, false
	why := "there is no AWS SSO token for this session in the " + string(s.backend.Name) + " credential store"
	for {
		t, err := s.usableToken(ctx, tok, why, &loggedIn)
		if err != nil {
			return roleCredsRecord{}, err
		}
		rec, err := s.getRoleCredentials(ctx, t)
		if err == nil {
			s.saveRole(ctx, leafKey, rec)
			return rec, nil
		}
		if !isSSOUnauthorized(err) {
			return roleCredsRecord{}, err
		}
		if !retried {
			retried = true
			next, rerr := s.refresh(ctx, t, true)
			if rerr == nil {
				tok = &next
				continue
			}
			if !isRefreshRejected(rerr) && !errors.Is(rerr, errSSOTokenGone) {
				// Transient: the token stays for the next attempt.
				return roleCredsRecord{}, rerr
			}
		}
		s.dropToken(ctx, t)
		if loggedIn {
			return roleCredsRecord{}, fmt.Errorf("the token from a new AWS SSO login was rejected: %w", err)
		}
		tok, why = nil, "the AWS SSO token was rejected ("+err.Error()+") and has been removed"
	}
}

// usableToken returns a token whose access token can be used now: the stored
// one, a refresh of it, or a fresh login. reason says why there is none, for
// when tok is nil.
func (s *ssoSource) usableToken(ctx context.Context, tok *ssoTokenRecord, reason string, loggedIn *bool) (ssoTokenRecord, error) {
	now := s.a.now()
	if tok != nil {
		if tok.ExpiresAt.After(now.Add(ssoRefreshWindow)) {
			return *tok, nil
		}
		if refreshable(*tok, now) {
			next, err := s.refresh(ctx, *tok, false)
			switch {
			case err == nil:
				return next, nil
			case accessUsable(*tok, now):
				// Decision 8: a failed refresh does not retire a token that still works.
				return *tok, nil
			case errors.Is(err, errSSOTokenGone), isRefreshRejected(err):
				reason = "the AWS SSO token expired and its refresh was rejected"
			default:
				return ssoTokenRecord{}, err
			}
		} else if accessUsable(*tok, now) {
			return *tok, nil
		} else {
			reason = "the AWS SSO token expired at " + formatExpiry(tok.ExpiresAt) + " and cannot be refreshed"
		}
	}
	t, err := s.login(ctx, reason)
	if err == nil {
		*loggedIn = true
	}
	return t, err
}

// refresh redeems the refresh token under the session lock. It re-reads the
// store first: another process may have refreshed, logged in or cleared while
// this one waited. force is the 401 path, which wants any token newer than the
// rejected one rather than one that merely outlives the refresh window.
func (s *ssoSource) refresh(ctx context.Context, seen ssoTokenRecord, force bool) (ssoTokenRecord, error) {
	lock, err := s.locks.lockSession(ctx, s.sessionKey())
	if err != nil {
		return ssoTokenRecord{}, err
	}
	defer lock.Unlock()
	cur, err := s.store.ReadToken(s.sessionKey())
	if errors.Is(err, errStoreItemNotFound) || (err == nil && !s.matches(cur)) {
		return ssoTokenRecord{}, errSSOTokenGone
	}
	if err != nil {
		return ssoTokenRecord{}, err
	}
	now := s.a.now()
	if cur.AccessToken != seen.AccessToken && accessUsable(cur, now) &&
		(force || cur.ExpiresAt.After(now.Add(ssoRefreshWindow))) {
		return cur, nil
	}
	if !refreshable(cur, now) {
		return ssoTokenRecord{}, &ssoRefreshError{rejected: true, err: errors.New("the token has no usable refresh token")}
	}
	out, err := s.oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(cur.ClientID),
		ClientSecret: aws.String(cur.ClientSecret),
		GrantType:    aws.String(grantRefreshToken),
		RefreshToken: aws.String(cur.RefreshToken),
	})
	if err != nil {
		rejected := isOIDCRejection(err)
		if rejected && (force || !accessUsable(cur, now)) {
			// Nothing left that works: dropping it keeps `bmcp login` from
			// short-circuiting on it and doctor from calling it refreshable.
			s.deleteLocked()
		}
		return ssoTokenRecord{}, &ssoRefreshError{rejected: rejected, err: withholdSSOError("CreateToken", err)}
	}
	if aws.ToString(out.AccessToken) == "" {
		return ssoTokenRecord{}, &ssoRefreshError{err: errors.New("IAM Identity Center returned no access token")}
	}
	next := cur
	next.AccessToken = aws.ToString(out.AccessToken)
	next.ExpiresAt = now.Add(time.Duration(out.ExpiresIn) * time.Second).UTC()
	if rt := aws.ToString(out.RefreshToken); rt != "" && rt != cur.RefreshToken {
		// Rotation consumed the old refresh token: a new generation, so role
		// credentials minted under the old one are retired with it.
		next.RefreshToken = rt
		saved, err := lock.saveNewToken(s.store, next)
		if err != nil {
			s.persistWarning("the refreshed AWS SSO token", err)
		}
		return saved, nil
	}
	if err := s.store.WriteToken(s.sessionKey(), next); err != nil {
		s.persistWarning("the refreshed AWS SSO token", err)
	}
	return next, nil
}

// deleteLocked removes the token and the role credentials it minted. Requires
// the session lock.
func (s *ssoSource) deleteLocked() {
	if err := errors.Join(s.store.DeleteToken(s.sessionKey()), s.store.DeleteSessionRoleCreds(s.sessionKey())); err != nil {
		s.persistWarning("the removal of a rejected AWS SSO token", err)
	}
}

// dropToken deletes a token the service rejected, unless another process has
// already replaced it.
func (s *ssoSource) dropToken(ctx context.Context, rejected ssoTokenRecord) {
	lock, err := s.locks.lockSession(ctx, s.sessionKey())
	if err != nil {
		return
	}
	defer lock.Unlock()
	cur, err := s.store.ReadToken(s.sessionKey())
	if err == nil && cur.AccessToken == rejected.AccessToken {
		s.deleteLocked()
	}
}

func (s *ssoSource) getRoleCredentials(ctx context.Context, tok ssoTokenRecord) (roleCredsRecord, error) {
	out, err := s.portal.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(tok.AccessToken),
		AccountId:   aws.String(s.chain.Leaf.AccountID),
		RoleName:    aws.String(s.chain.Leaf.RoleName),
	})
	if err != nil {
		return roleCredsRecord{}, withholdSSOError("GetRoleCredentials", err)
	}
	rc := out.RoleCredentials
	if rc == nil || aws.ToString(rc.AccessKeyId) == "" {
		return roleCredsRecord{}, errors.New("IAM Identity Center GetRoleCredentials returned no credentials")
	}
	return roleCredsRecord{
		AccessKeyID: aws.ToString(rc.AccessKeyId), SecretAccessKey: aws.ToString(rc.SecretAccessKey),
		SessionToken: aws.ToString(rc.SessionToken), Expiration: time.UnixMilli(rc.Expiration).UTC(),
		Generation: tok.Generation,
	}, nil
}

func isSSOUnauthorized(err error) bool {
	var unauthorized *ssotypes.UnauthorizedException
	if errors.As(err, &unauthorized) {
		return true
	}
	var resp *awshttp.ResponseError
	return errors.As(err, &resp) && resp.HTTPStatusCode() == http.StatusUnauthorized
}

// assumeHops walks the role_arn hops above the SSO leaf, each signed with the
// credentials the one below produced, as the SDK's own source_profile chain does.
func (s *ssoSource) assumeHops(ctx context.Context, creds aws.Credentials) (aws.Credentials, error) {
	for _, hop := range s.chain.Hops {
		source := credentials.StaticCredentialsProvider{Value: creds}
		client := sts.NewFromConfig(s.awsCfg, func(o *sts.Options) { o.Credentials = source })
		provider := stscreds.NewAssumeRoleProvider(client, hop.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = hop.RoleSessionName
			// The SDK's own rule: a duration of 15 minutes or less means the default.
			if hop.Duration/time.Minute > 15 {
				o.Duration = hop.Duration
			}
			if hop.ExternalID != "" {
				o.ExternalID = aws.String(hop.ExternalID)
			}
		})
		next, err := provider.Retrieve(ctx)
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("assuming %s for profile %s: %w", hop.RoleARN, hop.Profile, err)
		}
		creds = next
	}
	return creds, nil
}

// login runs, or waits for, the one browser login for this session. Browser
// logins never hold the lock while the operator approves (decision 11): a
// marker says one is in flight, and the lock is taken again only to save.
func (s *ssoSource) login(ctx context.Context, reason string) (ssoTokenRecord, error) {
	lock, err := s.locks.lockSession(ctx, s.sessionKey())
	if err != nil {
		return ssoTokenRecord{}, err
	}
	if cur, err := s.store.ReadToken(s.sessionKey()); err == nil && s.matches(cur) && accessUsable(cur, s.a.now()) {
		lock.Unlock()
		return cur, nil
	}
	marker, err := lock.LoginMarker(time.Now())
	if err != nil {
		lock.Unlock()
		return ssoTokenRecord{}, err
	}
	if marker != nil {
		lock.Unlock()
		return s.awaitLogin(ctx, marker, reason)
	}
	if !s.allowLogin {
		lock.Unlock()
		return ssoTokenRecord{}, &ssoLoginNeededError{reason: reason}
	}
	mine, err := lock.BeginLogin(s.chain.Profile, time.Now())
	lock.Unlock()
	if err != nil {
		return ssoTokenRecord{}, err
	}
	if s.announce != "" {
		fmt.Fprint(s.a.prose(), s.announce)
	}
	loginer := &ssoLoginer{oidc: s.oidc, sess: s.chain.Leaf, out: s.a.stderr, openURL: s.a.openURLFunc(), now: s.a.now, sleep: sleepCtx}
	tok, loginErr := loginer.login(ctx, s.deviceCode)

	// Saving must not be lost to a deadline that landed during the approval.
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	lock, err = s.locks.lockSession(saveCtx, s.sessionKey())
	if err != nil {
		if loginErr != nil {
			return ssoTokenRecord{}, &ssoLoginError{loginErr}
		}
		s.persistWarning("the new AWS SSO token", err)
		return tok, nil
	}
	defer lock.Unlock()
	// The marker goes last: waiters poll without the lock, and one that saw it
	// gone before the token landed would give up on a login that succeeded.
	defer lock.EndLogin(mine)
	wanted, werr := lock.LoginWanted(mine)
	if loginErr != nil {
		return ssoTokenRecord{}, &ssoLoginError{loginErr}
	}
	if werr == nil && !wanted {
		return ssoTokenRecord{}, &ssoLoginError{errSSOLoginDiscarded}
	}
	saved, err := lock.saveNewToken(s.store, tok)
	if err != nil {
		s.persistWarning("the new AWS SSO token", err)
	}
	return saved, nil
}

// awaitLogin waits for another process's browser login when this one has the
// budget a login itself would need; otherwise it fails at once.
func (s *ssoSource) awaitLogin(ctx context.Context, m *loginMarker, reason string) (ssoTokenRecord, error) {
	if !deviceFlowFits(ctx) {
		return ssoTokenRecord{}, &ssoLoginInProgressError{PID: m.PID, Profile: m.Profile}
	}
	for {
		if err := sleepCtx(ctx, loginPollInterval); err != nil {
			return ssoTokenRecord{}, fmt.Errorf("waiting for the browser login in bmcp process %d: %w", m.PID, err)
		}
		tok, err := s.readToken()
		if err != nil {
			return ssoTokenRecord{}, err
		}
		if tok != nil && accessUsable(*tok, s.a.now()) {
			return *tok, nil
		}
		live, err := s.locks.PeekLoginMarker(s.sessionKey(), time.Now())
		if err != nil {
			return ssoTokenRecord{}, err
		}
		if live == nil || live.ID != m.ID {
			if tok, err := s.readToken(); err == nil && tok != nil && accessUsable(*tok, s.a.now()) {
				return *tok, nil
			}
			// Not starting a login of its own: N waiters on a cancelled login
			// would otherwise open N tabs one after another.
			return ssoTokenRecord{}, &ssoLoginNeededError{reason: reason + ", and the browser login in bmcp process " +
				fmt.Sprint(m.PID) + " ended without one"}
		}
	}
}

// openURLFunc is the browser opener: injectable for tests, best effort otherwise.
func (a *app) openURLFunc() func(string) error {
	if a.openURL != nil {
		return a.openURL
	}
	return openBrowser
}

// ssoLoginCommand is the remedy a message hands back: the profile always, and
// --backend when the flag chose the store, or the retry would use another one.
func ssoLoginCommand(profile string, backend resolvedBackend) string {
	cmd := "bmcp --profile " + profile
	if backend.FromFlag {
		cmd += " --backend " + string(backend.Name)
	}
	return cmd + " login"
}

// ssoLoginOutcome is what `bmcp login` reports.
type ssoLoginOutcome struct {
	// Profile is the leaf profile whose session was logged in to.
	Profile      string
	Backend      resolvedBackend
	ExpiresAt    time.Time
	AlreadyValid bool
	Refreshed    bool
	Refreshable  bool
}

// ssoLogin is `bmcp login`: store prompts allowed, no budget gate (the caller
// supplies its 11 minutes), and no browser when the stored token is valid or
// a refresh succeeds.
func (a *app) ssoLogin(ctx context.Context, cfg effectiveConfig, profile string, explicitDeviceCode bool) (ssoLoginOutcome, error) {
	chain, err := resolveSSOChain(ctx, profile)
	if err != nil {
		return ssoLoginOutcome{}, err
	}
	if chain == nil {
		return ssoLoginOutcome{}, fmt.Errorf("profile %s does not resolve through AWS SSO", profile)
	}
	awsCfg, err := a.loadSSOConfig(ctx, cfg, profile)
	if err != nil {
		return ssoLoginOutcome{}, err
	}
	src, err := a.newSSOSource(ctx, cfg, *chain, awsCfg, true)
	out := ssoLoginOutcome{Profile: chain.Leaf.Profile, Backend: src.backend}
	if err != nil {
		return out, err
	}
	src.allowLogin = true
	// "blocks" because the caller may be an agent with a timeout of its own,
	// and a browser waiting on a human can outlast one.
	src.announce = fmt.Sprintf("Logging in to AWS SSO for profile %s. A browser opens on this machine, and bmcp blocks until the login is approved.\n", profile)
	finish := func(t ssoTokenRecord) ssoLoginOutcome {
		out.ExpiresAt, out.Refreshable = t.ExpiresAt, refreshable(t, a.now())
		return out
	}
	tok, err := src.readToken()
	if err != nil {
		return out, err
	}
	now := a.now()
	if tok != nil && tok.ExpiresAt.After(now.Add(ssoRefreshWindow)) {
		out.AlreadyValid = true
		return finish(*tok), nil
	}
	if tok != nil && refreshable(*tok, now) {
		if next, err := src.refresh(ctx, *tok, false); err == nil {
			out.Refreshed = true
			return finish(next), nil
		}
	}
	if src.deviceCode, _, err = ssoFlowChoice(cfg, explicitDeviceCode); err != nil {
		return out, err
	}
	t, err := src.login(ctx, "there was no usable AWS SSO token")
	if err != nil {
		return out, err
	}
	return finish(t), nil
}

// loadSSOConfig loads the SDK config for profile: region, HTTP client and
// endpoint settings the SSO clients inherit. It reads files only.
func (a *app) loadSSOConfig(ctx context.Context, cfg effectiveConfig, profile string) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithLogger(a.sdkLogger()),
		awsconfig.WithSharedConfigProfile(profile),
	}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	return awsconfig.LoadDefaultConfig(ctx, opts...)
}

// ssoClearOutcome is what `bmcp clear` reports.
type ssoClearOutcome struct {
	Backend resolvedBackend
	// Sessions names what was cleared: sso_session names or start URLs.
	Sessions []string
	// SharedWithAWSCLI is set on aws-cli-cache, where deleting the token file
	// also logs the AWS CLI out of that session.
	SharedWithAWSCLI bool
}

// ssoClear is `bmcp clear` for the session profile resolves through: token,
// client registration and every role credential minted from it, plus any
// in-flight browser login, whose result will be discarded.
func (a *app) ssoClear(ctx context.Context, cfg effectiveConfig, profile string, allowUI bool) (ssoClearOutcome, error) {
	chain, err := resolveSSOChain(ctx, profile)
	if err != nil {
		return ssoClearOutcome{}, err
	}
	if chain == nil {
		return ssoClearOutcome{}, fmt.Errorf("profile %s does not resolve through AWS SSO", profile)
	}
	store, backend, err := a.openSSOStore(ctx, cfg, allowUI)
	out := ssoClearOutcome{Backend: backend, SharedWithAWSCLI: backend.Name == backendAWSCLICache}
	if err != nil {
		return out, err
	}
	locks, err := newCredLocks()
	if err != nil {
		return out, err
	}
	lock, err := locks.lockSession(ctx, chain.Leaf.storeKey())
	if err != nil {
		return out, err
	}
	defer lock.Unlock()
	if err := lock.clearSession(store); err != nil {
		return out, err
	}
	out.Sessions = []string{firstNonEmpty(chain.Leaf.Name, chain.Leaf.StartURL)}
	return out, nil
}

// ssoClearAll is `bmcp clear --all`: every bmcp item in the active backend and
// bmcp's role-credential directory, under the global lock every login also
// takes before it saves. On aws-cli-cache only the token files of sessions
// named in the current AWS config are deleted, since the rest are the CLI's.
func (a *app) ssoClearAll(ctx context.Context, cfg effectiveConfig, allowUI bool) (ssoClearOutcome, error) {
	store, backend, err := a.openSSOStore(ctx, cfg, allowUI)
	out := ssoClearOutcome{Backend: backend, SharedWithAWSCLI: backend.Name == backendAWSCLICache}
	if err != nil {
		return out, err
	}
	locks, err := newCredLocks()
	if err != nil {
		return out, err
	}
	g, err := locks.lockAll(ctx)
	if err != nil {
		return out, err
	}
	defer g.Unlock()
	sessions := configuredSSOSessions()
	keys := make([]string, 0, len(sessions))
	for _, s := range sessions {
		keys = append(keys, s.key)
		out.Sessions = append(out.Sessions, s.label)
	}
	errs := []error{g.DiscardAllLogins(), store.ClearAll(keys)}
	if dir, err := bmcpCacheDir(); err == nil {
		errs = append(errs, os.RemoveAll(filepath.Join(dir, "creds")))
	}
	return out, errors.Join(errs...)
}

// evictRejectedSSOCreds is the gateway-rejection hook (decision 14): it drops
// the cached role credentials this run signed with, so the next invocation
// re-mints, and leaves the SSO token alone. A no-op when nothing native was
// issued, and when another process has already replaced the entry.
func (a *app) evictRejectedSSOCreds(ctx context.Context) error {
	a.ssoIssuedMu.Lock()
	iss := a.ssoIssued
	a.ssoIssued = nil
	a.ssoIssuedMu.Unlock()
	if iss == nil {
		return nil
	}
	lock, err := iss.locks.lockSession(ctx, iss.sessionKey)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	_, err = lock.evictRoleCredsIfSame(iss.store, iss.credKey, iss.rec)
	return err
}

// ssoStoreStatus is doctor's prompt-free view of the SSO token: which store,
// whether it could be read without UI, and what it holds. Nothing is
// contacted and nothing is refreshed.
type ssoStoreStatus struct {
	// Profile is the leaf profile; empty means the profile does not resolve
	// through SSO and there is nothing to report.
	Profile string
	// Session is the sso_session name, or the start URL for the legacy form.
	Session string
	Backend resolvedBackend
	// Locked is set when the store needs approval this run may not ask for.
	Locked *storeLockedError
	// Err is any other failure: backend resolution, an unreadable profile.
	Err error
	// OpenFailed marks an Err from resolving or opening the store, which
	// fails every SSO call, as opposed to one unreadable token.
	OpenFailed  bool
	HasToken    bool
	ExpiresAt   time.Time
	Refreshable bool
	// LeftoverCLITokenPath names a plaintext AWS CLI token file for this
	// session when the active backend is not aws-cli-cache.
	LeftoverCLITokenPath string
}

func (a *app) ssoStoreStatus(ctx context.Context, cfg effectiveConfig) ssoStoreStatus {
	var st ssoStoreStatus
	profile, _, _ := a.sharedProfileFor(cfg)
	if profile == "" {
		return st
	}
	chain, err := resolveSSOChain(ctx, profile)
	if chain == nil {
		st.Err = err
		return st
	}
	st.Profile, st.Session = chain.Leaf.Profile, firstNonEmpty(chain.Leaf.Name, chain.Leaf.StartURL)
	store, backend, err := a.openSSOStore(ctx, cfg, false)
	st.Backend = backend
	st.OpenFailed = err != nil
	if err == nil {
		var rec ssoTokenRecord
		rec, err = store.ReadToken(chain.Leaf.storeKey())
		if err == nil && rec.AccessToken != "" && rec.matchesSession(chain.Leaf.StartURL, chain.Leaf.Region, chain.Leaf.scopes()) {
			st.HasToken, st.ExpiresAt, st.Refreshable = true, rec.ExpiresAt, refreshable(rec, a.now())
		}
		if errors.Is(err, errStoreItemNotFound) {
			err = nil
		}
	}
	if errors.As(err, &st.Locked) {
		st.OpenFailed = false
	} else {
		st.Err = err
	}
	if backend.Name != backendAWSCLICache {
		if home, herr := os.UserHomeDir(); herr == nil {
			p := filepath.Join(home, ".aws", "sso", "cache", chain.Leaf.storeKey()+".json")
			if _, serr := os.Stat(p); serr == nil {
				st.LeftoverCLITokenPath = p
			}
		}
	}
	return st
}

type configuredSSOSession struct{ key, label string }

// awsConfigFile is the shared config file the SDK reads, honouring
// AWS_CONFIG_FILE.
func awsConfigFile() string {
	if env, err := awsconfig.NewEnvConfig(); err == nil && env.SharedConfigFile != "" {
		return env.SharedConfigFile
	}
	return awsconfig.DefaultSharedConfigFilename()
}

// scanAWSConfig calls fn for every key in the shared config file with its
// section header (e.g. "sso-session corp", "profile dev", "default"). The SDK
// does not expose keys it does not model, such as sso_registration_scopes.
func scanAWSConfig(fn func(section, key, value string)) {
	f, err := os.Open(awsConfigFile())
	if err != nil {
		return
	}
	defer f.Close()
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Join(strings.Fields(line[1:len(line)-1]), " ")
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			fn(section, strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
}

// ssoRegistrationScopes reads sso_registration_scopes from an sso-session
// section; the legacy profile form has no such key.
func ssoRegistrationScopes(sessionName string) []string {
	var scopes []string
	scanAWSConfig(func(section, key, value string) {
		if section != "sso-session "+sessionName || key != "sso_registration_scopes" {
			return
		}
		scopes = nil
		for _, s := range strings.Split(value, ",") {
			if s = strings.TrimSpace(s); s != "" {
				scopes = append(scopes, s)
			}
		}
	})
	return scopes
}

// configuredSSOSessions lists every SSO session the current AWS config names,
// for `clear --all` on aws-cli-cache.
func configuredSSOSessions() []configuredSSOSession {
	seen := map[string]bool{}
	var out []configuredSSOSession
	add := func(name, startURL string) {
		k := ssoSessionStoreKey(name, startURL)
		if !seen[k] {
			seen[k] = true
			out = append(out, configuredSSOSession{key: k, label: firstNonEmpty(name, startURL)})
		}
	}
	legacy := map[string]string{}
	usesSession := map[string]bool{}
	scanAWSConfig(func(section, key, value string) {
		switch {
		case strings.HasPrefix(section, "sso-session "):
			add(strings.TrimPrefix(section, "sso-session "), "")
		case key == "sso_start_url":
			legacy[section] = value
		case key == "sso_session":
			usesSession[section] = true
		}
	})
	for section, url := range legacy {
		if !usesSession[section] {
			add("", url)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label < out[j].label })
	return out
}
