package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/smithy-go/logging"
)

func (a *app) loadCredentials(ctx context.Context, cfg effectiveConfig) (aws.Credentials, string, error) {
	if a.credentials != nil {
		return a.credentials(ctx, cfg)
	}
	return a.awsCredentials(ctx, cfg)
}

// sharedProfileFor decides whether cfg.Profile may be handed to the SDK as a
// programmatic shared-config profile, and names what outranked it when it may
// not be.
//
// The distinction is not cosmetic. aws-sdk-go-v2's resolveCredentialChain asks
// whether a profile was set *programmatically* — WithSharedConfigProfile and
// nothing else — and if one was, it resolves credentials from that profile and
// never reaches the branches that read the environment's own credentials at
// all. The SDK says as much above that switch: "When checking if a profile was
// specified programmatically we should only consider the 'other' configuration
// sources that have been provided. This ensures we correctly honor the expected
// credential hierarchy." A bare AWS_PROFILE deliberately does not trip that
// check, so environment credentials still outrank it — and bmcp passing every
// profile it resolved, from wherever it resolved it, is what inverted that (#58).
//
// So: a profile named for this invocation still wins, because naming one now is
// an instruction rather than a default, and because BMCP_PROFILE is a variable
// the SDK will never read on its own — yielding it would drop the request
// silently rather than fall through to anything. An ambient profile
// (AWS_PROFILE, or aws_profile in config.toml) yields to ambient credentials.
// When it does not yield, passing it programmatically resolves exactly as the
// SDK's own AWS_PROFILE handling would, because that is the branch the SDK
// takes once the environment carries no credentials of its own.
//
// One exception to the yielding, and it is the whole of #66's third symptom:
// environment credentials that have provably expired are treated as absent —
// unless the environment also carries a web identity token, see below — so the
// ambient profile wins after all. Without it those credentials are
// inescapable — the SDK never reads AWS_CREDENTIAL_EXPIRATION, so it sees
// static keys with CanExpire false, hands them to the signer, and the gateway
// rejects every request. No profile in config.toml can help, because the dead
// keys outrank it, and bmcp would report a healthy credential source while
// every call 401s.
//
// The bypass is not total, and is not meant to be. resolveCredsFromProfile
// still falls through to AWS_CONTAINER_CREDENTIALS_* and IMDS beneath the
// profile, and a profile carrying credential_source = Environment reads the
// very keys just demoted. Those are the profile's own fallbacks, which this
// function has never had an opinion about.
//
// demotedAt is the instant those credentials expired, and the zero time when no
// demotion happened. It exists because the demoted case and the no-credentials
// case both return (cfg.Profile, ""), so without it nothing downstream can tell
// "the profile won because the environment was empty" from "the profile won
// because the environment was dead" — and the second is the one the operator
// has to be told about, since it is bmcp departing from the documented order.
func (a *app) sharedProfileFor(cfg effectiveConfig) (profile, outrankedBy string, demotedAt time.Time) {
	if cfg.Profile == "" {
		return "", "", time.Time{}
	}
	if cfg.ProfileSource.namedForThisInvocation() {
		return cfg.Profile, "", time.Time{}
	}
	if source := envCredentialSource(); source != "" {
		// The demotion is withheld when the environment also carries a web identity
		// token, and that exception is the difference between a recovery and a
		// wrong identity. WithSharedConfigProfile does not remove the expired keys
		// from the chain, it steps over the SDK's *entire* environment tier — the
		// web identity arm included — so on an IRSA pod that also happens to carry
		// stale static keys, demoting would authenticate as whatever profile
		// config.toml names instead of as the pod's own role. That is a different
		// account, silently, on a path whose whole purpose is to be less
		// surprising.
		//
		// Withholding it leaves that population exactly where it is today: the SDK
		// resolves the dead static keys, the request is rejected, and the operator
		// gets the same 401 as before — no worse, and no new identity. Healing it
		// properly would mean unsetting the keys out of the process environment,
		// which is a far larger claim than this change is making.
		if expired := a.envCredentialsExpiredAt(); !expired.IsZero() && !envCarriesWebIdentity() {
			return cfg.Profile, "", expired
		}
		return "", source, time.Time{}
	}
	return cfg.Profile, "", time.Time{}
}

// envCarriesWebIdentity reports whether the environment names a web identity
// token file — the one other credential source resolveCredentialChain places
// above every profile, and therefore the one a demotion would step over.
//
// The token file alone, matching the SDK's own arm and envCredentialSource's
// reasoning above it: a half-injected IRSA setup missing AWS_ROLE_ARN must fail
// closed rather than quietly resolve as an ambient profile.
func envCarriesWebIdentity() bool {
	env, err := awsconfig.NewEnvConfig()
	return err == nil && env.WebIdentityTokenFilePath != ""
}

// envCredentialsExpiredAt reports when the environment's static credentials
// expired, or the zero time when it carries none, when they name no expiry, or
// when that expiry has not been reached.
//
// AWS_CREDENTIAL_EXPIRATION is what aws-vault and most credential wrappers
// stamp alongside the keys they inject, and it is the only local evidence that
// exists: aws-sdk-go-v2/config does not read the variable, so the credentials
// it builds report CanExpire false and Expired() is permanently false for them.
// Reading it here is therefore not duplicating an SDK check, it is supplying
// one the SDK does not make.
//
// Static keys only, tested through the SDK's own parser rather than by reading
// AWS_ACCESS_KEY_ID directly, so which variables count cannot drift from the
// fields the SDK tests. A web identity token file carries its own expiry inside
// the token and is refreshed by the provider that reads it, so there is nothing
// here to demote and nothing this variable would be describing.
//
// Three deliberate non-answers, all of which return the zero time:
//
//   - An unparseable value. It is evidence of a wrapper bmcp does not
//     understand, not evidence that credentials are dead, and treating it as an
//     expiry would demote working credentials on the strength of a typo.
//   - A future instant. Credentials that have not expired are simply
//     credentials.
//   - Bare static keys with no expiration at all. A long-lived IAM user key is
//     the ordinary case and must keep outranking a profile exactly as before.
//
// a.now rather than time.Now, because the demotion is a comparison against the
// clock and a test has to be able to sit on both sides of it.
func (a *app) envCredentialsExpiredAt() time.Time {
	env, err := awsconfig.NewEnvConfig()
	if err != nil || !env.Credentials.HasKeys() {
		return time.Time{}
	}
	raw := os.Getenv("AWS_CREDENTIAL_EXPIRATION")
	if raw == "" {
		return time.Time{}
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil || !at.Before(a.now()) {
		return time.Time{}
	}
	return at
}

// envCredentialSource names the credentials the environment carries that
// outrank a shared-config profile, or "" when it carries none.
//
// "Outrank a profile" is the whole content of this function, and it is a
// narrower question than "does the environment have credentials somewhere".
// Only two sources sit in resolveCredentialChain's *outer* switch, above the
// profile branch: static keys, and a web identity token. Those two bypass every
// profile. Everything else the environment can carry — AWS_CONTAINER_CREDENTIALS_*
// at resolve_credentials.go:182-188, and IMDS below them — lives *inside*
// resolveCredsFromProfile, beneath that profile's own static keys,
// credential_source, web identity, SSO and credential_process arms. Those are a
// profile's fallback, never its superior.
//
// Naming one of the inner sources here would be wrong twice over. The claim
// itself would be false, and acting on it would not even reach the source
// named: declining the profile hands resolution to the `default` profile, which
// the SDK reads whenever no profile is set — so bmcp would announce container
// credentials and then sign as an unrelated identity, or block on the
// link-local endpoint on a machine whose profile had been resolving instantly.
//
// The environment is read through the SDK's own parser rather than a hand-kept
// list of variable names, so which variables count cannot drift from the fields
// the SDK tests.
func envCredentialSource() string {
	env, err := awsconfig.NewEnvConfig()
	if err != nil {
		// LoadDefaultConfig builds the same EnvConfig and fails with the same
		// error, so the run reports the real cause either way.
		return ""
	}
	switch {
	case env.Credentials.HasKeys():
		// HasKeys wants both halves, so a stray AWS_ACCESS_KEY_ID on its own does
		// not cost the operator their profile.
		return "environment credentials (AWS_ACCESS_KEY_ID)"
	case env.WebIdentityTokenFilePath != "":
		// The token file alone, exactly as the SDK's arm tests it, and deliberately
		// not "the token file and AWS_ROLE_ARN". Requiring the pair looks safer —
		// it keeps a working profile where a half-injected IRSA setup would
		// otherwise fail — but it fails open: an IRSA deployment whose role ARN
		// went missing would silently authenticate as the ambient profile, which
		// may be an unrelated and more privileged identity, and the operator would
		// never learn that IRSA was broken. The SDK fails closed here with "role
		// ARN is not set", every other AWS tool on that machine does the same, and
		// a credential path is the wrong place to be more forgiving than that.
		return "web identity credentials (AWS_WEB_IDENTITY_TOKEN_FILE)"
	}
	return ""
}

// ambientProfileRegion is the region a declined profile would have supplied, or
// "" when something better already supplies one.
//
// Declining a profile for credential purposes must not also drop the region it
// carried for SigV4 purposes. The SDK does not have this problem with
// AWS_PROFILE — it goes on reading that variable for non-credential config
// whatever the credential chain does — but a config.toml profile is invisible
// to it, so withholding the profile withheld its region too. With no region
// left, bmcp either signed with the `default` profile's region or refused the
// call outright with "AWS region could not be inferred", on a machine that had
// been working.
//
// The ordering mirrors what the SDK does for a bare AWS_PROFILE: an explicit
// region and the environment's own both win, and this fills in beneath them and
// ahead of the `default` profile. Errors are ignored because a profile that
// cannot be read has no region to offer, and reporting that is the credential
// path's job rather than this one's.
func ambientProfileRegion(ctx context.Context, cfg effectiveConfig) string {
	if cfg.Region != "" {
		return ""
	}
	env, err := awsconfig.NewEnvConfig()
	if err != nil || env.Region != "" {
		return ""
	}
	shared, err := sharedConfigProfile(ctx, cfg.Profile)
	if err != nil {
		return ""
	}
	return shared.Region
}

// sharedConfigProfile parses the shared config and credentials files for one
// profile, and nothing more.
//
// A second LoadDefaultConfig would have been shorter, and would have read the
// file locations itself, but it is not free: a profile carrying
// `defaults_mode = auto` makes the SDK probe IMDS for the runtime region
// (resolveDefaultsModeOptions in resolve.go), and a container full URI with a
// hostname makes it resolve that host synchronously
// (resolveLocalHTTPCredProvider in resolve_credentials.go). Either can block on
// the caller's context and spend the budget the real credential load is about
// to need. So the file locations are passed in instead, from the same
// EnvConfig the SDK would have consulted.
func sharedConfigProfile(ctx context.Context, profile string) (awsconfig.SharedConfig, error) {
	env, err := awsconfig.NewEnvConfig()
	if err != nil {
		return awsconfig.SharedConfig{}, err
	}
	files, credFiles := awsconfig.DefaultSharedConfigFiles, awsconfig.DefaultSharedCredentialsFiles
	if env.SharedConfigFile != "" {
		files = []string{env.SharedConfigFile}
	}
	if env.SharedCredentialsFile != "" {
		credFiles = []string{env.SharedCredentialsFile}
	}
	return awsconfig.LoadSharedConfigProfile(ctx, profile, func(o *awsconfig.LoadSharedConfigOptions) {
		o.ConfigFiles, o.CredentialsFiles = files, credFiles
	})
}

// describeCredentialSource says which credentials an invocation with this
// config will use. Local and free: it reads the environment and the resolved
// config, and authenticates nothing.
//
// It exists because #58's failure was as much about diagnosis as resolution.
// Nothing bmcp printed said which of the several possible credential sources
// was in play, so an operator whose environment credentials were being
// discarded had no way to see that from the outside.
func (a *app) describeCredentialSource(cfg effectiveConfig) string {
	profile, outrankedBy, demotedAt := a.sharedProfileFor(cfg)
	switch {
	case profile != "":
		// The expiry clause belongs here and not at the call site, so that every
		// message built from this function carries it: doctor's `credentials` row,
		// authFailure's "(using %s)", and the credential_process refusal. An
		// operator meeting a demotion for the first time meets it in whichever of
		// those they happen to hit.
		//
		// demotedAt is zero unless sharedProfileFor departed from the documented
		// order, which is exactly when this needs saying — and in particular it is
		// zero for a profile named with --profile or BMCP_PROFILE, where the
		// environment's expiry had no bearing on what resolved. Announcing it there
		// would be a fresh instance of the dishonesty this change exists to remove.
		return "AWS profile " + profile + profileOrigin(cfg.ProfileSource) + demotionClause(demotedAt)
	case outrankedBy != "":
		return outrankedBy + ", which outrank AWS profile " + cfg.Profile + profileOrigin(cfg.ProfileSource)
	}
	// No profile to report. Naming what the SDK's default chain will actually
	// pick still beats naming the chain.
	if source := envCredentialSource(); source != "" {
		// Expired here too, but with nothing to demote to: sharedProfileFor returned
		// at its first line, so these dead credentials are what the SDK will sign
		// with. Saying so is the only help available — the remedy is a fresh
		// `aws-vault exec`, or an aws_profile in config.toml for bmcp to fall back
		// on.
		if expired := a.envCredentialsExpiredAt(); !expired.IsZero() {
			return source + ", which expired at " + formatExpiry(expired)
		}
		return source
	}
	return "the default AWS credential chain"
}

// demotionClause names the expired environment credentials a profile was
// preferred over, or nothing when none were.
func demotionClause(demotedAt time.Time) string {
	if demotedAt.IsZero() {
		return ""
	}
	return ", after the credentials in the environment were passed over as expired at " + formatExpiry(demotedAt)
}

// formatExpiry renders an expiry the way every other instant bmcp prints is
// rendered: RFC 3339 in UTC, so a message read in a CI log and one read on a
// laptop name the same moment.
func formatExpiry(at time.Time) string {
	return at.UTC().Format(time.RFC3339)
}

// profileOrigin renders " from <source>", or nothing when the source is
// unknown. Nothing should reach it with a profile and no source, but a message
// trailing off after "from" would be a worse way to discover that than one
// which simply omits the clause.
func profileOrigin(source profileSource) string {
	if source == profileSourceNone {
		return ""
	}
	return " from " + string(source)
}

// ssoLoginBudget is the time an interactive device flow needs to be worth
// starting. Not a measurement of how long a login takes — it is the line below
// which starting one means arranging for it to be killed half-finished, which
// is worse than declining and printing the command the operator can run
// themselves.
const ssoLoginBudget = 3 * time.Minute

// deviceFlowFits reports whether the context leaves room for an interactive
// login to complete.
//
// time.Until, deliberately, rather than the injectable a.now: the clock that
// decides whether the subprocess is killed is the runtime's, so a test clock
// that disagreed with it would be measuring the wrong thing. An unbounded
// context fits by definition, though no production path supplies one.
func deviceFlowFits(ctx context.Context) bool {
	deadline, bounded := ctx.Deadline()
	return !bounded || time.Until(deadline) >= ssoLoginBudget
}

// ssoLoginTimeout bounds a login bmcp was *asked* for — `bmcp login` — as
// opposed to one it slips into the budget of some other command.
//
// Not a reuse of ssoLoginBudget, whose docstring calls it the line below which
// starting a flow is pointless: a minimum, not a measurement, and three minutes
// of it. aws-cli's own PKCE callback waits ten (_OVERALL_TIMEOUT in
// awscli/customizations/sso/utils.py), so a shorter bound here would have
// exec.CommandContext SIGKILL `aws` in the middle of a window the operator is
// still allowed to answer in — the operator approves in the browser, the token
// is never written, and bmcp reports `signal: killed` for a login that from the
// outside succeeded. That is the failure ssoLoginBudget exists to prevent,
// reintroduced by the command whose entire purpose is to finish one.
const ssoLoginTimeout = 10 * time.Minute

// runSSOLogin shells out to `aws sso login`, which stays the only writer of
// ~/.aws/sso/cache. Shared by the implicit branch in awsCredentials and by
// cmdLogin, so the two cannot drift.
//
// Three things it does that the inline version it replaces did not.
//
// The leaf profile, not the one bmcp resolved. profileUsesSSO answers about the
// leaf of the source_profile chain — it is the only node whose credential type
// the SDK dispatches — while `aws sso login --profile X` reads X's *own* SSO
// config. So a chained profile passed the check and then failed the login with
// "profile does not have valid SSO configuration".
//
// The resolved absolute path goes into the exec, so a hasCommand test and the
// command that runs cannot disagree about which `aws` this is — and it is the
// injection point that made the post-login retry untestable before.
//
// The pinned descriptors, not the globals: a retrieval abandoned earlier in the
// run may have left either variable pointing at /dev/null on purpose, and this
// subprocess is not the one those sinks exist to contain. Handing it the global
// stderr destroys the verification URL and user code, leaving bmcp blocked on a
// device flow with nothing on screen; handing it the global stdin gives
// `aws sso login` end-of-file for the one prompt it may still need. stdout goes
// to fd 2 alongside stderr, which is load-bearing under a machine format
// elsewhere and harmless here.
//
// Nothing interposes on those descriptors. A pipe would let bmcp frame the URL
// in its own prose, and it costs both of the above: the child hands its fds to
// a browser grandchild, so cmd.Wait blocks until that closes them, and every
// interposition tried so far has ended with the URL on the floor.
func (a *app) runSSOLogin(ctx context.Context, profile string) error {
	leaf := ssoLoginProfile(ctx, profile)
	path, err := a.resolveCommand("aws")
	if err != nil {
		return fmt.Errorf("the AWS CLI is not on PATH, and it is what performs the login: %w", err)
	}
	cmd := exec.CommandContext(ctx, path, "sso", "login", "--profile", leaf)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.subprocessStdin(), a.subprocessStderr(), a.subprocessStderr()
	return cmd.Run()
}

// ssoLoginProfile names the profile `aws sso login --profile` must be given for
// a login on behalf of profile: the leaf of its source_profile chain, which is
// where the SSO configuration actually lives.
//
// Falls back to the profile it was given whenever the chain cannot be read. The
// login then fails with the AWS CLI's own account of why, which is a better
// answer than bmcp inventing one from a config file it could not parse.
func ssoLoginProfile(ctx context.Context, profile string) string {
	leaf, ok := ssoLeafConfig(ctx, profile)
	if !ok || leaf.Profile == "" {
		return profile
	}
	return leaf.Profile
}

func (a *app) awsCredentials(ctx context.Context, cfg effectiveConfig) (aws.Credentials, string, error) {
	// The SDK builds its default logger from os.Stderr when the config loads and
	// keeps that writer (config's resolveDefaultAWSConfig, smithy logging). Two
	// problems with letting it: after retrieveCredentials latches a sink, a later
	// load captures /dev/null and every SDK diagnostic for the rest of the run
	// disappears — and on the other side, a raw fd 2 writer would put SDK prose on
	// the stream a machine format promises carries one document and nothing else.
	// a.prose() is the writer that already answers both: bmcp's own channel, and
	// io.Discard under --format json.
	opts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithLogger(logging.NewStandardLogger(a.prose())),
	}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	// profile, not cfg.Profile, from here down. Every branch below that used to
	// read cfg.Profile was really asking "did this attempt resolve credentials
	// through a profile", and once an ambient profile can be outranked those two
	// questions have different answers.
	profile, outrankedBy, _ := a.sharedProfileFor(cfg)
	switch {
	case profile != "":
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	case outrankedBy != "":
		if region := ambientProfileRegion(ctx, cfg); region != "" {
			opts = append(opts, awsconfig.WithRegion(region))
		}
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Credentials{}, "", authError{a.authFailure(cfg, err)}
	}
	creds, err := a.retrieveCredentials(ctx, cfg, awsCfg.Credentials)
	if err == nil {
		return creds, awsCfg.Region, nil
	}
	// Resolved once, from configuration, and reused by the branch below: whether
	// this is an SSO profile has one answer for the whole attempt, and it does not
	// change because a retry failed differently.
	usesSSO := profile != "" && profileUsesSSO(ctx, profile)
	// Deciding this from configuration rather than from the error means it can
	// still fire for a failure a login will not fix — a valid SSO token whose
	// outer AssumeRole cannot reach STS, say. That is accepted rather than
	// narrowed: the only typed SSO error the SDK offers, ssocreds.InvalidTokenError,
	// is produced by the legacy code path alone, so gating on it would disable
	// auto-login for the sso_session form AWS now recommends. The cost is bounded
	// to an unnecessary login attempt on an interactive terminal, and the branch
	// below reports the original cause either way.
	//
	// a.machine is the same gate cmdInit and requireConfig apply: a machine format
	// is never interactive. Without it, `bmcp --format json <tool>` on a terminal
	// would block on a browser login it has promised not to ask for, and the login
	// subprocess would write its own prose straight to the inherited stderr —
	// which is the one thing a machine format guarantees will not happen. Refusing
	// here falls through to the actionable "run aws sso login" error below.
	//
	// Too little time left is the third refusal, and the newest. An SSO device
	// flow is a human reading a code, switching to a browser, authenticating and
	// approving, and exec.CommandContext kills the subprocess the moment the
	// deadline lands — so started under a budget it cannot finish in, the login
	// is arranged to be destroyed part-way: the operator approves in the browser,
	// the token is never written, and bmcp reports `signal: killed` for a login
	// that from the outside succeeded.
	//
	// The test is how much budget is left, not whether there is one. Every
	// production path now carries a deadline — awsCredentials is reached only
	// through newMCPClient, and both of its callers wrap the context — so asking
	// merely whether one exists refuses every login bmcp can ever be asked to
	// make, including the ones with ten minutes in hand. That is a capability
	// deleted by accident rather than the narrow protection intended here.
	//
	// So the two budgets separate, which is what they were always meant to do: a
	// tool call's CallTimeout is ten minutes and comfortably fits a device flow,
	// while SyncTimeout is sixty seconds and does not. `bmcp sync` and
	// `bmcp doctor` therefore stop asking — and for doctor that is a second
	// endorsement of the audited failures in cmdDoctor's own docstring, where an
	// expired SSO session met a sandbox that could not reach device
	// authorization and a diagnostic command hung on work it had no business
	// doing. The silent mint from ~/.aws/sso/cache needs no browser and is
	// untouched on every path.
	if usesSSO && deviceFlowFits(ctx) && !cfg.NonInteractive && !a.machine && a.isInteractive() {
		// What it says, and not the command it is about to run. Naming
		// `aws sso login` here would teach the one remedy every other message on
		// this path now withholds: an agent that reads it runs the AWS CLI itself,
		// outside bmcp's profile resolution and outside whatever its operator's own
		// instructions say about SSO. The subprocess announces itself well enough.
		fmt.Fprintf(a.prose(), "AWS SSO credentials for profile %s are expired or missing. Logging in.\n", profile)
		if runErr := a.runSSOLogin(ctx, profile); runErr != nil {
			// Carrying the failure the login was trying to repair, because the branch
			// is chosen from configuration now and fires for causes a login cannot
			// fix. Reporting only "aws sso login failed: exit status 1" for a machine
			// whose real problem was DNS names the symptom this code created and
			// hides the one the operator has.
			return aws.Credentials{}, "", authError{fmt.Errorf("aws sso login failed: %v, and the credential failure it was trying to repair was: %w", runErr, a.authFailure(cfg, err))}
		}
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Credentials{}, "", authError{a.authFailure(cfg, err)}
		}
		// Through the same wrapper as the first attempt, as defence in depth rather
		// than because a helper is known to run here: reaching this line needs
		// profileUsesSSO to have said yes, which means the leaf of the
		// source_profile chain resolves through SSO — and the SDK's
		// resolveCredsFromProfile ranks SSO above credential_process at that leaf,
		// so no helper should be involved. Wrapped anyway, because the cost is one
		// call and the alternative is an unwrapped Retrieve whose safety depends on
		// that precedence never changing. No test covers it: reaching it needs the
		// `aws sso login` subprocess to succeed, and it is built inline with no
		// injection point.
		creds, err = a.retrieveCredentials(ctx, cfg, awsCfg.Credentials)
	}
	if err != nil {
		if usesSSO {
			// Wrapped around authFailure rather than replacing it. Deciding this
			// branch from configuration means it now fires for every failure an SSO
			// profile can produce, not only the ones whose text happened to mention
			// SSO — a DNS failure reaching STS, an AccessDenied on a chained role and
			// an expired token all land here — so replacing the cause with "run aws
			// sso login" would hide the ones a login cannot fix. Reporting the cause
			// and the remedy together is the only version that is true in both cases.
			//
			// Going through authFailure is also what keeps #60's withholding in force
			// on this path: a chain whose leaf is a credential_process helper can
			// reach it, and interpolating the raw error here would put the payload
			// straight back into the message.
			//
			// authFailure names the source, which is the message #58 was filed
			// against: an operator who never chose this profile was being sent to log
			// into it, with nothing saying where it had come from.
			//
			// `bmcp login` rather than `aws sso login`, and the old clause is replaced
			// rather than joined: a message carrying both would satisfy every assertion
			// here while readers took whichever they happened to reach first. The
			// remedy has to be one command, because it is also what the generated
			// instructions key on — an agent runs the command a bmcp message names, and
			// only that one. It is bmcp's own, so the login goes through bmcp's profile
			// resolution rather than around it, and it is the only remedy that works on
			// a stale catalog, where the implicit login above never gets to run: the
			// sixty-second sync budget is shorter than a device flow, so deviceFlowFits
			// refuses long before the format or the terminal is consulted.
			//
			// --profile is always spelled out, even though this branch is reached only
			// with a resolved profile and a bare `bmcp login` would usually resolve the
			// same one. "Usually" is the problem: a call made with --profile prod or
			// BMCP_PROFILE would otherwise send its reader to log into whatever
			// config.toml names instead.
			return aws.Credentials{}, "", authError{fmt.Errorf("%w. If the AWS SSO session for %s has expired, run: bmcp --profile %s login", a.authFailure(cfg, err), profile, profile)}
		}
		return aws.Credentials{}, "", authError{a.authFailure(cfg, err)}
	}
	return creds, awsCfg.Region, nil
}

// retrieveCredentials resolves credentials with a credential_process helper's
// stderr and stdin each pointed wherever this invocation can afford to have it —
// two streams under two different policies, decided below.
//
// #61 and #65. processcreds hands the helper the process-global os.Stderr *and*
// os.Stdin — DefaultNewCommandBuilder.NewCommand, "display stderr on console for
// MFA" and "enable stdin for MFA" — and reads both variables when Retrieve
// builds the command. Each is a defect, in opposite directions.
//
// Outward (#61): the helper writes to fd 2 directly, outside everything bmcp
// renders and outside everything #60 withholds. A helper with tracing on echoes
// the credential JSON it just printed, on *success*, into whatever is capturing
// that descriptor. That is a CI log or an agent transcript, and under a machine
// format it is also the stream bmcp promised would carry nothing but one
// parseable document.
//
// Inward (#65): the helper *reads* fd 0, which for `echo '{...}' | bmcp call
// <tool>` is the payload runCall has not read yet — credentials resolve first,
// through cacheForCatalog. A helper that reads stdin at all, which is what a
// wrapper prompting with `read -r code` does by accident, consumes it. bmcp then
// finds stdin empty, falls back to payload "{}", and calls the tool with no
// arguments at all — reporting ok:true and exit 0. A wrong answer wearing the
// shape of a right one, and the only defect in this file that is silent on the
// success path.
//
// The config API cannot reach the assignment — Provider.commandBuilder is
// unexported and processcreds.Options carries only Timeout and
// CredentialSources, so WithProcessCredentialOptions is no help. Swapping the
// package variable around Retrieve is what is left. Building the provider
// ourselves with a custom NewCommandBuilder was the alternative and was
// rejected: it would mean reimplementing source_profile and assume-role
// chaining inside the credential path, which is where subtle breakage lives.
//
// Two things make the swap containable rather than merely brief. a.stderr and
// a.realStderr hold os.Stderr's *value* from startup, so bmcp's own output and
// every subprocess bmcp spawns itself keep reaching the original descriptor
// whatever this does to the variable. And the only reader that races it is the
// SDK's — bmcp starts no goroutines of its own — which is the whole subject of
// the restore rule below: that reader outlives a cancelled call, so the variable
// is not always safe to put back.
//
// It wraps Retrieve and nothing else on purpose: the `aws sso login` branch
// above deliberately hands its subprocess the real fd 0 and fd 2, and that is a
// browser prompt an operator needs to see and answer.
func (a *app) retrieveCredentials(ctx context.Context, cfg effectiveConfig, provider aws.CredentialsProvider) (aws.Credentials, error) {
	// An earlier retrieval was abandoned with a sink still installed, and the
	// goroutine that outlived it may still read that variable to build its
	// command. Recording the discard is all there is to do here; what keeps the
	// variable from being touched again is the `a.stderrSunk ||` and
	// `a.stdinSunk ||` disjunct in each policy below, which answers "keep" for a
	// latched stream and so opens no second sink and registers no restore.
	//
	// That also declines to re-run the policy for that stream. For stderr it costs
	// an operator at a terminal the MFA prompt for the rest of a run in which a
	// retrieval was already abandoned — the conservative direction, and the same
	// one the sink itself takes.
	if a.stderrSunk {
		a.helperStderrDiscarded = true
	}
	if a.stdinSunk {
		a.helperStdinDiscarded = true
	}
	// Two streams, two policies, decided separately — which is the correction #65
	// turns on. Its own issue text proposed putting stdin behind the stderr gate;
	// that gate is an early return leaving both descriptors alone, and it fires
	// for precisely the shape that loses the payload. `echo '{...}' | bmcp call
	// <tool>` at a terminal has fd 2 on the tty and fd 0 on the pipe, so a shared
	// gate answers "keep" and hands the helper the payload. The questions are
	// different because the streams are: one asks who can *see* fd 2, the other
	// asks who is *reading* fd 0.
	//
	// One consequence of splitting them is worth naming, because it used to be
	// structural and is now an invariant held up from outside. Before, a single
	// `if a.stderrSunk { return }` meant one abandonment froze both globals for
	// the rest of the run. Now a latch on one stream does not stop a write to the
	// other, so "no global is written while an abandoned goroutine may read it"
	// holds only because neither policy can change between retrievals.
	//
	// Each input is fixed before the first one: a.machine and a.ownsStdin are set
	// before anything resolves credentials (selectOutput before dispatch, and
	// cmdServe and runCall each ahead of their own first resolution),
	// cfg.NonInteractive comes from a flag or the environment, and
	// stderrIsTerminal reads a descriptor pinned in run(). Note that "fixed before
	// the first retrieval" is the property, not "only ever goes false to true" —
	// a monotonic flag that flipped after an abandonment would write os.Stdin
	// under the goroutine that abandonment left behind. If any of these becomes
	// per-command, this needs a real guard rather than an argument.
	//
	// The MFA prompt the SDK's comment protects is worth keeping only where all
	// three of these hold: someone is watching fd 2, bmcp has not promised to keep
	// that stream free of prose, and this invocation has not declared that nothing
	// will answer a prompt. Anything else discards it.
	//
	// cfg.NonInteractive is in the conjunction because a prompt nobody will answer
	// buys nothing, so keeping it is pure exposure. That matters because of the
	// residual case below.
	//
	// The residual case, measured rather than assumed: a *pty* is a character
	// device, so `script -q log bmcp <tool>`, `docker run -t`, `ssh -t` and a
	// logging tmux pane all look exactly like an operator's own terminal here and
	// their transcripts do capture what the helper writes. No terminal test can
	// separate those — x/term.IsTerminal answers the same — so what is left is to
	// narrow the branch by something other than the descriptor, which is what
	// a.machine and cfg.NonInteractive do, and to say plainly that a human-format
	// interactive run under a recorder is still exposed.
	keepStderr := a.stderrSunk || (!a.machine && !cfg.NonInteractive && a.stderrIsTerminal())
	// Stdin asks something else entirely, and deliberately not a terminal test.
	// Whether a *person* is typing at fd 0 is not the question; whether *bmcp* is
	// reading it is. a.ownsStdin says so, and it is set by `bmcp call` when its
	// payload is arriving on stdin and by `bmcp serve` for the whole session.
	//
	// A third reader declines to set it: the `bmcp init` wizard, which prompts,
	// syncs, and then prompts again — so a helper spawned by that sync does
	// inherit the descriptor its later answers arrive on. Left that way on
	// purpose. The wizard runs only when fd 0 is a character device, which means
	// an operator is there, and first-run setup is the resolution most likely to
	// need an MFA prompt of its own; taking fd 0 away from the helper there would
	// trade a real prompt for a typed-ahead answer nobody has reported losing.
	//
	// A terminal test was the obvious gate and is wrong. It also fires for
	// `printf %s "$MFA_CODE" | bmcp call <tool> '{"query":"x"}'`, where the
	// payload came from argv and the pipe was put there *for the helper* — so
	// bmcp would answer a working setup with end-of-file to protect a payload
	// that was never on that descriptor. saml2aws hands os.Stdin to its prompter,
	// gimme-aws-creds reads it with input(), and a `vault login token=-` shim
	// needs it; none of them are bmcp's to break. The same applies to every
	// command that never reads stdin at all — sync, doctor, list, describe — which
	// a terminal test would have sunk for no benefit.
	//
	// Where bmcp does own the descriptor there is no prompt to preserve, because
	// the bytes on it are bmcp's. A helper that blocks waiting for input then
	// reads end-of-file rather than eating the call's arguments or the client's
	// protocol frames, which is the more honest failure.
	//
	// This is also the conjunct the stderr policy above notes it does not
	// establish, and it still does not: a run with stdin redirected and
	// --non-interactive unset keeps the helper's *stderr* visible even though
	// nothing can type at it. Deliberately left, because helpers that read
	// /dev/tty or a hardware token prompt without fd 0, and taking their prompt
	// away is a separate decision from protecting the payload.
	keepStdin := a.stdinSunk || !a.ownsStdin
	if keepStderr && keepStdin {
		return provider.Retrieve(ctx)
	}
	// Both sinks are opened before either is installed, so a failure on the second
	// cannot leave the first swapped in with no restore arranged. They are two
	// opens rather than one descriptor used twice because the modes differ: the
	// helper writes to fd 2 and reads fd 0, and /dev/null opened write-only is not
	// a readable stdin.
	var errSink, inSink *os.File
	if !keepStderr {
		f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return a.retrieveWithoutSinks(ctx, provider, err)
		}
		errSink = f
	}
	if !keepStdin {
		f, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
		if err != nil {
			if errSink != nil {
				errSink.Close()
			}
			return a.retrieveWithoutSinks(ctx, provider, err)
		}
		inSink = f
	}
	if inSink != nil {
		a.helperStdinDiscarded = true
		// The pinned startup descriptor rather than the global, for the reason the
		// stderr restore below gives. Reaching this line needs !a.stdinSunk, and
		// only the abandonment path leaves a sink installed, so the two agree
		// here today — the pin is the source that cannot go wrong rather than a
		// repair for a state this line can reach.
		restoreStdin := a.subprocessStdin()
		os.Stdin = inSink
		// The same restore rule as stderr's below, for the same abandoned
		// goroutine: it reads os.Stdin when it reaches NewCommand, which is after
		// a cancelled Retrieve has already returned. Putting fd 0 back on that path
		// hands the helper the payload this function exists to protect — the very
		// collision, merely later. So the sink stays and stdinSunk records it.
		defer func() {
			if ctx.Err() != nil {
				a.stdinSunk = true
				return
			}
			os.Stdin = restoreStdin
			inSink.Close()
		}()
	}
	if errSink != nil {
		a.helperStderrDiscarded = true
		// The pinned startup descriptor, not os.Stderr. Reading the global here
		// meant that a second call after an abandoned one saved the *first* call's
		// sink as the thing to restore, installed /dev/null permanently, and closed
		// the descriptor the live retrieval was using rather than the stale one.
		restore := a.subprocessStderr()
		os.Stderr = errSink
		// Put back only when the retrieval actually finished — and left in place,
		// still open, when it did not.
		//
		// The claim above that nothing races this is true of bmcp and false of the
		// SDK, in the one call it has to hold for. LoadDefaultConfig always wraps
		// the provider in an aws.CredentialsCache (config's
		// wrapWithCredentialsCache), whose Retrieve runs the real provider on a
		// singleflight goroutine and then selects on the caller's ctx.Done(). On a
		// cancelled or expired context it abandons that goroutine and returns — and
		// the goroutine is handed a suppressedContext, whose Done() is nil and
		// Deadline() reports none, so nothing ever stops it. It reaches NewCommand
		// afterwards, reads os.Stderr *then*, and runs the helper with whatever the
		// variable now holds.
		//
		// Restoring on that path therefore hands the helper the captured descriptor
		// after bmcp has already reported failure, which is exactly the disclosure
		// this function exists to prevent. Reproduced 3/3 before this check
		// existed. Closing the sink instead is no better: exec starts the child
		// anyway, with fd 2 closed, so the first file the helper opens becomes its
		// stderr.
		//
		// So the sink stays, the fd is leaked on purpose, and stderrSunk records
		// it. The latch is what the first version of this rule lacked: the run does
		// not necessarily end here — a failed sync is downgraded to a warning and
		// the run continues (see cacheForCatalog), resolving credentials again on a
		// fresh context — and without the latch that second call reassigned
		// os.Stderr underneath a goroutine still reading it, which could hand a
		// helper a closed descriptor and made the write a data race besides.
		//
		// ctx.Err() == nil is the conservative side of the test: it can only be nil
		// if Retrieve returned through the channel, which happens after the
		// goroutine's work is done. A context that expires just after a successful
		// retrieval merely keeps the sink for the rest of the run, which costs
		// nothing. This is a fact about aws-sdk-go-v2's cache, so it is worth
		// re-checking on an SDK bump.
		defer func() {
			if ctx.Err() != nil {
				a.stderrSunk = true
				return
			}
			os.Stderr = restore
			errSink.Close()
		}()
	}
	return provider.Retrieve(ctx)
}

// retrieveWithoutSinks is what retrieveCredentials does when /dev/null cannot be
// opened: fail closed where there is something to contain, and otherwise get on
// with the retrieval.
//
// Refusing unconditionally would fail static keys, SSO, web identity and IMDS —
// none of which spawn a subprocess — and would explain the refusal in terms of a
// credential_process helper the profile may not even have.
func (a *app) retrieveWithoutSinks(ctx context.Context, provider aws.CredentialsProvider, err error) (aws.Credentials, error) {
	if chainRunsACredentialProcess(provider) {
		return aws.Credentials{}, fmt.Errorf("cannot open %s to contain a credential_process helper's streams: %w", os.DevNull, err)
	}
	return provider.Retrieve(ctx)
}

// chainRunsACredentialProcess reports whether the resolved provider chain can
// execute a credential_process helper, so the refusal above is scoped to the
// chains that have something to disclose.
//
// aws.CredentialsCache forwards ProviderSources to the provider it wraps, and
// the assume-role provider forwards its source's — so a source_profile chain
// whose leaf is a helper reports the process source through every hop above it.
// Measured across the shapes that matter, and pinned by
// TestChainRunsACredentialProcessSeesEveryProcessShape: a plain
// credential_process profile reports it, an assume-role chain over one reports
// it, and static keys, an sso_session profile and a legacy SSO profile do not.
//
// A provider that does not implement the interface answers yes — but that arm
// describes an unwrapped provider, which is not what the call site hands in.
// LoadDefaultConfig always returns an *aws.CredentialsCache, which does
// implement the interface and returns an empty slice when the provider *it*
// wraps does not (aws/credential_cache.go). So an undescribed chain under the
// cache reaches the loop with nothing to match and answers no. Fail-open, not
// fail-closed, for the one shape the comment was written about. Left as it is
// rather than quietly changed: every provider this SDK ships reports its
// sources, so no measured chain answers differently, and making len == 0 mean
// yes would start refusing on a future provider that legitimately reports none.
//
// Both process constants are tested although no measured shape reports one
// without the other — dropping either arm changes no answer today. Cheap
// insurance rather than a pinned behaviour, and the test above prints the
// sources it saw so a future divergence says which arm carried it.
func chainRunsACredentialProcess(provider aws.CredentialsProvider) bool {
	source, ok := provider.(aws.CredentialProviderSource)
	if !ok {
		return true
	}
	for _, s := range source.ProviderSources() {
		if s == aws.CredentialSourceProcess || s == aws.CredentialSourceProfileProcess {
			return true
		}
	}
	return false
}

// authFailure names the credential source alongside the SDK's error, so the
// operator is not left guessing which of profile, environment and default chain
// produced it — and in particular is not sent to repair a profile this attempt
// never consulted.
func (a *app) authFailure(cfg effectiveConfig, err error) error {
	if withheld := a.credentialProcessFailure(cfg, err); withheld != nil {
		return withheld
	}
	return fmt.Errorf("%w (using %s)", err, a.describeCredentialSource(cfg))
}

// credentialProcessFailure replaces the SDK's own text when the failure came
// from a credential_process helper, and returns nil when it did not.
//
// processcreds embeds the helper's complete, uncapped stdout in its parse error
// ("parse failed of process output: %s", provider.go), and output json.Unmarshal
// rejects routinely still contains the credentials — the usual cause is
// something prepended to otherwise valid JSON: a wrapper's warning line, a
// helper banner, a progress line, a shell profile writing to stdout. bmcp's
// machine output exists to be parsed and logged, and BORIS.md tells agents to
// call bmcp and summarise what it says, so forwarding that error puts live keys
// into agent transcripts and CI logs. That is #60, and it is one stray `echo`
// away for every aws-vault, saml2aws or in-house shell wrapper.
//
// Withheld rather than scrubbed. Redaction over an arbitrary helper's output
// means guessing at formats it may not use, and a partial redaction reads as
// safe when it is not. The operator loses nothing they cannot recover: the
// helper is a command they can run themselves, which is what the message says.
//
// Every processcreds error is withheld, not only the parse error that leaks
// today. Which of them carries a payload is the SDK's decision, revisited on
// every dependency bump, and a credential path is the wrong place to track
// that. What went wrong is still reported — from the error's own type, never
// its text, so nothing the helper wrote can reach the message by another route.
func (a *app) credentialProcessFailure(cfg effectiveConfig, err error) error {
	var provErr *processcreds.ProviderError
	if !errors.As(err, &provErr) {
		return nil
	}
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
		exitErr   *exec.ExitError
	)
	cause := "did not return usable credentials"
	switch {
	case errors.As(err, &syntaxErr), errors.As(err, &typeErr):
		cause = "printed output that is not valid credential JSON"
	case errors.As(err, &exitErr) && exitErr.ExitCode() >= 0:
		// An exit status is an integer, so it cannot carry a payload, and it is the
		// one detail worth keeping: processcreds runs the helper through `sh -c`,
		// so 127 and 126 name one that is missing or not executable, which is most
		// of what goes wrong here.
		cause = fmt.Sprintf("exited with status %d", exitErr.ExitCode())
	case errors.As(err, &exitErr):
		// A negative ExitCode means a signal rather than an exit, and the signal
		// this path sees is processcreds killing a helper that overran its own
		// timeout (DefaultTimeout, one minute). Reporting that as "status -1" would
		// name something that is not a status and lose the fact that it was killed.
		cause = "was killed before it returned credentials, which is what happens when it overruns its timeout"
	}
	// Naming the discards, when there were any. Withholding the SDK's error text
	// leaves the helper's own diagnostics as the operator's next step, and #61
	// took those away too — so a message that only said "run it yourself" would
	// let an empty CI log read as "the helper printed nothing" when bmcp is what
	// threw it away.
	//
	// The stdin line is the same courtesy for a failure bmcp *caused*: #65 gives a
	// helper /dev/null to read wherever nobody is typing, so one that prompts sees
	// end-of-file and whatever it does next — exit non-zero, return nothing —
	// arrives here as the helper's own fault with nothing to say bmcp closed the
	// input. It also tells the operator why running the helper themselves, at a
	// terminal, may succeed where bmcp did not.
	discarded := ""
	if a.helperStderrDiscarded {
		discarded = ", and anything it wrote to stderr was discarded rather than shown here, for the same reason"
	}
	if a.helperStdinDiscarded {
		discarded += ". Its stdin was /dev/null, so a helper that prompts for input read end-of-file — bmcp does that when it is reading fd 0 itself, to keep the helper from consuming the payload of the call or the frames of a serve session"
	}
	return fmt.Errorf("credential_process helper %s (using %s). Run the helper yourself to see what it printed — its output is withheld here because it can contain live credentials%s", cause, a.describeCredentialSource(cfg), discarded)
}

// profileUsesSSO reports whether profile resolves through AWS SSO, following
// source_profile links so a role assumed from an SSO profile counts too.
//
// It decides SSO remediation from configuration, replacing looksLikeSSO, which
// lowercased the error text and matched "sso", "token" or "expired". Those are
// ordinary words in unrelated AWS errors — and one of them appears in the
// credentials themselves. A credential_process helper whose leaked payload
// carried a SessionToken matched on "token", so #60's two defects masked each
// other: whether a secret escaped or the advice was wrong depended on whether
// the helper happened to emit that substring. When it did, an operator with no
// SSO configuration anywhere was told to run `aws sso login`, the real cause
// was never mentioned, and interactively the branch above would have run it.
//
// A profile that cannot be read is not an SSO profile. Saying so here is not
// hiding the failure: whatever made it unreadable is the error being reported.
func profileUsesSSO(ctx context.Context, profile string) bool {
	leaf, ok := ssoLeafConfig(ctx, profile)
	if !ok {
		return false
	}
	// Static keys, credential_source and web_identity_token_file are all ranked
	// above SSO in that same switch, and nothing validates them as mutually
	// exclusive with SSO keys — validateCredentialType does not mention SSO at
	// all. So a profile carrying `credential_source = Ec2InstanceMetadata`
	// alongside a stale `sso_session` resolves through IMDS, and calling it SSO
	// would send an operator whose IMDS is unreachable to a login that has
	// nothing to do with the failure. credential_process is deliberately not in
	// this list: the SDK ranks it *below* SSO, so a profile with both does
	// resolve through SSO.
	switch {
	case leaf.Credentials.HasKeys(), leaf.CredentialSource != "", leaf.WebIdentityTokenFile != "":
		return false
	}
	// The SDK's own hasSSOConfiguration predicate, key for key: sso_session for
	// the current form, and any one of the legacy keys, which it accepts
	// individually. Mirroring it rather than picking the two obvious keys is
	// what keeps this from drifting away from the branch it is predicting.
	return leaf.SSOSessionName != "" || leaf.SSOStartURL != "" ||
		leaf.SSORegion != "" || leaf.SSOAccountID != "" || leaf.SSORoleName != ""
}

// ssoLeafConfig resolves profile and follows source_profile to the leaf, which
// is the only node whose credential type the SDK ever dispatches:
// resolveCredsFromProfile tests Source != nil first and recurses, so a node
// carrying source_profile never has its own SSO fields consulted. Asking every
// node instead would call a profile SSO on the strength of a stale sso_session
// line sitting above a chain that resolves from static keys — and
// clearCredentialOptions is what makes that reachable, since it wipes the legacy
// SSO keys off a chained profile but leaves SSOSessionName behind
// (shared_config.go).
//
// ok is false when the profile cannot be read at all. Every caller treats that
// as "not SSO", which is not hiding the failure: whatever made it unreadable is
// the error being reported.
func ssoLeafConfig(ctx context.Context, profile string) (awsconfig.SharedConfig, bool) {
	shared, err := sharedConfigProfile(ctx, profile)
	if err != nil {
		return awsconfig.SharedConfig{}, false
	}
	leaf := &shared
	for leaf.Source != nil {
		leaf = leaf.Source
	}
	return *leaf, true
}

// ssoTokenExpiry reports when the cached SSO token for this profile's leaf
// expires, reading ~/.aws/sso/cache and contacting nothing.
//
// It exists because `aws sso login` runs with force_refresh=True
// (awscli/customizations/sso/login.py) and so never short-circuits on a token
// that is still good — without this guard, `bmcp login` would open a browser
// every time it is run, including on the runs where nothing is wrong.
//
// A file read rather than a credential resolution, deliberately. Asking
// awsCredentials whether the credentials work would re-enter the very branch
// whose gate `bmcp login` exists to sit outside, and would spawn a
// credential_process helper on the way. The cost of the cheap version is that it
// is blind to a token the BORIS gateway rejects for some reason of its own —
// which is a failure no login repairs, and which the remedy text deliberately
// does not fire for either.
//
// The cache key follows the SDK's own derivation, which differs between the two
// profile forms: the sso_session name for the current form (resolveSSOCredentials
// hashes SSOSession.Name), the start URL for the legacy one (ssocreds.New hashes
// StartURL). Getting this wrong is invisible rather than loud — it names a file
// that does not exist, and a missing file means "expired", so the failure mode
// is a browser that opens when it need not have.
func ssoTokenExpiry(ctx context.Context, profile string) (time.Time, error) {
	leaf, ok := ssoLeafConfig(ctx, profile)
	if !ok {
		return time.Time{}, fmt.Errorf("profile %s could not be read", profile)
	}
	key := leaf.SSOStartURL
	if leaf.SSOSession != nil {
		key = leaf.SSOSession.Name
	}
	if key == "" {
		return time.Time{}, fmt.Errorf("profile %s names no SSO session or start URL", profile)
	}
	path, err := ssocreds.StandardCachedTokenFilepath(key)
	if err != nil {
		return time.Time{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	// Only the one field, and no accessToken: a token this function returned as
	// valid would otherwise be one it had read into memory for no reason, and the
	// zero value of a struct nobody logs is the cheapest way to keep it out of a
	// panic trace. aws-cli writes this file non-atomically (O_WRONLY|O_CREAT then
	// truncate then write, botocore/utils.py), so a read racing a concurrent login
	// can land on a zero-length window — which arrives here as a parse error and
	// is treated as "expired", the same as absent.
	var cached struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(body, &cached); err != nil {
		return time.Time{}, fmt.Errorf("cached SSO token at %s is not readable JSON: %w", path, err)
	}
	if cached.ExpiresAt == "" {
		return time.Time{}, fmt.Errorf("cached SSO token at %s names no expiry", path)
	}
	at, err := time.Parse(time.RFC3339, cached.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("cached SSO token at %s has an unparseable expiry: %w", path, err)
	}
	return at, nil
}
