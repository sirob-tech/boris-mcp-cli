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
	// A bounded context is the third refusal, and the newest. An SSO device flow
	// is a human walking to a browser, and exec.CommandContext kills the
	// subprocess the moment the deadline lands — so under a budget the login does
	// not merely risk being slow, it is arranged to be destroyed part-way: the
	// operator approves in the browser, the token is never written, and bmcp
	// reports `signal: killed` for a login that from the outside succeeded. That
	// is already what `bmcp sync` does today, whose credential load runs inside
	// the same SyncTimeout, and doctor joins it once doctor stops resolving
	// credentials outside the sync. Refusing is not a capability lost: the silent
	// mint from ~/.aws/sso/cache, which is the heal that matters and needs no
	// browser, happens inside retrieveCredentials above and is untouched. What is
	// lost is a login that could not have completed anyway, replaced by the
	// `aws sso login --profile X` remedy the branch below already prints.
	_, bounded := ctx.Deadline()
	if usesSSO && !bounded && !cfg.NonInteractive && !a.machine && a.isInteractive() {
		fmt.Fprintf(a.prose(), "AWS SSO credentials for profile %s are expired or missing. Running aws sso login --profile %s\n", profile, profile)
		cmd := exec.CommandContext(ctx, "aws", "sso", "login", "--profile", profile)
		// The pinned descriptor, not os.Stderr: a retrieval abandoned earlier in
		// this run may have left the variable pointing at /dev/null on purpose, and
		// this subprocess is not the one that sink exists to contain. Handing it the
		// global destroyed the verification URL and user code, leaving bmcp blocked
		// on a device flow with nothing on screen to answer.
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, a.subprocessStderr(), a.subprocessStderr()
		if runErr := cmd.Run(); runErr != nil {
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
			return aws.Credentials{}, "", authError{fmt.Errorf("%w. If the AWS SSO session for %s has expired, run: aws sso login --profile %s", a.authFailure(cfg, err), profile, profile)}
		}
		return aws.Credentials{}, "", authError{a.authFailure(cfg, err)}
	}
	return creds, awsCfg.Region, nil
}

// retrieveCredentials resolves credentials with a credential_process helper's
// stderr pointed wherever this invocation can afford to have it.
//
// #61. processcreds hands the helper the process-global os.Stderr —
// DefaultNewCommandBuilder.NewCommand, "display stderr on console for MFA" — and
// reads that variable when Retrieve builds the command. So the helper writes to
// fd 2 directly, outside everything bmcp renders and outside everything #60
// withholds: a helper with tracing on echoes the credential JSON it just
// printed, on *success*, into whatever is capturing that descriptor. That is a
// CI log or an agent transcript, and under a machine format it is also the
// stream bmcp promised would carry nothing but one parseable document.
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
// above deliberately hands its subprocess os.Stderr, and that is a browser
// prompt an operator needs to see.
func (a *app) retrieveCredentials(ctx context.Context, cfg effectiveConfig, provider aws.CredentialsProvider) (aws.Credentials, error) {
	// An earlier retrieval was abandoned with the sink still installed, and the
	// goroutine that outlived it may still read os.Stderr to build its command.
	// So the variable is left exactly as it is: no second sink, no restore. It
	// already points at /dev/null, which is the containment this function exists
	// for, so there is nothing to do but retrieve.
	//
	// Returning here also declines to re-run the policy, which would answer on a
	// descriptor that is now /dev/null rather than on fd 2. That costs an operator
	// at a terminal the MFA prompt for the rest of a run in which a retrieval was
	// already abandoned — the conservative direction, and the same one the sink
	// itself takes.
	if a.stderrSunk {
		a.helperStderrDiscarded = true
		return provider.Retrieve(ctx)
	}
	// The MFA prompt the SDK's comment protects is worth keeping only where all
	// three of these hold: someone is watching fd 2, bmcp has not promised to keep
	// that stream free of prose, and this invocation has not declared that nothing
	// will answer a prompt. Anything else discards it.
	//
	// cfg.NonInteractive is in the conjunction because a prompt nobody will answer
	// buys nothing, so keeping it is pure exposure. That matters because of the
	// residual case below.
	//
	// Note what this does *not* establish. The SSO branch above asks
	// a.isInteractive(), which tests stdin; this asks about stderr, and
	// cfg.NonInteractive is only a flag or an environment variable. So a run with
	// stdin redirected and the flag unset keeps the helper's stderr visible even
	// though nothing can type an MFA code at it. Narrowing that means adding the
	// stdin test here too, which would take the prompt away from helpers that read
	// /dev/tty or a hardware token rather than stdin — a live question, not an
	// oversight.
	//
	// The residual case, measured rather than assumed: a *pty* is a character
	// device, so `script -q log bmcp <tool>`, `docker run -t`, `ssh -t` and a
	// logging tmux pane all look exactly like an operator's own terminal here and
	// their transcripts do capture what the helper writes. No terminal test can
	// separate those — x/term.IsTerminal answers the same — so what is left is to
	// narrow the branch by something other than the descriptor, which is what
	// a.machine and cfg.NonInteractive do, and to say plainly that a human-format
	// interactive run under a recorder is still exposed.
	if !a.machine && !cfg.NonInteractive && a.stderrIsTerminal() {
		return provider.Retrieve(ctx)
	}
	sink, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		// Failing closed, but only where there is something to contain. Refusing
		// unconditionally would fail static keys, SSO, web identity and IMDS —
		// none of which spawn a subprocess — and would explain the refusal in
		// terms of a credential_process helper the profile may not even have.
		if chainRunsACredentialProcess(provider) {
			return aws.Credentials{}, fmt.Errorf("cannot open %s to contain a credential_process helper's output: %w", os.DevNull, err)
		}
		return provider.Retrieve(ctx)
	}
	a.helperStderrDiscarded = true
	// The pinned startup descriptor, not os.Stderr. Reading the global here meant
	// that a second call after an abandoned one saved the *first* call's sink as
	// the thing to restore, installed /dev/null permanently, and closed the
	// descriptor the live retrieval was using rather than the stale one.
	restore := a.subprocessStderr()
	os.Stderr = sink
	// Put back only when the retrieval actually finished — and left in place,
	// still open, when it did not.
	//
	// The claim above that nothing races this is true of bmcp and false of the
	// SDK, in the one call it has to hold for. LoadDefaultConfig always wraps the
	// provider in an aws.CredentialsCache (config's wrapWithCredentialsCache),
	// whose Retrieve runs the real provider on a singleflight goroutine and then
	// selects on the caller's ctx.Done(). On a cancelled or expired context it
	// abandons that goroutine and returns — and the goroutine is handed a
	// suppressedContext, whose Done() is nil and Deadline() reports none, so
	// nothing ever stops it. It reaches NewCommand afterwards, reads os.Stderr
	// *then*, and runs the helper with whatever the variable now holds.
	//
	// Restoring on that path therefore hands the helper the captured descriptor
	// after bmcp has already reported failure, which is exactly the disclosure
	// this function exists to prevent. Reproduced 3/3 before this check existed.
	// Closing the sink instead is no better: exec starts the child anyway, with
	// fd 2 closed, so the first file the helper opens becomes its stderr.
	//
	// So the sink stays, the fd is leaked on purpose, and stderrSunk records it.
	// The latch is what the first version of this rule lacked: the run does not
	// necessarily end here — a failed sync is downgraded to a warning and the run
	// continues (see cacheForCatalog), resolving credentials again on a fresh
	// context — and without the latch that second call reassigned os.Stderr
	// underneath a goroutine still reading it, which could hand a helper a closed
	// descriptor and made the write a data race besides.
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
		sink.Close()
	}()
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
	// Naming the discard, when there was one. Withholding the SDK's error text
	// leaves the helper's own diagnostics as the operator's next step, and #61
	// took those away too — so a message that only said "run it yourself" would
	// let an empty CI log read as "the helper printed nothing" when bmcp is what
	// threw it away.
	discarded := ""
	if a.helperStderrDiscarded {
		discarded = ", and anything it wrote to stderr was discarded rather than shown here, for the same reason"
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
	shared, err := sharedConfigProfile(ctx, profile)
	if err != nil {
		return false
	}
	// The leaf of the source_profile chain, because it is the only node whose
	// credential type the SDK ever dispatches: resolveCredsFromProfile tests
	// Source != nil first and recurses, so a node carrying source_profile never
	// has its own SSO fields consulted. Asking every node instead would call a
	// profile SSO on the strength of a stale sso_session line sitting above a
	// chain that resolves from static keys — and clearCredentialOptions is what
	// makes that reachable, since it wipes the legacy SSO keys off a chained
	// profile but leaves SSOSessionName behind (shared_config.go).
	leaf := &shared
	for leaf.Source != nil {
		leaf = leaf.Source
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
