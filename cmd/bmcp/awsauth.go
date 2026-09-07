package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
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
func sharedProfileFor(cfg effectiveConfig) (profile, outrankedBy string) {
	if cfg.Profile == "" {
		return "", ""
	}
	if cfg.ProfileSource.namedForThisInvocation() {
		return cfg.Profile, ""
	}
	if source := envCredentialSource(); source != "" {
		return "", source
	}
	return cfg.Profile, ""
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
func describeCredentialSource(cfg effectiveConfig) string {
	profile, outrankedBy := sharedProfileFor(cfg)
	switch {
	case profile != "":
		return "AWS profile " + profile + profileOrigin(cfg.ProfileSource)
	case outrankedBy != "":
		return outrankedBy + ", which outrank AWS profile " + cfg.Profile + profileOrigin(cfg.ProfileSource)
	}
	// No profile to report. Naming what the SDK's default chain will actually
	// pick still beats naming the chain.
	if source := envCredentialSource(); source != "" {
		return source
	}
	return "the default AWS credential chain"
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
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	// profile, not cfg.Profile, from here down. Every branch below that used to
	// read cfg.Profile was really asking "did this attempt resolve credentials
	// through a profile", and once an ambient profile can be outranked those two
	// questions have different answers.
	profile, outrankedBy := sharedProfileFor(cfg)
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
		return aws.Credentials{}, "", authError{authFailure(cfg, err)}
	}
	creds, err := awsCfg.Credentials.Retrieve(ctx)
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
	if usesSSO && !cfg.NonInteractive && !a.machine && isInteractive() {
		fmt.Fprintf(a.prose(), "AWS SSO credentials for profile %s are expired or missing. Running aws sso login --profile %s\n", profile, profile)
		cmd := exec.CommandContext(ctx, "aws", "sso", "login", "--profile", profile)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if runErr := cmd.Run(); runErr != nil {
			// Carrying the failure the login was trying to repair, because the branch
			// is chosen from configuration now and fires for causes a login cannot
			// fix. Reporting only "aws sso login failed: exit status 1" for a machine
			// whose real problem was DNS names the symptom this code created and
			// hides the one the operator has.
			return aws.Credentials{}, "", authError{fmt.Errorf("aws sso login failed: %v, and the credential failure it was trying to repair was: %w", runErr, authFailure(cfg, err))}
		}
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Credentials{}, "", authError{authFailure(cfg, err)}
		}
		creds, err = awsCfg.Credentials.Retrieve(ctx)
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
			return aws.Credentials{}, "", authError{fmt.Errorf("%w. If the AWS SSO session for %s has expired, run: aws sso login --profile %s", authFailure(cfg, err), profile, profile)}
		}
		return aws.Credentials{}, "", authError{authFailure(cfg, err)}
	}
	return creds, awsCfg.Region, nil
}

// authFailure names the credential source alongside the SDK's error, so the
// operator is not left guessing which of profile, environment and default chain
// produced it — and in particular is not sent to repair a profile this attempt
// never consulted.
func authFailure(cfg effectiveConfig, err error) error {
	if withheld := credentialProcessFailure(cfg, err); withheld != nil {
		return withheld
	}
	return fmt.Errorf("%w (using %s)", err, describeCredentialSource(cfg))
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
func credentialProcessFailure(cfg effectiveConfig, err error) error {
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
	return fmt.Errorf("credential_process helper %s (using %s). Run the helper yourself to see what it printed — its output is withheld here because it can contain live credentials", cause, describeCredentialSource(cfg))
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
