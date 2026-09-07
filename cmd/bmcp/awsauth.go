package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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
	// Parses the shared config files and nothing more. A second
	// LoadDefaultConfig would have been shorter, and would have read the file
	// locations itself, but it is not free: a profile carrying
	// `defaults_mode = auto` makes the SDK probe IMDS for the runtime region
	// (resolveDefaultsModeOptions in resolve.go), and a container full URI with
	// a hostname makes it resolve that host synchronously
	// (resolveLocalHTTPCredProvider in resolve_credentials.go). Either can block
	// on the caller's context and spend the budget the real credential load is
	// about to need — which is the same class of defect as the link-local stall
	// this change removed. So the file locations are passed in instead, from the
	// same EnvConfig the SDK would have consulted.
	files, credFiles := awsconfig.DefaultSharedConfigFiles, awsconfig.DefaultSharedCredentialsFiles
	if env.SharedConfigFile != "" {
		files = []string{env.SharedConfigFile}
	}
	if env.SharedCredentialsFile != "" {
		credFiles = []string{env.SharedCredentialsFile}
	}
	shared, err := awsconfig.LoadSharedConfigProfile(ctx, cfg.Profile, func(o *awsconfig.LoadSharedConfigOptions) {
		o.ConfigFiles, o.CredentialsFiles = files, credFiles
	})
	if err != nil {
		return ""
	}
	return shared.Region
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
	// a.machine is the same gate cmdInit and requireConfig apply: a machine format
	// is never interactive. Without it, `bmcp --format json <tool>` on a terminal
	// would block on a browser login it has promised not to ask for, and the login
	// subprocess would write its own prose straight to the inherited stderr —
	// which is the one thing a machine format guarantees will not happen. Refusing
	// here falls through to the actionable "run aws sso login" error below.
	if profile != "" && !cfg.NonInteractive && !a.machine && looksLikeSSO(err) && isInteractive() {
		fmt.Fprintf(a.prose(), "AWS SSO credentials for profile %s are expired or missing. Running aws sso login --profile %s\n", profile, profile)
		cmd := exec.CommandContext(ctx, "aws", "sso", "login", "--profile", profile)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if runErr := cmd.Run(); runErr != nil {
			return aws.Credentials{}, "", authError{fmt.Errorf("aws sso login failed: %w", runErr)}
		}
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Credentials{}, "", authError{authFailure(cfg, err)}
		}
		creds, err = awsCfg.Credentials.Retrieve(ctx)
	}
	if err != nil {
		if profile != "" && looksLikeSSO(err) {
			// Naming the source here too, because this is the message #58 was filed
			// against: an operator who never chose this profile was being sent to log
			// into it, with nothing saying where it had come from.
			return aws.Credentials{}, "", authError{fmt.Errorf("AWS SSO credentials unavailable (using %s). Run: aws sso login --profile %s", describeCredentialSource(cfg), profile)}
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
	return fmt.Errorf("%w (using %s)", err, describeCredentialSource(cfg))
}

func looksLikeSSO(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "sso") || strings.Contains(s, "token") || strings.Contains(s, "expired")
}
