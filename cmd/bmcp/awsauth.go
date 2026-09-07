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
// check, so environment credentials still outrank it.
//
// bmcp used to pass every profile it resolved, wherever it resolved it from.
// That gave a value `bmcp init` persisted into config.toml months ago more
// precedence than the credentials the operator injected into this very process
// — so `aws-vault exec <profile> -- bmcp ...` never worked, no CI runner or
// container with credentials in the environment could call a tool, and the
// failure advised `aws sso login --profile X` for a profile the operator had
// deliberately not asked for (#58).
//
// So: a profile named for this invocation (--profile, BMCP_PROFILE) still wins,
// because naming a profile now is an instruction rather than a default, and
// BMCP_PROFILE is a variable the SDK will never read on its own — yielding it
// would drop it silently. An ambient profile (AWS_PROFILE, or aws_profile in
// config.toml) yields to ambient credentials. When it does not yield, passing
// it programmatically resolves exactly as the SDK's own AWS_PROFILE handling
// would, because that is the branch the SDK takes once the environment carries
// no credentials of its own.
func sharedProfileFor(cfg effectiveConfig) (profile, outrankedBy string) {
	if cfg.Profile == "" {
		return "", ""
	}
	switch cfg.ProfileSource {
	case profileSourceFlag, profileSourceBMCPEnv:
		return cfg.Profile, ""
	}
	if source := envCredentialSource(); source != "" {
		return "", source
	}
	return cfg.Profile, ""
}

// envCredentialSource names the credentials the environment carries on its own,
// or "" when it carries none.
//
// It reads the environment through the SDK's own parser rather than a hand-kept
// list of variable names, and tests exactly the fields the switches in
// resolveCredentialChain and resolveCredsFromProfile test — so what counts as
// "the environment has credentials" here cannot drift from what the SDK would
// actually have used.
//
// IMDS is absent by design: an instance role is not an environment signal,
// there is nothing to detect without a network probe, and the SDK reaches it
// from inside the profile branch anyway.
func envCredentialSource() string {
	env, err := awsconfig.NewEnvConfig()
	if err != nil {
		// A malformed AWS_* value is the SDK's to report from LoadDefaultConfig,
		// with its own message. Reporting "no environment credentials" here would
		// only change which error the operator sees.
		return ""
	}
	switch {
	case env.Credentials.HasKeys():
		return "environment credentials (AWS_ACCESS_KEY_ID)"
	case env.WebIdentityTokenFilePath != "":
		return "web identity credentials (AWS_WEB_IDENTITY_TOKEN_FILE)"
	case env.ContainerCredentialsRelativePath != "" || env.ContainerCredentialsEndpoint != "":
		return "container credentials (AWS_CONTAINER_CREDENTIALS_*)"
	}
	return ""
}

// describeCredentialSource says which credentials an invocation with this
// config will use. Local and free: it reads the environment and the resolved
// config, and authenticates nothing.
//
// It exists because #58's failure was as much about diagnosis as resolution.
// Nothing bmcp printed — not the auth error, not doctor — said which of the
// several possible credential sources was in play, so an operator whose
// environment credentials were being ignored had no way to see that from the
// outside.
func describeCredentialSource(cfg effectiveConfig) string {
	profile, outrankedBy := sharedProfileFor(cfg)
	switch {
	case profile != "":
		return fmt.Sprintf("AWS profile %s from %s", profile, cfg.ProfileSource)
	case outrankedBy != "":
		return fmt.Sprintf("%s, which outrank AWS profile %s from %s", outrankedBy, cfg.Profile, cfg.ProfileSource)
	}
	// No profile configured at all. The SDK's default chain would still pick the
	// environment up, and naming what it will pick beats naming the chain.
	if source := envCredentialSource(); source != "" {
		return source
	}
	return "the default AWS credential chain"
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
	profile, _ := sharedProfileFor(cfg)
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
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
			return aws.Credentials{}, "", authError{fmt.Errorf("AWS SSO credentials unavailable. Run: aws sso login --profile %s", profile)}
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
