package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials/processcreds"
)

// The static credentials the fixture profile carries, and the ones the
// environment carries. Distinct on purpose: every test below asserts which of
// the two came back, so a test that passes for the wrong reason is visible.
const (
	profileKey = "AKIAPROFILEFIXTURE"
	envKey     = "AKIAENVFIXTURE"
)

// isolateAWSEnv clears every AWS credential, profile and region variable the
// SDK reads and points the shared config and credentials files at fixtures, so
// a test observes only what it sets — never the developer's own ~/.aws, and
// never a leftover aws-vault session from the shell that ran `go test`.
//
// HOME is redirected too, because that is where the SDK looks for the SSO token
// cache: a test that applies the sso-only profile would otherwise read the
// developer's real cached token and pass or fail on whether they happened to be
// logged in.
//
// IMDS is disabled for a related reason: a case that resolves no credentials at
// all must fail on that, not on a several-second probe of a link-local address.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "BMCP_PROFILE",
		"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY",
		"AWS_SESSION_TOKEN", "AWS_ACCOUNT_ID",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN",
		"AWS_REGION", "AWS_DEFAULT_REGION",
	} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	credsPath := filepath.Join(dir, "credentials")
	// has-static resolves offline, so a test can assert which identity won rather
	// than only which error came back, and it carries a region so the region tests
	// have something to lose. sso-only is the shape #58 was reported against: a
	// profile that resolves through SSO, and so cannot work in CI or a container.
	// Deliberately no [default] profile — nothing here should quietly fall back to
	// one, and its absence is what makes that assertable.
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(configPath, `[profile has-static]
region = eu-west-1

[profile sso-only]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
sso_account_id = 123456789012
sso_role_name = ExampleRole
region = us-east-1
`)
	write(credsPath, "[has-static]\naws_access_key_id = "+profileKey+"\naws_secret_access_key = profilesecret\n")
	t.Setenv("AWS_CONFIG_FILE", configPath)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credsPath)
}

// setEnvCredentials injects static credentials the way aws-vault exec and every
// CI runner that assumes a role do.
func setEnvCredentials(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", envKey)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	t.Setenv("AWS_SESSION_TOKEN", "envtoken")
}

// applyProfileProvenance puts the environment into the state that would have
// produced this provenance, so no test asserts against a shape resolveProfile
// could never hand it.
//
// AWS_PROFILE especially is not inert: its mere presence switches the SDK to the
// strict shared-config loader (resolveConfigLoaders in config.go), so a test
// that claims that provenance while leaving the variable unset exercises the
// lenient loader and the default profile instead of the path it names.
func applyProfileProvenance(t *testing.T, source profileSource, profile string) {
	t.Helper()
	switch source {
	case profileSourceBMCPEnv:
		t.Setenv("BMCP_PROFILE", profile)
	case profileSourceAWSEnv:
		t.Setenv("AWS_PROFILE", profile)
	case profileSourceAWSDefaultEnv:
		t.Setenv("AWS_DEFAULT_PROFILE", profile)
	}
}

func authTestApp() *app {
	return &app{
		stdin:  strings.NewReader(""),
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		now:    time.Now,
		// A machine invocation, so no branch here may shell out to `aws sso login`
		// even if the test host happens to have a terminal.
		machine: true,
	}
}

// A deadline, so a reintroduced bug that sends resolution to the link-local
// container or IMDS endpoint fails in seconds instead of hanging the suite for
// a minute and a half.
func authTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The reproduction from #58, as a test. A profile persisted in config.toml used
// to be passed to the SDK programmatically, which made the SDK resolve
// credentials from that profile and never consider the environment's own — so
// `aws-vault exec <profile> -- bmcp ...` and every CI runner with credentials
// in the environment failed.
//
// The profile named here does not exist in the fixtures, which is what makes
// the assertion sharp: before the fix this could only fail, and it failed with
// "failed to get shared config profile" while perfectly good credentials sat in
// the environment.
func TestConfigFileProfileYieldsToEnvironmentCredentials(t *testing.T) {
	isolateAWSEnv(t)
	setEnvCredentials(t)
	cfg := effectiveConfig{
		Profile:        "definitely-not-a-real-profile",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}
	creds, region, err := authTestApp().awsCredentials(authTestContext(t), cfg)
	if err != nil {
		t.Fatalf("environment credentials should have resolved: %v", err)
	}
	if creds.AccessKeyID != envKey {
		t.Fatalf("resolved %q, want the environment's %q", creds.AccessKeyID, envKey)
	}
	if region != "us-east-1" {
		t.Fatalf("region %q, want us-east-1", region)
	}
}

// AWS_PROFILE is ambient in the same way, and the SDK already places it below
// environment credentials on its own — bmcp promoting it into a programmatic
// option was what inverted that. Both sources resolve successfully here, so the
// test can only pass by picking the right one.
func TestAWSProfileEnvYieldsToEnvironmentCredentials(t *testing.T) {
	isolateAWSEnv(t)
	applyProfileProvenance(t, profileSourceAWSEnv, "has-static")
	setEnvCredentials(t)
	cfg := effectiveConfig{
		Profile:        "has-static",
		ProfileSource:  profileSourceAWSEnv,
		Region:         "us-east-1",
		NonInteractive: true,
	}
	creds, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
	if err != nil {
		t.Fatalf("credentials should have resolved: %v", err)
	}
	if creds.AccessKeyID != envKey {
		t.Fatalf("resolved %q, want the environment's %q", creds.AccessKeyID, envKey)
	}
}

// The other half of the hierarchy. Naming a profile for this invocation is an
// instruction, not a default, so it still outranks whatever the environment
// carries — and BMCP_PROFILE has to, because the SDK never reads that variable
// itself, so yielding it would drop the operator's request silently.
func TestExplicitProfileOutranksEnvironmentCredentials(t *testing.T) {
	for _, source := range []profileSource{profileSourceFlag, profileSourceBMCPEnv} {
		t.Run(string(source), func(t *testing.T) {
			isolateAWSEnv(t)
			applyProfileProvenance(t, source, "has-static")
			setEnvCredentials(t)
			cfg := effectiveConfig{
				Profile:        "has-static",
				ProfileSource:  source,
				Region:         "us-east-1",
				NonInteractive: true,
			}
			creds, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
			if err != nil {
				t.Fatalf("credentials should have resolved: %v", err)
			}
			if creds.AccessKeyID != profileKey {
				t.Fatalf("resolved %q, want the profile's %q", creds.AccessKeyID, profileKey)
			}
		})
	}
}

// The regression the fix must not cause. A config-file profile is still the
// only place bmcp's own persisted default lives, and the SDK cannot discover
// it — so with nothing in the environment to outrank it, it has to be applied
// or `bmcp init --profile x` would stop meaning anything.
func TestConfigFileProfileStillAppliesWithoutEnvironmentCredentials(t *testing.T) {
	isolateAWSEnv(t)
	cfg := effectiveConfig{
		Profile:        "has-static",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}
	creds, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
	if err != nil {
		t.Fatalf("the configured profile should have resolved: %v", err)
	}
	if creds.AccessKeyID != profileKey {
		t.Fatalf("resolved %q, want the profile's %q", creds.AccessKeyID, profileKey)
	}
}

// Container credentials are a profile's *fallback* in the SDK, never its
// superior: they sit inside resolveCredsFromProfile, below that profile's own
// static keys, SSO and credential_process arms. So an ambient profile must
// still be applied when they are present.
//
// Treating them as outranking was wrong in three ways, and this test catches
// all three. With no [default] profile in the fixtures, declining the profile
// resolves through the container endpoint — a 90-second block on a link-local
// address that the deadline turns into a fast failure; with one, it would sign
// as an unrelated identity; and either way bmcp announced a precedence the SDK
// does not implement. Assertable entirely offline, precisely because the
// correct answer never dials anything.
func TestContainerCredentialsDoNotDisplaceAProfile(t *testing.T) {
	for _, source := range []profileSource{profileSourceAWSEnv, profileSourceFile} {
		for _, envVar := range []string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI"} {
			t.Run(string(source)+"/"+envVar, func(t *testing.T) {
				isolateAWSEnv(t)
				applyProfileProvenance(t, source, "has-static")
				t.Setenv(envVar, "http://169.254.170.23/v1/credentials")
				cfg := effectiveConfig{
					Profile:        "has-static",
					ProfileSource:  source,
					Region:         "us-east-1",
					NonInteractive: true,
				}
				creds, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
				if err != nil {
					t.Fatalf("the profile should have resolved without reaching the container endpoint: %v", err)
				}
				if creds.AccessKeyID != profileKey {
					t.Fatalf("resolved %q, want the profile's %q", creds.AccessKeyID, profileKey)
				}
			})
		}
	}
}

// Declining a profile for credential purposes must not also drop the region it
// carried for signing. An outranked config.toml profile used to take its region
// with it, and since the SDK cannot see that profile there was nothing to fall
// back to: on a BORIS URL whose host carries no region for inferRegion to find,
// the call died with "AWS region could not be inferred" on a machine that had
// been working — or, with a [default] profile present, silently signed in that
// profile's region instead.
func TestOutrankedProfileStillSuppliesItsRegion(t *testing.T) {
	for _, tc := range []struct {
		name      string
		envRegion string
		cfgRegion string
		want      string
	}{
		// eu-west-1 is what [profile has-static] carries in the fixture.
		{name: "the outranked profile supplies it", want: "eu-west-1"},
		// Both of these outrank the profile's region in the SDK when AWS_PROFILE is
		// what names the profile, so they have to here too.
		{name: "the environment still wins", envRegion: "ap-south-1", want: "ap-south-1"},
		{name: "an explicit region still wins", cfgRegion: "us-west-2", want: "us-west-2"},
		{
			name:      "an explicit region wins over the environment",
			envRegion: "ap-south-1", cfgRegion: "us-west-2", want: "us-west-2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			setEnvCredentials(t)
			if tc.envRegion != "" {
				t.Setenv("AWS_REGION", tc.envRegion)
			}
			cfg := effectiveConfig{
				Profile:        "has-static",
				ProfileSource:  profileSourceFile,
				Region:         tc.cfgRegion,
				NonInteractive: true,
			}
			creds, region, err := authTestApp().awsCredentials(authTestContext(t), cfg)
			if err != nil {
				t.Fatalf("environment credentials should have resolved: %v", err)
			}
			if creds.AccessKeyID != envKey {
				t.Fatalf("resolved %q, want the environment's %q", creds.AccessKeyID, envKey)
			}
			if region != tc.want {
				t.Fatalf("region %q, want %q", region, tc.want)
			}
		})
	}
}

// The truth table, stated once, with each expectation attached to the axis that
// owns it rather than to a row's position in a parallel slice.
//
// Written against sharedProfileFor rather than through the SDK because two of
// these environment shapes cannot resolve offline — and every shape that *can*
// is covered end to end by the tests above.
func TestSharedProfileForHierarchy(t *testing.T) {
	environments := []struct {
		name string
		set  func(t *testing.T)
		// outranksProfile is whether this environment carries a source that
		// resolveCredentialChain's outer switch places above every profile.
		outranksProfile bool
	}{
		{name: "empty"},
		{name: "static keys", set: setEnvCredentials, outranksProfile: true},
		{
			name: "web identity with a role",
			set: func(t *testing.T) {
				t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", filepath.Join(t.TempDir(), "token"))
				t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/Example")
			},
			outranksProfile: true,
		},
		// A token file with no role ARN still outranks, matching the SDK's arm,
		// which tests the token file alone and then fails closed with "role ARN is
		// not set". Keeping the profile here would fail *open*: a half-injected
		// IRSA deployment would silently authenticate as the ambient profile,
		// which may be an unrelated and more privileged identity.
		{
			name: "web identity with no role",
			set: func(t *testing.T) {
				t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", filepath.Join(t.TempDir(), "token"))
			},
			outranksProfile: true,
		},
		// Partial static keys are not credentials either — HasKeys wants both —
		// which is what a hand-rolled env check would most likely get wrong.
		{name: "access key id alone", set: func(t *testing.T) {
			t.Setenv("AWS_ACCESS_KEY_ID", envKey)
		}},
		{name: "secret access key alone", set: func(t *testing.T) {
			t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
		}},
		// Container credentials and IMDS live below the profile, not above it.
		{name: "container credentials", set: func(t *testing.T) {
			t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc")
		}},
	}
	sources := []struct {
		source profileSource
		// yieldsToEnv is whether this provenance makes the profile ambient.
		yieldsToEnv bool
	}{
		{source: profileSourceFlag},
		{source: profileSourceBMCPEnv},
		{source: profileSourceAWSEnv, yieldsToEnv: true},
		{source: profileSourceAWSDefaultEnv, yieldsToEnv: true},
		{source: profileSourceFile, yieldsToEnv: true},
	}
	for _, s := range sources {
		for _, e := range environments {
			t.Run(string(s.source)+"/"+e.name, func(t *testing.T) {
				isolateAWSEnv(t)
				applyProfileProvenance(t, s.source, "p")
				if e.set != nil {
					e.set(t)
				}
				want := !(s.yieldsToEnv && e.outranksProfile)
				profile, outrankedBy := sharedProfileFor(effectiveConfig{Profile: "p", ProfileSource: s.source})
				if (profile != "") != want {
					t.Fatalf("profile applied=%v (%q, outranked by %q), want applied=%v",
						profile != "", profile, outrankedBy, want)
				}
				// Exactly one of the two is set, so a caller can always say why.
				if (profile != "") == (outrankedBy != "") {
					t.Fatalf("expected exactly one of profile=%q and outrankedBy=%q", profile, outrankedBy)
				}
			})
		}
	}
	t.Run("no profile at all", func(t *testing.T) {
		isolateAWSEnv(t)
		setEnvCredentials(t)
		profile, outrankedBy := sharedProfileFor(effectiveConfig{})
		if profile != "" || outrankedBy != "" {
			t.Fatalf("no profile means nothing to apply and nothing to outrank, got %q/%q", profile, outrankedBy)
		}
	})
}

// #58's second complaint: the failure named nothing. It reported
// "failed to get shared config profile" — or worse, told the operator to run
// `aws sso login --profile X` — without ever saying which credential source
// the attempt had actually used, so an operator whose environment credentials
// were being discarded could not see that from the outside.
func TestAuthFailureNamesTheCredentialSource(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      func(t *testing.T)
		cfg      effectiveConfig
		contains []string
		absent   []string
	}{
		{
			// The profile was applied, so say so, and say where it came from: the
			// operator cannot fix a config.toml value they do not know is in play.
			name: "profile that does not exist",
			cfg: effectiveConfig{
				Profile:       "definitely-not-a-real-profile",
				ProfileSource: profileSourceFile,
				Region:        "us-east-1",
			},
			contains: []string{
				"failed to get shared config profile",
				"AWS profile definitely-not-a-real-profile from aws_profile in config.toml",
			},
		},
		{
			// An explicit profile is a hard failure even with usable credentials in
			// the environment, because the operator named it. Asserted so the
			// absence of a fallback reads as a decision rather than an oversight.
			name: "explicit profile does not fall back to the environment",
			env:  setEnvCredentials,
			cfg: effectiveConfig{
				Profile:       "definitely-not-a-real-profile",
				ProfileSource: profileSourceFlag,
				Region:        "us-east-1",
			},
			contains: []string{
				"failed to get shared config profile",
				"AWS profile definitely-not-a-real-profile from --profile",
			},
		},
		{
			// The profile was outranked, so the failure came from the environment.
			// Advising `aws sso login` for the configured profile — which is what
			// this used to do — sends the operator to repair something this attempt
			// never consulted.
			name: "environment credentials outranking an SSO profile",
			env: func(t *testing.T) {
				// A token file that does not exist, with the role ARN that makes it
				// count: the environment carries web identity credentials, and they
				// fail, with no network involved.
				t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", filepath.Join(t.TempDir(), "absent-token"))
				t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/Example")
			},
			cfg: effectiveConfig{
				Profile:       "sso-only",
				ProfileSource: profileSourceFile,
				Region:        "us-east-1",
			},
			contains: []string{
				"web identity credentials (AWS_WEB_IDENTITY_TOKEN_FILE)",
				"which outrank AWS profile sso-only from aws_profile in config.toml",
			},
			absent: []string{"aws sso login"},
		},
		{
			// And the converse: when the SSO profile *was* what resolution used, the
			// advice is right — but it still has to say where the profile came from,
			// which is the specific thing #58 called "actively misleading".
			name: "SSO profile that was applied",
			cfg: effectiveConfig{
				Profile:       "sso-only",
				ProfileSource: profileSourceFile,
				Region:        "us-east-1",
			},
			contains: []string{
				"aws sso login --profile sso-only",
				"AWS profile sso-only from aws_profile in config.toml",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			if tc.env != nil {
				tc.env(t)
			}
			cfg := tc.cfg
			cfg.NonInteractive = true
			_, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
			if err == nil {
				t.Fatal("expected an auth failure")
			}
			if !isAuthErr(err) {
				t.Fatalf("expected an auth_failure, got %T: %v", err, err)
			}
			for _, want := range tc.contains {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("message %q should contain %q", err.Error(), want)
				}
			}
			for _, unwanted := range tc.absent {
				if strings.Contains(err.Error(), unwanted) {
					t.Fatalf("message %q should not contain %q", err.Error(), unwanted)
				}
			}
		})
	}
}

// The precedence order, and the source that answered. AWS_DEFAULT_PROFILE is
// new here: the SDK treats it as an alias of AWS_PROFILE, so leaving it out
// meant a config-file profile was applied programmatically over one the
// operator had exported.
func TestResolveProfileTracksProvenance(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bmcpEnv    string
		awsEnv     string
		awsDefault string
		file       string
		wantValue  string
		wantSource profileSource
	}{
		{name: "nothing set", wantSource: profileSourceNone},
		{name: "file only", file: "from-file", wantValue: "from-file", wantSource: profileSourceFile},
		{
			name: "aws env beats file", awsEnv: "from-aws", file: "from-file",
			wantValue: "from-aws", wantSource: profileSourceAWSEnv,
		},
		{
			name: "aws default profile beats file", awsDefault: "from-aws-default", file: "from-file",
			// Named as itself, not as AWS_PROFILE: an operator told to check the
			// wrong variable is the failure mode this change is about.
			wantValue: "from-aws-default", wantSource: profileSourceAWSDefaultEnv,
		},
		{
			name: "aws profile beats aws default profile", awsEnv: "from-aws", awsDefault: "from-aws-default",
			wantValue: "from-aws", wantSource: profileSourceAWSEnv,
		},
		{
			name:    "bmcp env beats everything",
			bmcpEnv: "from-bmcp", awsEnv: "from-aws", awsDefault: "from-aws-default", file: "from-file",
			wantValue: "from-bmcp", wantSource: profileSourceBMCPEnv,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BMCP_PROFILE", tc.bmcpEnv)
			t.Setenv("AWS_PROFILE", tc.awsEnv)
			t.Setenv("AWS_DEFAULT_PROFILE", tc.awsDefault)
			value, source := resolveProfile(tc.file)
			if value != tc.wantValue || source != tc.wantSource {
				t.Fatalf("got (%q, %q), want (%q, %q)", value, source, tc.wantValue, tc.wantSource)
			}
		})
	}
}

// --profile has to arrive as profileSourceFlag through loadEffective, not just
// through resolveProfile, because defaultEffective is where the flag is read
// and it is the branch resolveProfile never sees.
func TestFlagProfileIsRecordedAsExplicit(t *testing.T) {
	isolateAWSEnv(t)
	home := t.TempDir()
	t.Setenv("BMCP_HOME", home)
	fileCfg := configFile{URL: "https://example.agentcore.aws/mcp", AWSProfile: "from-file"}
	applyDefaults(&fileCfg)
	if err := writeConfig(filepath.Join(home, "config.toml"), fileCfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	a := &app{stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, now: time.Now}

	cfg, _, err := a.loadEffective(globalFlags{profile: "from-flag"}, false)
	if err != nil {
		t.Fatalf("loadEffective: %v", err)
	}
	if cfg.Profile != "from-flag" || cfg.ProfileSource != profileSourceFlag {
		t.Fatalf("got (%q, %q), want (\"from-flag\", %q)", cfg.Profile, cfg.ProfileSource, profileSourceFlag)
	}

	cfg, _, err = a.loadEffective(globalFlags{}, false)
	if err != nil {
		t.Fatalf("loadEffective: %v", err)
	}
	if cfg.Profile != "from-file" || cfg.ProfileSource != profileSourceFile {
		t.Fatalf("got (%q, %q), want (\"from-file\", %q)", cfg.Profile, cfg.ProfileSource, profileSourceFile)
	}
}

// What doctor prints and what an auth failure names, for each shape the
// resolution can settle into.
func TestDescribeCredentialSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  func(t *testing.T)
		cfg  effectiveConfig
		want string
	}{
		{
			name: "nothing configured and nothing in the environment",
			want: "the default AWS credential chain",
		},
		{
			// No profile to outrank, but naming what the default chain will pick
			// still beats naming the chain.
			name: "environment credentials and no profile",
			env:  setEnvCredentials,
			want: "environment credentials (AWS_ACCESS_KEY_ID)",
		},
		{
			name: "profile applied",
			cfg:  effectiveConfig{Profile: "has-static", ProfileSource: profileSourceFile},
			want: "AWS profile has-static from aws_profile in config.toml",
		},
		{
			name: "profile outranked",
			env:  setEnvCredentials,
			cfg:  effectiveConfig{Profile: "has-static", ProfileSource: profileSourceAWSEnv},
			want: "environment credentials (AWS_ACCESS_KEY_ID), which outrank AWS profile has-static from AWS_PROFILE",
		},
		{
			name: "profile named for this invocation wins anyway",
			env:  setEnvCredentials,
			cfg:  effectiveConfig{Profile: "has-static", ProfileSource: profileSourceFlag},
			want: "AWS profile has-static from --profile",
		},
		{
			// Unreachable through resolveProfile, which never returns a value
			// without a source. Pinned because a message trailing off after "from"
			// would be a poor way to discover it had become reachable.
			name: "profile with no provenance",
			cfg:  effectiveConfig{Profile: "typed-at-a-prompt"},
			want: "AWS profile typed-at-a-prompt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			if tc.env != nil {
				tc.env(t)
			}
			if got := describeCredentialSource(tc.cfg); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// doctorCredentials seeds a machine with a catalog and an aws_profile, then runs
// doctor and returns its stdout. args selects the routine or the deep path.
func doctorCredentials(t *testing.T, profile string, creds credentialsFunc, args ...string) (string, int) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	tools := []tool{{Name: "tools___search_aws", Description: "Search."}}
	borisHome := setupInstallCatalog(t, home, tools)
	fileCfg, err := readConfig(filepath.Join(borisHome, "config.toml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	fileCfg.AWSProfile = profile
	if err := writeConfig(filepath.Join(borisHome, "config.toml"), fileCfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{tools: tools}, credentials: creds,
	}
	code := a.run(append([]string{"doctor"}, args...))
	if stderr.Len() > 0 {
		t.Logf("doctor stderr: %s", stderr.String())
	}
	// Both streams, because a fix that moved the SDK's text from the report to a
	// warning on stderr would satisfy an assertion that only read stdout.
	assertNoLeak(t, stderr.String())
	return stdout.String(), code
}

// The diagnostic half of #58. A machine silently discarding its environment
// credentials used to print exactly what a healthy one did, so the operator had
// no way to see which identity was in play — and the routine path is where they
// would look, because it is the one BORIS.md puts in front of every session.
//
// Reported on that path too, and that is safe: describeCredentialSource reads
// the environment and the resolved config, so the promise that a fresh-catalog
// doctor reaches neither AWS nor the server still holds. refusingCreds is what
// holds it: it fails the test if anything authenticates.
func TestDoctorNamesTheCredentialSourceWithoutAuthenticating(t *testing.T) {
	isolateAWSEnv(t)
	setEnvCredentials(t)
	stdout, code := doctorCredentials(t, "has-static", refusingCreds(t))
	if code != 0 {
		t.Fatalf("doctor exit %d, stdout:\n%s", code, stdout)
	}
	rows := doctorRows(t, stdout)
	if rows["credentials"] != "ok" {
		t.Fatalf("credentials row %q, want ok, in:\n%s", rows["credentials"], stdout)
	}
	if _, ok := rows["auth"]; ok {
		t.Fatalf("the routine path must not report auth, got:\n%s", stdout)
	}
	want := "environment credentials (AWS_ACCESS_KEY_ID), which outrank AWS profile has-static from aws_profile in config.toml"
	if !strings.Contains(stdout, want) {
		t.Fatalf("doctor should report %q, got:\n%s", want, stdout)
	}
}

// The failing auth row, end to end, with credentials resolved for real. It is
// the highest-stakes output in the change: AGENTS.md says agents read a failing
// doctor as "BORIS is broken" and stop, so the exit code and the message both
// have to be right.
func TestDoctorDeepReportsAFailingAuthRowWithItsSource(t *testing.T) {
	isolateAWSEnv(t)
	stdout, code := doctorCredentials(t, "definitely-not-a-real-profile", nil, "--deep")
	if code != exitGeneric {
		t.Fatalf("doctor exit %d, want %d, stdout:\n%s", code, exitGeneric, stdout)
	}
	rows := doctorRows(t, stdout)
	if rows["auth"] != "fail" {
		t.Fatalf("auth row %q, want fail, in:\n%s", rows["auth"], stdout)
	}
	for _, want := range []string{
		"failed to get shared config profile",
		"AWS profile definitely-not-a-real-profile from aws_profile in config.toml",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("doctor should report %q, got:\n%s", want, stdout)
		}
	}
}

// Half-injected IRSA has to fail closed. A token file with no AWS_ROLE_ARN is
// how a broken webhook or Helm template presents, and the tempting fix — keep
// the ambient profile, since the SDK is going to error anyway — silently
// authenticates as a different, possibly more privileged identity and hides the
// fact that IRSA is broken at all.
func TestHalfInjectedWebIdentityDoesNotFallBackToTheProfile(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", filepath.Join(t.TempDir(), "token"))
	cfg := effectiveConfig{
		Profile:        "has-static",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}
	creds, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
	if err == nil {
		t.Fatalf("expected a closed failure, got credentials %q", creds.AccessKeyID)
	}
	if creds.AccessKeyID == profileKey {
		t.Fatal("resolved the ambient profile, masking the broken IRSA configuration")
	}
	if !strings.Contains(err.Error(), "role ARN is not set") {
		t.Fatalf("want the SDK's own diagnosis, got: %v", err)
	}
}

// ambientProfileRegion reads the region from the shared config files and must
// not do anything else. A second LoadDefaultConfig would have been shorter but
// is not free: `defaults_mode = auto` in the profile makes the SDK probe IMDS,
// and a container full URI with a hostname makes it resolve that host — either
// can block on the caller's context and spend the budget the real credential
// load then needs.
//
// AWS_EC2_METADATA_DISABLED is deliberately NOT set here, unlike everywhere
// else, so that a regression actually reaches for IMDS rather than being waved
// off. The deadline is what converts the block into a failure.
func TestAmbientProfileRegionDoesNotProbeTheNetwork(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://a-host-that-does-not-resolve.invalid/creds")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config")
	if err := os.WriteFile(configPath, []byte(`[profile auto-mode]
region = eu-north-1
defaults_mode = auto
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("AWS_CONFIG_FILE", configPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	region := ambientProfileRegion(ctx, effectiveConfig{Profile: "auto-mode", ProfileSource: profileSourceFile})
	if region != "eu-north-1" {
		t.Fatalf("region %q, want eu-north-1 read straight from the shared config", region)
	}
	// Generous, because it only has to separate "parsed a file" from "waited on
	// a network round trip that cannot succeed".
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %s, so something went to the network", elapsed)
	}
}

// A profile typed at the init prompt outranks the environment, like the flag,
// but must not claim to have come from the flag.
func TestInitPromptProfileNamesItselfHonestly(t *testing.T) {
	isolateAWSEnv(t)
	setEnvCredentials(t)
	cfg := effectiveConfig{Profile: "has-static", ProfileSource: profileSourcePrompt}
	if !cfg.ProfileSource.namedForThisInvocation() {
		t.Fatal("a profile typed at the prompt was named for this invocation")
	}
	want := "AWS profile has-static from the bmcp init prompt"
	if got := describeCredentialSource(cfg); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// The fake secret the credential_process fixtures emit. Distinct from every
// other key in this file so an assertion that it is absent cannot pass because
// something else was redacted.
const (
	leakedKeyID  = "AKIALEAKEDFIXTURE"
	leakedSecret = "leakedsecretfixturevalue"
)

// credentialProcessProfile appends a profile backed by a credential_process
// helper to the fixture config and returns its name. body is written to the
// helper's stdout verbatim — including whatever precedes the JSON, which is the
// whole point: a banner, a warning line or a shell profile's own output is what
// makes the SDK's parse fail with the credentials still in the buffer.
func credentialProcessProfile(t *testing.T, name, body string) string {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\ncat <<'CREDENTIALS'\n"+body+"\nCREDENTIALS\n"), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	appendSharedConfig(t, "\n[profile "+name+"]\nregion = us-east-1\ncredential_process = "+helper+"\n")
	return name
}

// appendSharedConfig adds sections to the config file isolateAWSEnv installed,
// so a case needing its own profile shape does not have to be carried by every
// test that calls isolateAWSEnv.
func appendSharedConfig(t *testing.T, body string) {
	t.Helper()
	// Checked against the temp root rather than merely for being set. A developer
	// who exports AWS_CONFIG_FILE would otherwise have had these fixture profiles
	// — and a credential_process line naming a path that vanishes at test exit —
	// appended to their own ~/.aws/config by a test that believed it was isolated.
	path := os.Getenv("AWS_CONFIG_FILE")
	if !strings.HasPrefix(path, os.TempDir()) {
		t.Fatalf("appendSharedConfig would write outside the test's fixtures: AWS_CONFIG_FILE=%q; isolateAWSEnv must run first", path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open shared config: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(body); err != nil {
		t.Fatalf("append shared config: %v", err)
	}
}

// #60. processcreds embeds the helper's complete stdout in its parse error, and
// bmcp forwarded that error unchanged into the auth_failure `message` field and
// doctor --deep's auth row — both places built to be captured verbatim into
// agent transcripts and CI logs.
//
// The assertion is that the secret is absent, not that the wording is right: an
// assertion on the wording would pass on output that still carried the key.
func TestCredentialProcessOutputNeverReachesAnErrorMessage(t *testing.T) {
	// A banner line before otherwise valid JSON, which is the shape every real
	// report of this takes — a wrapper, a helper, or the operator's own shell
	// profile writing one line to stdout.
	const bannerThenJSON = `Note: vault backend v2
{"Version":1,"AccessKeyId":"` + leakedKeyID + `","SecretAccessKey":"` + leakedSecret + `"}`

	// The same output with a SessionToken, as any helper issuing temporary
	// credentials returns. This is case B from the issue: looksLikeSSO matched the
	// substring "token" inside the leaked payload, so the two defects masked each
	// other — the secret was suppressed, and the operator was told to run
	// `aws sso login` for a profile with no SSO configuration at all.
	const withSessionToken = `Note: vault backend v2
{"Version":1,"AccessKeyId":"` + leakedKeyID + `","SecretAccessKey":"` + leakedSecret + `","SessionToken":"` + leakedSecret + `"}`

	for _, tc := range []struct {
		name     string
		body     string
		contains []string
	}{
		{
			name: "unparseable output",
			body: bannerThenJSON,
			contains: []string{
				"credential_process helper printed output that is not valid credential JSON",
				"AWS profile leaky from aws_profile in config.toml",
			},
		},
		{
			name: "unparseable output carrying a session token",
			body: withSessionToken,
			contains: []string{
				"credential_process helper printed output that is not valid credential JSON",
				"AWS profile leaky from aws_profile in config.toml",
			},
		},
		{
			// Valid JSON of the wrong shape, which reaches json.UnmarshalTypeError
			// rather than json.SyntaxError. A separate arm of the type switch, and
			// one an assertion on the SyntaxError case alone would leave dead.
			name: "output whose fields have the wrong type",
			body: `{"Version":"1","AccessKeyId":"` + leakedKeyID + `","SecretAccessKey":"` + leakedSecret + `"}`,
			contains: []string{
				"credential_process helper printed output that is not valid credential JSON",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			profile := credentialProcessProfile(t, "leaky", tc.body)
			cfg := effectiveConfig{
				Profile:        profile,
				ProfileSource:  profileSourceFile,
				Region:         "us-east-1",
				NonInteractive: true,
			}
			_, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
			if err == nil {
				t.Fatal("expected an auth failure")
			}
			if !isAuthErr(err) {
				t.Fatalf("expected an auth_failure, got %T: %v", err, err)
			}
			assertNoLeak(t, err.Error())
			// And the advice is about the helper rather than about SSO, which the
			// profile does not use.
			if strings.Contains(err.Error(), "aws sso login") {
				t.Fatalf("credential_process profile sent to aws sso login: %q", err.Error())
			}
			for _, want := range tc.contains {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("message %q should contain %q", err.Error(), want)
				}
			}
		})
	}
}

// The same leak through doctor --deep, which is the other place the SDK's error
// text is printed verbatim — and the one BORIS.md tells agents to run when a
// call has already failed on auth, so it is the more likely of the two to end
// up in a transcript.
func TestDoctorDeepDoesNotPrintCredentialProcessOutput(t *testing.T) {
	isolateAWSEnv(t)
	profile := credentialProcessProfile(t, "leaky", `Note: vault backend v2
{"Version":1,"AccessKeyId":"`+leakedKeyID+`","SecretAccessKey":"`+leakedSecret+`"}`)
	stdout, code := doctorCredentials(t, profile, nil, "--deep")
	if code != exitGeneric {
		t.Fatalf("doctor exit %d, want %d, stdout:\n%s", code, exitGeneric, stdout)
	}
	rows := doctorRows(t, stdout)
	if rows["auth"] != "fail" {
		t.Fatalf("auth row %q, want fail, in:\n%s", rows["auth"], stdout)
	}
	assertNoLeak(t, stdout)
	if !strings.Contains(stdout, "credential_process helper printed output that is not valid credential JSON") {
		t.Fatalf("doctor should name the helper as the cause, got:\n%s", stdout)
	}
}

// assertNoLeak fails if any part of the helper's stdout survived into text bmcp
// printed. The banner is checked alongside the keys because it is the reason
// the parse failed: if it reached the output, so did everything after it.
//
// The eight-character prefixes are what make this an assertion about redaction
// rather than about exact strings. A fix that truncated the SDK's text at a
// byte budget, or kept a recognisable head of the key the way a masked value
// does, would pass a whole-string check while still handing over enough to
// identify the credential — and #60 is explicit that a partial redaction reads
// as safe when it is not.
func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	for _, secret := range []string{
		leakedSecret, leakedKeyID, "vault backend v2", "parse failed of process output",
		leakedSecret[:8], leakedKeyID[:8],
	} {
		if strings.Contains(out, secret) {
			t.Fatalf("credential_process output leaked %q into:\n%s", secret, out)
		}
	}
}

// A helper that fails outright rather than printing something unparseable. It
// carries no payload, but it is withheld on the same rule, so what the operator
// gets has to still say enough to act on — and the exit status is the detail
// worth keeping, since 127 and 126 name a helper that is missing or not
// executable.
func TestCredentialProcessExitStatusIsReported(t *testing.T) {
	isolateAWSEnv(t)
	helper := filepath.Join(t.TempDir(), "missing-helper.sh")
	appendSharedConfig(t, "\n[profile broken]\nregion = us-east-1\ncredential_process = "+helper+"\n")
	cfg := effectiveConfig{
		Profile:        "broken",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}
	_, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
	if err == nil {
		t.Fatal("expected an auth failure")
	}
	// "exited with status" and not just "credential_process helper": the generic
	// fallback satisfies the looser string, so without this the exec.ExitError
	// branch could be deleted with the suite still green.
	for _, want := range []string{"credential_process helper exited with status ", "AWS profile broken from aws_profile in config.toml"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q should contain %q", err.Error(), want)
		}
	}
}

// SSO remediation is decided by configuration now, not by whether the error
// text happens to contain "sso", "token" or "expired".
func TestProfileUsesSSO(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[sso-session corp]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1

[profile sso-session-form]
sso_session = corp
sso_account_id = 123456789012
sso_role_name = ExampleRole
region = us-east-1

[profile role-from-sso]
role_arn = arn:aws:iam::123456789012:role/Chained
source_profile = sso-session-form
region = us-east-1

[profile role-from-static]
role_arn = arn:aws:iam::123456789012:role/Chained
source_profile = has-static
region = us-east-1

[profile stale-sso-over-static]
sso_session = corp
role_arn = arn:aws:iam::123456789012:role/Chained
source_profile = has-static
region = us-east-1

[profile imds-over-sso]
role_arn = arn:aws:iam::123456789012:role/Target
credential_source = Ec2InstanceMetadata
sso_session = corp
region = us-east-1

[profile sso-over-helper]
sso_session = corp
sso_account_id = 123456789012
sso_role_name = ExampleRole
credential_process = /bin/false
region = us-east-1
`)
	for _, tc := range []struct {
		name    string
		profile string
		want    bool
	}{
		// The legacy form, with the start URL on the profile itself.
		{name: "legacy sso_start_url", profile: "sso-only", want: true},
		// The current form. Matched on sso_session, because the start URL lives in
		// the session section rather than on the profile.
		{name: "sso_session", profile: "sso-session-form", want: true},
		// A role assumed from an SSO profile. The profile carries no SSO keys of its
		// own, but an expired token still stops it working and `aws sso login` is
		// still the fix, so the source_profile chain has to be followed.
		{name: "role chained onto an SSO profile", profile: "role-from-sso", want: true},
		{name: "role chained onto static keys", profile: "role-from-static", want: false},
		// A stale sso_session line above a chain that resolves from static keys.
		// clearCredentialOptions wipes the legacy SSO keys off a chained profile
		// but leaves SSOSessionName, so a walk that asked every node would call
		// this SSO and send the operator to a login the chain never uses.
		{name: "stale sso_session above static keys", profile: "stale-sso-over-static", want: false},
		{name: "static keys", profile: "has-static", want: false},
		// The SDK ranks credential_source above SSO and validates no collision
		// between them, so this profile resolves through IMDS. Calling it SSO
		// would send an operator whose IMDS is unreachable to an irrelevant login.
		{name: "credential_source outranking sso_session", profile: "imds-over-sso", want: false},
		// The converse, and the reason credential_process is not in that list:
		// the SDK ranks it below SSO, so a profile with both does resolve SSO.
		{name: "sso_session outranking credential_process", profile: "sso-over-helper", want: true},
		// The case the substring match got wrong: no SSO anywhere, and a failure
		// whose text is full of the word "token".
		{name: "credential_process", profile: credentialProcessProfile(t, "helper-backed", `{"Version":1}`), want: false},
		{name: "profile that does not exist", profile: "definitely-not-a-real-profile", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := profileUsesSSO(authTestContext(t), tc.profile); got != tc.want {
				t.Fatalf("profileUsesSSO(%q) = %v, want %v", tc.profile, got, tc.want)
			}
		})
	}
}

// The regression the config-based SSO check introduced, and the fix for it.
//
// looksLikeSSO fired only on errors whose text mentioned SSO, so a network
// failure on an SSO profile reported the network failure. profileUsesSSO fires
// on every failure an SSO profile can produce, which is the point — but the
// first version of it replaced the cause with "run aws sso login", so a DNS
// failure, an AccessDenied on a chained role and an expired token all rendered
// identically, and only one of the three is fixed by logging in.
func TestSSOFailureStillReportsItsCause(t *testing.T) {
	isolateAWSEnv(t)
	// sso-only rather than a profile with a malformed SSO section: a malformed one
	// fails inside LoadDefaultConfig, which returns before the branch this test is
	// about. This one loads cleanly and fails at Retrieve, with no cached token
	// under the temp HOME isolateAWSEnv installed.
	cfg := effectiveConfig{
		Profile:        "sso-only",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}
	_, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
	if err == nil {
		t.Fatal("expected an auth failure")
	}
	// The remedy, the source, and — the part that regressed — the cause the SDK
	// reported, which the first version of this branch replaced outright.
	for _, want := range []string{
		"failed to refresh cached credentials",
		"AWS profile sso-only from aws_profile in config.toml",
		"aws sso login --profile sso-only",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q should contain %q", err.Error(), want)
		}
	}
}

// The signal case of the exit-status branch, which no fixture can reach in
// reasonable time: processcreds kills a helper that overruns DefaultTimeout,
// one minute. Fed a synthetic ProviderError instead, wrapping a real
// *exec.ExitError from a process that died on a signal, because the thing under
// test is what ExitCode() returns for one — -1, which is not a status and must
// not be printed as one.
func TestCredentialProcessKilledHelperIsNotReportedAsAStatus(t *testing.T) {
	isolateAWSEnv(t)
	runErr := exec.Command("sh", "-c", "kill -9 $$").Run()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		t.Fatalf("expected an *exec.ExitError from a killed process, got %T: %v", runErr, runErr)
	}
	if exitErr.ExitCode() >= 0 {
		t.Skipf("this platform reports a signalled process as status %d, so there is nothing to guard", exitErr.ExitCode())
	}
	err := credentialProcessFailure(
		effectiveConfig{Profile: "cp", ProfileSource: profileSourceFile},
		&processcreds.ProviderError{Err: fmt.Errorf("credential process timed out: %w", exitErr)},
	)
	if err == nil {
		t.Fatal("a processcreds error must be withheld and replaced")
	}
	if strings.Contains(err.Error(), "-1") {
		t.Fatalf("a signalled helper reported as a status: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "killed") {
		t.Fatalf("message %q should say the helper was killed", err.Error())
	}
}

// #60's misdiagnosis class, in the one shape that survived the first fix: a
// profile carrying a stale sso_session line above a source_profile chain whose
// leaf is a credential_process helper.
//
// The SDK resolves this through source_profile (resolveCredsFromProfile tests
// Source first), so the helper is what actually fails — but a walk that asked
// every node whether it had SSO keys would call this an SSO profile and send
// the operator to `aws sso login` for a chain that never touches SSO.
func TestSSOKeysAboveACredentialProcessChainDoNotClaimSSO(t *testing.T) {
	isolateAWSEnv(t)
	leaf := credentialProcessProfile(t, "helper-leaf", `Note: vault backend v2
{"Version":1,"AccessKeyId":"`+leakedKeyID+`","SecretAccessKey":"`+leakedSecret+`"}`)
	appendSharedConfig(t, `
[profile mixed]
sso_session = corp
role_arn = arn:aws:iam::123456789012:role/Chained
source_profile = `+leaf+`
region = us-east-1

[sso-session corp]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
`)
	if profileUsesSSO(authTestContext(t), "mixed") {
		t.Fatal("a chain resolving through credential_process was classified as SSO")
	}
	cfg := effectiveConfig{
		Profile:        "mixed",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}
	_, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
	if err == nil {
		t.Fatal("expected an auth failure")
	}
	assertNoLeak(t, err.Error())
	if strings.Contains(err.Error(), "aws sso login") {
		t.Fatalf("sent to aws sso login for a credential_process chain: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "credential_process helper") {
		t.Fatalf("message %q should name the helper as the cause", err.Error())
	}
}

// The contract surface #60 was reported against, asserted where it is actually
// produced rather than on the Go error behind it: stdout stays empty, the
// failure document is alone on stderr, and its `message` field carries no part
// of what the helper printed.
func TestFormatJSONFailureDocumentCarriesNoCredentialProcessOutput(t *testing.T) {
	isolateAWSEnv(t)
	profile := credentialProcessProfile(t, "leaky", `Note: vault backend v2
{"Version":1,"AccessKeyId":"`+leakedKeyID+`","SecretAccessKey":"`+leakedSecret+`"}`)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	tools := []tool{{Name: "tools___search_aws", Description: "Search."}}
	borisHome := setupInstallCatalog(t, home, tools)
	fileCfg, err := readConfig(filepath.Join(borisHome, "config.toml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	fileCfg.AWSProfile = profile
	if err := writeConfig(filepath.Join(borisHome, "config.toml"), fileCfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var stdout, stderr bytes.Buffer
	a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now}
	if code := a.run([]string{"--format", "json", "--non-interactive", "tools___search_aws"}); code == 0 {
		t.Fatalf("expected a failure, got exit 0; stdout:\n%s", stdout.String())
	}
	assertNoLeak(t, stdout.String())
	assertNoLeak(t, stderr.String())
	if stdout.Len() != 0 {
		t.Fatalf("a failure must leave stdout empty, got:\n%s", stdout.String())
	}
	var doc struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
		t.Fatalf("stderr is not one JSON document (%v):\n%s", err, stderr.String())
	}
	if doc.OK {
		t.Fatalf("expected ok:false, got:\n%s", stderr.String())
	}
	assertNoLeak(t, doc.Message)
	if !strings.Contains(doc.Message, "credential_process helper") {
		t.Fatalf("message %q should name the helper as the cause", doc.Message)
	}
}
