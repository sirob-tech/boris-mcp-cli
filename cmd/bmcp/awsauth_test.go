package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		// A token file with no role ARN is not usable credentials: the SDK's own
		// arm takes it and then fails with "role ARN is not set", so treating it
		// as outranking would trade a working profile for a certain error.
		{name: "web identity with no role", set: func(t *testing.T) {
			t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", filepath.Join(t.TempDir(), "token"))
		}},
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
			wantValue: "from-aws-default", wantSource: profileSourceAWSEnv,
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
