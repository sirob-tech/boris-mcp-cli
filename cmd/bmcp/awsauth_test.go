package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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
		// Cleared for the same reason as the keys it accompanies, and more
		// urgently: aws-vault stamps it into every shell it opens, and a
		// maintainer whose session has lapsed would otherwise run the suite with a
		// *past* expiry in the environment — switching the demotion on underneath
		// four #58 regression pins, which would then fail on a machine where
		// nothing is wrong. A fixture that leaks this leaks a behaviour change,
		// not just a value.
		"AWS_CREDENTIAL_EXPIRATION",
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
		//
		// #61's cases turn this off to reach the human-format branch of the stderr
		// policy, so that guarantee no longer rests here alone. What holds for them
		// is the rest of the same condition: the login branch needs profileUsesSSO
		// as well, and their profiles are credential_process ones with no SSO
		// anywhere. A case that turns machine off for an SSO profile has to set
		// cfg.NonInteractive itself.
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

// #66's third symptom: environment credentials that have expired are
// inescapable, and nothing says why.
//
// aws-sdk-go-v2/config does not read AWS_CREDENTIAL_EXPIRATION, so a lapsed
// `aws-vault exec` shell hands the SDK static keys it believes can never
// expire. They outrank the profile in config.toml, the SSO branch that would
// have healed the run is unreachable because no profile was applied, and every
// request 401s while bmcp reports a perfectly ordinary credential source.
//
// The table is written around the demotion's two edges, because both are ways
// to get this wrong and only one of them is the bug. Demote too little and #66
// stands; demote too eagerly and a long-lived IAM user key or a wrapper bmcp
// does not understand loses to a profile that may be an unrelated identity —
// which is #58 again, reintroduced from the other side.
func TestExpiredEnvironmentCredentialsYieldToTheConfiguredProfile(t *testing.T) {
	const (
		past   = "2020-01-02T03:04:05Z"
		future = "2099-01-02T03:04:05Z"
	)
	fileProfile := effectiveConfig{Profile: "has-static", ProfileSource: profileSourceFile, Region: "us-east-1"}
	for _, tc := range []struct {
		name string
		env  func(t *testing.T)
		cfg  effectiveConfig
		// wantProfile is the profile handed to the SDK programmatically, and
		// wantDemotion whether expired environment credentials are why.
		wantProfile  string
		wantDemotion bool
		wantSource   string
	}{
		{
			// The fix. The dead keys are treated as absent, so the profile wins and
			// the message says the environment was passed over rather than leaving
			// the operator to wonder why their aws-vault shell stopped counting.
			name: "expired environment credentials yield to the profile",
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_CREDENTIAL_EXPIRATION", past)
			},
			cfg:          fileProfile,
			wantProfile:  "has-static",
			wantDemotion: true,
			wantSource: "AWS profile has-static from aws_profile in config.toml, " +
				"after the credentials in the environment were passed over as expired at " + past,
		},
		{
			// Expired with nothing to fall back to. There is no demotion to make —
			// sharedProfileFor returns at its first line with no profile at all — but
			// the operator still has to be told, because these are the credentials
			// that will be signed with and they are already dead.
			name: "expired environment credentials with no profile to fall back to",
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_CREDENTIAL_EXPIRATION", past)
			},
			wantSource: "environment credentials (AWS_ACCESS_KEY_ID), which expired at " + past,
		},
		{
			// The #58 behaviour, untouched: a live aws-vault session still outranks
			// the profile in config.toml, which is the entire point of running bmcp
			// under one.
			name: "unexpired environment credentials still outrank the profile",
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_CREDENTIAL_EXPIRATION", future)
			},
			cfg:        fileProfile,
			wantSource: "environment credentials (AWS_ACCESS_KEY_ID), which outrank AWS profile has-static from aws_profile in config.toml",
		},
		{
			// A long-lived IAM user key names no expiry, and is the ordinary CI
			// shape. Demoting it would be #58 all over again.
			name:       "static keys with no expiration are untouched",
			env:        setEnvCredentials,
			cfg:        fileProfile,
			wantSource: "environment credentials (AWS_ACCESS_KEY_ID), which outrank AWS profile has-static from aws_profile in config.toml",
		},
		{
			// Evidence of a wrapper bmcp does not understand, not evidence that
			// credentials are dead. Failing open here costs a confusing 401; failing
			// closed would silently sign as a different identity over a typo.
			name: "an unparseable expiration is not an expiry",
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_CREDENTIAL_EXPIRATION", "some time last tuesday")
			},
			cfg:        fileProfile,
			wantSource: "environment credentials (AWS_ACCESS_KEY_ID), which outrank AWS profile has-static from aws_profile in config.toml",
		},
		{
			// Expired static keys alongside a web identity token: demoting would hand
			// the SDK a profile, which steps over its whole environment tier and
			// authenticates an IRSA pod as that profile instead of as its own role.
			// A different account, silently — so the demotion is withheld and this
			// population stays exactly where it was before #66.
			name: "a web identity token is never stepped over",
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_CREDENTIAL_EXPIRATION", past)
				t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", filepath.Join(t.TempDir(), "token"))
				t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/Example")
			},
			cfg:        fileProfile,
			wantSource: "environment credentials (AWS_ACCESS_KEY_ID), which outrank AWS profile has-static from aws_profile in config.toml",
		},
		{
			// --profile already beat the environment, expired or not, so the expiry
			// had no bearing on what resolved. Announcing it here would be a fresh
			// instance of the dishonesty this change exists to remove.
			name: "a profile named for this invocation does not advertise the expiry",
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_CREDENTIAL_EXPIRATION", past)
			},
			cfg:         effectiveConfig{Profile: "has-static", ProfileSource: profileSourceFlag, Region: "us-east-1"},
			wantProfile: "has-static",
			wantSource:  "AWS profile has-static from --profile",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			tc.env(t)
			a := authTestApp()
			profile, _, demotedAt := a.sharedProfileFor(tc.cfg)
			if profile != tc.wantProfile {
				t.Fatalf("profile %q, want %q", profile, tc.wantProfile)
			}
			if demotedAt.IsZero() == tc.wantDemotion {
				t.Fatalf("demotedAt %v, want a demotion=%v", demotedAt, tc.wantDemotion)
			}
			if got := a.describeCredentialSource(tc.cfg); got != tc.wantSource {
				t.Fatalf("source %q, want %q", got, tc.wantSource)
			}
		})
	}

	// And the demotion end to end, through the SDK, because everything above
	// tests bmcp's own bookkeeping and none of it proves the SDK then resolves
	// the profile. has-static resolves offline and carries a key distinct from
	// the environment's, so only one of the two can produce this answer.
	t.Run("the profile is what actually resolves", func(t *testing.T) {
		isolateAWSEnv(t)
		setEnvCredentials(t)
		t.Setenv("AWS_CREDENTIAL_EXPIRATION", past)
		cfg := fileProfile
		cfg.NonInteractive = true
		creds, _, err := authTestApp().awsCredentials(authTestContext(t), cfg)
		if err != nil {
			t.Fatalf("the profile should have resolved: %v", err)
		}
		if creds.AccessKeyID != profileKey {
			t.Fatalf("resolved %q, want the profile's %q", creds.AccessKeyID, profileKey)
		}
	})
}

// The device-flow budget, from both sides.
//
// exec.CommandContext kills the login subprocess when the deadline lands, so a
// flow started under a budget it cannot finish in is arranged to be destroyed
// part-way: the operator approves in the browser and the token is never
// written. But every production path carries *some* deadline — awsCredentials
// is reached only through newMCPClient, and both callers wrap the context — so
// a gate that asked merely whether a deadline existed would refuse every login
// bmcp could ever make, including a tool call's ten-minute one. Both halves are
// pinned here because each without the other is a bug that ships.
//
// The fake `aws` on PATH is the observation: it exists to record that it ran.
func TestADeviceFlowStartsOnlyWhenItCouldFinish(t *testing.T) {
	for _, tc := range []struct {
		name      string
		budget    time.Duration
		wantLogin bool
		// wantMessage separates the two outcomes by what the operator is told, not
		// only by whether the subprocess ran: a refusal has to hand over the command
		// to run by hand, and an attempt has to report that the login itself failed
		// rather than quietly reporting only the credential error underneath it.
		wantMessage string
	}{
		// SyncTimeout's sixty seconds — what `bmcp sync` and `bmcp doctor` carry.
		{name: "a sync budget is too short", budget: 60 * time.Second, wantMessage: "bmcp --profile sso-only login"},
		{name: "just under the budget", budget: ssoLoginBudget - time.Second, wantMessage: "bmcp --profile sso-only login"},
		// CallTimeout's ten minutes — what `bmcp <tool>` carries, and ample.
		{name: "a call budget is ample", budget: 10 * time.Minute, wantLogin: true, wantMessage: "aws sso login failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			binDir := t.TempDir()
			marker := filepath.Join(t.TempDir(), "aws-was-run")
			script := "#!/bin/sh\ntouch '" + marker + "'\nexit 1\n"
			if err := os.WriteFile(filepath.Join(binDir, "aws"), []byte(script), 0o700); err != nil {
				t.Fatalf("write fake aws: %v", err)
			}
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			a := authTestApp()
			// Everything the login branch needs except the budget, so the remaining
			// time is the only thing that decides this.
			a.machine = false
			a.interactive = func() bool { return true }
			ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
			defer cancel()
			_, _, err := a.awsCredentials(ctx, effectiveConfig{
				Profile:       "sso-only",
				ProfileSource: profileSourceFile,
				Region:        "us-east-1",
			})
			if err == nil {
				t.Fatal("an sso-only profile should not have resolved in a test")
			}
			_, statErr := os.Stat(marker)
			if ran := statErr == nil; ran != tc.wantLogin {
				t.Fatalf("aws sso login ran=%v, want %v, with %v of budget; error was: %v",
					ran, tc.wantLogin, tc.budget, err)
			}
			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("message %q should contain %q", err.Error(), tc.wantMessage)
			}
			// Either way the cause underneath survives, so a failure no login could
			// have fixed is never replaced by advice about logging in.
			if !strings.Contains(err.Error(), "AWS profile sso-only from aws_profile in config.toml") {
				t.Fatalf("message %q should still name the credential source", err.Error())
			}
		})
	}
}

// The expiry is read against the injected clock, not the wall clock, so the
// comparison is pinned on both sides of the instant rather than only on values
// far enough from now to be safe by accident.
func TestEnvCredentialsExpiredAtSitsOnBothSidesOfTheClock(t *testing.T) {
	at := time.Date(2026, 9, 10, 16, 34, 1, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		now         time.Time
		wantExpired bool
	}{
		{name: "a second after the expiry", now: at.Add(time.Second), wantExpired: true},
		// Not yet expired at the instant itself: the SDK's own providers treat an
		// expiry as the last moment the credentials are good, and a boundary that
		// disagreed would demote a credential the signer would still have accepted.
		{name: "at the expiry itself", now: at},
		{name: "a second before the expiry", now: at.Add(-time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			setEnvCredentials(t)
			t.Setenv("AWS_CREDENTIAL_EXPIRATION", at.Format(time.RFC3339))
			a := authTestApp()
			a.now = func() time.Time { return tc.now }
			if got := a.envCredentialsExpiredAt(); got.IsZero() == tc.wantExpired {
				t.Fatalf("expiredAt %v with now=%v, want expired=%v", got, tc.now, tc.wantExpired)
			}
		})
	}

	// No keys, no expiry to speak of — the variable alone describes nothing, and
	// a web identity token carries its own expiry inside the token.
	t.Run("the variable alone without static keys", func(t *testing.T) {
		isolateAWSEnv(t)
		t.Setenv("AWS_CREDENTIAL_EXPIRATION", at.Format(time.RFC3339))
		if got := authTestApp().envCredentialsExpiredAt(); !got.IsZero() {
			t.Fatalf("expiredAt %v, want the zero time", got)
		}
	})
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
				profile, outrankedBy, _ := authTestApp().sharedProfileFor(effectiveConfig{Profile: "p", ProfileSource: s.source})
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
		profile, outrankedBy, _ := authTestApp().sharedProfileFor(effectiveConfig{})
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
			// Advising a login for the configured profile — which is what this used
			// to do — sends the operator to repair something this attempt never
			// consulted.
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
			// Both spellings of the remedy. The old one alone would pass trivially
			// now that nothing produces it, and the assertion would have stopped
			// testing anything on the day the message changed.
			absent: []string{"aws sso login", "bmcp --profile sso-only login"},
		},
		{
			// #66. The environment's credentials expired, so the configured profile
			// was preferred over them — and the failure has to say so, because the
			// operator is looking at a message naming a profile they may not know is
			// in play, in a shell whose whole purpose was to supply credentials.
			//
			// The two halves of this assertion are what keep R5 and R6 apart. The
			// expiry is a fact about the credentials, so it rides inside
			// describeCredentialSource and reaches "(using %s)" here; "found, not
			// verified" is a fact about what doctor's credentials row tested, so it
			// stays at that row and must never appear on an error path — this
			// attempt verified the credentials by failing with them.
			name: "expired environment credentials demoted to the configured profile",
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_CREDENTIAL_EXPIRATION", "2020-01-02T03:04:05Z")
			},
			cfg: effectiveConfig{
				Profile:       "definitely-not-a-real-profile",
				ProfileSource: profileSourceFile,
				Region:        "us-east-1",
			},
			contains: []string{
				"AWS profile definitely-not-a-real-profile from aws_profile in config.toml",
				"after the credentials in the environment were passed over as expired at 2020-01-02T03:04:05Z",
			},
			absent: []string{"found, not verified"},
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
				"bmcp --profile sso-only login",
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
			if got := authTestApp().describeCredentialSource(tc.cfg); got != tc.want {
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
	if got := authTestApp().describeCredentialSource(cfg); got != want {
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
			// profile does not use. "login" rather than either spelling of the
			// remedy: the old one is a string nothing produces any more, so asserting
			// its absence would test nothing, and the next rewording would escape a
			// pin on the new one just as easily.
			if strings.Contains(err.Error(), "login") {
				t.Fatalf("credential_process profile sent to an SSO login: %q", err.Error())
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
		"bmcp --profile sso-only login",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q should contain %q", err.Error(), want)
		}
	}
	// And exactly one remedy. The replacement of `aws sso login` was an append in
	// an earlier draft, which would have passed every assertion above while the
	// message named two different commands and readers took whichever they
	// reached first. The generated instructions key on the one bmcp names.
	if strings.Contains(err.Error(), "aws sso login") {
		t.Fatalf("message carries both remedies, so a reader picks one at random: %q", err.Error())
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
	err := authTestApp().credentialProcessFailure(
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
	// "login" rather than the old `aws sso login`, which nothing produces any
	// more: an absence assertion against a string the code can no longer emit
	// passes whatever the message says.
	if strings.Contains(err.Error(), "login") {
		t.Fatalf("sent to an SSO login for a credential_process chain: %q", err.Error())
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

// #61. The channel #60's fix cannot reach: processcreds hands the helper the
// process-global os.Stderr, so whatever the helper writes there lands on fd 2
// directly, without passing through a bmcp error at all. It fires on
// *successful* retrieval, which is what makes it worse than #60 — a helper with
// tracing on echoes the credential JSON it just printed.
//
// The rows below are the ways the policy's conjunction can resolve, with one row
// per conjunct carrying the decision alone — so dropping any of the three fails a
// test rather than only narrowing coverage. A row that leaves interactive false
// cannot do that job: cfg.NonInteractive short-circuits the whole conjunction, so
// each of the other two conjuncts needs an interactive row as well.
func TestCredentialProcessStderrDoesNotReachACapturedDescriptor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		machine bool
		tty     bool
		// interactive drives cfg.NonInteractive, inverted so the zero value is the
		// safe one: a case that says nothing about prompting does not get a prompt.
		interactive bool
		// visible is what the policy promises for this shape: only a terminal that
		// could answer a prompt still gets one.
		visible bool
	}{
		{
			// The CI and agent-harness shape, and the one the issue was filed
			// against: fd 2 is a pipe or a file, so anything written to it is kept.
			name: "human format with stderr captured",
			tty:  false,
		},
		{
			// A machine format discards it even on a terminal. --format json
			// promises that stderr carries one parseable document and nothing else,
			// and a prompt no machine caller can answer is not worth breaking that
			// for.
			name:    "machine format on a terminal",
			machine: true,
			tty:     true,
		},
		{
			// The MFA path the SDK's assignment exists for, and the one this policy
			// keeps: an operator at a terminal who has not said that nothing will
			// answer a prompt.
			name:        "human format on a terminal",
			tty:         true,
			interactive: true,
			visible:     true,
		},
		{
			// The same terminal, with --non-interactive. A prompt nobody will answer
			// is pure exposure, and this is the case that closes the pty recorder:
			// `script -q log bmcp --non-interactive <tool>` no longer captures it.
			name: "non-interactive on a terminal",
			tty:  true,
		},
		{
			// The same terminal and an operator who could answer, under a machine
			// format. Only !a.machine can carry this row — the other two conjuncts
			// both say "keep" — so without it, deleting a.machine from the policy
			// leaves the whole suite green.
			name:        "machine format interactive on a terminal",
			machine:     true,
			tty:         true,
			interactive: true,
		},
		{
			// #61's own reproduction, with nothing else to fall back on: a human
			// format, no --non-interactive, and fd 2 on a file or a pipe. Only
			// a.stderrIsTerminal() can carry it, and it is the shape a plain
			// `bmcp <tool>` has in CI, where no flag is passed at all.
			name:        "human format interactive with stderr captured",
			tty:         false,
			interactive: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			profile := stderrWritingCredentialProcessProfile(t, "chatty")
			cfg := effectiveConfig{
				Profile:        profile,
				ProfileSource:  profileSourceFile,
				Region:         "us-east-1",
				NonInteractive: !tc.interactive,
			}
			a := authTestApp()
			a.machine = tc.machine
			a.stderrTTY = func() bool { return tc.tty }

			var creds aws.Credentials
			var err error
			captured := captureStderrFd(t, func() {
				creds, _, err = a.awsCredentials(authTestContext(t), cfg)
				// Written after the call, through the variable rather than through
				// a saved copy: the swap is only safe if it puts os.Stderr back, and
				// a fix that left it pointing at /dev/null would silence every later
				// subprocess in the process — starting with `aws sso login`.
				fmt.Fprintln(os.Stderr, afterRetrieval)
			})
			// Asserted first, and asserted on the key that came back rather than on
			// err alone: if the helper had failed it would have written no trace, and
			// every leak assertion below would pass on an empty string. The point of
			// #61 is that the leak happens when nothing goes wrong.
			if err != nil {
				t.Fatalf("retrieval should have succeeded, got: %v", err)
			}
			if creds.AccessKeyID != leakedKeyID {
				t.Fatalf("credentials came from %q, want the helper's %q", creds.AccessKeyID, leakedKeyID)
			}

			if !strings.Contains(captured, afterRetrieval) {
				t.Fatalf("os.Stderr was not restored after retrieval; captured:\n%s", captured)
			}
			if tc.visible {
				if !strings.Contains(captured, mfaPrompt) {
					t.Fatalf("a terminal must still see the helper's prompt %q, got:\n%s", mfaPrompt, captured)
				}
				// The other half of the before/after pair, and the reason the
				// absences below mean anything: this asserts the fixture actually
				// reproduces #61. The secret reaches fd 2 only through `set -x`, so
				// if this shell ever stopped tracing, every assertNoLeak above would
				// go vacuous and nothing would say so.
				if !strings.Contains(captured, leakedSecret) {
					t.Fatalf("the fixture no longer traces the credential to stderr, so the discard cases assert nothing:\n%s", captured)
				}
				return
			}
			assertNoLeak(t, captured)
			if strings.Contains(captured, mfaPrompt) {
				t.Fatalf("helper stderr reached a captured descriptor:\n%s", captured)
			}
			// And bmcp's own writer is untouched by the swap: a.stderr holds the
			// value os.Stderr had at startup, so restoring the variable is not what
			// keeps bmcp's output working — nothing ever redirected it.
			if out := a.stderr.(*bytes.Buffer).String(); out != "" {
				t.Fatalf("bmcp wrote prose of its own during retrieval:\n%s", out)
			}
		})
	}
}

// The same channel through the surface it breaks: a caller merging the streams
// under --format json is promised one parseable document on stderr, and a
// helper's trace lands on that stream ahead of it.
func TestFormatJSONSuccessIsNotPollutedByCredentialProcessStderr(t *testing.T) {
	isolateAWSEnv(t)
	profile := stderrWritingCredentialProcessProfile(t, "chatty")
	cfg := effectiveConfig{
		Profile:       profile,
		ProfileSource: profileSourceFile,
		Region:        "us-east-1",
		// Left false on purpose. With --non-interactive set here too, that conjunct
		// discarded on its own and deleting a.machine from the policy left this test
		// green — so authTestApp's machine format is the only gate in play.
		NonInteractive: false,
	}
	a := authTestApp()
	// A terminal that could answer a prompt, so the machine format is the only
	// thing doing the work here. Without that gate this case is the leak.
	a.stderrTTY = func() bool { return true }
	var creds aws.Credentials
	captured := captureStderrFd(t, func() {
		var err error
		creds, _, err = a.awsCredentials(authTestContext(t), cfg)
		if err != nil {
			t.Errorf("retrieval should have succeeded, got: %v", err)
			return
		}
		fmt.Fprintln(os.Stderr, afterRetrieval)
	})
	// Asserted for the same reason as in the table above: an empty fd 2 is what a
	// helper that never ran would also produce.
	if creds.AccessKeyID != leakedKeyID {
		t.Fatalf("credentials came from %q, want the helper's %q", creds.AccessKeyID, leakedKeyID)
	}
	if !strings.Contains(captured, afterRetrieval) {
		t.Fatalf("os.Stderr was not restored after retrieval; captured:\n%s", captured)
	}
	if strings.TrimSpace(strings.ReplaceAll(captured, afterRetrieval, "")) != "" {
		t.Fatalf("a machine format must leave fd 2 clean, got:\n%s", captured)
	}
}

// The line standing in for the MFA prompt the SDK's os.Stderr assignment exists
// to show. Distinct from the fixture keys so an assertion about the prompt
// cannot be satisfied by a leaked credential, and vice versa.
const mfaPrompt = "Enter MFA code for arm-token:"

// A marker written to os.Stderr once retrieval has returned, to prove the
// variable is back where it started.
const afterRetrieval = "bmcp-still-owns-fd-2"

// stderrWritingCredentialProcessProfile appends a profile whose helper writes to
// stderr as well as stdout: `set -x` makes the shell trace the credential echo,
// which is #61's reproduction verbatim, and the prompt line stands for a helper
// waiting on a hardware token.
//
// Note that the trace fires on the successful path. Unlike #60's fixtures this
// helper emits valid credential JSON and exits 0.
func stderrWritingCredentialProcessProfile(t *testing.T, name string) string {
	t.Helper()
	helper := tracingCredentialHelper(t)
	appendSharedConfig(t, "\n[profile "+name+"]\nregion = us-east-1\ncredential_process = "+helper+"\n")
	return name
}

// tracingCredentialHelper writes the fixture that reproduces #61 and returns its
// path, for the cases that build a processcreds provider directly rather than
// going through a profile.
//
// `set -x` is the whole point: it echoes the credential JSON to stderr on
// *success*, which is the channel this file exists to close. A shell that
// stopped tracing would make every assertNoLeak in the package vacuous.
func tracingCredentialHelper(t *testing.T) string {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "helper.sh")
	script := "#!/bin/sh\nset -x\necho '" + mfaPrompt + "' >&2\n" +
		`echo '{"Version":1,"AccessKeyId":"` + leakedKeyID + `","SecretAccessKey":"` + leakedSecret + `"}'` + "\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return helper
}

// guardStdFds restores os.Stdin and os.Stderr to their current values when the
// test ends.
//
// A retrieval that is abandoned leaves its sink installed on purpose and latches
// so nothing puts it back — which is correct in production, where the process is
// about to exit, and a leak across tests here: every test that runs afterwards
// in the same binary would see /dev/null on the global. For stderr that is only
// noise, since later tests write to their own buffers. For stdin it changes an
// answer: /dev/null is a character device, so an unrestored sink makes
// isInteractive() report a terminal for the rest of the run.
//
// captureStderrFd restores stderr wherever it wraps a case, and withStdinFd
// restores stdin wherever it supplies one, so most cases need nothing. This is
// for the two that install a sink through production code with one of those
// wrappers missing.
func guardStdFds(t *testing.T) {
	t.Helper()
	in, err := os.Stdin, os.Stderr
	t.Cleanup(func() {
		os.Stdin, os.Stderr = in, err
	})
}

// captureStderrFd points os.Stderr at a file for the duration of fn and returns
// what was written to it.
//
// The variable, not the descriptor: a raw syscall.Write(2, …) is not captured
// here, and does not need to be. #61's channel is precisely the *value* of
// os.Stderr at the moment processcreds reads it to build the helper command —
// that file becomes the child's fd 2 — so this is the only thing a test can
// observe. Injecting app.stderr, which every other test in this file does, sees
// nothing of it.
//
// A file rather than an os.Pipe on purpose. A pipe would deadlock a fixture that
// wrote more than its buffer, because nothing drains it until fn returns; a
// fixture writing a megabyte is a reasonable thing to want and would have failed
// for a reason that had nothing to do with the code under test.
//
// Safe to swap a package variable because nothing under cmd/bmcp starts a
// goroutine of its own, and Go runs a package's tests sequentially unless they
// ask otherwise. Nothing here may call t.Parallel().
func captureStderrFd(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("create capture file: %v", err)
	}
	restore := os.Stderr
	// Deferred as well as done below, because a t.Fatalf inside fn unwinds through
	// runtime.Goexit rather than returning: the restore still has to happen, and
	// nothing after fn runs.
	defer func() {
		os.Stderr = restore
		f.Close()
	}()
	os.Stderr = f
	fn()
	os.Stderr = restore
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	return string(out)
}

// The default the shipped binary uses, since every case above injects stderrTTY
// to reach a branch a test cannot otherwise produce. A pipe is what CI, a shell
// redirect and an agent harness all present, and it is the answer that decides
// whether the helper's output is discarded — so it is worth asserting directly
// rather than trusting that the injected form and the real one agree.
func TestStderrIsTerminalIsFalseForACapturedDescriptor(t *testing.T) {
	var direct, throughApp bool
	captureStderrFd(t, func() {
		direct = stderrIsTerminal(os.Stderr)
		throughApp = (&app{}).stderrIsTerminal()
	})
	if direct {
		t.Fatal("a regular file reported itself as a terminal")
	}
	if throughApp {
		t.Fatal("an app with no injected stderrTTY did not fall through to the real check")
	}
	// A character device that is not a terminal must answer no. This is the
	// distinction a ModeCharDevice test cannot draw, and the one that matters:
	// /dev/kmsg and /dev/console are character devices whose contents persist,
	// so treating every character device as "a person is watching" put a
	// helper's trace into a kernel or serial-console log. /dev/null stands in
	// for them here because it is the one such device every machine has.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()
	if stderrIsTerminal(devNull) {
		t.Fatalf("%s is a character device but not a terminal, and must not take the visible branch", os.DevNull)
	}
	// The answer in the other direction, which nothing else pins: a detector
	// stuck on "captured" would take the MFA prompt away from every operator at
	// a terminal with the whole suite still green. Needs a real tty, so it is
	// skipped where the test host has no controlling terminal — CI, mostly.
	if tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
		defer tty.Close()
		if !stderrIsTerminal(tty) {
			t.Fatal("a controlling terminal was not recognised as one, which would discard every MFA prompt")
		}
	} else {
		t.Logf("no controlling terminal here, so the positive case is unasserted: %v", err)
	}
	// And the reason the decision may not be taken on the live global: an app
	// whose realStderr is pinned answers for fd 2 even while os.Stderr holds a
	// sink. Without that, an abandoned retrieval's /dev/null decided every later
	// policy question in the process.
	captured, err := os.CreateTemp(t.TempDir(), "fd2")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer captured.Close()
	pinned := &app{realStderr: captured}
	restore := os.Stderr
	defer func() { os.Stderr = restore }()
	os.Stderr = devNull
	if pinned.stderrIsTerminal() {
		t.Fatal("the terminal test read the installed sink instead of the pinned descriptor")
	}
}

// The property every case above assumes and none of them can check: that
// a.machine is already set by the time credentials resolve.
//
// It is assigned in selectFormat during dispatch (cmd/bmcp/commands.go), and the
// unit cases reach retrieveCredentials with it set by hand — so a dispatch order
// that resolved credentials before selectFormat ran would leave them all green
// while `bmcp --format json` leaked on a terminal. This goes through a.run, and
// claims a terminal, so the machine gate is the only thing standing between the
// helper and the descriptor.
func TestFormatJSONDispatchSetsTheMachineGateBeforeCredentialsResolve(t *testing.T) {
	isolateAWSEnv(t)
	profile := stderrWritingCredentialProcessProfile(t, "chatty")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
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
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		stderrTTY: func() bool { return true },
	}
	var code int
	captured := captureStderrFd(t, func() {
		// No --non-interactive: that conjunct would discard on its own, and this
		// test would stay green with a.machine deleted from the policy — which is
		// the one thing it exists to catch.
		code = a.run([]string{"--format", "json", "tools___search_aws"})
	})
	// The pin has to have happened, and run() is the only place it can: every
	// subprocess descriptor and the terminal test read it, so an app that reached
	// a credential path without it would be one abandoned retrieval away from
	// handing `aws sso login` a /dev/null.
	if a.realStderr == nil {
		t.Fatal("run() did not pin the startup stderr, so nothing can tell what fd 2 is")
	}
	// exitSync rather than "non-zero", because that is what says the helper ran.
	// The catalog is cached and localhost:8787 is not listening, so a run that
	// resolved credentials fails on the call; one that never got that far fails
	// with exitAuth, having spawned nothing, and every absence below would then
	// hold on an empty string.
	if code != exitSync {
		t.Fatalf("want exit %d, the failure of a run that resolved credentials, got %d; stderr:\n%s", exitSync, code, captured)
	}
	assertNoLeak(t, captured)
	if strings.Contains(captured, mfaPrompt) {
		t.Fatalf("helper stderr reached fd 2 under --format json:\n%s", captured)
	}
	// The contract the leak breaks, asserted where the caller sees it: bmcp's own
	// writer holds one document, and fd 2 held nothing to interleave with it.
	if captured != "" {
		t.Fatalf("--format json must leave fd 2 clean, got:\n%s", captured)
	}
	assertNoLeak(t, stdout.String())
	assertNoLeak(t, stderr.String())
}

// The hole the first version of this fix had, and the reason the swap is not
// simply put back in a defer.
//
// LoadDefaultConfig always wraps the provider in an aws.CredentialsCache, whose
// Retrieve runs the real provider on a singleflight goroutine and abandons it
// the moment the caller's context is done — handing it a context whose Done() is
// nil, so nothing ever stops it. That goroutine reads os.Stderr when it builds
// the helper command, which is *after* Retrieve has returned. Restoring the
// variable there handed the helper the captured descriptor after bmcp had
// already reported failure; it reproduced 3 times out of 3.
//
// A cancelled context is not exotic: it is any invocation whose --call-timeout
// or --sync-timeout is consumed before credentials resolve.
//
// The cache and the provider are built here rather than through
// LoadDefaultConfig so the test can hold a real happens-before edge to that
// goroutine. Waiting on a file the helper touches would order the two in
// practice and still be a data race by definition — which is exactly what the
// first version of this test was, intermittently failing `go test -race`.
// TestChainRunsACredentialProcessSeesEveryProcessShape covers the other half,
// that the config path really does produce an aws.CredentialsCache.
func TestCredentialProcessStderrSurvivesACancelledRetrieval(t *testing.T) {
	isolateAWSEnv(t)
	helper := filepath.Join(t.TempDir(), "helper.sh")
	script := "#!/bin/sh\nset -x\n" +
		`echo '{"Version":1,"AccessKeyId":"` + leakedKeyID + `","SecretAccessKey":"` + leakedSecret + `"}'` + "\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	retrieved := make(chan struct{})
	// Held until the cancelled retrieval has returned, so the helper command is
	// built — and os.Stderr read — strictly afterwards. That is the ordering the
	// restore rule has to survive, and without the gate the worker is free to do
	// its reading first, which would let an unconditional restore pass here.
	release := make(chan struct{})
	worker := &signallingProvider{
		inner:   processcreds.NewProvider(helper),
		release: release,
		done:    retrieved,
	}
	cache := aws.NewCredentialsCache(worker)
	a := authTestApp()
	// Both inert, and kept only to say so. cfg.NonInteractive below already sends
	// this case down the discard branch, which is the branch it needs: the visible
	// branch installs no sink, so there would be nothing for the restore rule to
	// get wrong. What this case pins is that the sink is *not* put back while an
	// abandoned goroutine may still read it.
	a.machine = false
	a.stderrTTY = func() bool { return true }
	cfg := effectiveConfig{
		Profile:        "racy",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}

	var err error
	captured := captureStderrFd(t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = a.retrieveCredentials(ctx, cfg, cache)
		// Only now may the worker proceed, which is what puts its read of
		// os.Stderr after the retrieval returned.
		close(release)
		// Receiving here is what makes restoring os.Stderr afterwards safe: the
		// send happens after the abandoned goroutine has finished reading it.
		select {
		case <-retrieved:
		case <-time.After(30 * time.Second):
			t.Error("the abandoned helper never finished, so this case asserted nothing")
		}
	})
	if err == nil {
		t.Fatal("a cancelled retrieval should have failed")
	}
	// Before any absence: the helper has to have actually run, or an empty capture
	// would satisfy every check below.
	assertAbandonedHelperRan(t, worker)
	assertNoLeak(t, captured)
	assertNoLeak(t, err.Error())
}

// signallingProvider drives the singleflight goroutine aws.CredentialsCache
// abandons on cancellation, so a test can order it rather than hope.
//
// Two channels, and both are load-bearing. release holds the provider before it
// runs, which is what forces the helper command to be *built* — the moment
// processcreds reads os.Stderr — after the cancelled retrieval has already
// returned. Without it the worker may do its reading first, and a test meant to
// catch an unconditional restore passes on the wrong schedule. done closes once
// the inner provider is finished, and result() then says whether it actually
// produced credentials: the SDK returns command-start failures the same way it
// returns a cancelled retrieval, so a test that only waited for the signal could
// accept a run where the helper never executed and assert absences against an
// empty capture.
//
// ProviderSources is forwarded so the chain still describes itself the way the
// real one does.
type signallingProvider struct {
	inner   aws.CredentialsProvider
	release <-chan struct{}
	done    chan struct{}

	mu    sync.Mutex
	creds aws.Credentials
	err   error
}

func (p *signallingProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if p.release != nil {
		<-p.release
	}
	creds, err := p.inner.Retrieve(ctx)
	p.mu.Lock()
	p.creds, p.err = creds, err
	p.mu.Unlock()
	close(p.done)
	return creds, err
}

// result reports what the abandoned retrieval produced. Safe to call once done
// is closed.
func (p *signallingProvider) result() (aws.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.creds, p.err
}

// assertAbandonedHelperRan fails unless the goroutine the cache walked away from
// actually executed the helper and got its credentials. Every absence a
// cancellation test asserts is vacuous without it.
func assertAbandonedHelperRan(t *testing.T, p *signallingProvider) {
	t.Helper()
	creds, err := p.result()
	if err != nil {
		t.Fatalf("the abandoned retrieval never produced credentials, so the case asserted nothing: %v", err)
	}
	if creds.AccessKeyID != leakedKeyID {
		t.Fatalf("the abandoned retrieval returned %q, want the helper's %q", creds.AccessKeyID, leakedKeyID)
	}
}

func (p *signallingProvider) ProviderSources() []aws.CredentialSource {
	return reportedSources(p.inner)
}

// Withholding the SDK's error text (#60) left "run the helper yourself" as the
// operator's next step. #61 then discarded the helper's own stderr, so on a
// captured descriptor there is nothing in the log at all — and a message that
// still said only "run it yourself" would let that emptiness read as "the
// helper printed nothing". The message has to name the discard, and only when
// there was one.
func TestCredentialProcessFailureSaysWhenItDiscardedTheHelpersStderr(t *testing.T) {
	// The one case in this file that installs a stdin sink through production code
	// with nothing wrapping fd 0: the ownsStdin rows below go through
	// retrieveCredentials, and captureStderrFd restores only stderr. A retrieval
	// that timed out would latch and skip the restore, leaving /dev/null on
	// os.Stdin for every test after this one.
	guardStdFds(t)
	const clause = "discarded rather than shown"
	const stdinClause = "Its stdin was /dev/null"
	for _, tc := range []struct {
		name string
		tty  bool
		// interactive drives cfg.NonInteractive, inverted, exactly as in the policy
		// table above: the clause has to track the gate, not a stand-in for it.
		interactive bool
		// ownsStdin drives the stdin half of the same policy, independently — the
		// two clauses must track their own gates, not each other.
		ownsStdin bool
		says      bool
		saysStdin bool
	}{
		{name: "stderr captured", says: true},
		{name: "non-interactive on a terminal", tty: true, says: true},
		{name: "stderr is a terminal", tty: true, interactive: true, says: false},
		{
			// #65's headline shape, and the one combination no test read before:
			// stderr kept, stdin discarded, so the message must name the second and
			// not the first. An edit that merged the two clauses fails here.
			name: "piped payload at a terminal", tty: true, interactive: true,
			ownsStdin: true, says: false, saysStdin: true,
		},
		{
			// Both discarded, which is CI. The two clauses have to compose into one
			// readable sentence rather than one overwriting the other.
			name: "both discarded", ownsStdin: true, says: true, saysStdin: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			helper := filepath.Join(t.TempDir(), "helper.sh")
			// The shape #60's fixtures cannot produce: a helper that explains itself
			// on stderr and then fails, which is what every real wrapper does.
			body := "#!/bin/sh\necho 'vault: profile prod is not unlocked' >&2\nexit 1\n"
			if err := os.WriteFile(helper, []byte(body), 0o700); err != nil {
				t.Fatalf("write helper: %v", err)
			}
			appendSharedConfig(t, "\n[profile broken]\nregion = us-east-1\ncredential_process = "+helper+"\n")
			cfg := effectiveConfig{
				Profile:        "broken",
				ProfileSource:  profileSourceFile,
				Region:         "us-east-1",
				NonInteractive: !tc.interactive,
			}
			a := authTestApp()
			a.machine = false
			a.stderrTTY = func() bool { return tc.tty }
			a.ownsStdin = tc.ownsStdin
			var err error
			captureStderrFd(t, func() {
				_, _, err = a.awsCredentials(authTestContext(t), cfg)
			})
			if err == nil {
				t.Fatal("expected an auth failure")
			}
			if got := strings.Contains(err.Error(), clause); got != tc.says {
				t.Fatalf("message names the stderr discard = %v, want %v: %q", got, tc.says, err.Error())
			}
			if got := strings.Contains(err.Error(), stdinClause); got != tc.saysStdin {
				t.Fatalf("message names the stdin discard = %v, want %v: %q", got, tc.saysStdin, err.Error())
			}
			// Whichever way that went, the helper's own words are still withheld —
			// the clause explains the silence, it does not lift the rule.
			if strings.Contains(err.Error(), "not unlocked") {
				t.Fatalf("the helper's stderr reached the message: %q", err.Error())
			}
		})
	}
}

// The contract #61 breaks, asserted on the stream the contract is about.
//
// Every other case here gives a.stderr a bytes.Buffer, so bmcp's document and
// the helper's trace never land on the same place and nothing checks the claim
// BORIS.md actually makes: that under a machine format stderr carries one
// parseable document, so `2>&1` is safe. This builds the app with the captured
// file as its own stderr — the arrangement a caller merging the streams has —
// and decodes it.
func TestFormatJSONMergedStderrIsExactlyOneDocument(t *testing.T) {
	isolateAWSEnv(t)
	profile := stderrWritingCredentialProcessProfile(t, "chatty")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(t.TempDir())
	borisHome := setupInstallCatalog(t, home, []tool{{Name: "tools___search_aws", Description: "Search."}})
	fileCfg, err := readConfig(filepath.Join(borisHome, "config.toml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	fileCfg.AWSProfile = profile
	if err := writeConfig(filepath.Join(borisHome, "config.toml"), fileCfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var stdout bytes.Buffer
	var code int
	captured := captureStderrFd(t, func() {
		// os.Stderr, not a buffer: inside this closure that is the capture file, so
		// bmcp's own output and anything the helper writes share one stream exactly
		// as they would for a caller who wrote `2>&1`.
		a := &app{stdin: strings.NewReader(""), stdout: &stdout, stderr: os.Stderr, now: time.Now}
		code = a.run([]string{"--format", "json", "--non-interactive", "tools___search_aws"})
	})
	// exitSync rather than merely non-zero: the run has to have got past credential
	// resolution, or the helper never ran and "one document, no leak" holds
	// trivially for an auth failure that spawned nothing.
	if code != exitSync {
		t.Fatalf("want exit %d, the failure of a run that resolved credentials, got %d; stderr:\n%s", exitSync, code, captured)
	}
	if stdout.Len() != 0 {
		t.Fatalf("a failure must leave stdout empty, got:\n%s", stdout.String())
	}
	assertNoLeak(t, captured)
	// One document and nothing after it. A trace line ahead of the document would
	// fail on the first Decode; one appended would fail on the io.EOF check, which
	// is the half a single Unmarshal would have missed.
	dec := json.NewDecoder(strings.NewReader(captured))
	var doc struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("merged stderr is not one JSON document (%v):\n%s", err, captured)
	}
	if _, err := dec.Token(); err != io.EOF {
		t.Fatalf("merged stderr carries more than the document (%v):\n%s", err, captured)
	}
	if doc.OK {
		t.Fatalf("expected ok:false, got:\n%s", captured)
	}
	assertNoLeak(t, doc.Message)
}

// The SDK assumption chainRunsACredentialProcess rests on, pinned so an SDK bump
// that stopped reporting a process source fails here rather than silently
// narrowing the refusal it guards.
//
// The chain case is the one that matters: the helper sits at the leaf of a
// source_profile chain under an assume-role provider, and the report has to
// survive both hops.
func TestChainRunsACredentialProcessSeesEveryProcessShape(t *testing.T) {
	isolateAWSEnv(t)
	leaf := credentialProcessProfile(t, "cp-leaf", `{"Version":1,"AccessKeyId":"`+leakedKeyID+`","SecretAccessKey":"`+leakedSecret+`"}`)
	appendSharedConfig(t, "\n[profile cp-chain]\nregion = us-east-1\nsource_profile = "+leaf+"\nrole_arn = arn:aws:iam::123456789012:role/example\n")
	appendSharedConfig(t, `
[profile sso-session-form]
region = us-east-1
sso_session = s
sso_account_id = 123456789012
sso_role_name = Example

[sso-session s]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
`)
	for _, tc := range []struct {
		profile string
		want    bool
	}{
		{profile: leaf, want: true},
		{profile: "cp-chain", want: true},
		{profile: "has-static", want: false},
		{profile: "sso-only", want: false},
		{profile: "sso-session-form", want: false},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			awsCfg, err := awsconfig.LoadDefaultConfig(authTestContext(t), awsconfig.WithSharedConfigProfile(tc.profile))
			if err != nil {
				t.Fatalf("load config for %s: %v", tc.profile, err)
			}
			if got := chainRunsACredentialProcess(awsCfg.Credentials); got != tc.want {
				t.Fatalf("chainRunsACredentialProcess(%s) = %v, want %v (sources reported: %v)",
					tc.profile, got, tc.want, reportedSources(awsCfg.Credentials))
			}
		})
	}
	// And the unknown case answers yes, which is the direction that keeps a chain
	// the SDK stops describing from running a helper uncontained.
	if !chainRunsACredentialProcess(staticProviderWithoutSources{}) {
		t.Fatal("a provider that reports no sources must be assumed to run a process")
	}
}

// A provider deliberately not implementing aws.CredentialProviderSource.
type staticProviderWithoutSources struct{}

func (staticProviderWithoutSources) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, nil
}

func reportedSources(provider aws.CredentialsProvider) []aws.CredentialSource {
	if source, ok := provider.(aws.CredentialProviderSource); ok {
		return source.ProviderSources()
	}
	return nil
}

// The hole the conditional restore left open, and what the latch closes.
//
// Two retrievals in one run, the first cancelled and — the point of the case —
// *not* waited for, so the goroutine it abandoned may still be reading os.Stderr
// to build its command. bmcp produces exactly this shape: a sync whose timeout
// expires is downgraded to a warning rather than ending the run (cacheForCatalog),
// and credentials are resolved again on a fresh context.
//
// The assertion is descriptor identity: the second retrieval must run under the
// very file the abandoned one left installed. Before the latch it ran under a
// second sink, which it then closed — while a worker that had already read the
// variable held that same file as its child's fd 2. That is a closed descriptor
// handed to a helper, and an unsynchronised write to os.Stderr besides.
func TestASecondRetrievalDoesNotReassignStderrUnderAnAbandonedOne(t *testing.T) {
	isolateAWSEnv(t)
	helper := tracingCredentialHelper(t)
	abandoned := make(chan struct{})
	// Held until *both* retrievals have returned. That is the worst ordering for
	// the bug under test: the abandoned worker reads os.Stderr after a second
	// call has had every chance to reassign it.
	release := make(chan struct{})
	worker := &signallingProvider{
		inner:   processcreds.NewProvider(helper),
		release: release,
		done:    abandoned,
	}
	first := aws.NewCredentialsCache(worker)
	recorder := &stderrRecordingProvider{inner: processcreds.NewProvider(helper)}
	second := aws.NewCredentialsCache(recorder)

	a := authTestApp()
	// Inert, and kept to say so: cfg.NonInteractive below sends both calls down
	// the discard branch on its own, which is the branch this case needs. The
	// visible branch installs no sink, and there would be nothing to reassign.
	a.machine = false
	a.stderrTTY = func() bool { return true }
	cfg := effectiveConfig{
		Profile:        "racy",
		ProfileSource:  profileSourceFile,
		Region:         "us-east-1",
		NonInteractive: true,
	}

	var creds aws.Credentials
	var installed, ranUnder *os.File
	captured := captureStderrFd(t, func() {
		// Pinned where os.Stderr is still the capture file — the same moment main()
		// pins it, before anything has installed a sink.
		a.realStderr = os.Stderr

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := a.retrieveCredentials(ctx, cfg, first); err == nil {
			t.Error("a cancelled retrieval should have failed")
		}
		installed = os.Stderr

		// Deliberately no wait on `abandoned`: a second retrieval racing the
		// goroutine the first one left behind is the situation under test.
		var err error
		creds, err = a.retrieveCredentials(authTestContext(t), cfg, second)
		if err != nil {
			t.Errorf("the second retrieval should have succeeded, got: %v", err)
		}
		ranUnder = recorder.saw()

		// Only now, so the abandoned worker builds its command after both calls.
		close(release)
		select {
		case <-abandoned:
		case <-time.After(30 * time.Second):
			t.Error("the abandoned helper never finished, so this case asserted nothing")
		}
	})

	// Asserted before any absence: a second retrieval that failed would have
	// written no trace, and every check below would hold on an empty string.
	if creds.AccessKeyID != leakedKeyID {
		t.Fatalf("second retrieval returned %q, want the helper's %q", creds.AccessKeyID, leakedKeyID)
	}
	// The abandoned helper has to have actually executed, or "no leak" below holds
	// for the trivial reason that nothing ever wrote.
	assertAbandonedHelperRan(t, worker)
	if installed == nil || ranUnder == nil {
		t.Fatal("the retrievals did not record the descriptor they ran under")
	}
	if ranUnder != installed {
		t.Fatal("the second retrieval installed a sink of its own over the one an abandoned goroutine may still be reading")
	}
	if !a.stderrSunk {
		t.Fatal("an abandoned retrieval did not latch, so a later call is free to reassign os.Stderr under it")
	}
	assertNoLeak(t, captured)
	if strings.Contains(captured, mfaPrompt) {
		t.Fatalf("helper stderr reached the captured descriptor:\n%s", captured)
	}
}

// stderrRecordingProvider reports the os.Stderr its retrieval actually ran
// under, which is the thing processcreds reads to build the helper command.
type stderrRecordingProvider struct {
	inner aws.CredentialsProvider
	mu    sync.Mutex
	seen  *os.File
}

func (p *stderrRecordingProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	p.mu.Lock()
	p.seen = os.Stderr
	p.mu.Unlock()
	return p.inner.Retrieve(ctx)
}

func (p *stderrRecordingProvider) saw() *os.File {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}

// The consequence that made the leaked sink worse than an untidy global, pinned
// through the subprocess that suffers it.
//
// After a retrieval is abandoned, os.Stderr stays pointed at /dev/null on
// purpose. `aws sso login` is not what that sink exists to contain — it is
// bmcp's own subprocess, and an operator has to read the verification URL and
// user code it prints. Handing it the global destroyed both and left bmcp
// blocking on a device flow with nothing on screen.
//
// The fake `aws` on PATH is how the shell-out is observed without a real login.
func TestSSOLoginAfterAnAbandonedRetrievalStillReachesTheOperator(t *testing.T) {
	const verification = "bmcp-verification-url-and-user-code"
	isolateAWSEnv(t)

	// A fake `aws` that prints where a real one prints its device code, copies
	// whatever it is given on fd 0, and fails so the caller still reports the
	// original credential problem.
	//
	// The copy is the stdin half of the same rule. A real `aws sso login` reads
	// fd 0 — for the browser-or-code choice, and for anything a profile's own
	// prompts need — and the abandoned retrieval above has left /dev/null on the
	// os.Stdin global on purpose. Handing the subprocess the global rather than
	// the pinned descriptor gives the login end-of-file for the one prompt it may
	// still need, which is exactly the failure the sink is not supposed to cause.
	binDir := t.TempDir()
	answered := filepath.Join(t.TempDir(), "answered")
	fake := filepath.Join(binDir, "aws")
	script := "#!/bin/sh\nhead -c 512 >> '" + answered + "'\necho '" + verification + "' >&2\nexit 1\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake aws: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	helper := tracingCredentialHelper(t)
	release := make(chan struct{})
	finished := make(chan struct{})
	worker := &signallingProvider{
		inner:   processcreds.NewProvider(helper),
		release: release,
		done:    finished,
	}

	a := authTestApp()
	// The shape that reaches the login: a human format, nothing saying the run is
	// non-interactive, and a stdin someone could answer at.
	a.machine = false
	a.interactive = func() bool { return true }
	a.stderrTTY = func() bool { return false }
	// And a command that reads fd 0 itself, so the abandoned retrieval below
	// installs the stdin sink as well as the stderr one. Without it there is no
	// sink for the login to be wrongly handed, and the stdin assertion is vacuous.
	a.ownsStdin = true

	const loginAnswer = "bmcp-operator-typed-this-at-the-login"
	captured := captureStderrFd(t, func() {
		a.realStderr = os.Stderr
		withStdinFd(t, a, loginAnswer, func() {

			// Abandon a retrieval, which is what installs the sink and latches it.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := a.retrieveCredentials(ctx, effectiveConfig{
				Profile:        "racy",
				ProfileSource:  profileSourceFile,
				Region:         "us-east-1",
				NonInteractive: true,
			}, aws.NewCredentialsCache(worker)); err == nil {
				t.Error("a cancelled retrieval should have failed")
			}
			if !a.stderrSunk {
				t.Fatal("the retrieval did not latch, so the rest of this case proves nothing")
			}
			// The same guard for fd 0, and it is load-bearing in the same way: without
			// a latched stdin sink os.Stdin is still the fixture, subprocessStdin()
			// returns the same descriptor either way, and the `answered` assertion at
			// the end passes whichever one the login is handed. Dropping a.ownsStdin
			// from the setup above used to leave this test green.
			if !a.stdinSunk {
				t.Fatal("no stdin sink was latched, so the login has nothing to be wrongly handed")
			}

			// Now an SSO profile, whose retrieval cannot succeed here, so the login
			// branch runs. Its subprocess must reach fd 2, not the sink.
			//
			// A generous deadline rather than authTestContext's ten seconds:
			// awsCredentials declines to start a device flow that cannot finish inside
			// the budget left, and ten seconds cannot. This mirrors a real `bmcp <tool>`
			// call, whose CallTimeout is ten minutes, so the branch is reached the same
			// way production reaches it. Still bounded, so a resolution that went to a
			// link-local endpoint would not hang the suite indefinitely.
			loginCtx, cancelLogin := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancelLogin()
			_, _, err := a.awsCredentials(loginCtx, effectiveConfig{
				Profile:       "sso-only",
				ProfileSource: profileSourceFile,
				Region:        "us-east-1",
			})
			if err == nil {
				t.Error("an sso-only profile should not have resolved in a test")
			}

			close(release)
			select {
			case <-finished:
			case <-time.After(30 * time.Second):
				t.Error("the abandoned helper never finished")
			}
		})
	})

	assertAbandonedHelperRan(t, worker)
	if !strings.Contains(captured, verification) {
		t.Fatalf("aws sso login was handed the sink, so its device code never reached the operator; captured:\n%s", captured)
	}
	// The other direction, on the descriptor the credential_process helper was
	// just denied. Reverting cmd.Stdin to the os.Stdin global leaves this empty.
	got, err := os.ReadFile(answered)
	if err != nil {
		t.Fatalf("aws sso login recorded nothing from fd 0: %v", err)
	}
	if string(got) != loginAnswer {
		t.Fatalf("aws sso login read %q from fd 0, want the operator's %q — it was handed the sink", got, loginAnswer)
	}
	// And the sink still did its job for the thing it was installed for.
	assertNoLeak(t, captured)
}

// The payload standing in for what `echo '{...}' | bmcp call <tool>` puts on fd
// 0. Distinct from every fixture credential in this file so an assertion that
// the helper ate it cannot be satisfied by something else, and long enough that
// a helper reading a fixed number of bytes takes all of it.
const callPayload = `{"query":"BMCP-65-CALLER-PAYLOAD-SENTINEL"}`

// stdinEatingCredentialHelper writes #65's reproduction and returns the helper's
// path alongside the file it copies stdin into.
//
// `head -c 512` stands in for the `read -r code` an MFA wrapper does by
// accident: the SDK hands the helper bmcp's own fd 0, the child shares the file
// description and therefore the offset, and whatever it takes is gone from the
// payload runCall has not read yet. Against /dev/null the same line reads zero
// bytes and returns at once, which is what the fix is asserted to produce.
//
// It emits valid credential JSON and exits 0, so every assertion below is about
// a *successful* retrieval — the shape that makes #65 silent.
func stdinEatingCredentialHelper(t *testing.T) (helper, stolen string) {
	t.Helper()
	dir := t.TempDir()
	stolen = filepath.Join(dir, "stolen")
	helper = filepath.Join(dir, "helper.sh")
	// Appended, not truncated. Two of the tests below run the helper twice — a
	// second retrieval, or an abandoned goroutine finishing last — and with `>` the
	// final run's empty read erased the evidence of an earlier one that had eaten
	// the payload, leaving the assertion to pass on a wiped file.
	//
	// The `||` arm distinguishes the two ways this file ends up empty. Containment
	// means a *readable* /dev/null answering end-of-file; a descriptor the helper
	// cannot read at all — fd 0 opened write-only, say — also writes nothing, and
	// every "the helper ate nothing" assertion below would hold for that too. A
	// marker turns it into a failure instead.
	script := "#!/bin/sh\nhead -c 512 >> '" + stolen + "' || echo UNREADABLE-STDIN >> '" + stolen + "'\n" +
		"echo '" + mfaPrompt + "' >&2\n" +
		`echo '{"Version":1,"AccessKeyId":"` + leakedKeyID + `","SecretAccessKey":"` + leakedSecret + `"}'` + "\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	return helper, stolen
}

// stdinEatingCredentialProcessProfile appends a profile backed by that helper
// and returns its name and the file the helper copies stdin into.
func stdinEatingCredentialProcessProfile(t *testing.T, name string) (profile, stolen string) {
	t.Helper()
	helper, stolen := stdinEatingCredentialHelper(t)
	appendSharedConfig(t, "\n[profile "+name+"]\nregion = us-east-1\ncredential_process = "+helper+"\n")
	return name, stolen
}

// withStdinFd points os.Stdin at a file holding content for the duration of fn,
// pins it on a as the startup descriptor the way run() does, and returns
// whatever is left unread afterwards.
//
// A regular file rather than a pipe, and that is not a weakening: both answer
// "not a character device", which is the only thing either policy asks, and an
// inherited regular fd shares its offset with the child exactly as a pipe shares
// its unread bytes. It also lets the test read back what survived, which a
// consumed pipe cannot be asked.
func withStdinFd(t *testing.T, a *app, content string, fn func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write stdin fixture: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open stdin fixture: %v", err)
	}
	restore := os.Stdin
	// Deferred as well as done below, because a t.Fatalf inside fn unwinds through
	// runtime.Goexit rather than returning.
	defer func() {
		os.Stdin = restore
		f.Close()
	}()
	os.Stdin = f
	a.realStdin = f
	fn()
	os.Stdin = restore
	rest, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read back what survived on stdin: %v", err)
	}
	return string(rest)
}

// #65, at the one shape its own issue text would not have fixed.
//
// The issue proposed putting os.Stdin behind the three-way stderr gate. That
// gate is an early return leaving both descriptors alone, and `echo '{...}' |
// bmcp call <tool>` run at a terminal satisfies it: fd 2 is the tty, the format
// is human, no --non-interactive. So the shared gate answers "keep", the helper
// is handed the pipe, and the payload is gone — the fix would have shipped
// green and changed nothing about the bug it was written for.
//
// Everything here is therefore asserted with stderr *kept*: the helper's MFA
// prompt must still reach fd 2 in the same run where its stdin is /dev/null.
// Collapsing the two gates back into one fails this test in both directions.
func TestCredentialProcessHelperCannotEatTheCallPayload(t *testing.T) {
	isolateAWSEnv(t)
	profile, stolen := stdinEatingCredentialProcessProfile(t, "greedy")
	cfg := effectiveConfig{
		Profile:       profile,
		ProfileSource: profileSourceFile,
		Region:        "us-east-1",
	}
	a := authTestApp()
	// A human format at a terminal, which is what makes this the shape the shared
	// gate keeps. Both are load-bearing: either one alone sinks stderr too and the
	// split stops being what the test proves.
	a.machine = false
	a.stderrTTY = func() bool { return true }
	// What `bmcp call <tool>` sets when its payload is arriving on stdin. The
	// production wiring for this is asserted end to end by
	// TestPipedPayloadSurvivesAStaleCatalogSync, which goes through run().
	a.ownsStdin = true

	var creds aws.Credentials
	var err error
	var survived string
	var fixture, afterRetrieve *os.File
	captured := captureStderrFd(t, func() {
		a.realStderr = os.Stderr
		survived = withStdinFd(t, a, callPayload, func() {
			fixture = os.Stdin
			creds, _, err = a.awsCredentials(authTestContext(t), cfg)
			// Read here, not after withStdinFd returns — it restores the descriptor
			// itself, so outside the closure the variable says nothing about what
			// the retrieval left behind. Deleting the restore in retrieveCredentials
			// used to keep the whole suite green; this is the assertion that notices.
			afterRetrieve = os.Stdin
		})
	})

	// Asserted first: a helper that failed would have read nothing either, and
	// every assertion below would pass for the wrong reason. #65 is a bug on the
	// success path, so the success has to be real.
	if err != nil {
		t.Fatalf("retrieval should have succeeded, got: %v", err)
	}
	if creds.AccessKeyID != leakedKeyID {
		t.Fatalf("credentials came from %q, want the helper's %q", creds.AccessKeyID, leakedKeyID)
	}

	if survived != callPayload {
		t.Fatalf("the payload on fd 0 did not survive the helper.\n got: %q\nwant: %q", survived, callPayload)
	}
	if eaten, readErr := os.ReadFile(stolen); readErr == nil && len(eaten) > 0 {
		t.Fatalf("the helper read %q from bmcp's stdin", eaten)
	}
	if !a.helperStdinDiscarded {
		t.Fatal("the helper's stdin was replaced but nothing recorded it, so a failure message cannot say so")
	}
	// Put back on a retrieval that finished. In production today this is hygiene
	// rather than a live fix — runCall reads a.stdin, which holds the descriptor's
	// *value* and is immune to the swap — but the variable is what the AWS SDK
	// reads to build its next command, and that is not ours to reason about
	// forever. Deleting the restore used to keep the whole suite green.
	if afterRetrieve != fixture {
		t.Fatal("os.Stdin was left pointing at the sink after a retrieval that completed")
	}

	// The other half of the split: stderr was never the problem here, and taking
	// the MFA prompt away to fix stdin would be a regression of #61's kept case.
	if !strings.Contains(captured, mfaPrompt) {
		t.Fatalf("fixing stdin took the helper's MFA prompt off fd 2; captured:\n%s", captured)
	}
	if a.helperStderrDiscarded {
		t.Fatal("stderr was discarded in a run whose policy keeps it")
	}
}

// The two policies are separate, and this is the table that says so. Each row
// asserts the observable rather than bmcp's own bookkeeping: stderr is kept iff
// the helper's prompt reached fd 2, stdin is kept iff the helper ate what was on
// it.
//
// The pairs matter more than the rows. Rows 1 and 2 hold everything constant
// except who the bytes on fd 0 belong to, and get opposite answers for stdin
// with the same answer for stderr; rows 5 and 6 do the same under a machine
// format. Putting stdin back behind any of the three stderr conjuncts collapses
// one of those pairs.
func TestHelperStreamPolicyDecidesStdinAndStderrSeparately(t *testing.T) {
	for _, tc := range []struct {
		name           string
		machine        bool
		nonInteractive bool
		stderrTTY      bool
		// ownsStdin is the gate under test: bmcp reads fd 0 itself this
		// invocation, so no subprocess may.
		ownsStdin  bool
		keepStderr bool
		keepStdin  bool
	}{
		{
			// #65's shape: `echo '{...}' | bmcp call <tool>` at a terminal. The two
			// streams disagree, and the answer differs per stream.
			name:       "piped payload at a terminal",
			stderrTTY:  true,
			ownsStdin:  true,
			keepStderr: true,
			keepStdin:  false,
		},
		{
			// The row that says the gate is not a terminal test. Same terminal, same
			// non-terminal stdin — but the payload came from argv, so the pipe was
			// put there for the helper. `printf %s "$CODE" | bmcp call <tool> '{...}'`
			// must still reach it. A terminal test answers this row "sink" and takes
			// a working setup away.
			name:       "piped MFA code, payload from argv",
			stderrTTY:  true,
			ownsStdin:  false,
			keepStderr: true,
			keepStdin:  true,
		},
		{
			// CI, and bmcp owns the descriptor. Both sunk.
			name:      "neither stream is a terminal, bmcp reads stdin",
			stderrTTY: false,
			ownsStdin: true,
		},
		{
			// The same CI run of a command that never reads stdin — sync, doctor,
			// list. #61's disclosure is live, and there is nothing on fd 0 to
			// protect, so the helper keeps it.
			name:      "neither stream is a terminal, bmcp does not read stdin",
			stderrTTY: false,
			ownsStdin: false,
			keepStdin: true,
		},
		{
			// A machine format overrides stderr the way it overrides the SSO login
			// branch. Only a.machine can carry this row.
			name:      "machine format on a terminal, bmcp reads stdin",
			machine:   true,
			stderrTTY: true,
			ownsStdin: true,
		},
		{
			// And the pair that proves a.machine does *not* reach stdin. Same machine
			// format, same terminal — the helper keeps fd 0 because nothing of bmcp's
			// is on it.
			name:      "machine format on a terminal, bmcp does not read stdin",
			machine:   true,
			stderrTTY: true,
			ownsStdin: false,
			keepStdin: true,
		},
		{
			// The flag that says nothing will answer a prompt. Only cfg.NonInteractive
			// can carry this row, and it too stops at stderr.
			name:           "non-interactive on a terminal, bmcp does not read stdin",
			nonInteractive: true,
			stderrTTY:      true,
			ownsStdin:      false,
			keepStdin:      true,
		},
		{
			// Its partner, so the table is self-sufficient about the third conjunct
			// as well. Without this row, adding cfg.NonInteractive to the stdin gate
			// leaves all the others green — the pair is what says the flag decides
			// stderr and not stdin.
			name:           "non-interactive on a terminal, bmcp reads stdin",
			nonInteractive: true,
			stderrTTY:      true,
			ownsStdin:      true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			profile, stolen := stdinEatingCredentialProcessProfile(t, "greedy")
			cfg := effectiveConfig{
				Profile:        profile,
				ProfileSource:  profileSourceFile,
				Region:         "us-east-1",
				NonInteractive: tc.nonInteractive,
			}
			a := authTestApp()
			a.machine = tc.machine
			a.stderrTTY = func() bool { return tc.stderrTTY }
			a.ownsStdin = tc.ownsStdin

			var creds aws.Credentials
			var err error
			var survived string
			captured := captureStderrFd(t, func() {
				a.realStderr = os.Stderr
				survived = withStdinFd(t, a, callPayload, func() {
					creds, _, err = a.awsCredentials(authTestContext(t), cfg)
				})
			})
			if err != nil {
				t.Fatalf("retrieval should have succeeded, got: %v", err)
			}
			if creds.AccessKeyID != leakedKeyID {
				t.Fatalf("credentials came from %q, want the helper's %q", creds.AccessKeyID, leakedKeyID)
			}

			gotStderr := strings.Contains(captured, mfaPrompt)
			if gotStderr != tc.keepStderr {
				t.Errorf("helper stderr reached fd 2 = %v, want %v; captured:\n%s", gotStderr, tc.keepStderr, captured)
			}
			eaten, _ := os.ReadFile(stolen)
			gotStdin := len(eaten) > 0
			if gotStdin != tc.keepStdin {
				t.Errorf("helper read bmcp's stdin = %v, want %v; it got %q and %q survived", gotStdin, tc.keepStdin, eaten, survived)
			}
			// The bytes are either wholly intact or wholly gone; a partial read
			// would be a third outcome neither policy describes.
			if !tc.keepStdin && survived != callPayload {
				t.Errorf("what was on fd 0 did not survive intact: %q", survived)
			}
		})
	}
}

// isInteractive has to answer for the descriptor bmcp started with, not for
// whatever os.Stdin holds now — and the sink this package installs is the exact
// case that separates them, because /dev/null *is* a character device.
//
// Without the pin, one abandoned retrieval makes every later isInteractive()
// answer yes: `bmcp init` prompts into a void, and the SSO device flow is
// started with nothing able to read the code or type the approval. That is a
// worse failure than the one #65 set out to fix, arrived at by fixing it.
func TestIsInteractiveAnswersForTheStartupDescriptorNotTheSink(t *testing.T) {
	pinned, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("create pinned stdin: %v", err)
	}
	defer pinned.Close()
	// A regular file: not a character device, so the honest answer is no.
	a := &app{realStdin: pinned}
	if a.isInteractive() {
		t.Fatal("a regular file was reported as a terminal")
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()
	// Exactly what retrieveCredentials leaves behind on an abandoned retrieval.
	restore := os.Stdin
	defer func() { os.Stdin = restore }()
	os.Stdin = devNull

	// The control, and the reason this test is not vacuous: read through the
	// global, /dev/null answers yes.
	if !isInteractive(os.Stdin) {
		t.Skip("this platform does not report /dev/null as a character device, so the pin cannot be distinguished here")
	}
	if a.isInteractive() {
		t.Fatal("isInteractive answered for the /dev/null sink rather than for the startup descriptor")
	}
}

// The restore rule, for fd 0. aws.CredentialsCache abandons its singleflight
// goroutine on a cancelled context and that goroutine reads os.Stdin *later*,
// when it reaches NewCommand — so a sink put back unconditionally hands the
// helper the payload after bmcp has already returned. Later is not safer; it is
// the same collision with the evidence further away.
//
// So the sink stays installed, the descriptor is leaked on purpose, and
// stdinSunk latches to stop a second retrieval reassigning the variable
// underneath a goroutine still reading it.
func TestAnAbandonedRetrievalLeavesTheStdinSinkInstalled(t *testing.T) {
	guardStdFds(t)
	isolateAWSEnv(t)
	helper, stolen := stdinEatingCredentialHelper(t)

	abandoned := make(chan struct{})
	release := make(chan struct{})
	worker := &signallingProvider{
		inner:   processcreds.NewProvider(helper),
		release: release,
		done:    abandoned,
	}
	first := aws.NewCredentialsCache(worker)
	second := aws.NewCredentialsCache(processcreds.NewProvider(helper))

	a := authTestApp()
	// bmcp reads fd 0 this invocation, which sends both calls down the discard
	// branch for stdin.
	a.ownsStdin = true
	cfg := effectiveConfig{Profile: "racy", ProfileSource: profileSourceFile, Region: "us-east-1"}

	var installed, afterSecond *os.File
	var creds aws.Credentials
	survived := withStdinFd(t, a, callPayload, func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := a.retrieveCredentials(ctx, cfg, first); err == nil {
			t.Error("a cancelled retrieval should have failed")
		}
		installed = os.Stdin

		// Deliberately no wait on `abandoned`: a second retrieval racing the
		// goroutine the first left behind is the situation under test.
		var err error
		creds, err = a.retrieveCredentials(authTestContext(t), cfg, second)
		if err != nil {
			t.Errorf("the second retrieval should have succeeded, got: %v", err)
		}
		// Read here rather than after withStdinFd returns: the helper restores the
		// descriptor it installed, so outside fn the variable says nothing about
		// what the second retrieval did to it.
		afterSecond = os.Stdin

		// Only now, so the abandoned worker builds its command after both calls —
		// reading os.Stdin at the moment the restore would have put fd 0 back.
		close(release)
		select {
		case <-abandoned:
		case <-time.After(30 * time.Second):
			t.Error("the abandoned helper never finished, so this case asserted nothing")
		}
	})

	if creds.AccessKeyID != leakedKeyID {
		t.Fatalf("second retrieval returned %q, want the helper's %q", creds.AccessKeyID, leakedKeyID)
	}
	assertAbandonedHelperRan(t, worker)
	if !a.stdinSunk {
		t.Fatal("an abandoned retrieval did not latch, so a later call is free to reassign os.Stdin under it")
	}
	if installed == nil || afterSecond == nil {
		t.Fatal("the retrievals did not record the descriptor they left installed")
	}
	if afterSecond != installed {
		t.Fatal("the second retrieval reassigned os.Stdin over the sink an abandoned goroutine may still be reading")
	}
	// The whole point: two helpers ran, one of them after bmcp had returned, and
	// neither got a byte of the payload.
	if eaten, err := os.ReadFile(stolen); err == nil && len(eaten) > 0 {
		t.Fatalf("a helper read %q from bmcp's stdin", eaten)
	}
	if survived != callPayload {
		t.Fatalf("the payload did not survive: %q", survived)
	}
}

// The SSO start URL the sso-only fixture profile carries, and the sha1 of it
// spelled out rather than computed by the code under test.
//
// That derivation is the one thing about `bmcp login`'s idempotence guard that
// fails invisibly: a wrong key names a file that does not exist, a missing file
// reads as "expired", and the only symptom is a browser opening on a run where
// nothing was wrong. Pinning it against a literal is what makes a drift in
// either direction — bmcp's or the SDK's — a failure rather than a regression
// nobody sees.
const (
	fixtureStartURL  = "https://example.awsapps.com/start"
	fixtureTokenFile = "e8be5486177c5b5392bd9aa76563515b29358e6e.json"
)

// ssoCachePath is where the AWS CLI and the Go SDK agree the cached token for
// key lives: ~/.aws/sso/cache/<sha1-hex>.json, under whatever HOME this test
// isolated.
func ssoCachePath(t *testing.T, key string) string {
	t.Helper()
	sum := sha1.Sum([]byte(key))
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolve home: %v", err)
	}
	// Checked against the temp root, exactly as appendSharedConfig checks
	// AWS_CONFIG_FILE, and for a sharper reason. The callers below write and
	// *truncate* files in this directory: reached without isolateAWSEnv having
	// repointed HOME, the truncating case would zero a maintainer's own cached SSO
	// token and log them out of AWS. Both current callers isolate first; this is
	// what keeps that true for the next one.
	if !strings.HasPrefix(home, os.TempDir()) {
		t.Fatalf("the SSO cache helpers would write outside the test's fixtures: HOME=%q; isolateAWSEnv must run first", home)
	}
	return filepath.Join(home, ".aws", "sso", "cache", hex.EncodeToString(sum[:])+".json")
}

// writeSSOToken puts a cached token with this expiry where the SSO cache keeps
// it. accessToken is present but inert: the readers require the field, and
// nothing here ever presents it to anything.
func writeSSOToken(t *testing.T, key string, expiresAt time.Time) {
	t.Helper()
	path := ssoCachePath(t, key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir sso cache: %v", err)
	}
	body := fmt.Sprintf(`{"accessToken":"not-a-real-token","expiresAt":%q}`,
		expiresAt.UTC().Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write cached token: %v", err)
	}
}

// loginTestEnv isolates everything `bmcp login` reads and puts a fake `aws` on
// PATH that records the arguments it was given.
//
// The recording is the observation every case below makes about this
// subprocess: whether it ran at all, and — the part the leaf-profile fix is
// about — which profile it was pointed at.
func loginTestEnv(t *testing.T, exitCode int) (argvFile string) {
	t.Helper()
	isolateAWSEnv(t)
	// Not in isolateAWSEnv's list, because nothing else in that file reads them.
	// Every one would otherwise let a maintainer's own shell decide what these
	// cases assert: a BMCP_HOME pointing at their real config, a
	// BMCP_NON_INTERACTIVE that turns every case into the refusal path, a
	// BMCP_SYNC_TTL that decides whether the walk test's catalog counts as stale,
	// or a BMCP_PROFILE that silently renames the profile a refusal hands back.
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	for _, name := range []string{
		"BMCP_NON_INTERACTIVE", "BMCP_PROFILE", "BMCP_URL", "BMCP_REGION", "BMCP_SERVICE",
		"BMCP_SYNC_TTL", "BMCP_SYNC_TIMEOUT", "BMCP_CONNECT_TIMEOUT", "BMCP_CALL_TIMEOUT",
		"BMCP_AUTO_UPDATE", "BMCP_VERSION",
	} {
		t.Setenv(name, "")
	}
	binDir := t.TempDir()
	argvFile = filepath.Join(t.TempDir(), "aws-argv")
	script := "#!/bin/sh\necho \"$@\" > '" + argvFile + "'\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(filepath.Join(binDir, "aws"), []byte(script), 0o700); err != nil {
		t.Fatalf("write fake aws: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argvFile
}

// loginTestApp builds the app a `bmcp login` case runs, with both subprocess
// descriptors pinned at /dev/null.
//
// Pinned rather than left to run() to fill from the globals, for two reasons:
// the fake `aws` would otherwise write into the test binary's own streams, and
// nothing here should depend on whether `go test` was run at a terminal.
func loginTestApp(t *testing.T, stdout, stderr *bytes.Buffer) *app {
	t.Helper()
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	t.Cleanup(func() { devNull.Close() })
	return &app{
		stdin: strings.NewReader(""), stdout: stdout, stderr: stderr, now: time.Now,
		realStdin: devNull, realStderr: devNull,
	}
}

// corruptBMCPConfig makes config.toml unreadable, which is the only way
// readConfig fails — its parser skips anything it cannot understand, so a
// malformed file parses to defaults. A directory where the file belongs gives
// os.ReadFile an EISDIR that is not os.ErrNotExist, which is exactly the
// distinction loadEffective turns into config_invalid.
func corruptBMCPConfig(t *testing.T) {
	t.Helper()
	home := os.Getenv("BMCP_HOME")
	if home == "" {
		t.Fatal("corruptBMCPConfig needs BMCP_HOME; loginTestEnv must run first")
	}
	if err := os.MkdirAll(filepath.Join(home, "config.toml"), 0o700); err != nil {
		t.Fatalf("make config.toml unreadable: %v", err)
	}
}

// awsRan reports what the fake `aws` was invoked with, and whether it ran at
// all. The absence is as load-bearing as the arguments: half of what this
// command promises is the runs on which no browser opens.
func awsRan(t *testing.T, argvFile string) (string, bool) {
	t.Helper()
	body, err := os.ReadFile(argvFile)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(body)), true
}

// The shapes that must refuse rather than open a browser, each with its own
// name and its own escape.
//
// interactive_login_required, never auth_failure, is the whole point of the
// name: the generated instructions tell an agent to run `bmcp login` when a
// bmcp message names it, so a refusal wearing the name agents react to would
// have them run it again, in the same format, indefinitely.
func TestLoginRefusesWhereABrowserCannotBeOpened(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  func(*testing.T)
		// structured is true where the refusal must arrive as one parseable
		// document on stderr — both machine formats, and the legacy --json.
		structured bool
		contains   []string
		absent     []string
	}{
		{
			name:       "under --format json",
			args:       []string{"--format", "json", "--profile", "sso-only", "login"},
			structured: true,
			// The invocation carries --profile, so the command handed back must too.
			// A bare `bmcp login` would send its reader to log into whatever
			// config.toml names instead.
			contains: []string{"--format json", "bmcp --profile sso-only login"},
		},
		{
			name:       "under --format ndjson",
			args:       []string{"--format", "ndjson", "login"},
			structured: true,
			contains:   []string{"--format ndjson", "bmcp login"},
		},
		{
			// Not the contract, but its callers parse what bmcp writes just the
			// same, and a login would block and then write English into it.
			name:       "under the legacy --json",
			args:       []string{"--json", "login"},
			structured: true,
			contains:   []string{"--json"},
		},
		{
			name: "under --non-interactive",
			args: []string{"--non-interactive", "--profile", "sso-only", "login"},
			// Its own message naming its own escape. The flag and the variable are
			// OR'd together with no --interactive to clear either, so handing back
			// any form of "run bmcp login" would be advice this invocation has just
			// disproved. "Run" rather than the command: the message opens with the
			// words "bmcp login", so only the imperative separates advice from
			// description, and pinning the command would pin nothing.
			contains: []string{"--non-interactive", "BMCP_NON_INTERACTIVE"},
			absent:   []string{"Run"},
		},
		{
			name: "under BMCP_NON_INTERACTIVE",
			args: []string{"--profile", "sso-only", "login"},
			env:  func(t *testing.T) { t.Setenv("BMCP_NON_INTERACTIVE", "1") },
			// A human format, so the refusal is prose — and it still must not be the
			// format refusal, which would name formats nothing here selected.
			contains: []string{"BMCP_NON_INTERACTIVE"},
			absent:   []string{"--format json", "Run"},
		},
		{
			// The ordering the format refusal's comment claims: ahead of anything
			// that reads config or disk, so it cannot depend on whether the machine
			// happens to be configured. Without this, moving the guard below
			// loadEffective passes every other row — a missing config resolves
			// cleanly — and a machine-format login on a machine with a corrupt
			// config.toml answers config_invalid instead of refusing.
			name:       "under --format json with a corrupt config",
			args:       []string{"--format", "json", "login"},
			env:        func(t *testing.T) { corruptBMCPConfig(t) },
			structured: true,
			contains:   []string{"--format json"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argvFile := loginTestEnv(t, 0)
			if tc.env != nil {
				tc.env(t)
			}
			var stdout, stderr bytes.Buffer
			if code := loginTestApp(t, &stdout, &stderr).run(tc.args); code != exitAuth {
				t.Fatalf("exit %d, want %d; stderr: %s", code, exitAuth, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("a refusal must leave stdout empty, got: %s", stdout.String())
			}
			if argv, ran := awsRan(t, argvFile); ran {
				t.Fatalf("a refusal spawned the login anyway: aws %s", argv)
			}
			message := stderr.String()
			if tc.structured {
				var doc struct {
					OK      bool   `json:"ok"`
					Error   string `json:"error"`
					Message string `json:"message"`
				}
				if err := json.Unmarshal(stderr.Bytes(), &doc); err != nil {
					t.Fatalf("stderr is not one JSON document (%v): %s", err, stderr.String())
				}
				if doc.OK || doc.Error != "interactive_login_required" {
					t.Fatalf("unexpected envelope: %+v", doc)
				}
				message = doc.Message
			}
			for _, want := range tc.contains {
				if !strings.Contains(message, want) {
					t.Fatalf("message %q should contain %q", message, want)
				}
			}
			for _, unwanted := range tc.absent {
				if strings.Contains(message, unwanted) {
					t.Fatalf("message %q should not contain %q", message, unwanted)
				}
			}
		})
	}
}

// The guard that makes `bmcp login` safe for an agent to run on a message it
// may have reached for some other reason.
//
// `aws sso login` runs with force_refresh=True and never short-circuits on a
// token that is still good, so without a check of bmcp's own a browser opens on
// every invocation — including the ones where the session is fine and the real
// failure is something a login cannot fix.
func TestLoginWithAValidSessionOpensNothing(t *testing.T) {
	argvFile := loginTestEnv(t, 0)
	writeSSOToken(t, fixtureStartURL, time.Now().Add(6*time.Hour))
	var stdout, stderr bytes.Buffer
	if code := loginTestApp(t, &stdout, &stderr).run([]string{"--profile", "sso-only", "login"}); code != 0 {
		t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
	}
	if argv, ran := awsRan(t, argvFile); ran {
		t.Fatalf("a valid session still opened a browser: aws %s", argv)
	}
	if !strings.Contains(stdout.String(), "already valid") {
		t.Fatalf("the no-op should say why it did nothing, got: %s", stdout.String())
	}
}

// The other half: absent, expired and unreadable are all "log in", and the
// third of those is not hypothetical — aws-cli writes this file
// non-atomically, so a read racing a concurrent login lands on a zero-length
// window.
func TestLoginWithoutAValidSessionLogsIn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token func(*testing.T)
	}{
		{name: "no cached token at all", token: func(*testing.T) {}},
		{
			name:  "a cached token past its expiry",
			token: func(t *testing.T) { writeSSOToken(t, fixtureStartURL, time.Now().Add(-time.Hour)) },
		},
		{
			name: "a truncated token file",
			token: func(t *testing.T) {
				writeSSOToken(t, fixtureStartURL, time.Now().Add(6*time.Hour))
				if err := os.Truncate(ssoCachePath(t, fixtureStartURL), 0); err != nil {
					t.Fatalf("truncate cached token: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argvFile := loginTestEnv(t, 0)
			tc.token(t)
			var stdout, stderr bytes.Buffer
			if code := loginTestApp(t, &stdout, &stderr).run([]string{"--profile", "sso-only", "login"}); code != 0 {
				t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
			}
			argv, ran := awsRan(t, argvFile)
			if !ran {
				t.Fatal("no login was started")
			}
			if argv != "sso login --profile sso-only" {
				t.Fatalf("aws %s, want `sso login --profile sso-only`", argv)
			}
		})
	}
}

// The cache key, pinned against a literal rather than against the function that
// derives it, and then round-tripped through the reader. See fixtureTokenFile.
func TestSSOTokenCacheKeyMatchesWhatTheAWSCLIWrites(t *testing.T) {
	isolateAWSEnv(t)
	if got := filepath.Base(ssoCachePath(t, fixtureStartURL)); got != fixtureTokenFile {
		t.Fatalf("token file %q, want %q — the sha1 of the start URL", got, fixtureTokenFile)
	}
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	writeSSOToken(t, fixtureStartURL, expiry)
	got, err := ssoTokenExpiry(authTestContext(t), "sso-only")
	if err != nil {
		t.Fatalf("bmcp could not read the token it and the AWS CLI agree on: %v", err)
	}
	if !got.Equal(expiry) {
		t.Fatalf("expiry %v, want %v", got, expiry)
	}
}

// A login pointed at the leaf of a source_profile chain, which is where the SSO
// configuration lives.
//
// profileUsesSSO answers about the leaf — the only node whose credential type
// the SDK ever dispatches — while `aws sso login --profile X` reads X's own SSO
// config. So a chained profile passed the check and then failed the login with
// "profile does not have valid SSO configuration". The implicit login inside
// awsCredentials had the same defect and is fixed by the same helper.
func TestLoginTargetsTheLeafOfASourceProfileChain(t *testing.T) {
	argvFile := loginTestEnv(t, 0)
	appendSharedConfig(t, `
[profile chained]
role_arn = arn:aws:iam::123456789012:role/Chained
source_profile = sso-only
region = us-east-1
`)
	var stdout, stderr bytes.Buffer
	if code := loginTestApp(t, &stdout, &stderr).run([]string{"--profile", "chained", "login"}); code != 0 {
		t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
	}
	argv, ran := awsRan(t, argvFile)
	if !ran {
		t.Fatal("no login was started")
	}
	if argv != "sso login --profile sso-only" {
		t.Fatalf("aws %s, want the leaf profile: `sso login --profile sso-only`", argv)
	}
}

// Where there is no SSO session to refresh, the refusal has to say what bmcp
// did resolve and how to name something else — not merely decline.
//
// The second row is the one that makes this worth a test rather than a
// docstring: unexpired-looking ambient keys make sharedProfileFor yield, so
// there is no profile to log into even though the environment names one.
func TestLoginRefusesWhatIsNotAnSSOProfile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		env      func(*testing.T)
		contains []string
	}{
		{
			name:     "a static-credentials profile",
			args:     []string{"--profile", "has-static", "login"},
			contains: []string{"AWS profile has-static from --profile"},
		},
		{
			name: "environment credentials outranking an ambient SSO profile",
			args: []string{"login"},
			env: func(t *testing.T) {
				setEnvCredentials(t)
				t.Setenv("AWS_PROFILE", "sso-only")
			},
			contains: []string{
				"environment credentials (AWS_ACCESS_KEY_ID)",
				"which outrank AWS profile sso-only",
			},
		},
		{
			name:     "no profile and nothing in the environment",
			args:     []string{"login"},
			contains: []string{"the default AWS credential chain"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			argvFile := loginTestEnv(t, 0)
			if tc.env != nil {
				tc.env(t)
			}
			var stdout, stderr bytes.Buffer
			if code := loginTestApp(t, &stdout, &stderr).run(tc.args); code != exitAuth {
				t.Fatalf("exit %d, want %d; stderr: %s", code, exitAuth, stderr.String())
			}
			if argv, ran := awsRan(t, argvFile); ran {
				t.Fatalf("a refusal spawned the login anyway: aws %s", argv)
			}
			for _, want := range append(tc.contains, "bmcp --profile <name> login") {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("message %q should contain %q", stderr.String(), want)
				}
			}
		})
	}
}

// A failed `bmcp login` must not tell its reader to run `bmcp login`.
//
// This is the loop guard that actually bears weight. The error *name* is the one
// the code comments talk about, but it is unobservable here: this command
// refuses every machine format, and failDoc prints only the message in a human
// one — so no caller ever sees `sso_login_failed` at all, and a test asserting
// the absence of "auth_failure" on stderr would pass whatever the name was.
//
// The message is what the generated instructions key on: "when a bmcp message
// tells you to run `bmcp login`, run it". So a failed login whose message named
// the command again would be an agent's infinite loop, written in prose.
func TestAFailedLoginDoesNotTellTheReaderToLogInAgain(t *testing.T) {
	loginTestEnv(t, 1)
	var stdout, stderr bytes.Buffer
	code := loginTestApp(t, &stdout, &stderr).run([]string{"--profile", "sso-only", "login"})
	if code != exitAuth {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitAuth, stderr.String())
	}
	for _, loop := range []string{"bmcp login", "bmcp --profile sso-only login", "Run:"} {
		if strings.Contains(stderr.String(), loop) {
			t.Fatalf("a failed login handed back %q, which is the loop: %s", loop, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), "sso-only") {
		t.Fatalf("the failure should name the profile it was for, got: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("a failed login must not report success on stdout, got: %s", stdout.String())
	}
}

// The modern profile form, which nothing else in this file exercises and whose
// cache key is derived differently: the SDK hashes the sso_session *name* for
// it (resolveSSOCredentials) and the start URL only for the legacy form
// (ssocreds.New). The fixture's `sso-only` is legacy, so without this the
// `leaf.SSOSession != nil` arm has no coverage at all — and deleting it, or
// reaching for the URL sitting right there on the same struct, would make
// `bmcp login` open a browser on every single run for every user on the form
// AWS now recommends, silently, because a key that names no file reads as
// "expired".
func TestSSOTokenCacheKeyFollowsTheProfileForm(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
		// key is what the SDK would hash for this profile, spelled out here rather
		// than taken from the code under test.
		key string
	}{
		{name: "legacy sso_start_url", profile: "sso-only", key: fixtureStartURL},
		{name: "sso_session names the session", profile: "modern-sso", key: "corp-session"},
		{name: "a chain resolves through its leaf", profile: "chained-sso", key: fixtureStartURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			appendSharedConfig(t, `
[profile modern-sso]
sso_session = corp-session
sso_account_id = 123456789012
sso_role_name = ExampleRole
region = us-east-1

[sso-session corp-session]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1

[profile chained-sso]
role_arn = arn:aws:iam::123456789012:role/Chained
source_profile = sso-only
region = us-east-1
`)
			// A start URL on the session and a different one nowhere else, so a
			// derivation that reached for SSOSession.SSOStartURL instead of its Name
			// would look in the wrong place and find nothing.
			expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
			writeSSOToken(t, tc.key, expiry)
			got, err := ssoTokenExpiry(authTestContext(t), tc.profile)
			if err != nil {
				t.Fatalf("profile %s: %v — bmcp looked somewhere the AWS CLI does not write", tc.profile, err)
			}
			if !got.Equal(expiry) {
				t.Fatalf("expiry %v, want %v", got, expiry)
			}
		})
	}
}

// A cached token carrying an expiry but no accessToken must read as expired.
//
// The SDK rejects that file outright — loadCachedToken requires both fields —
// so calling it valid produces the worst shape this command has: `bmcp login`
// reports "already valid, nothing to do", the call it was run for fails exactly
// as before, and the agent is sent back to the command that just declined to
// act. An expiry-only check cannot tell the two apart.
func TestACachedTokenWithNoAccessTokenIsNotValid(t *testing.T) {
	argvFile := loginTestEnv(t, 0)
	path := ssoCachePath(t, fixtureStartURL)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir sso cache: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"expiresAt":"2099-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("write cached token: %v", err)
	}
	if _, err := ssoTokenExpiry(authTestContext(t), "sso-only"); err == nil {
		t.Fatal("a token the SDK would reject was reported as readable")
	}
	var stdout, stderr bytes.Buffer
	if code := loginTestApp(t, &stdout, &stderr).run([]string{"--profile", "sso-only", "login"}); code != 0 {
		t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
	}
	if _, ran := awsRan(t, argvFile); !ran {
		t.Fatalf("no login was started, so bmcp believed a token the SDK rejects: %s", stdout.String())
	}
}

// The success line reports how long the new session lasts.
//
// It needs a fake `aws` that writes a token, which no other case here does —
// so without this, loginValidity always takes its error path and returning ""
// unconditionally would be invisible.
func TestASuccessfulLoginReportsTheNewExpiry(t *testing.T) {
	isolateAWSEnv(t)
	t.Setenv("BMCP_HOME", filepath.Join(t.TempDir(), "absent"))
	t.Setenv("BMCP_NON_INTERACTIVE", "")
	expiry := time.Now().Add(8 * time.Hour).UTC().Truncate(time.Second)
	// The fake writes the token where `aws sso login` writes it, so the command
	// reads back what the subprocess produced rather than what the test staged.
	path := ssoCachePath(t, fixtureStartURL)
	binDir := t.TempDir()
	script := "#!/bin/sh\nmkdir -p '" + filepath.Dir(path) + "'\n" +
		"printf '%s' '{\"accessToken\":\"t\",\"expiresAt\":\"" + expiry.Format(time.RFC3339) + "\"}' > '" + path + "'\n"
	if err := os.WriteFile(filepath.Join(binDir, "aws"), []byte(script), 0o700); err != nil {
		t.Fatalf("write fake aws: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var stdout, stderr bytes.Buffer
	if code := loginTestApp(t, &stdout, &stderr).run([]string{"--profile", "sso-only", "login"}); code != 0 {
		t.Fatalf("exit %d, want 0; stderr: %s", code, stderr.String())
	}
	for _, want := range []string{"Logged in", "sso-only", formatExpiry(expiry)} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout %q should contain %q", stdout.String(), want)
		}
	}
}

// `bmcp login` takes no arguments, and a typo must not be read as one.
func TestLoginTakesNoArguments(t *testing.T) {
	argvFile := loginTestEnv(t, 0)
	var stdout, stderr bytes.Buffer
	if code := loginTestApp(t, &stdout, &stderr).run([]string{"login", "sso-only"}); code != exitValidation {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitValidation, stderr.String())
	}
	if argv, ran := awsRan(t, argvFile); ran {
		t.Fatalf("a usage error spawned a login: aws %s", argv)
	}
}

// A profile bmcp cannot parse is reported as that, not as "name an SSO profile".
//
// profileUsesSSO answers false for an unreadable profile deliberately: wherever
// it is used inside awsCredentials, the SDK failure that made the profile
// unreadable is already the error being reported. cmdLogin has no such preceding
// failure, so without its own check it would answer a caller who named a broken
// SSO profile by telling them to name an SSO profile.
func TestLoginReportsAnUnreadableProfileRatherThanBlamingTheChoice(t *testing.T) {
	argvFile := loginTestEnv(t, 0)
	// A profile naming a session section that does not exist: the SDK fails with
	// "failed to find SSO session section", which is the answer worth keeping.
	appendSharedConfig(t, `
[profile dangling-session]
sso_session = nowhere
sso_account_id = 123456789012
sso_role_name = ExampleRole
region = us-east-1
`)
	var stdout, stderr bytes.Buffer
	if code := loginTestApp(t, &stdout, &stderr).run([]string{"--profile", "dangling-session", "login"}); code != exitConfig {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitConfig, stderr.String())
	}
	if argv, ran := awsRan(t, argvFile); ran {
		t.Fatalf("an unreadable profile still started a login: aws %s", argv)
	}
	if !strings.Contains(stderr.String(), "SSO session section") {
		t.Fatalf("the SDK's own account of the problem was lost: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "Name an SSO profile") {
		t.Fatalf("a broken SSO profile was answered by telling the caller to name one: %s", stderr.String())
	}
}

// The implicit login gets the same leaf-profile fix as the command, because
// both now go through runSSOLogin.
//
// This is the half of the shared-helper claim that nothing else pins.
// TestADeviceFlowStartsOnlyWhenItCouldFinish records only that the subprocess
// ran, so reverting awsCredentials to building the command inline —
// reinstating both the outer-profile and unresolved-path defects on the path a
// tool call actually takes — would pass every other test in the package.
func TestTheImplicitLoginAlsoTargetsTheLeafProfile(t *testing.T) {
	isolateAWSEnv(t)
	appendSharedConfig(t, `
[profile chained-implicit]
role_arn = arn:aws:iam::123456789012:role/Chained
source_profile = sso-only
region = us-east-1
`)
	binDir := t.TempDir()
	argvFile := filepath.Join(t.TempDir(), "aws-argv")
	script := "#!/bin/sh\necho \"$@\" > '" + argvFile + "'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "aws"), []byte(script), 0o700); err != nil {
		t.Fatalf("write fake aws: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	a := authTestApp()
	// Everything the implicit branch needs: a human format, a terminal, and a
	// budget a login could finish in.
	a.machine = false
	a.interactive = func() bool { return true }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	_, _, err := a.awsCredentials(ctx, effectiveConfig{
		Profile:       "chained-implicit",
		ProfileSource: profileSourceFile,
		Region:        "us-east-1",
	})
	if err == nil {
		t.Fatal("a chain onto an sso-only profile should not have resolved in a test")
	}
	argv, ran := awsRan(t, argvFile)
	if !ran {
		t.Fatalf("the implicit login never ran; error was: %v", err)
	}
	if argv != "sso login --profile sso-only" {
		t.Fatalf("aws %s, want the leaf profile: `sso login --profile sso-only` — "+
			"`aws sso login --profile chained-implicit` reads that profile's own SSO "+
			"config, which is empty", argv)
	}
}
