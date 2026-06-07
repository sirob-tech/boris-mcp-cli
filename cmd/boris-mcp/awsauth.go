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

func (a *app) awsCredentials(ctx context.Context, cfg effectiveConfig) (aws.Credentials, string, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(cfg.Profile))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Credentials{}, "", authError{err}
	}
	creds, err := awsCfg.Credentials.Retrieve(ctx)
	if err == nil {
		return creds, awsCfg.Region, nil
	}
	if cfg.Profile != "" && !cfg.NonInteractive && looksLikeSSO(err) && isInteractive() {
		fmt.Fprintf(a.stderr, "AWS SSO credentials for profile %s are expired or missing. Running aws sso login --profile %s\n", cfg.Profile, cfg.Profile)
		cmd := exec.CommandContext(ctx, "aws", "sso", "login", "--profile", cfg.Profile)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		if runErr := cmd.Run(); runErr != nil {
			return aws.Credentials{}, "", authError{fmt.Errorf("aws sso login failed: %w", runErr)}
		}
		awsCfg, err = awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Credentials{}, "", authError{err}
		}
		creds, err = awsCfg.Credentials.Retrieve(ctx)
	}
	if err != nil {
		if cfg.Profile != "" && looksLikeSSO(err) {
			return aws.Credentials{}, "", authError{fmt.Errorf("AWS SSO credentials unavailable. Run: aws sso login --profile %s", cfg.Profile)}
		}
		return aws.Credentials{}, "", authError{err}
	}
	return creds, awsCfg.Region, nil
}

func looksLikeSSO(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "sso") || strings.Contains(s, "token") || strings.Contains(s, "expired")
}
