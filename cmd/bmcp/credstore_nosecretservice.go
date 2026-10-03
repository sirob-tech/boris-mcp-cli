//go:build !linux

package main

import (
	"context"
	"errors"
)

func probeSecretService(context.Context) secretServiceStatus {
	return secretServiceStatus{State: ssNoBus}
}

func newSecretServiceStore(string, storeOptions) (credStore, error) {
	return nil, errors.New("the secret-service backend is Linux only; use --backend keychain, file or aws-cli-cache")
}
