//go:build !(darwin && cgo)

package main

import (
	"errors"
	"runtime"
)

func newKeychainStore(string, storeOptions) (credStore, error) {
	if runtime.GOOS == "darwin" {
		return nil, errors.New("this bmcp was built without cgo, so it cannot reach the macOS Keychain; use --backend file or aws-cli-cache")
	}
	return nil, errors.New("the keychain backend is macOS only; use --backend secret-service, file or aws-cli-cache")
}
