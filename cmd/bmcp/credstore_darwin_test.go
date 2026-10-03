//go:build darwin && cgo

package main

import (
	"errors"
	"os"
	"testing"
)

// realHome is captured before any test isolates HOME: the Security framework
// finds the login keychain through $HOME, so a temp HOME has no keychain.
var realHome = os.Getenv("HOME")

// The keychain runs against the real login keychain, because there is no
// other: a test-only service name keeps it away from bmcp's items, every
// operation is no-UI so nothing prompts, and cleanup removes what it wrote.
func init() {
	platformContractStores["keychain"] = func(t *testing.T) credStore {
		t.Setenv("HOME", realHome)
		service := "bmcp-test-" + newGeneration()
		s, _ := newKeychainStore(service, storeOptions{AllowUI: false})
		t.Cleanup(func() { s.ClearAll(nil) })
		probe := ssoSessionStoreKey("probe", "")
		if err := s.WriteToken(probe, sampleToken("probe")); err != nil {
			t.Skipf("login keychain not usable here: %v", err)
		}
		if _, err := s.ReadToken(probe); err != nil {
			t.Skipf("login keychain not readable without UI here: %v", err)
		}
		if err := s.DeleteToken(probe); err != nil {
			t.Skipf("login keychain delete failed: %v", err)
		}
		return s
	}
}

func TestKeychainMissingItemIsNotFoundNotLocked(t *testing.T) {
	t.Setenv("HOME", realHome)
	s, _ := newKeychainStore("bmcp-test-"+newGeneration(), storeOptions{AllowUI: false})
	_, err := s.ReadToken(ssoSessionStoreKey("absent", ""))
	var locked *storeLockedError
	if errors.As(err, &locked) {
		t.Skipf("login keychain locked here: %v", err)
	}
	if !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
}
