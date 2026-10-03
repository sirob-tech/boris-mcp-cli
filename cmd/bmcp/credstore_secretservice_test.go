//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
)

// The Secret Service tests need a real, unlocked keyring on the session bus,
// which CI does not have, so they run only when BMCP_TEST_SECRET_SERVICE=1.
// Items use a test-only application attribute and are removed afterwards.
func secretServiceTestEnabled() bool { return os.Getenv("BMCP_TEST_SECRET_SERVICE") == "1" }

func init() {
	if !secretServiceTestEnabled() {
		return
	}
	platformContractStores["secret-service"] = func(t *testing.T) credStore {
		s, err := newSecretServiceStore("bmcp-test-"+newGeneration(), storeOptions{AllowUI: false})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.ClearAll(nil) })
		return s
	}
}

func TestSecretServiceProbeAndLockedCollection(t *testing.T) {
	if !secretServiceTestEnabled() {
		t.Skip("set BMCP_TEST_SECRET_SERVICE=1 with an unlocked keyring on the session bus")
	}
	ctx := context.Background()
	if st := probeSecretService(ctx); st.State != ssAvailable {
		t.Fatalf("probe: %+v", st)
	}
	s, _ := newSecretServiceStore("bmcp-test-"+newGeneration(), storeOptions{AllowUI: false})
	defer s.ClearAll(nil)
	key := ssoSessionStoreKey("ss", "")
	if err := s.WriteToken(key, sampleToken("g1")); err != nil {
		t.Fatal(err)
	}

	// Lock the default collection, as a screen lock would, and check that a
	// no-UI store fails closed instead of reading as "not found". Unlocking
	// needs a prompt, so this leaves it locked: run it after the contract test.
	addr, _ := sessionBusAddress()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	coll, err := ssDefaultCollection(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	var locked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := conn.Object(ssBusName, ssServicePath).Call(ssServiceIface+".Lock", 0, []dbus.ObjectPath{coll}).Store(&locked, &prompt); err != nil {
		t.Fatal(err)
	}
	if st := probeSecretService(ctx); st.State != ssLocked {
		t.Fatalf("probe after lock: %+v", st)
	}
	fresh, _ := newSecretServiceStore("bmcp-test-x", storeOptions{AllowUI: false})
	_, err = fresh.ReadToken(key)
	var lockedErr *storeLockedError
	if !errors.As(err, &lockedErr) {
		t.Fatalf("locked collection without UI: want storeLockedError, got %v", err)
	}
	got, err := resolveBackend(ctx, backendAuto, backendSourceDefault, defaultBackendEnv(false))
	if !errors.As(err, &lockedErr) || got.Name != backendSecretService {
		t.Fatalf("auto on a locked keyring must fail closed, got %+v %v", got, err)
	}
}
