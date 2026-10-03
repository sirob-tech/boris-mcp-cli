//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	ssBusName       = "org.freedesktop.secrets"
	ssServicePath   = dbus.ObjectPath("/org/freedesktop/secrets")
	ssServiceIface  = "org.freedesktop.Secret.Service"
	ssCollectionIfc = "org.freedesktop.Secret.Collection"
	ssItemIface     = "org.freedesktop.Secret.Item"
	ssPromptIface   = "org.freedesktop.Secret.Prompt"
	ssCallTimeout   = 10 * time.Second
	ssPromptTimeout = 2 * time.Minute
	ssAttrApp       = "application"
	ssAttrItem      = "bmcp-item"
	ssNoPrompt      = dbus.ObjectPath("/")
	ssErrIsLocked   = "org.freedesktop.Secret.Error.IsLocked"
	ssErrNoSuchObj  = "org.freedesktop.Secret.Error.NoSuchObject"
	ssUnknownObjErr = "org.freedesktop.DBus.Error.UnknownObject"
)

// sessionBusAddress never autolaunches a bus: dbus-launch on a headless box
// would start a daemon nobody owns, and then report a Secret Service that is
// not there.
func sessionBusAddress() (string, bool) {
	if a := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); a != "" {
		return a, true
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		p := filepath.Join(d, "bus")
		if info, err := os.Stat(p); err == nil && info.Mode()&os.ModeSocket != 0 {
			return "unix:path=" + p, true
		}
	}
	return "", false
}

// dialSessionBus bounds the connect and auth handshake by ctx, which godbus's
// Connect does not do on its own.
func dialSessionBus(ctx context.Context, addr string) (*dbus.Conn, error) {
	type res struct {
		c   *dbus.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := dbus.Connect(addr)
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// probeSecretService answers auto resolution without UI: it never unlocks and
// never creates a collection.
func probeSecretService(ctx context.Context) secretServiceStatus {
	addr, ok := sessionBusAddress()
	if !ok {
		return secretServiceStatus{State: ssNoBus}
	}
	conn, err := dialSessionBus(ctx, addr)
	if err != nil {
		if p, isPath := strings.CutPrefix(addr, "unix:path="); isPath {
			if _, statErr := os.Stat(p); errors.Is(statErr, os.ErrNotExist) {
				return secretServiceStatus{State: ssNoBus}
			}
		}
		return secretServiceStatus{State: ssError, Err: err}
	}
	defer conn.Close()
	var owned bool
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, ssBusName).Store(&owned); err != nil {
		return secretServiceStatus{State: ssError, Err: err}
	}
	if !owned {
		return secretServiceStatus{State: ssNotOwned}
	}
	coll, err := ssDefaultCollection(ctx, conn)
	if err != nil {
		return secretServiceStatus{State: ssError, Err: err}
	}
	locked, err := ssLockedProp(ctx, conn, coll)
	if err != nil {
		return secretServiceStatus{State: ssError, Err: err}
	}
	if locked {
		return secretServiceStatus{State: ssLocked}
	}
	return secretServiceStatus{State: ssAvailable}
}

func ssDefaultCollection(ctx context.Context, conn *dbus.Conn) (dbus.ObjectPath, error) {
	var coll dbus.ObjectPath
	if err := conn.Object(ssBusName, ssServicePath).CallWithContext(ctx, ssServiceIface+".ReadAlias", 0, "default").Store(&coll); err != nil {
		return "", err
	}
	if coll == ssNoPrompt || coll == "" {
		return "", errors.New("the Secret Service has no default collection")
	}
	return coll, nil
}

func ssLockedProp(ctx context.Context, conn *dbus.Conn, coll dbus.ObjectPath) (bool, error) {
	var v dbus.Variant
	if err := conn.Object(ssBusName, coll).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, ssCollectionIfc, "Locked").Store(&v); err != nil {
		return false, err
	}
	locked, ok := v.Value().(bool)
	if !ok {
		return false, fmt.Errorf("unexpected Locked property type %T", v.Value())
	}
	return locked, nil
}

// ssSecret is the Secret Service wire struct (oayays).
type ssSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// secretServiceBackend talks to org.freedesktop.secrets over the session bus,
// in the default collection. The secret travels over the "plain" transport,
// which is the local bus socket between processes of the same user.
type secretServiceBackend struct {
	app     string
	allowUI bool

	mu      sync.Mutex
	conn    *dbus.Conn
	session dbus.ObjectPath
	coll    dbus.ObjectPath
}

func newSecretServiceStore(app string, opts storeOptions) (credStore, error) {
	return keyedStore{b: &secretServiceBackend{app: app, allowUI: opts.AllowUI}}, nil
}

func (s *secretServiceBackend) name() backendName { return backendSecretService }

func ssLockedErr(reason string, err error) error {
	return &storeLockedError{Backend: backendSecretService, Reason: reason, Hint: secretServiceUnlockHint, Err: err}
}

// ssFailure classifies a D-Bus error. Only a vanished object means "not
// found"; anything else fails closed as a locked store.
func ssFailure(op string, err error) error {
	var de dbus.Error
	if errors.As(err, &de) {
		switch de.Name {
		case ssErrNoSuchObj, ssUnknownObjErr:
			return errStoreItemNotFound
		case ssErrIsLocked:
			return ssLockedErr("the Secret Service collection is locked", err)
		}
		return ssLockedErr(fmt.Sprintf("Secret Service %s failed: %s", op, de.Name), err)
	}
	return ssLockedErr(fmt.Sprintf("Secret Service %s failed", op), err)
}

func (s *secretServiceBackend) open() error {
	if s.conn != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), ssCallTimeout)
	defer cancel()
	addr, ok := sessionBusAddress()
	if !ok {
		return errors.New("the secret-service backend is unavailable: no D-Bus session bus; use --backend aws-cli-cache or file")
	}
	conn, err := dialSessionBus(ctx, addr)
	if err != nil {
		return ssFailure("connect", err)
	}
	var out dbus.Variant
	var session dbus.ObjectPath
	if err := conn.Object(ssBusName, ssServicePath).CallWithContext(ctx, ssServiceIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&out, &session); err != nil {
		conn.Close()
		return ssFailure("open session", err)
	}
	coll, err := ssDefaultCollection(ctx, conn)
	if err != nil {
		conn.Close()
		return ssFailure("find the default collection", err)
	}
	locked, err := ssLockedProp(ctx, conn, coll)
	if err != nil {
		conn.Close()
		return ssFailure("read the collection state", err)
	}
	if locked {
		if !s.allowUI {
			conn.Close()
			return ssLockedErr("the Secret Service collection is locked", nil)
		}
		if err := s.unlock(conn, coll); err != nil {
			conn.Close()
			return err
		}
	}
	s.conn, s.session, s.coll = conn, session, coll
	return nil
}

func (s *secretServiceBackend) unlock(conn *dbus.Conn, coll dbus.ObjectPath) error {
	ctx, cancel := context.WithTimeout(context.Background(), ssCallTimeout)
	defer cancel()
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := conn.Object(ssBusName, ssServicePath).CallWithContext(ctx, ssServiceIface+".Unlock", 0, []dbus.ObjectPath{coll}).Store(&unlocked, &prompt); err != nil {
		return ssFailure("unlock", err)
	}
	return s.runPrompt(conn, prompt)
}

// runPrompt shows a Secret Service prompt and waits for its Completed signal.
// Without UI it refuses instead, since the prompt would wait for nobody.
func (s *secretServiceBackend) runPrompt(conn *dbus.Conn, prompt dbus.ObjectPath) error {
	if prompt == ssNoPrompt || prompt == "" {
		return nil
	}
	if !s.allowUI {
		return ssLockedErr("the Secret Service asked for a prompt", nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), ssPromptTimeout)
	defer cancel()
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchObjectPath(prompt), dbus.WithMatchInterface(ssPromptIface), dbus.WithMatchMember("Completed")); err != nil {
		return ssFailure("prompt", err)
	}
	ch := make(chan *dbus.Signal, 4)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)
	if err := conn.Object(ssBusName, prompt).CallWithContext(ctx, ssPromptIface+".Prompt", 0, "").Err; err != nil {
		return ssFailure("prompt", err)
	}
	for {
		select {
		case sig := <-ch:
			if sig == nil || sig.Path != prompt || sig.Name != ssPromptIface+".Completed" {
				continue
			}
			if len(sig.Body) > 0 {
				if dismissed, _ := sig.Body[0].(bool); dismissed {
					return ssLockedErr("the Secret Service prompt was dismissed", nil)
				}
			}
			return nil
		case <-ctx.Done():
			return ssLockedErr("the Secret Service prompt was not answered", ctx.Err())
		}
	}
}

func (s *secretServiceBackend) attrs(item string) map[string]string {
	m := map[string]string{ssAttrApp: s.app}
	if item != "" {
		m[ssAttrItem] = item
	}
	return m
}

func (s *secretServiceBackend) search(ctx context.Context, item string) ([]dbus.ObjectPath, error) {
	var found []dbus.ObjectPath
	if err := s.conn.Object(ssBusName, s.coll).CallWithContext(ctx, ssCollectionIfc+".SearchItems", 0, s.attrs(item)).Store(&found); err != nil {
		return nil, ssFailure("search", err)
	}
	return found, nil
}

func (s *secretServiceBackend) get(item string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ssCallTimeout)
	defer cancel()
	found, err := s.search(ctx, item)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, errStoreItemNotFound
	}
	var secret ssSecret
	if err := s.conn.Object(ssBusName, found[0]).CallWithContext(ctx, ssItemIface+".GetSecret", 0, s.session).Store(&secret); err != nil {
		return nil, ssFailure("read", err)
	}
	return secret.Value, nil
}

func (s *secretServiceBackend) set(item, label string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ssCallTimeout)
	defer cancel()
	props := map[string]dbus.Variant{
		ssItemIface + ".Label":      dbus.MakeVariant(label),
		ssItemIface + ".Attributes": dbus.MakeVariant(s.attrs(item)),
	}
	secret := ssSecret{Session: s.session, Value: data, ContentType: "application/json"}
	var created, prompt dbus.ObjectPath
	if err := s.conn.Object(ssBusName, s.coll).CallWithContext(ctx, ssCollectionIfc+".CreateItem", 0, props, secret, true).Store(&created, &prompt); err != nil {
		return ssFailure("write", err)
	}
	return s.runPrompt(s.conn, prompt)
}

func (s *secretServiceBackend) del(item string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ssCallTimeout)
	defer cancel()
	found, err := s.search(ctx, item)
	if err != nil {
		return err
	}
	for _, p := range found {
		var prompt dbus.ObjectPath
		if err := s.conn.Object(ssBusName, p).CallWithContext(ctx, ssItemIface+".Delete", 0).Store(&prompt); err != nil {
			if failure := ssFailure("delete", err); !errors.Is(failure, errStoreItemNotFound) {
				return failure
			}
			continue
		}
		if err := s.runPrompt(s.conn, prompt); err != nil {
			return err
		}
	}
	return nil
}

func (s *secretServiceBackend) list() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.open(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), ssCallTimeout)
	defer cancel()
	found, err := s.search(ctx, "")
	if err != nil {
		return nil, err
	}
	var items []string
	for _, p := range found {
		var v dbus.Variant
		if err := s.conn.Object(ssBusName, p).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, ssItemIface, "Attributes").Store(&v); err != nil {
			return nil, ssFailure("list", err)
		}
		if attrs, ok := v.Value().(map[string]string); ok && attrs[ssAttrItem] != "" {
			items = append(items, attrs[ssAttrItem])
		}
	}
	return items, nil
}
