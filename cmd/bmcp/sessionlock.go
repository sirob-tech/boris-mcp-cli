//go:build darwin || linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// credLocks coordinates bmcp processes that share one SSO session. Its path
// does not depend on the backend, so processes on different backends still
// exclude each other. flock is unreliable on NFS home directories.
type credLocks struct{ dir string }

func newCredLocks() (*credLocks, error) {
	cfg, err := bmcpConfigDir()
	if err != nil {
		return nil, err
	}
	return &credLocks{dir: filepath.Join(cfg, "locks")}, nil
}

// lockPollInterval is how often a waiter retries a non-blocking flock. A
// blocking flock cannot be abandoned when the caller's context expires.
var lockPollInterval = 25 * time.Millisecond

const lockPollMax = 250 * time.Millisecond

// sessionLock is held for every store mutation of one SSO session. It also
// holds the global lock shared, so `clear --all` (global, exclusive) waits for
// in-flight mutations and they wait for it.
//
// Not re-entrant: flock locks belong to an open file, so a second
// lockSession from the same process waits like any other process would.
type sessionLock struct {
	locks      *credLocks
	sessionKey string
	files      []*os.File
}

// globalLock is `clear --all`'s exclusive hold over every session.
type globalLock struct {
	locks *credLocks
	file  *os.File
}

func (l *credLocks) lockSession(ctx context.Context, sessionKey string) (*sessionLock, error) {
	if err := validStoreKey(sessionKey); err != nil {
		return nil, err
	}
	g, err := l.flock(ctx, "global.lock", syscall.LOCK_SH)
	if err != nil {
		return nil, err
	}
	s, err := l.flock(ctx, sessionKey+".lock", syscall.LOCK_EX)
	if err != nil {
		unlockFile(g)
		return nil, err
	}
	return &sessionLock{locks: l, sessionKey: sessionKey, files: []*os.File{s, g}}, nil
}

func (l *credLocks) lockAll(ctx context.Context) (*globalLock, error) {
	f, err := l.flock(ctx, "global.lock", syscall.LOCK_EX)
	if err != nil {
		return nil, err
	}
	return &globalLock{locks: l, file: f}, nil
}

func (h *sessionLock) Unlock() {
	for _, f := range h.files {
		unlockFile(f)
	}
	h.files = nil
}

func (h *globalLock) Unlock() {
	if h.file != nil {
		unlockFile(h.file)
		h.file = nil
	}
}

func unlockFile(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
}

func (l *credLocks) flock(ctx context.Context, name string, how int) (*os.File, error) {
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(l.dir, name), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	wait := lockPollInterval
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", f.Name(), err)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			f.Close()
			return nil, fmt.Errorf("waiting for another bmcp process to release %s: %w", f.Name(), ctx.Err())
		case <-t.C:
		}
		if wait *= 2; wait > lockPollMax {
			wait = lockPollMax
		}
	}
}

// loginMarker says a browser login for this session is waiting for approval.
// Logins do not hold the lock while waiting, so this is how other processes
// learn to wait for its result instead of opening a second browser tab.
type loginMarker struct {
	ID        string    `json:"id"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"startedAt"`
	Profile   string    `json:"profile"`
	// Discard is set by `bmcp clear`, so a login it raced is not saved.
	Discard bool `json:"discard,omitempty"`
}

// loginMarkerMaxAge outlives `bmcp login`'s 11-minute budget; an older marker
// is stale even if its pid has been reused by an unrelated process.
const loginMarkerMaxAge = 15 * time.Minute

func (l *credLocks) markerPath(sessionKey string) string {
	return filepath.Join(l.dir, sessionKey+".login")
}

// PeekLoginMarker reads the marker without the lock, for waiters polling
// whether a login is still in flight. Writes are atomic renames, so a read
// sees one whole marker or none. A dead or stale marker reads as none.
func (l *credLocks) PeekLoginMarker(sessionKey string, now time.Time) (*loginMarker, error) {
	if err := validStoreKey(sessionKey); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(l.markerPath(sessionKey))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m loginMarker
	if json.Unmarshal(b, &m) != nil || !m.live(now) {
		return nil, nil
	}
	return &m, nil
}

func (m loginMarker) live(now time.Time) bool {
	return m.PID > 0 && now.Sub(m.StartedAt) < loginMarkerMaxAge && pidAlive(m.PID)
}

// pidAlive treats EPERM as alive: the process exists, it just is not ours.
func pidAlive(pid int) bool {
	if pid == os.Getpid() {
		return true
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// LoginMarker is the live marker for this session, or nil. A dead one is
// removed while the lock is held.
func (h *sessionLock) LoginMarker(now time.Time) (*loginMarker, error) {
	m, err := h.locks.PeekLoginMarker(h.sessionKey, now)
	if err != nil || m != nil {
		return m, err
	}
	return nil, removeIfExists(h.locks.markerPath(h.sessionKey))
}

// BeginLogin records this process's login. The caller checks LoginMarker first;
// this overwrites whatever is there.
func (h *sessionLock) BeginLogin(profile string, now time.Time) (*loginMarker, error) {
	m := &loginMarker{ID: newGeneration(), PID: os.Getpid(), StartedAt: now, Profile: profile}
	return m, h.writeMarker(*m)
}

// LoginWanted reports whether the login m started may still save its result:
// its marker is still the current one and `clear` has not discarded it.
func (h *sessionLock) LoginWanted(m *loginMarker) (bool, error) {
	cur, err := h.readMarker()
	if err != nil || cur == nil {
		return false, err
	}
	return cur.ID == m.ID && !cur.Discard, nil
}

// EndLogin removes m's marker, and leaves anyone else's alone.
func (h *sessionLock) EndLogin(m *loginMarker) error {
	cur, err := h.readMarker()
	if err != nil || cur == nil || cur.ID != m.ID {
		return err
	}
	return removeIfExists(h.locks.markerPath(h.sessionKey))
}

// DiscardLogin marks any in-flight login so its result is thrown away. `clear`
// calls it instead of waiting for the browser.
func (h *sessionLock) DiscardLogin() error {
	cur, err := h.readMarker()
	if err != nil || cur == nil {
		return err
	}
	cur.Discard = true
	return h.writeMarker(*cur)
}

func (h *sessionLock) readMarker() (*loginMarker, error) {
	b, err := os.ReadFile(h.locks.markerPath(h.sessionKey))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m loginMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, nil
	}
	return &m, nil
}

func (h *sessionLock) writeMarker(m loginMarker) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeSecretFileAtomic(h.locks.markerPath(h.sessionKey), b)
}

// DiscardAllLogins is `clear --all`'s DiscardLogin for every session.
func (g *globalLock) DiscardAllLogins() error {
	entries, err := os.ReadDir(g.locks.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		key, ok := strings.CutSuffix(e.Name(), ".login")
		if !ok || validStoreKey(key) != nil {
			continue
		}
		// Every session lock holder also holds the global lock shared, so with
		// it exclusive here nobody else is touching this marker.
		h := &sessionLock{locks: g.locks, sessionKey: key}
		if err := h.DiscardLogin(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// writeRoleCredsIfCurrent saves role credentials only while the token they
// were minted from is still the stored one, so a credential from a superseded
// login or a cleared session is never written. Requires the session lock.
func (h *sessionLock) writeRoleCredsIfCurrent(store credStore, credKey string, rec roleCredsRecord) (bool, error) {
	tok, err := store.ReadToken(h.sessionKey)
	if errors.Is(err, errStoreItemNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if rec.Generation == "" || tok.Generation != rec.Generation {
		return false, nil
	}
	return true, store.WriteRoleCreds(h.sessionKey, credKey, rec)
}

// evictRoleCredsIfSame removes cached role credentials only if they are the
// ones that were rejected, so a late rejection never evicts newer credentials
// another process saved meanwhile. Requires the session lock.
func (h *sessionLock) evictRoleCredsIfSame(store credStore, credKey string, rejected roleCredsRecord) (bool, error) {
	cur, err := store.ReadRoleCreds(h.sessionKey, credKey)
	if errors.Is(err, errStoreItemNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if cur.Generation != rejected.Generation || cur.AccessKeyID != rejected.AccessKeyID {
		return false, nil
	}
	return true, store.DeleteRoleCreds(h.sessionKey, credKey)
}

// saveNewToken stamps a fresh generation, for a login or a refresh that
// rotated the refresh token, and drops role credentials the old token minted.
// Requires the session lock.
func (h *sessionLock) saveNewToken(store credStore, rec ssoTokenRecord) (ssoTokenRecord, error) {
	rec.Generation = newGeneration()
	if err := store.WriteToken(h.sessionKey, rec); err != nil {
		return rec, err
	}
	return rec, store.DeleteSessionRoleCreds(h.sessionKey)
}

// clearSession is `bmcp clear` for one session: token, client registration
// (stored with the token) and role credentials, plus any in-flight login.
// Requires the session lock.
func (h *sessionLock) clearSession(store credStore) error {
	return errors.Join(
		h.DiscardLogin(),
		store.DeleteToken(h.sessionKey),
		store.DeleteSessionRoleCreds(h.sessionKey),
	)
}
