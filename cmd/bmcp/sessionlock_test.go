//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The lock tests run real processes against one lock directory: flock's
// guarantees are between open files, and only separate processes show that the
// lock, not some in-process mutex, is what excludes them.
const lockHelperEnv = "BMCP_LOCK_TEST_HELPER"

// TestLockHelperProcess is not a test: it is the body of the subprocesses the
// tests below start, selected by lockHelperEnv.
func TestLockHelperProcess(t *testing.T) {
	mode := os.Getenv(lockHelperEnv)
	if mode == "" {
		return
	}
	os.Exit(runLockHelper(mode))
}

func runLockHelper(mode string) int {
	locks, err := newCredLocks()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	key := os.Getenv("BMCP_LOCK_TEST_KEY")
	signal := os.Getenv("BMCP_LOCK_TEST_DIR")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	waitForRelease := func() {
		for {
			if _, err := os.Stat(filepath.Join(signal, "release")); err == nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ready := func() { os.WriteFile(filepath.Join(signal, "ready-"+strconv.Itoa(os.Getpid())), nil, 0o600) }
	switch mode {
	case "hold-session":
		h, err := locks.lockSession(ctx, key)
		if err != nil {
			return 2
		}
		ready()
		waitForRelease()
		h.Unlock()
	case "hold-all":
		g, err := locks.lockAll(ctx)
		if err != nil {
			return 2
		}
		ready()
		waitForRelease()
		g.Unlock()
	case "increment":
		// Read-modify-write with a pause in the middle: without exclusion two
		// processes read the same value and one increment is lost.
		h, err := locks.lockSession(ctx, key)
		if err != nil {
			return 2
		}
		counter := filepath.Join(signal, "counter")
		b, _ := os.ReadFile(counter)
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		time.Sleep(20 * time.Millisecond)
		os.WriteFile(counter, []byte(strconv.Itoa(n+1)), 0o600)
		h.Unlock()
	case "marker-and-exit":
		h, err := locks.lockSession(ctx, key)
		if err != nil {
			return 2
		}
		if _, err := h.BeginLogin("dead-profile", time.Now()); err != nil {
			return 2
		}
		h.Unlock()
	case "marker-and-wait":
		h, err := locks.lockSession(ctx, key)
		if err != nil {
			return 2
		}
		m, err := h.BeginLogin("live-profile", time.Now())
		h.Unlock()
		if err != nil {
			return 2
		}
		ready()
		waitForRelease()
		// The browser approved; save only if clear did not discard the login.
		h, err = locks.lockSession(ctx, key)
		if err != nil {
			return 2
		}
		defer h.Unlock()
		wanted, err := h.LoginWanted(m)
		if err != nil {
			return 2
		}
		h.EndLogin(m)
		if !wanted {
			return 3
		}
	case "clear":
		h, err := locks.lockSession(ctx, key)
		if err != nil {
			return 2
		}
		defer h.Unlock()
		if err := h.DiscardLogin(); err != nil {
			return 2
		}
	default:
		return 2
	}
	return 0
}

type lockHelpers struct {
	t      *testing.T
	signal string
	key    string
}

func newLockHelpers(t *testing.T) *lockHelpers {
	isolateCredStoreEnv(t)
	return &lockHelpers{t: t, signal: t.TempDir(), key: ssoSessionStoreKey("lock-test", "")}
}

func (l *lockHelpers) start(mode string) *exec.Cmd {
	l.t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$")
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+mode, "BMCP_LOCK_TEST_KEY="+l.key, "BMCP_LOCK_TEST_DIR="+l.signal)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return cmd
}

func (l *lockHelpers) waitReady(cmd *exec.Cmd) {
	l.t.Helper()
	path := filepath.Join(l.signal, "ready-"+strconv.Itoa(cmd.Process.Pid))
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.t.Fatal("helper never became ready")
}

func (l *lockHelpers) release() {
	os.WriteFile(filepath.Join(l.signal, "release"), nil, 0o600)
}

func exitCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	err := cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0
}

func TestSessionLockExcludesOtherProcessesAndRespectsTheDeadline(t *testing.T) {
	l := newLockHelpers(t)
	holder := l.start("hold-session")
	l.waitReady(holder)

	locks, _ := newCredLocks()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := locks.lockSession(ctx, l.key); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want a deadline error while another process holds the lock, got %v", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("waited %v past a 300ms deadline", waited)
	}
	// Another session is not blocked by this one.
	other, err := locks.lockSession(context.Background(), ssoSessionStoreKey("another", ""))
	if err != nil {
		t.Fatalf("an unrelated session must not wait: %v", err)
	}
	other.Unlock()

	l.release()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	h, err := locks.lockSession(ctx2, l.key)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	h.Unlock()
	if code := exitCode(t, holder); code != 0 {
		t.Fatalf("holder exit %d", code)
	}
}

func TestSessionLockSerialisesParallelProcesses(t *testing.T) {
	l := newLockHelpers(t)
	const n = 8
	var cmds []*exec.Cmd
	for i := 0; i < n; i++ {
		cmds = append(cmds, l.start("increment"))
	}
	for _, c := range cmds {
		if code := exitCode(t, c); code != 0 {
			t.Fatalf("helper exit %d", code)
		}
	}
	b, _ := os.ReadFile(filepath.Join(l.signal, "counter"))
	if got := strings.TrimSpace(string(b)); got != strconv.Itoa(n) {
		t.Fatalf("counter = %s after %d locked increments; an increment was lost", got, n)
	}
}

func TestClearAllLockExcludesSessionLocks(t *testing.T) {
	l := newLockHelpers(t)
	holder := l.start("hold-all")
	l.waitReady(holder)
	locks, _ := newCredLocks()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := locks.lockSession(ctx, l.key); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a session lock must wait for clear --all, got %v", err)
	}
	l.release()
	if code := exitCode(t, holder); code != 0 {
		t.Fatalf("holder exit %d", code)
	}

	// And the other way round: clear --all waits for an in-flight mutation.
	os.Remove(filepath.Join(l.signal, "release"))
	holder = l.start("hold-session")
	l.waitReady(holder)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel3()
	if _, err := locks.lockAll(ctx3); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("clear --all must wait for a session lock holder, got %v", err)
	}
	l.release()
	exitCode(t, holder)
	g, err := locks.lockAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g.Unlock()
}

// Two goroutines of one process (serve) exclude each other too, and the lock
// is not re-entrant: a second acquisition waits rather than nesting.
func TestSessionLockIsNotReentrant(t *testing.T) {
	isolateCredStoreEnv(t)
	locks, _ := newCredLocks()
	key := ssoSessionStoreKey("s", "")
	h, err := locks.lockSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := locks.lockSession(ctx, key); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("re-acquiring in the same process must wait, got %v", err)
	}
	var wg sync.WaitGroup
	acquired := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		h2, err := locks.lockSession(context.Background(), key)
		if err == nil {
			close(acquired)
			h2.Unlock()
		}
	}()
	select {
	case <-acquired:
		t.Fatal("a goroutine acquired a held lock")
	case <-time.After(100 * time.Millisecond):
	}
	h.Unlock()
	wg.Wait()
}

func TestDeadLoginMarkerIsIgnored(t *testing.T) {
	l := newLockHelpers(t)
	if code := exitCode(t, l.start("marker-and-exit")); code != 0 {
		t.Fatalf("helper exit %d", code)
	}
	locks, _ := newCredLocks()
	if _, err := os.Stat(locks.markerPath(l.key)); err != nil {
		t.Fatalf("helper left no marker: %v", err)
	}
	m, err := locks.PeekLoginMarker(l.key, time.Now())
	if err != nil || m != nil {
		t.Fatalf("a dead process's marker must read as none, got %#v %v", m, err)
	}
	h, _ := locks.lockSession(context.Background(), l.key)
	defer h.Unlock()
	if m, err := h.LoginMarker(time.Now()); m != nil || err != nil {
		t.Fatalf("LoginMarker: %#v %v", m, err)
	}
	if _, err := os.Stat(locks.markerPath(l.key)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dead marker must be removed under the lock: %v", err)
	}
}

func TestLiveLoginMarkerIsSeenAndStaleOneIsNot(t *testing.T) {
	l := newLockHelpers(t)
	waiter := l.start("marker-and-wait")
	l.waitReady(waiter)
	locks, _ := newCredLocks()
	m, err := locks.PeekLoginMarker(l.key, time.Now())
	if err != nil || m == nil || m.PID != waiter.Process.Pid || m.Profile != "live-profile" {
		t.Fatalf("live marker: %#v %v", m, err)
	}
	if m, _ := locks.PeekLoginMarker(l.key, time.Now().Add(loginMarkerMaxAge+time.Minute)); m != nil {
		t.Fatal("a marker older than the login budget must read as none, whatever its pid")
	}
	l.release()
	if code := exitCode(t, waiter); code != 0 {
		t.Fatalf("an undisturbed login must be allowed to save, exit %d", code)
	}
	if m, _ := locks.PeekLoginMarker(l.key, time.Now()); m != nil {
		t.Fatal("EndLogin left the marker behind")
	}
}

func TestClearDiscardsAnInFlightLogin(t *testing.T) {
	l := newLockHelpers(t)
	login := l.start("marker-and-wait")
	l.waitReady(login)
	if code := exitCode(t, l.start("clear")); code != 0 {
		t.Fatalf("clear exit %d", code)
	}
	l.release()
	if code := exitCode(t, login); code != 3 {
		t.Fatalf("a login cleared while waiting must discard its result (exit 3), got %d", code)
	}
}

func TestClearAllDiscardsEveryInFlightLogin(t *testing.T) {
	isolateCredStoreEnv(t)
	locks, _ := newCredLocks()
	var markers []*loginMarker
	var keys []string
	for _, name := range []string{"a", "b"} {
		key := ssoSessionStoreKey(name, "")
		h, _ := locks.lockSession(context.Background(), key)
		m, err := h.BeginLogin(name, time.Now())
		h.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		keys, markers = append(keys, key), append(markers, m)
	}
	g, err := locks.lockAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := g.DiscardAllLogins(); err != nil {
		t.Fatal(err)
	}
	g.Unlock()
	for i, key := range keys {
		h, _ := locks.lockSession(context.Background(), key)
		wanted, err := h.LoginWanted(markers[i])
		h.Unlock()
		if err != nil || wanted {
			t.Fatalf("session %d: login still wanted after clear --all (%v)", i, err)
		}
	}
}

func TestGenerationConditionalRoleCredWrites(t *testing.T) {
	isolateCredStoreEnv(t)
	store, _ := newAWSCLICacheStore()
	locks, _ := newCredLocks()
	key := ssoSessionStoreKey("gen", "")
	credKey := roleCacheKey(roleCacheKeyInput{SSOSession: "gen", AccountID: "1", RoleName: "R"})
	h, err := locks.lockSession(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Unlock()

	if ok, err := h.writeRoleCredsIfCurrent(store, credKey, sampleRoleCreds("g0", "AKIA0")); ok || err != nil {
		t.Fatalf("no token: must not write (ok=%v err=%v)", ok, err)
	}

	tok, err := h.saveNewToken(store, sampleToken(""))
	if err != nil || tok.Generation == "" {
		t.Fatalf("saveNewToken: %#v %v", tok, err)
	}
	g1 := tok.Generation
	if ok, err := h.writeRoleCredsIfCurrent(store, credKey, sampleRoleCreds(g1, "AKIA1")); !ok || err != nil {
		t.Fatalf("current generation must write (ok=%v err=%v)", ok, err)
	}

	// A new login supersedes g1: its role creds go, and a late g1 write is refused.
	tok2, err := h.saveNewToken(store, sampleToken(""))
	if err != nil || tok2.Generation == g1 {
		t.Fatalf("second login must bump the generation: %#v %v", tok2, err)
	}
	if _, err := store.ReadRoleCreds(key, credKey); !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("role creds of a superseded token survived a new login: %v", err)
	}
	if ok, _ := h.writeRoleCredsIfCurrent(store, credKey, sampleRoleCreds(g1, "AKIA1")); ok {
		t.Fatal("credentials minted from a superseded login were written")
	}

	g2 := tok2.Generation
	if ok, _ := h.writeRoleCredsIfCurrent(store, credKey, sampleRoleCreds(g2, "AKIA2")); !ok {
		t.Fatal("current generation write refused")
	}
	// A late rejection of older credentials must not evict the newer ones.
	if ok, err := h.evictRoleCredsIfSame(store, credKey, sampleRoleCreds(g1, "AKIA1")); ok || err != nil {
		t.Fatalf("stale rejection evicted newer creds (ok=%v err=%v)", ok, err)
	}
	if ok, err := h.evictRoleCredsIfSame(store, credKey, sampleRoleCreds(g2, "AKIA2")); !ok || err != nil {
		t.Fatalf("matching rejection must evict (ok=%v err=%v)", ok, err)
	}
	if _, err := store.ReadRoleCreds(key, credKey); !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("evicted creds still readable: %v", err)
	}

	if ok, _ := h.writeRoleCredsIfCurrent(store, credKey, sampleRoleCreds(g2, "AKIA3")); !ok {
		t.Fatal("write refused")
	}
	if err := h.clearSession(store); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadToken(key); !errors.Is(err, errStoreItemNotFound) {
		t.Fatalf("clear left the token: %v", err)
	}
	if ok, _ := h.writeRoleCredsIfCurrent(store, credKey, sampleRoleCreds(g2, "AKIA3")); ok {
		t.Fatal("a refresh racing clear must not resurrect role creds")
	}
}
