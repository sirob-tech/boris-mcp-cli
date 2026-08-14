package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeGitHub serves the release endpoints bmcp update talks to. Responses to
// the redirect probe carry a Request whose URL is the post-follow landing URL,
// because that is the only place the tag survives once the client has consumed
// the Location header.
type fakeGitHub struct {
	latestTag     string
	assets        map[string][]byte
	redirectFails bool
	apiCalls      int
	headCalls     int
	assetCalls    int
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return u
}

func (g *fakeGitHub) Do(req *http.Request) (*http.Response, error) {
	respond := func(status int, body []byte, finalURL string) (*http.Response, error) {
		parsed, _ := url.Parse(finalURL)
		return &http.Response{
			StatusCode: status,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(body)),
			Request:    &http.Request{URL: parsed},
		}, nil
	}

	path := req.URL.Path
	switch {
	case req.Method == http.MethodHead && strings.HasSuffix(path, "/releases/latest"):
		g.headCalls++
		if g.redirectFails {
			return respond(404, nil, req.URL.String())
		}
		return respond(200, nil, fmt.Sprintf("https://github.com/%s/releases/tag/%s", updateRepo, g.latestTag))
	case req.URL.Host == "api.github.com":
		g.apiCalls++
		if g.latestTag == "" {
			return respond(403, []byte(`{"message":"rate limited"}`), req.URL.String())
		}
		body, _ := json.Marshal(map[string]string{"tag_name": g.latestTag})
		return respond(200, body, req.URL.String())
	case strings.Contains(path, "/releases/download/"):
		g.assetCalls++
		name := filepath.Base(path)
		if body, ok := g.assets[name]; ok {
			return respond(200, body, req.URL.String())
		}
		return respond(404, []byte("Not Found"), req.URL.String())
	}
	return respond(404, []byte("Not Found"), req.URL.String())
}

// releaseArchive builds a tar.gz shaped like a real release asset, which
// carries LICENSE and README.md alongside the binary.
func releaseArchive(t *testing.T, binary []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, content []byte) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	write("LICENSE", []byte("Apache-2.0"))
	write("bmcp", binary)
	write("README.md", []byte("# bmcp"))
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func checksumsFor(assets map[string][]byte) []byte {
	var b strings.Builder
	for name, body := range assets {
		if name == "checksums.txt" {
			continue
		}
		sum := sha256.Sum256(body)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return []byte(b.String())
}

// asReleaseBuild makes the binary under test look like a shipped release.
// Without it every update path short-circuits as a source build, which is
// exactly what keeps the rest of the suite off the network.
func asReleaseBuild(t *testing.T, v string) {
	t.Helper()
	oldCommit, oldVersion := buildCommit, version
	buildCommit, version = "deadbeef", v
	t.Cleanup(func() { buildCommit, version = oldCommit, oldVersion })
}

// stagedBinary lays out a fake managed install: a binary, and an install.sh
// receipt marking it self-replaceable.
func stagedBinary(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bmcp")
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	receipt := installReceipt{Method: "install.sh", Repo: updateRepo, Version: "v0.4.0"}
	b, _ := json.MarshalIndent(receipt, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, ".bmcp.install.json"), b, 0o644); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	return path
}

func TestNormalizeVersionBridgesTheTagPrefixGap(t *testing.T) {
	// GoReleaser injects the version unprefixed while tags carry a v. Comparing
	// them raw is what would make every invocation see an update forever.
	if normalizeVersion("v0.3.0") != "0.3.0" || normalizeVersion("0.3.0") != "0.3.0" {
		t.Fatal("normalizeVersion should strip the v prefix and be idempotent")
	}
	if normalizeVersion("  v1.2.3  ") != "1.2.3" {
		t.Fatalf("normalizeVersion should trim, got %q", normalizeVersion("  v1.2.3  "))
	}
	if taggedVersion("0.3.0") != "v0.3.0" || taggedVersion("v0.3.0") != "v0.3.0" {
		t.Fatal("taggedVersion should produce exactly one v prefix")
	}
	if taggedVersion("") != "" {
		t.Fatal("taggedVersion should leave an empty version empty")
	}
}

func TestClassifyInstallUsesTheResolvedPath(t *testing.T) {
	asReleaseBuild(t, "0.4.0")

	cellar := filepath.Join(t.TempDir(), "Cellar", "bmcp", "0.3.0", "bin", "bmcp")
	if err := os.MkdirAll(filepath.Dir(cellar), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if got := classifyInstall(cellar); got != installBrew {
		t.Fatalf("a Cellar path should classify as brew, got %v", got)
	}

	managed := filepath.Join(t.TempDir(), "bmcp")
	if got := classifyInstall(managed); got != installManaged {
		t.Fatalf("a plain path should classify as managed, got %v", got)
	}
}

func TestClassifyInstallTrustsTheInstallReceiptOverThePathHeuristic(t *testing.T) {
	asReleaseBuild(t, "0.4.0")
	path := stagedBinary(t, "old")
	if got := classifyInstall(path); got != installManaged {
		t.Fatalf("an install.sh receipt should classify as managed, got %v", got)
	}
}

func TestClassifyInstallRefusesVersionManagedLayouts(t *testing.T) {
	// mise, asdf, Nix and MacPorts all store the binary under a directory named
	// after its version. Replacing it writes the new binary into a directory
	// named after the old one.
	asReleaseBuild(t, "0.5.0")
	root := t.TempDir()
	for _, layout := range []string{
		"mise/installs/bmcp/0.5.0/bin/bmcp",
		".asdf/installs/bmcp/0.5.0/bin/bmcp",
		"opt/bmcp/v1.2.3/bmcp",
	} {
		path := filepath.Join(root, layout)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if got := classifyInstall(path); got != installVersioned {
			t.Fatalf("%s should classify as version-managed, got %v", layout, got)
		}
	}

	// A bare numeric directory is far too common to count as evidence.
	plain := filepath.Join(root, "001", "bin", "bmcp")
	if err := os.MkdirAll(filepath.Dir(plain), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if got := classifyInstall(plain); got != installManaged {
		t.Fatalf("a bare integer directory should stay managed, got %v", got)
	}
}

func TestAcquireUpdateLockIsExclusiveAndOwnershipScoped(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	release, err := acquireUpdateLock(dir, now)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := acquireUpdateLock(dir, now); err == nil {
		t.Fatal("a held lock must not be acquirable twice")
	}
	release()
	release2, err := acquireUpdateLock(dir, now)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	release2()

	// Releasing must not remove a lock we do not own: the stale-steal path
	// otherwise lets one process delete another's fresh lock.
	lock := filepath.Join(dir, ".bmcp.update.lock")
	if err := os.WriteFile(lock, []byte("bmcp 999999\n"), 0o600); err != nil {
		t.Fatalf("write foreign lock: %v", err)
	}
	release2()
	if _, err := os.Stat(lock); err != nil {
		t.Fatal("release removed a lock owned by another process")
	}
}

func TestClassifyInstallTreatsSourceBuildsAsUntouchable(t *testing.T) {
	// buildCommit is "unknown" under `go test`, which is the whole reason the
	// rest of the suite never reaches the network.
	if got := classifyInstall("/anywhere/bmcp"); got != installSource {
		t.Fatalf("a source build should classify as source, got %v", got)
	}
}

func TestResolveExecutableFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-bmcp")
	if err := os.WriteFile(real, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "bmcp")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	a := &app{executable: func() (string, error) { return link, nil }}
	got, err := a.resolveExecutable()
	if err != nil {
		t.Fatalf("resolveExecutable: %v", err)
	}
	resolvedReal, _ := filepath.EvalSymlinks(real)
	if got != resolvedReal {
		t.Fatalf("expected the symlink target %s, got %s", resolvedReal, got)
	}
}

func TestVerifyArchiveChecksumFailsClosed(t *testing.T) {
	archive := []byte("release archive")
	sum := sha256.Sum256(archive)
	good := []byte(fmt.Sprintf("%s  bmcp-linux-amd64.tar.gz\n", hex.EncodeToString(sum[:])))

	if err := verifyArchiveChecksum(archive, good, "bmcp-linux-amd64.tar.gz"); err != nil {
		t.Fatalf("a matching checksum should verify: %v", err)
	}

	cases := []struct {
		name      string
		checksums []byte
		asset     string
		want      string
	}{
		{"empty checksums", nil, "bmcp-linux-amd64.tar.gz", "empty"},
		{"no line for our asset", good, "bmcp-darwin-arm64.tar.gz", "no entry"},
		{
			"wrong digest",
			[]byte("0000000000000000000000000000000000000000000000000000000000000000  bmcp-linux-amd64.tar.gz\n"),
			"bmcp-linux-amd64.tar.gz",
			"mismatch",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyArchiveChecksum(archive, tc.checksums, tc.asset)
			if err == nil {
				t.Fatal("expected a hard failure, never a skip")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestExtractBinaryTakesOnlyTheRegularBmcpMember(t *testing.T) {
	archive := releaseArchive(t, []byte("new binary"))
	got, err := extractBinary(archive)
	if err != nil {
		t.Fatalf("extractBinary: %v", err)
	}
	if string(got) != "new binary" {
		t.Fatalf("expected the bmcp member, got %q", got)
	}
}

func TestExtractBinaryRejectsNonRegularMembers(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	// A symlink named bmcp: chmod and exec would follow it out of the archive.
	if err := tw.WriteHeader(&tar.Header{
		Name: "bmcp", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777,
	}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	tw.Close()
	gz.Close()

	_, err := extractBinary(buf.Bytes())
	if err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("expected a non-regular member to be rejected, got %v", err)
	}
}

func TestExtractBinaryRejectsAnArchiveWithoutBmcp(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	content := []byte("Apache-2.0")
	tw.WriteHeader(&tar.Header{Name: "LICENSE", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
	tw.Write(content)
	tw.Close()
	gz.Close()

	if _, err := extractBinary(buf.Bytes()); err == nil {
		t.Fatal("expected an archive without a bmcp member to be rejected")
	}
}

func TestLatestReleaseTagPrefersTheRedirectAndFallsBackToTheAPI(t *testing.T) {
	gh := &fakeGitHub{latestTag: "v0.6.0"}
	a := &app{httpClient: gh, stderr: &bytes.Buffer{}}

	tag, err := a.latestReleaseTag(context.Background())
	if err != nil {
		t.Fatalf("latestReleaseTag: %v", err)
	}
	if tag != "v0.6.0" {
		t.Fatalf("expected v0.6.0, got %s", tag)
	}
	if gh.headCalls != 1 || gh.apiCalls != 0 {
		t.Fatalf("the redirect should answer alone: head=%d api=%d", gh.headCalls, gh.apiCalls)
	}

	gh.redirectFails = true
	tag, err = a.latestReleaseTag(context.Background())
	if err != nil {
		t.Fatalf("latestReleaseTag via API: %v", err)
	}
	if tag != "v0.6.0" || gh.apiCalls != 1 {
		t.Fatalf("expected the API fallback to answer, got %s after %d api calls", tag, gh.apiCalls)
	}
}

func TestLatestReleaseTagReportsBothFailures(t *testing.T) {
	gh := &fakeGitHub{redirectFails: true}
	a := &app{httpClient: gh, stderr: &bytes.Buffer{}}
	if _, err := a.latestReleaseTag(context.Background()); err == nil {
		t.Fatal("expected an error when neither lookup succeeds")
	}
}

func TestInspectUpdateTargetsThePinRatherThanLatest(t *testing.T) {
	// The loop this prevents: with BMCP_VERSION pinned, computing `available`
	// against latest reports an update, the update downgrades to the pin, and
	// the next session reports it again, forever.
	asReleaseBuild(t, "0.3.0")
	gh := &fakeGitHub{latestTag: "v0.6.0"}
	path := stagedBinary(t, "old")
	a := &app{
		stderr:     &bytes.Buffer{},
		httpClient: gh,
		now:        time.Now,
		executable: func() (string, error) { return path, nil },
	}

	cfg := effectiveConfig{PinnedVersion: "v0.3.0"}
	st := a.inspectUpdate(context.Background(), cfg, "")
	if st.Latest != "0.6.0" {
		t.Fatalf("latest should still be reported, got %q", st.Latest)
	}
	if st.Target != "0.3.0" {
		t.Fatalf("target should be the pin, got %q", st.Target)
	}
	if st.Available {
		t.Fatal("a machine already on the pinned version has no update available")
	}
}

func TestInspectUpdateSkipsTheLookupForAnExplicitTarget(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	gh := &fakeGitHub{latestTag: "v0.6.0"}
	path := stagedBinary(t, "old")
	a := &app{
		stderr:     &bytes.Buffer{},
		httpClient: gh,
		now:        time.Now,
		executable: func() (string, error) { return path, nil },
	}

	st := a.inspectUpdate(context.Background(), effectiveConfig{}, "v0.2.0")
	if gh.headCalls != 0 || gh.apiCalls != 0 {
		t.Fatalf("an explicit target needs no lookup: head=%d api=%d", gh.headCalls, gh.apiCalls)
	}
	if st.Target != "0.2.0" || !st.Available {
		t.Fatalf("expected a downgrade to be available, got target=%q available=%v", st.Target, st.Available)
	}
}

func TestApplyUpdateSwapsTheBinaryAndRecordsTheTrail(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	path := stagedBinary(t, "old binary")
	archive := releaseArchive(t, []byte("brand new binary"))
	assets := map[string][]byte{"bmcp-" + hostAsset(): archive}
	assets["checksums.txt"] = checksumsFor(assets)

	gh := &fakeGitHub{latestTag: "v0.6.0", assets: assets}
	var stderr bytes.Buffer
	a := &app{
		stderr:     &stderr,
		httpClient: gh,
		now:        time.Now,
		executable: func() (string, error) { return path, nil },
		// Stands in for codesign, which cannot verify a fake binary.
		verifySignature: func(string) error { return nil },
	}

	st := a.inspectUpdate(context.Background(), effectiveConfig{}, "")
	if !st.Available {
		t.Fatalf("expected an update to be available: %+v", st)
	}
	if err := a.applyUpdate(context.Background(), globalFlags{}, st, st.Target); err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read swapped binary: %v", err)
	}
	if string(got) != "brand new binary" {
		t.Fatalf("binary was not replaced, got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("expected mode 0755, got %v", info.Mode().Perm())
	}

	receipt, err := readInstallReceipt(path)
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if receipt.Method != "install.sh" {
		t.Fatalf("the update must preserve the install method, got %q", receipt.Method)
	}
	if len(receipt.Updates) != 1 || receipt.Updates[0].From != "0.5.0" || receipt.Updates[0].To != "0.6.0" {
		t.Fatalf("expected one 0.5.0 -> 0.6.0 record, got %+v", receipt.Updates)
	}

	// The replaced binary is kept so --rollback has something to restore.
	if _, err := os.Stat(priorBinaryPath(path)); err != nil {
		t.Fatalf("expected the previous binary to be kept: %v", err)
	}
}

func TestApplyUpdateRefusesAMismatchedChecksum(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	path := stagedBinary(t, "old binary")
	assets := map[string][]byte{
		"bmcp-" + hostAsset(): releaseArchive(t, []byte("tampered")),
		"checksums.txt":       []byte("0000000000000000000000000000000000000000000000000000000000000000  bmcp-" + hostAsset() + "\n"),
	}
	gh := &fakeGitHub{latestTag: "v0.6.0", assets: assets}
	a := &app{
		stderr:          &bytes.Buffer{},
		httpClient:      gh,
		now:             time.Now,
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return nil },
	}

	st := a.inspectUpdate(context.Background(), effectiveConfig{}, "")
	err := a.applyUpdate(context.Background(), globalFlags{}, st, st.Target)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected a checksum mismatch to abort the update, got %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old binary" {
		t.Fatalf("a rejected update must leave the binary untouched, got %q", got)
	}
}

func TestApplyUpdateRefusesWhenAnotherUpdateHoldsTheLock(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	path := stagedBinary(t, "old binary")
	lock := filepath.Join(filepath.Dir(path), ".bmcp.update.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("new"))}
	assets["checksums.txt"] = checksumsFor(assets)
	a := &app{
		stderr:          &bytes.Buffer{},
		httpClient:      &fakeGitHub{latestTag: "v0.6.0", assets: assets},
		now:             time.Now,
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return nil },
	}

	st := a.inspectUpdate(context.Background(), effectiveConfig{}, "")
	err := a.applyUpdate(context.Background(), globalFlags{}, st, st.Target)
	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("expected the lock to block a concurrent swap, got %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "old binary" {
		t.Fatalf("the blocked update must not have swapped, got %q", got)
	}
}

func TestAcquireUpdateLockStealsAStaleLock(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, ".bmcp.update.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	// A crashed update would otherwise block every future one forever.
	release, err := acquireUpdateLock(dir, time.Now().Add(2*staleLockAge))
	if err != nil {
		t.Fatalf("a stale lock should be reclaimed: %v", err)
	}
	release()
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("releasing the lock should remove it")
	}
}

// The two codesign tests are inverses guarded on the same constant, so exactly
// one runs. Keeping both means flipping codesignFailClosed — including flipping
// it back in an emergency — never leaves the suite asserting behaviour the
// binary no longer has.
func TestCodesignFailureRefusesTheUpdateWhenFailClosed(t *testing.T) {
	if !codesignFailClosed {
		t.Skip("fail-closed is disabled; TestCodesignFailureOnlyWarns covers that setting")
	}
	asReleaseBuild(t, "0.5.0")
	path := stagedBinary(t, "old binary")
	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("new binary"))}
	assets["checksums.txt"] = checksumsFor(assets)

	var stderr bytes.Buffer
	a := &app{
		stderr:          &stderr,
		httpClient:      &fakeGitHub{latestTag: "v0.6.0", assets: assets},
		now:             time.Now,
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return fmt.Errorf("signature does not match") },
	}

	st := a.inspectUpdate(context.Background(), effectiveConfig{}, "")
	err := a.applyUpdate(context.Background(), globalFlags{}, st, st.Target)
	if err == nil || !strings.Contains(err.Error(), "refusing to install an unverified binary") {
		t.Fatalf("expected the update to be refused, got %v", err)
	}
	// The running binary is the thing that must survive: refusing an update is
	// only safe if it leaves a working bmcp behind.
	got, _ := os.ReadFile(path)
	if string(got) != "old binary" {
		t.Fatalf("a refused update must not swap the binary, got %q", got)
	}
	// A staged file left behind would be committed by the next update without
	// ever being verified again.
	if _, err := os.Stat(stagedPath(path)); !os.IsNotExist(err) {
		t.Fatalf("a refused update must clear its staged binary, stat gave %v", err)
	}
}

func TestCodesignFailureOnlyWarns(t *testing.T) {
	if codesignFailClosed {
		t.Skip("fail-closed is enabled; TestCodesignFailureRefusesTheUpdateWhenFailClosed covers that setting")
	}
	asReleaseBuild(t, "0.5.0")
	path := stagedBinary(t, "old binary")
	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("new binary"))}
	assets["checksums.txt"] = checksumsFor(assets)

	var stderr bytes.Buffer
	a := &app{
		stderr:          &stderr,
		httpClient:      &fakeGitHub{latestTag: "v0.6.0", assets: assets},
		now:             time.Now,
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return fmt.Errorf("signature does not match") },
	}

	st := a.inspectUpdate(context.Background(), effectiveConfig{}, "")
	if err := a.applyUpdate(context.Background(), globalFlags{}, st, st.Target); err != nil {
		t.Fatalf("warn-only should still apply the update: %v", err)
	}
	if !strings.Contains(stderr.String(), "could not verify the signature") {
		t.Fatalf("expected a signature warning, got: %s", stderr.String())
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new binary" {
		t.Fatalf("expected the update to apply, got %q", got)
	}
}

func TestRollbackRestoresThePreviousBinary(t *testing.T) {
	asReleaseBuild(t, "0.6.0")
	path := stagedBinary(t, "new binary")
	if err := os.WriteFile(priorBinaryPath(path), []byte("previous binary"), 0o755); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	var stderr bytes.Buffer
	a := &app{
		stderr:     &stderr,
		now:        time.Now,
		executable: func() (string, error) { return path, nil },
	}
	if code := a.rollbackUpdate(globalFlags{}, path); code != 0 {
		t.Fatalf("rollback exit %d: %s", code, stderr.String())
	}
	got, _ := os.ReadFile(path)
	if string(got) != "previous binary" {
		t.Fatalf("expected the previous binary to be restored, got %q", got)
	}
}

func TestRollbackWithoutABackupExplainsHowToRecover(t *testing.T) {
	asReleaseBuild(t, "0.6.0")
	path := stagedBinary(t, "current")
	var stderr bytes.Buffer
	a := &app{stderr: &stderr, now: time.Now, executable: func() (string, error) { return path, nil }}
	if code := a.rollbackUpdate(globalFlags{}, path); code != exitValidation {
		t.Fatalf("expected exitValidation, got %d", code)
	}
	if !strings.Contains(stderr.String(), "BMCP_VERSION") {
		t.Fatalf("expected recovery instructions, got: %s", stderr.String())
	}
}

func hostAsset() string {
	return strings.TrimPrefix(assetName(), "bmcp-")
}

// configuredHome writes a usable config and tool cache so requireConfig does
// not divert into first-run setup and doctor's own checks all pass — leaving
// the update row as the only thing under test.
func configuredHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	cfg := configFile{URL: "http://localhost:8787/mcp"}
	applyDefaults(&cfg)
	if err := writeConfig(filepath.Join(home, "config.toml"), cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	cache := &toolCache{
		Version:  1,
		URL:      cfg.URL,
		LastSync: time.Now().UTC(),
		Tools:    []tool{{Name: "search_aws_memory", Description: "d"}},
	}
	if err := writeCache(filepath.Join(home, "tools.json"), cache); err != nil {
		t.Fatalf("writeCache: %v", err)
	}
	return home
}

// syncableMCP is a fake server that lists the same tool configuredHome seeds, so
// `bmcp sync` against it succeeds.
//
// A fake with no tools makes sync exit 4 by design: an empty tools/list must not
// overwrite a non-empty cache. These tests are about auto-update, so they should
// not be exercising that refusal by accident — before the guard existed they
// were quietly asserting auto-update behaviour across a catalog-wiping sync.
func syncableMCP(gh *fakeGitHub) *fakeMCP {
	return &fakeMCP{tools: []tool{{Name: "search_aws_memory", Description: "d"}}, github: gh}
}

// jsonTail returns the JSON document at the end of a stream that also carries
// human prose — doctor --json shares stderr with "Syncing tools...".
func jsonTail(t *testing.T, s string) []byte {
	t.Helper()
	idx := strings.Index(s, "{")
	if idx < 0 {
		t.Fatalf("no JSON found in: %s", s)
	}
	return []byte(s[idx:])
}

func TestToolCallsNeverReachTheUpdateEndpoints(t *testing.T) {
	// The load-bearing guarantee: an agent making dozens of tool calls per
	// session must never pay for a network round trip, let alone a binary swap.
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	for _, args := range [][]string{
		{"list"},
		{"describe", "search_aws_memory"},
		{"call", "search_aws_memory", `{"query":"x"}`},
		{"search_aws_memory", "--query", "x"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			m := &fakeMCP{
				tools:      []tool{{Name: "search_aws_memory", Description: "d"}},
				callResult: []byte(`{"content":[{"type":"text","text":"{}"}]}`),
			}
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: m, credentials: staticCreds(),
				lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
				executable: func() (string, error) { return path, nil },
			}
			a.run(args)
			if m.githubRequests != 0 {
				t.Fatalf("%v made %d GitHub requests; tool calls must never check for updates", args, m.githubRequests)
			}
		})
	}

	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("no tool call may replace the binary, got %q", got)
	}
}

func TestFirstRunSetupDoesNotTriggerAnUpdate(t *testing.T) {
	// requireConfig calls cmdInit when config is missing and the session is
	// interactive, so a first-run `bmcp list` reaches the init code path. The
	// hook hangs off dispatch precisely so that this does not count as an
	// explicit init.
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	m := &fakeMCP{tools: []tool{{Name: "search_aws_memory", Description: "d"}}}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:       strings.NewReader("http://localhost:8787/mcp\n\n"),
		stdout:      &stdout,
		stderr:      &stderr,
		now:         time.Now,
		httpClient:  m,
		credentials: staticCreds(),
		lookPath:    func(string) (string, error) { return "", os.ErrNotExist },
		interactive: func() bool { return true },
		executable:  func() (string, error) { return path, nil },
	}
	a.run([]string{"list"})
	if m.githubRequests != 0 {
		t.Fatalf("first-run setup made %d GitHub requests, want 0", m.githubRequests)
	}
}

func TestExplicitInitChecksForUpdatesExactlyOnce(t *testing.T) {
	// cmdInit calls cmdSyncWithRefresh one line away from cmdSync's own call, so
	// hooking the shared function would check twice for every init.
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BMCP_AUTO_UPDATE", "0")
	path := stagedBinary(t, "old binary")

	gh := &fakeGitHub{latestTag: "v0.5.0"}
	m := &fakeMCP{github: gh}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
		executable: func() (string, error) { return path, nil },
	}
	if code := a.run([]string{"init", "--url", "http://localhost:8787/mcp"}); code != 0 {
		t.Fatalf("init exit %d: %s", code, stderr.String())
	}
	if gh.headCalls != 1 {
		t.Fatalf("expected exactly one update check, got %d", gh.headCalls)
	}
}

func TestAutoUpdateDisabledNudgesInsteadOfSwapping(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BMCP_AUTO_UPDATE", "false")
	path := stagedBinary(t, "old binary")

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("new binary"))}
	assets["checksums.txt"] = checksumsFor(assets)
	m := syncableMCP(&fakeGitHub{latestTag: "v0.6.0", assets: assets})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:        func(string) (string, error) { return "", os.ErrNotExist },
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return nil },
	}
	a.run([]string{"sync"})

	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("auto_update=false must not swap the binary, got %q", got)
	}
	if !strings.Contains(stderr.String(), "bmcp update") {
		t.Fatalf("expected a nudge naming the command, got: %s", stderr.String())
	}
}

func TestAutoUpdateAppliesOnSyncWhenEnabled(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("new binary"))}
	assets["checksums.txt"] = checksumsFor(assets)
	m := syncableMCP(&fakeGitHub{latestTag: "v0.6.0", assets: assets})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:        func(string) (string, error) { return "", os.ErrNotExist },
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return nil },
	}
	if code := a.run([]string{"sync"}); code != 0 {
		t.Fatalf("sync exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "new binary" {
		t.Fatalf("expected the binary to be replaced, got %q", got)
	}
	// No re-exec, so the run must say which version actually served it.
	if !strings.Contains(stderr.String(), "still uses 0.5.0") {
		t.Fatalf("expected the no-re-exec notice, got: %s", stderr.String())
	}
}

func TestDoctorReportsAFailedUpdateCheckWithoutFailing(t *testing.T) {
	// BORIS.md tells agents to read a failing doctor as "BORIS is broken", so a
	// GitHub outage must never reach the exit code.
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	m := &fakeMCP{
		tools:  []tool{{Name: "search_aws_memory", Description: "d"}},
		github: &fakeGitHub{redirectFails: true},
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
		executable: func() (string, error) { return path, nil },
	}
	if code := a.run([]string{"doctor"}); code != 0 {
		t.Fatalf("a failed update check must not fail doctor, got exit %d\n%s", code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "update check failed") {
		t.Fatalf("expected the failure to be reported, got: %s", stdout.String())
	}
}

func TestDoctorJSONCarriesTheUpdateObject(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BMCP_AUTO_UPDATE", "0")
	path := stagedBinary(t, "old binary")

	m := &fakeMCP{
		tools:  []tool{{Name: "search_aws_memory", Description: "d"}},
		github: &fakeGitHub{latestTag: "v0.6.0"},
	}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
		executable: func() (string, error) { return path, nil },
	}
	a.run([]string{"doctor", "--json"})

	var payload struct {
		Update map[string]any `json:"update"`
	}
	if err := json.Unmarshal(jsonTail(t, stderr.String()), &payload); err != nil {
		t.Fatalf("doctor --json is not valid JSON: %v\n%s", err, stderr.String())
	}
	if payload.Update == nil {
		t.Fatalf("expected an update object, got: %s", stderr.String())
	}
	for _, key := range []string{"current", "latest", "target", "available", "checked", "error", "applied", "action"} {
		if _, ok := payload.Update[key]; !ok {
			t.Fatalf("update object is missing %q: %v", key, payload.Update)
		}
	}
	if payload.Update["current"] != "0.5.0" || payload.Update["target"] != "0.6.0" {
		t.Fatalf("unexpected version fields: %v", payload.Update)
	}
	if payload.Update["available"] != true || payload.Update["checked"] != true {
		t.Fatalf("expected available and checked to be true: %v", payload.Update)
	}
	if payload.Update["error"] != nil || payload.Update["applied"] != false {
		t.Fatalf("expected no error and applied=false: %v", payload.Update)
	}
	// Under --json there must be no free-text prose on the machine channel.
	if strings.Contains(stdout.String(), "available") {
		t.Fatalf("--json must not emit the human version row: %s", stdout.String())
	}
}

func TestBrewInstallsRefuseToSelfUpdate(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())

	dir := filepath.Join(t.TempDir(), "Cellar", "bmcp", "0.5.0", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "bmcp")
	if err := os.WriteFile(path, []byte("brew binary"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	m := &fakeMCP{github: &fakeGitHub{latestTag: "v0.6.0"}}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
		executable: func() (string, error) { return path, nil },
	}
	if code := a.cmdUpdate(globalFlags{}, nil); code == 0 {
		t.Fatal("a Homebrew install must refuse to replace itself")
	}
	if !strings.Contains(stderr.String(), brewUpgradeCmd) {
		t.Fatalf("expected the brew upgrade command, got: %s", stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "brew binary" {
		t.Fatalf("the Cellar binary must be untouched, got %q", got)
	}
}

func TestAutoUpdateStandsDownWhenAVersionIsPinned(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BMCP_VERSION", "v0.3.0")
	path := stagedBinary(t, "old binary")

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("downgraded"))}
	assets["checksums.txt"] = checksumsFor(assets)
	m := syncableMCP(&fakeGitHub{latestTag: "v0.6.0", assets: assets})
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:        func(string) (string, error) { return "", os.ErrNotExist },
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return nil },
	}
	a.run([]string{"sync"})
	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("auto-update must never downgrade to a pin unattended, got %q", got)
	}
}

func TestResolveAutoUpdatePrecedence(t *testing.T) {
	cases := []struct {
		name  string
		file  string
		env   string
		flag  bool
		want  bool
		warns bool
	}{
		{name: "default on", want: true},
		{name: "file off", file: "false", want: false},
		{name: "env overrides file", file: "false", env: "true", want: true},
		{name: "flag overrides env", file: "true", env: "true", flag: true, want: false},
		{name: "env off", env: "off", want: false},
		{name: "garbage in file is ignored", file: "bogus", want: true, warns: true},
		{name: "garbage in env is ignored", env: "bogus", want: true, warns: true},
		{name: "garbage does not mask a valid file value", file: "false", env: "bogus", want: false, warns: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BMCP_AUTO_UPDATE", tc.env)
			var stderr bytes.Buffer
			a := &app{stderr: &stderr}
			got := a.resolveAutoUpdate(globalFlags{noAutoUpdate: tc.flag}, tc.file)
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
			if warned := strings.Contains(stderr.String(), "is not a boolean"); warned != tc.warns {
				t.Fatalf("expected warning=%v, got %q", tc.warns, stderr.String())
			}
		})
	}
}

func TestWriteConfigLeavesAnUnsetAutoUpdateUnset(t *testing.T) {
	// Stamping the current default into every rewritten config would silently
	// pin users to whatever the default was on the day they ran init.
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := configFile{URL: "https://example.agentcore.aws/mcp"}
	applyDefaults(&cfg)
	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(b), "auto_update") {
		t.Fatalf("an unset auto_update must not be written:\n%s", b)
	}
}

func TestConfigRoundTripPreservesAnExplicitAutoUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := configFile{URL: "https://example.agentcore.aws/mcp", AutoUpdate: "false"}
	applyDefaults(&cfg)
	if err := writeConfig(path, cfg); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	got, err := readConfig(path)
	if err != nil {
		t.Fatalf("readConfig: %v", err)
	}
	if got != cfg {
		t.Fatalf("config mismatch:\n got: %#v\nwant: %#v", got, cfg)
	}
}

func TestUpdateFlagsAreRejectedOutsideTheUpdateCommand(t *testing.T) {
	// The flags live in the switch every non-rawArgs command shares. Unscoped,
	// `bmcp call <tool> --to x` stopped being a flag error that did nothing and
	// became a real call against the live server, with --to eating the next
	// argument.
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	cases := [][]string{
		{"call", "search_aws_memory", "--to", "x"},
		{"call", "search_aws_memory", "--check"},
		{"call", "search_aws_memory", "--rollback"},
		{"list", "--to", "x"},
		{"list", "--check"},
		{"describe", "--to", "search_aws_memory"},
		{"doctor", "--check"},
		{"--to", "x", "sync"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			m := &fakeMCP{
				tools:      []tool{{Name: "search_aws_memory", Description: "d"}},
				callResult: []byte(`{"content":[{"type":"text","text":"{}"}]}`),
			}
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: m, credentials: staticCreds(),
				lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
				executable: func() (string, error) { return path, nil },
			}
			if code := a.run(args); code == 0 {
				t.Fatalf("%v should be rejected as an unknown flag, got exit 0\nstderr: %s", args, stderr.String())
			}
			if strings.Contains(stderr.String(), "Calling ") {
				t.Fatalf("%v must not reach the server: %s", args, stderr.String())
			}
		})
	}
}

func TestUpdateCommandAcceptsItsOwnFlagsThroughArgv(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	m := &fakeMCP{github: &fakeGitHub{latestTag: "v0.6.0"}}
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: m, credentials: staticCreds(),
		lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
		executable: func() (string, error) { return path, nil },
	}
	if code := a.run([]string{"update", "--check"}); code != 0 {
		t.Fatalf("update --check exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "0.6.0") {
		t.Fatalf("expected the available version, got: %s", stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("--check must change nothing, got %q", got)
	}
}

func TestUpdateRejectsCheckCombinedWithRollback(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "current")
	if err := os.WriteFile(priorBinaryPath(path), []byte("previous"), 0o755); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, httpClient: &fakeMCP{}, credentials: staticCreds(),
		lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
		executable: func() (string, error) { return path, nil },
	}
	if code := a.run([]string{"update", "--check", "--rollback"}); code != exitValidation {
		t.Fatalf("expected exitValidation, got %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "current" {
		t.Fatalf("--check must never mutate the binary, got %q", got)
	}
}

func TestUpdateRejectsMalformedVersions(t *testing.T) {
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	for _, bad := range []string{
		"../../../../golang/go/archive/refs/tags",
		"v1.2.3/../evil",
		// Normalizes to v0.3.0, downloads the real v0.3.0, then never matches
		// the installed 0.3.0 — an update that is "available" forever.
		"vv0.3.0",
		"latest",
		" ",
	} {
		t.Run(bad, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			a := &app{
				stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
				now: time.Now, httpClient: &fakeMCP{}, credentials: staticCreds(),
				lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
				executable: func() (string, error) { return path, nil },
			}
			if code := a.run([]string{"update", "--to", bad}); code != exitValidation {
				t.Fatalf("expected %q to be rejected, got exit %d: %s", bad, code, stderr.String())
			}
		})
	}

	for _, good := range []string{"v1.2.3", "1.2.3", "v0.4.0-rc.1"} {
		if err := validateVersionRef(good); err != nil {
			t.Fatalf("%q should be accepted: %v", good, err)
		}
	}
}

func TestRollbackStopsAutoUpdateReinstallingTheRejectedRelease(t *testing.T) {
	// Without this, rollback is undone by the very next doctor/sync/init, which
	// makes the only single-machine remedy the feature ships useless.
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "old binary")

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("bad new binary"))}
	assets["checksums.txt"] = checksumsFor(assets)
	gh := &fakeGitHub{latestTag: "v0.6.0", assets: assets}
	newApp := func() (*app, *bytes.Buffer) {
		stderr := &bytes.Buffer{}
		return &app{
			stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: stderr,
			now: time.Now, httpClient: syncableMCP(gh), credentials: staticCreds(),
			lookPath:        func(string) (string, error) { return "", os.ErrNotExist },
			executable:      func() (string, error) { return path, nil },
			verifySignature: func(string) error { return nil },
		}, stderr
	}

	a, stderr := newApp()
	if code := a.run([]string{"sync"}); code != 0 {
		t.Fatalf("sync exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "bad new binary" {
		t.Fatalf("setup: expected the auto-update to apply, got %q", got)
	}

	// The rolled-back binary is 0.5.0 again; simulate running it.
	asReleaseBuild(t, "0.6.0")
	a, stderr = newApp()
	if code := a.run([]string{"update", "--rollback"}); code != 0 {
		t.Fatalf("rollback exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("expected the previous binary back, got %q", got)
	}

	asReleaseBuild(t, "0.5.0")
	a, stderr = newApp()
	if code := a.run([]string{"sync"}); code != 0 {
		t.Fatalf("post-rollback sync exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "old binary" {
		t.Fatalf("auto-update reinstalled the rolled-back release, got %q", got)
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Fatalf("expected the hold to be explained, got: %s", stderr.String())
	}

	// An explicit request still wins, and clears the hold.
	a, stderr = newApp()
	if code := a.run([]string{"update", "--to", "v0.6.0"}); code != 0 {
		t.Fatalf("explicit update exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "bad new binary" {
		t.Fatalf("an explicit --to must override the hold, got %q", got)
	}
}

func TestAutoUpdateNeverMovesBackwards(t *testing.T) {
	// Available is string inequality, so a machine deliberately ahead of the
	// published release would otherwise be walked backwards.
	asReleaseBuild(t, "0.9.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "newer binary")

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("older binary"))}
	assets["checksums.txt"] = checksumsFor(assets)
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, credentials: staticCreds(),
		httpClient:      &fakeMCP{github: &fakeGitHub{latestTag: "v0.6.0", assets: assets}},
		lookPath:        func(string) (string, error) { return "", os.ErrNotExist },
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return nil },
	}
	a.run([]string{"sync"})
	if got, _ := os.ReadFile(path); string(got) != "newer binary" {
		t.Fatalf("auto-update must not downgrade, got %q", got)
	}
}

func TestBareUpdateDoesNotDowngradeAMachineAheadOfTheRelease(t *testing.T) {
	asReleaseBuild(t, "0.9.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())
	path := stagedBinary(t, "newer binary")

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("older binary"))}
	assets["checksums.txt"] = checksumsFor(assets)
	newApp := func() (*app, *bytes.Buffer) {
		stderr := &bytes.Buffer{}
		return &app{
			stdin: strings.NewReader(""), stdout: &bytes.Buffer{}, stderr: stderr,
			now: time.Now, credentials: staticCreds(),
			httpClient:      &fakeMCP{github: &fakeGitHub{latestTag: "v0.6.0", assets: assets}},
			lookPath:        func(string) (string, error) { return "", os.ErrNotExist },
			executable:      func() (string, error) { return path, nil },
			verifySignature: func(string) error { return nil },
		}, stderr
	}

	a, stderr := newApp()
	if code := a.run([]string{"update"}); code != 0 {
		t.Fatalf("update exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "newer binary" {
		t.Fatalf("a bare update must not downgrade, got %q", got)
	}
	if !strings.Contains(stderr.String(), "newer than the latest release") {
		t.Fatalf("expected an explanation, got: %s", stderr.String())
	}

	// Naming the version is an explicit downgrade request and must be honoured.
	a, stderr = newApp()
	if code := a.run([]string{"update", "--to", "v0.6.0"}); code != 0 {
		t.Fatalf("explicit downgrade exit %d: %s", code, stderr.String())
	}
	if got, _ := os.ReadFile(path); string(got) != "older binary" {
		t.Fatalf("an explicit --to downgrade must apply, got %q", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.6.0", "0.5.0", 1},
		{"0.5.0", "0.6.0", -1},
		{"0.5.0", "0.5.0", 0},
		{"v0.6.0", "0.5.0", 1},
		{"0.10.0", "0.9.0", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.5", "0.5.0", 0},
		// Unknown rather than equal: callers must treat 0 as "not provably newer".
		{"0.5.0-rc.1", "0.5.0", 0},
		{"garbage", "0.5.0", 0},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestApplyUpdateClearsAPrePlantedStagingFile(t *testing.T) {
	// The library opens the staged path without O_EXCL or O_NOFOLLOW, so a
	// planted symlink is written through and a planted regular file keeps its
	// own mode and owner while TargetMode is ignored.
	asReleaseBuild(t, "0.5.0")
	path := stagedBinary(t, "old binary")
	victim := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.Symlink(victim, stagedPath(path)); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}

	assets := map[string][]byte{"bmcp-" + hostAsset(): releaseArchive(t, []byte("new binary"))}
	assets["checksums.txt"] = checksumsFor(assets)
	a := &app{
		stderr:          &bytes.Buffer{},
		httpClient:      &fakeGitHub{latestTag: "v0.6.0", assets: assets},
		now:             time.Now,
		executable:      func() (string, error) { return path, nil },
		verifySignature: func(string) error { return nil },
	}
	st := a.inspectUpdate(context.Background(), effectiveConfig{}, "")
	if err := a.applyUpdate(context.Background(), globalFlags{}, st, st.Target); err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "untouched" {
		t.Fatalf("the planted symlink was followed, victim now: %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("expected mode 0755, got %v", info.Mode().Perm())
	}
}

func TestVerifyStagedBinaryRejectsATruncatedWrite(t *testing.T) {
	staged := filepath.Join(t.TempDir(), ".bmcp.new")
	if err := os.WriteFile(staged, []byte("trunc"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := verifyStagedBinary(staged, []byte("the full binary")); err == nil {
		t.Fatal("expected a truncated staged binary to be rejected")
	}
	if err := verifyStagedBinary(staged, []byte("trunc")); err != nil {
		t.Fatalf("a matching staged binary should verify: %v", err)
	}
}

func TestExtractBinaryToleratesDirectoryMembers(t *testing.T) {
	// Rejecting every non-regular member would mean a future archive that adds
	// a directory entry bricks updating for every binary already in the field.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "completions/", Typeflag: tar.TypeDir, Mode: 0o755})
	content := []byte("the binary")
	tw.WriteHeader(&tar.Header{Name: "bmcp", Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
	tw.Write(content)
	tw.Close()
	gz.Close()

	got, err := extractBinary(buf.Bytes())
	if err != nil {
		t.Fatalf("a directory member should not fail extraction: %v", err)
	}
	if string(got) != "the binary" {
		t.Fatalf("got %q", got)
	}
}

func TestDoctorFailsWhenTheSwapLeftTheInstallBroken(t *testing.T) {
	// A GitHub outage must not fail doctor, but "there may be no binary at this
	// path" must — otherwise doctor exits 0 while bmcp is gone.
	asReleaseBuild(t, "0.5.0")
	t.Setenv("BMCP_HOME", configuredHome(t))
	t.Setenv("HOME", t.TempDir())

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr,
		now: time.Now, credentials: staticCreds(),
		httpClient: &fakeMCP{tools: []tool{{Name: "search_aws_memory"}}},
		lookPath:   func(string) (string, error) { return "", os.ErrNotExist },
	}
	a.update = &updateState{
		Current: "0.5.0", Checked: true, Stage: updateStageApply,
		Err: fmt.Errorf("%w: bmcp may be missing", errUpdateCorrupted),
	}
	if code := a.cmdDoctor(globalFlags{}, nil); code == 0 {
		t.Fatalf("doctor must fail when the install is broken\n%s", stdout.String())
	}
}

func TestParseStrictBoolDistinguishesFalseFromGarbage(t *testing.T) {
	if v, ok := parseStrictBool("false"); !ok || v {
		t.Fatal("false should parse as an explicit false")
	}
	if _, ok := parseStrictBool("bogus"); ok {
		t.Fatal("garbage must not parse, or a typo silently disables updates")
	}
	if _, ok := parseStrictBool(""); ok {
		t.Fatal("an empty value must not parse")
	}
	// truthy is built on it and must keep its old behaviour.
	if truthy("bogus") || !truthy("1") || truthy("0") {
		t.Fatal("truthy changed behaviour")
	}
}
