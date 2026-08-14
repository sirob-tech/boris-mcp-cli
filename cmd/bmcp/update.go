package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/minio/selfupdate"
)

const (
	updateRepo     = "sirob-tech/boris-mcp-cli"
	brewUpgradeCmd = "brew upgrade sirob-tech/tap/bmcp"

	updateCheckTimeout = 15 * time.Second
	updateApplyTimeout = 5 * time.Minute

	// The release archive is ~12 MB. The caps exist so a redirect to something
	// unexpected cannot stream indefinitely into memory.
	maxArchiveBytes   = 128 << 20
	maxBinaryBytes    = 256 << 20
	maxChecksumsBytes = 1 << 20

	// codesignRequirement pins the signing identity. The leading `=` is
	// mandatory: without it codesign reads the argument as a *filename* and
	// fails with "invalid requirement specification", which would refuse every
	// darwin update on every machine.
	codesignRequirement = `=anchor apple generic and certificate leaf[subject.OU] = T962D4K3Y7`

	// codesignFailClosed stays false until a release has shipped under the
	// fail-closed signing in .goreleaser.yaml. A fleet that refuses every
	// update cannot receive the fix for whatever made it refuse, so the first
	// release verifies and warns only. Flip once a signed release exists and
	// the macOS CI job has exercised a real N-1 -> N swap.
	codesignFailClosed = false

	staleLockAge = 10 * time.Minute
)

type installKind int

const (
	// installManaged is a binary bmcp may replace in place.
	installManaged installKind = iota
	// installSource is a `go build` binary. Never touched: there is no release
	// that corresponds to it and no version to compare against.
	installSource
	// installBrew is a Homebrew install. Replacing it works mechanically but
	// leaves brew's metadata permanently lying about what is installed.
	installBrew
	// installVersioned is any other layout that stores the binary under a
	// directory named after its version — mise, asdf, Nix, MacPorts. Replacing
	// it writes the new binary into a directory named after the old version,
	// so the managing tool's metadata and shims disagree with reality forever.
	installVersioned
)

const (
	updateStageCheck = "check"
	updateStageApply = "apply"
)

type updateState struct {
	Current   string
	Latest    string
	Target    string
	Path      string
	Kind      installKind
	Available bool
	Checked   bool
	Applied   bool
	Action    string
	// Stage says which half of the work Err came from, so a lock collision is
	// not reported to the user as "could not reach GitHub".
	Stage string
	Err   error
}

func (k installKind) String() string {
	switch k {
	case installSource:
		return "source"
	case installBrew:
		return "homebrew"
	case installVersioned:
		return "version-managed"
	default:
		return "managed"
	}
}

// updateJSON renders the doctor --json `update` object. checked and error are
// separate fields on purpose: a rate-limited check, a 404, a DNS failure and
// "already current" must not all collapse into available:false.
func (s *updateState) updateJSON() map[string]any {
	out := map[string]any{
		"current":   s.Current,
		"latest":    emptyToNil(s.Latest),
		"target":    emptyToNil(s.Target),
		"available": s.Available,
		"checked":   s.Checked,
		"error":     nil,
		"applied":   s.Applied,
		"action":    emptyToNil(s.Action),
		// Without kind, a source build is indistinguishable from a failed
		// check: both report checked:false with no error.
		"kind": s.Kind.String(),
	}
	if s.Err != nil {
		out["error"] = s.Err.Error()
	}
	return out
}

func emptyToNil(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// normalizeVersion strips the `v` prefix. GoReleaser injects the version
// unprefixed while tags and the release redirect carry the prefix; comparing
// them raw makes every invocation believe an update is available, forever.
func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

func taggedVersion(v string) string {
	if v == "" {
		return ""
	}
	return "v" + normalizeVersion(v)
}

// versionRefPattern is deliberately strict. The value reaches a download URL,
// and it also has to round-trip through normalizeVersion without changing
// meaning: `vv0.3.0` would otherwise normalize to `v0.3.0`, download the real
// v0.3.0, and then never match the installed `0.3.0` — reporting the same
// update as available forever.
var versionRefPattern = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$`)

func validateVersionRef(v string) error {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return errors.New("version must not be empty")
	}
	if !versionRefPattern.MatchString(trimmed) {
		return fmt.Errorf("invalid version %q: expected a release tag such as v1.2.3", v)
	}
	return nil
}

// compareVersions orders two dotted numeric versions, returning 0 when it
// cannot tell. "Cannot tell" includes any non-numeric or prerelease component,
// so callers must treat 0 as "not provably newer" rather than "equal".
func compareVersions(a, b string) int {
	parse := func(v string) ([]int, bool) {
		core, _, _ := strings.Cut(normalizeVersion(v), "-")
		core, _, _ = strings.Cut(core, "+")
		if core == "" {
			return nil, false
		}
		var parts []int
		for _, field := range strings.Split(core, ".") {
			n, err := strconv.Atoi(field)
			if err != nil {
				return nil, false
			}
			parts = append(parts, n)
		}
		return parts, true
	}
	left, okLeft := parse(a)
	right, okRight := parse(b)
	if !okLeft || !okRight {
		return 0
	}
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r int
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if l != r {
			if l > r {
				return 1
			}
			return -1
		}
	}
	return 0
}

// resolveExecutable returns the path bmcp should replace, with symlinks
// resolved. Resolution is load-bearing rather than cosmetic: os.Executable is
// already symlink-resolved on Linux but not on darwin, so an unresolved path
// both misclassifies Homebrew installs as managed and makes selfupdate replace
// the symlink with a regular file.
func (a *app) resolveExecutable() (string, error) {
	fn := a.executable
	if fn == nil {
		fn = os.Executable
	}
	path, err := fn()
	if err != nil {
		return "", fmt.Errorf("could not locate the running bmcp binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("could not resolve %s: %w", path, err)
	}
	return resolved, nil
}

// classifyInstall decides whether bmcp may replace this binary. It must be
// handed the *resolved* path: ~/.local/bin/bmcp is routinely a symlink into
// /opt/homebrew/Cellar, and classifying before resolution writes the new binary
// into a directory named after the old version.
//
// The receipt is the sound test and the Cellar check is only a fallback
// heuristic — "not brew" is not the same as "safe to self-replace", since Nix,
// asdf, mise, MacPorts and versioned-symlink layouts all land here too.
func classifyInstall(resolved string) installKind {
	if buildCommit == "unknown" {
		return installSource
	}
	if receipt, err := readInstallReceipt(resolved); err == nil && receipt.Method == "install.sh" {
		return installManaged
	}
	if strings.Contains(filepath.ToSlash(resolved), "/Cellar/") {
		return installBrew
	}
	if hasVersionedParent(resolved) {
		return installVersioned
	}
	return installManaged
}

// versionedDirPattern requires at least one dot. A bare integer is far too
// common a directory name — `001`, `2` — to treat as evidence that something
// else manages this path.
var versionedDirPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.]+)?$`)

// hasVersionedParent reports whether any directory above the binary is named
// like a version. That is what mise, asdf, Nix and MacPorts layouts have in
// common, and it is the signal that something else owns this path.
func hasVersionedParent(resolved string) bool {
	dir := filepath.Dir(resolved)
	for {
		if versionedDirPattern.MatchString(filepath.Base(dir)) {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

type installReceipt struct {
	Method      string `json:"method"`
	Repo        string `json:"repo,omitempty"`
	Version     string `json:"version,omitempty"`
	Asset       string `json:"asset,omitempty"`
	InstalledAt string `json:"installed_at,omitempty"`
	// Blocked names a version auto-update must not install on its own. Set by
	// --rollback, because without it the next doctor/sync/init would reinstall
	// exactly the release the operator just rejected, and keep doing so — which
	// makes rollback, the only single-machine remedy this feature ships,
	// useless. An explicit `bmcp update` still overrides it and clears it.
	Blocked string         `json:"blocked,omitempty"`
	Updates []updateRecord `json:"updates,omitempty"`
}

// updateRecord is the trail behind "bmcp broke after it updated itself". Without
// it such a report arrives with no way to tell which version replaced which, or
// when.
type updateRecord struct {
	From string `json:"from"`
	To   string `json:"to"`
	At   string `json:"at"`
}

func receiptPath(binary string) string {
	return filepath.Join(filepath.Dir(binary), ".bmcp.install.json")
}

func readInstallReceipt(binary string) (installReceipt, error) {
	var receipt installReceipt
	b, err := os.ReadFile(receiptPath(binary))
	if err != nil {
		return receipt, err
	}
	if err := json.Unmarshal(b, &receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func recordUpdate(binary, from, to string, at time.Time) error {
	return amendReceipt(binary, func(receipt *installReceipt) {
		receipt.Version = taggedVersion(to)
		// A successful install supersedes any hold: reaching here means either
		// a different version, or an explicit request for this one.
		receipt.Blocked = ""
		receipt.Updates = append(receipt.Updates, updateRecord{
			From: normalizeVersion(from), To: normalizeVersion(to), At: at.UTC().Format(time.RFC3339),
		})
	})
}

func recordRollback(binary, from, to string, at time.Time) error {
	return amendReceipt(binary, func(receipt *installReceipt) {
		receipt.Version = taggedVersion(to)
		receipt.Blocked = normalizeVersion(from)
		receipt.Updates = append(receipt.Updates, updateRecord{
			From: normalizeVersion(from), To: normalizeVersion(to), At: at.UTC().Format(time.RFC3339),
		})
	})
}

func amendReceipt(binary string, mutate func(*installReceipt)) error {
	receipt, err := readInstallReceipt(binary)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if receipt.Method == "" {
		receipt.Method = "unknown"
	}
	mutate(&receipt)
	if len(receipt.Updates) > 10 {
		receipt.Updates = receipt.Updates[len(receipt.Updates)-10:]
	}
	b, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(receiptPath(binary), append(b, '\n'), 0o644)
}

func (a *app) updateHTTPClient() httpDoer {
	// Falls back to a.httpClient so tests can intercept. A private client here
	// would bypass the injection point and make every doctor test reach the
	// real github.com.
	if a.httpClient != nil {
		return a.httpClient
	}
	return &http.Client{
		Timeout:   updateApplyTimeout,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
	}
}

// latestReleaseTag mirrors install.sh: follow the /releases/latest redirect,
// then fall back to the API. The redirect is cheaper and is not rate-limited.
func (a *app) latestReleaseTag(ctx context.Context) (string, error) {
	tag, redirectErr := a.latestTagFromRedirect(ctx)
	if redirectErr == nil && tag != "" {
		return tag, nil
	}
	tag, apiErr := a.latestTagFromAPI(ctx)
	if apiErr == nil && tag != "" {
		return tag, nil
	}
	if redirectErr == nil {
		redirectErr = errors.New("release redirect returned no tag")
	}
	if apiErr == nil {
		apiErr = errors.New("release API returned no tag")
	}
	return "", fmt.Errorf("could not determine the latest release: %v; %v", redirectErr, apiErr)
}

func (a *app) latestTagFromRedirect(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead,
		fmt.Sprintf("https://github.com/%s/releases/latest", updateRepo), nil)
	if err != nil {
		return "", err
	}
	resp, err := a.updateHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxChecksumsBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("release redirect returned HTTP %d", resp.StatusCode)
	}
	// The client follows redirects, so Location is already consumed and the
	// landing URL is the only place the tag survives.
	if resp.Request == nil || resp.Request.URL == nil {
		return "", errors.New("release redirect returned no URL")
	}
	path := resp.Request.URL.Path
	idx := strings.LastIndex(path, "/tag/")
	if idx < 0 {
		return "", fmt.Errorf("release redirect did not land on a tag: %s", path)
	}
	return strings.Trim(path[idx+len("/tag/"):], "/"), nil
}

func (a *app) latestTagFromAPI(ctx context.Context) (string, error) {
	body, err := a.fetch(ctx, fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", updateRepo), maxChecksumsBytes)
	if err != nil {
		return "", err
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", fmt.Errorf("invalid release API response: %w", err)
	}
	return release.TagName, nil
}

// fetch checks the status before reading the body, so a 404 page is never
// mistaken for content and hashed as if it were an artifact.
func (a *app) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.updateHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("GET %s exceeded the %d byte limit", url, limit)
	}
	return body, nil
}

func assetName() string {
	return fmt.Sprintf("bmcp-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

// verifyArchiveChecksum fails closed. A missing checksums.txt, or a
// checksums.txt with no line for our asset, is a hard failure and never a skip.
func verifyArchiveChecksum(archive, checksums []byte, asset string) error {
	if len(checksums) == 0 {
		return errors.New("checksums.txt is empty")
	}
	sum := sha256.Sum256(archive)
	actual := hex.EncodeToString(sum[:])
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != asset {
			continue
		}
		if !strings.EqualFold(fields[0], actual) {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", asset, fields[0], actual)
		}
		return nil
	}
	return fmt.Errorf("checksums.txt has no entry for %s", asset)
}

// extractBinary pulls exactly the `bmcp` member out of the release archive.
// The archive also carries LICENSE and README.md, which are skipped; anything
// that is not a regular file is rejected outright rather than skipped, so a
// symlink or hardlink named bmcp cannot be mistaken for the payload. Archive
// mode bits are ignored — the caller sets the mode.
func extractBinary(archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("release archive is not valid gzip: %w", err)
	}
	defer gz.Close()

	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("release archive is not a valid tar: %w", err)
		}
		if filepath.Base(filepath.Clean(header.Name)) != "bmcp" || strings.Contains(header.Name, "/") {
			continue
		}
		// Checked only for the member actually being installed. Rejecting every
		// non-regular member outright would mean a future archive that merely
		// adds a directory entry, shell completions, or a pax global header
		// bricks updating for every binary already in the field — and those
		// binaries could never receive the fix.
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("release archive contains a non-regular bmcp member (type %q) — refusing to extract", header.Typeflag)
		}
		binary, err := io.ReadAll(io.LimitReader(reader, maxBinaryBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(binary)) > maxBinaryBytes {
			return nil, fmt.Errorf("bmcp member exceeded the %d byte limit", maxBinaryBytes)
		}
		if len(binary) == 0 {
			return nil, errors.New("release archive contains an empty bmcp binary")
		}
		return binary, nil
	}
	return nil, errors.New("release archive does not contain a bmcp binary")
}

// checkSignature verifies the staged binary carries our Developer ID.
//
// It authenticates the signer, not the payload: a correctly signed but
// mislabelled artifact still passes. It is also not a GitHub-independent trust
// root, since the signing certificate is itself a repository secret. What it
// does defend against is a tampered or swapped release asset, and a token with
// contents:write but no access to the signing secrets.
func (a *app) checkSignature(ctx context.Context, path string) error {
	if a.verifySignature != nil {
		return a.verifySignature(path)
	}
	if runtime.GOOS != "darwin" {
		return nil
	}
	// Absolute path: a PATH-resolved codesign can be shadowed.
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R", codesignRequirement, path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Exit 3 is "signature is bad"; anything else is codesign being
			// unable to evaluate it. Collapsing the two hides our own bugs as
			// if they were attacks.
			if exitErr.ExitCode() == 3 {
				return fmt.Errorf("signature does not match the expected Developer ID: %s", detail)
			}
			return fmt.Errorf("codesign could not evaluate the signature (exit %d): %s", exitErr.ExitCode(), detail)
		}
		return fmt.Errorf("could not run codesign: %w", err)
	}
	return nil
}

// acquireUpdateLock serialises swaps. selfupdate stages through fixed,
// unlocked paths (.bmcp.new and .bmcp.old), so two agents updating at once
// would otherwise corrupt each other's staging and recovery files.
func acquireUpdateLock(dir string, now time.Time) (func(), error) {
	path := filepath.Join(dir, ".bmcp.update.lock")
	owner := fmt.Sprintf("bmcp %d\n", os.Getpid())
	inProgress := errors.New("another bmcp update is already in progress")

	create := func() (bool, error) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Ownership is recorded so release only ever removes our own lock.
		_, writeErr := f.WriteString(owner)
		closeErr := f.Close()
		if writeErr != nil {
			return false, writeErr
		}
		return true, closeErr
	}

	release := func() {
		if b, err := os.ReadFile(path); err == nil && string(b) == owner {
			_ = os.Remove(path)
		}
	}

	ok, err := create()
	if err != nil {
		return nil, err
	}
	if ok {
		return release, nil
	}

	info, statErr := os.Stat(path)
	if statErr != nil || now.Sub(info.ModTime()) < staleLockAge {
		return nil, inProgress
	}

	// Steal atomically. Removing the stale lock directly is a race: two
	// processes can both judge it stale, and the second's Remove deletes the
	// first's *fresh* lock, leaving both believing they hold it. Renaming means
	// only the process that moves the stale file aside may recreate it —
	// everyone else loses the rename with ENOENT.
	stolen := fmt.Sprintf("%s.stale-%d", path, os.Getpid())
	if err := os.Rename(path, stolen); err != nil {
		// Lost the steal, or the owner cleaned up first. Either way somebody
		// else is now ahead of us.
		return nil, inProgress
	}
	_ = os.Remove(stolen)

	ok, err = create()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, inProgress
	}
	return release, nil
}

func stagedPath(target string) string {
	// Mirrors selfupdate's own construction in PrepareAndCheckBinary. Coupled
	// on purpose: it is the only way to inspect the staged binary between
	// staging and commit.
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".new")
}

func priorBinaryPath(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".old")
}

// applyUpdate downloads, verifies and swaps in the target version.
//
// The swap is temp-in-same-directory plus rename, never a write over the live
// file. Rename-over is safe while bmcp is running: the process keeps its
// original inode and its mapped pages still validate against the signature in
// that inode. Writing over the live inode instead invalidates those pages and
// gets the running process killed on the next page-in.
func (a *app) applyUpdate(ctx context.Context, flags globalFlags, st *updateState, target string) error {
	dir := filepath.Dir(st.Path)
	opts := selfupdate.Options{
		TargetPath: st.Path,
		TargetMode: 0o755,
		// Must live in the target's own directory or the rename hits EXDEV and
		// the update silently never works.
		OldSavePath: priorBinaryPath(st.Path),
	}
	if err := opts.CheckPermissions(); err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}

	release, err := acquireUpdateLock(dir, a.now())
	if err != nil {
		return err
	}
	defer release()

	tag := taggedVersion(target)
	asset := assetName()
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", updateRepo, tag)

	archive, err := a.fetch(ctx, base+"/"+asset, maxArchiveBytes)
	if err != nil {
		return err
	}
	checksums, err := a.fetch(ctx, base+"/checksums.txt", maxChecksumsBytes)
	if err != nil {
		return fmt.Errorf("could not fetch checksums.txt: %w", err)
	}
	if err := verifyArchiveChecksum(archive, checksums, asset); err != nil {
		return err
	}
	binary, err := extractBinary(archive)
	if err != nil {
		return err
	}

	staged := stagedPath(st.Path)
	// The library opens the staged path with O_CREATE|O_WRONLY|O_TRUNC and no
	// O_EXCL or O_NOFOLLOW, so a pre-planted symlink there would be written
	// through, and a pre-planted regular file would keep its own mode and owner
	// while TargetMode is silently ignored. Removing it first means the open
	// always creates.
	if err := os.Remove(staged); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not clear the staging path %s: %w", staged, err)
	}
	if err := selfupdate.PrepareAndCheckBinary(bytes.NewReader(binary), opts); err != nil {
		return fmt.Errorf("could not stage the new binary: %w", err)
	}
	// Read the staged bytes back rather than trusting the write. The library
	// hashes its in-memory copy and discards the error from its own Close, so a
	// short write that only surfaces at close — ENOSPC, a quota, NFS — would
	// otherwise be committed over a working binary. On Linux nothing else would
	// catch it, since checkSignature is a no-op there.
	if err := verifyStagedBinary(staged, binary); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if err := a.checkSignature(ctx, staged); err != nil {
		if codesignFailClosed {
			_ = os.Remove(staged)
			return fmt.Errorf("refusing to install an unverified binary: %w", err)
		}
		if !flags.jsonOut {
			fmt.Fprintf(a.stderr, "Warning: could not verify the signature of the new bmcp: %v\n", err)
		}
	}
	if err := selfupdate.CommitBinary(opts); err != nil {
		if rollbackErr := selfupdate.RollbackError(err); rollbackErr != nil {
			return fmt.Errorf("%w: update failed (%v) and restoring the previous binary also failed (%v); %s may be missing — reinstall with install.sh",
				errUpdateCorrupted, err, rollbackErr, st.Path)
		}
		return fmt.Errorf("could not install the new binary: %w", err)
	}
	if err := recordUpdate(st.Path, st.Current, target, a.now()); err != nil && !flags.jsonOut {
		fmt.Fprintf(a.stderr, "Warning: updated, but could not record the update: %v\n", err)
	}
	return nil
}

// errUpdateCorrupted marks the one update failure that is not safe to shrug
// off: the swap left the install in a bad state locally. A GitHub outage must
// never fail the host command, but "there may be no bmcp at this path" must.
var errUpdateCorrupted = errors.New("bmcp install may be broken")

func verifyStagedBinary(staged string, want []byte) error {
	f, err := os.Open(staged)
	if err != nil {
		return fmt.Errorf("could not re-open the staged binary: %w", err)
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return fmt.Errorf("could not read the staged binary back: %w", err)
	}
	expected := sha256.Sum256(want)
	if !bytes.Equal(hash.Sum(nil), expected[:]) {
		return errors.New("the staged binary does not match what was downloaded — refusing to install it")
	}
	return nil
}

// inspectUpdate resolves what version this binary should be on and whether it
// can get there itself. It never returns nil.
func (a *app) inspectUpdate(ctx context.Context, cfg effectiveConfig, explicit string) *updateState {
	st := &updateState{Current: normalizeVersion(version)}
	path, err := a.resolveExecutable()
	if err != nil {
		st.Err = err
		return st
	}
	st.Path = path
	st.Kind = classifyInstall(path)
	switch st.Kind {
	case installSource:
		// No release corresponds to a source build, so there is nothing to
		// check against and nothing to suggest.
		return st
	case installBrew:
		st.Action = brewUpgradeCmd
	case installVersioned:
		// Reported so doctor can still say a new version exists; the command is
		// whatever manages that directory, which we cannot name.
		st.Action = ""
	default:
		st.Action = "bmcp update"
	}

	if explicit != "" {
		// An explicit target needs no lookup, and skipping it removes a network
		// failure mode from the one path the user asked for by name.
		st.Target = normalizeVersion(explicit)
		st.Checked = true
		st.Available = st.Target != st.Current
		return st
	}

	tag, err := a.latestReleaseTag(ctx)
	st.Checked = true
	if err != nil {
		st.Err = err
		st.Stage = updateStageCheck
		return st
	}
	st.Latest = normalizeVersion(tag)
	st.Target = st.Latest
	if cfg.PinnedVersion != "" {
		st.Target = normalizeVersion(cfg.PinnedVersion)
	}
	// Computed against the resolved target, not latest. Against latest, a
	// pinned BMCP_VERSION would report an update forever: update, downgrade to
	// the pin, report again, every session.
	st.Available = st.Target != st.Current
	return st
}

// maybeAutoUpdate runs before doctor, sync and explicit init. Failures here
// never fail the host command: a GitHub outage must not read as "BORIS is
// broken".
func (a *app) maybeAutoUpdate(flags globalFlags) {
	cfg, _, err := a.loadEffective(flags, false)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
	defer cancel()

	st := a.inspectUpdate(ctx, cfg, "")
	a.update = st
	if st.Kind == installSource || !st.Checked || st.Err != nil || !st.Available {
		return
	}

	// Auto-update stands down whenever the operator has taken the wheel: a pin
	// names a version to converge to, which may be a downgrade, and downgrading
	// a binary nobody asked to downgrade is not something to do unattended.
	if !cfg.AutoUpdate || cfg.PinnedVersion != "" || st.Kind != installManaged {
		a.nudge(flags, st)
		return
	}

	// Only ever move forwards unattended. `Available` is string inequality, so
	// without this a machine deliberately running a newer or prerelease build
	// would be silently walked back to whatever GitHub currently calls latest.
	switch compareVersions(st.Target, st.Current) {
	case -1:
		// Ahead of the published release. Nudging here would read as an
		// invitation to downgrade.
		return
	case 0:
		// Cannot order them — a prerelease, most likely. Mention it, act on
		// nothing.
		a.nudge(flags, st)
		return
	}

	if receipt, err := readInstallReceipt(st.Path); err == nil && receipt.Blocked != "" &&
		normalizeVersion(receipt.Blocked) == st.Target {
		if !flags.jsonOut {
			fmt.Fprintf(a.stderr, "bmcp %s is available but was rolled back on this machine, so it will not be installed automatically.\nRun `bmcp update --to %s` to install it anyway.\n",
				st.Target, taggedVersion(st.Target))
		}
		return
	}

	applyCtx, applyCancel := context.WithTimeout(context.Background(), updateApplyTimeout)
	defer applyCancel()
	if err := a.applyUpdate(applyCtx, flags, st, st.Target); err != nil {
		st.Err = err
		st.Stage = updateStageApply
		if !flags.jsonOut {
			fmt.Fprintf(a.stderr, "Could not update bmcp automatically: %v\n", err)
		}
		return
	}
	st.Applied = true
	if !flags.jsonOut {
		// No re-exec: this process finishes on the code it already loaded, so
		// the new version takes effect on the next invocation.
		fmt.Fprintf(a.stderr, "Updated bmcp %s -> %s (this run still uses %s)\n", st.Current, st.Target, st.Current)
	}
}

func (a *app) nudge(flags globalFlags, st *updateState) {
	if flags.jsonOut || !st.Available || st.Action == "" {
		return
	}
	fmt.Fprintf(a.stderr, "bmcp %s is available (running %s). Run: %s\n", st.Target, st.Current, st.Action)
}

func (a *app) cmdUpdate(flags globalFlags, args []string) int {
	if len(args) != 0 {
		return a.fail(flags, exitValidation, "usage", "usage: bmcp update [--check] [--to <version>] [--rollback]")
	}
	if flags.updateRollback && flags.updateCheck {
		return a.fail(flags, exitValidation, "usage",
			"--check and --rollback cannot be combined: --check changes nothing, --rollback replaces the binary")
	}
	cfg, _, err := a.loadEffective(flags, false)
	if err != nil {
		return a.fail(flags, exitConfig, "config_invalid", err.Error())
	}

	// --to wins over BMCP_VERSION: one is this invocation, the other is ambient.
	// A pin is irrelevant to a rollback, which restores whatever was replaced.
	explicit := flags.updateTo
	if explicit == "" && !flags.updateRollback {
		explicit = cfg.PinnedVersion
	}
	if explicit != "" {
		if err := validateVersionRef(explicit); err != nil {
			return a.fail(flags, exitValidation, "invalid_version", err.Error())
		}
	}

	// Classified before anything writes, and before --rollback is honoured:
	// rolling a Cellar binary back would write into Homebrew's prefix, the same
	// thing the forward path refuses to do.
	path, err := a.resolveExecutable()
	if err != nil {
		return a.fail(flags, exitGeneric, "update_failed", err.Error())
	}
	switch classifyInstall(path) {
	case installSource:
		return a.fail(flags, exitValidation, "update_unsupported",
			"This bmcp was built from source, so there is no release to update to.")
	case installBrew:
		return a.fail(flags, exitValidation, "update_unsupported", fmt.Sprintf(
			"This bmcp was installed with Homebrew (%s) and cannot replace itself.\nRun: %s\nOr switch to a self-updating install: curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sh",
			path, brewUpgradeCmd, updateRepo))
	case installVersioned:
		return a.fail(flags, exitValidation, "update_unsupported", fmt.Sprintf(
			"This bmcp lives under a version-managed directory (%s), so replacing it in place would leave the tool that manages it describing a version that is no longer there.\nUpgrade it with that tool, or switch to a self-updating install: curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sh",
			path, updateRepo))
	}

	if flags.updateRollback {
		return a.rollbackUpdate(flags, path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateApplyTimeout)
	defer cancel()
	st := a.inspectUpdate(ctx, cfg, explicit)

	if st.Err != nil {
		return a.fail(flags, exitUpstream, "update_check_failed", st.Err.Error())
	}

	// Being ahead of the latest release is only a downgrade request when the
	// user named a version. A bare `bmcp update` means "get me current", which
	// a machine already past current already is.
	behind := explicit == "" && compareVersions(st.Target, st.Current) < 0

	if flags.updateCheck {
		switch {
		case flags.jsonOut:
			out, _ := json.MarshalIndent(st.updateJSON(), "", "  ")
			fmt.Fprintln(a.stderr, string(out))
		case behind:
			fmt.Fprintf(a.stderr, "bmcp %s is newer than the latest release (%s); nothing to update to\n", st.Current, st.Target)
		case st.Available:
			fmt.Fprintf(a.stderr, "bmcp %s is available (running %s)\n", st.Target, st.Current)
		default:
			fmt.Fprintf(a.stderr, "bmcp %s is up to date\n", st.Current)
		}
		return 0
	}

	if behind {
		fmt.Fprintf(a.stderr, "bmcp %s is newer than the latest release (%s); nothing to update to.\nRun `bmcp update --to %s` to move to it anyway.\n",
			st.Current, st.Target, taggedVersion(st.Target))
		return 0
	}

	if !st.Available {
		fmt.Fprintf(a.stderr, "bmcp %s is already installed\n", st.Current)
		return 0
	}

	if err := a.applyUpdate(ctx, flags, st, st.Target); err != nil {
		return a.fail(flags, exitUpstream, "update_failed", err.Error())
	}
	st.Applied = true
	fmt.Fprintf(a.stderr, "Updated bmcp %s -> %s (this run still uses %s)\n", st.Current, st.Target, st.Current)
	return 0
}

// rollbackUpdate restores the binary the last update replaced. selfupdate does
// not do this for us: it rolls back only when its own second rename fails, so a
// successful-but-broken install is never restored automatically.
func (a *app) rollbackUpdate(flags globalFlags, path string) int {
	backup := priorBinaryPath(path)
	if _, err := os.Stat(backup); err != nil {
		return a.fail(flags, exitValidation, "no_backup", fmt.Sprintf(
			"No previous bmcp to roll back to (looked for %s).\nReinstall a specific version with: BMCP_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sh",
			backup, updateRepo))
	}
	release, err := acquireUpdateLock(filepath.Dir(path), a.now())
	if err != nil {
		return a.fail(flags, exitGeneric, "update_rollback_failed", err.Error())
	}
	defer release()

	// Read before the rename: the trail is how we learn which version we are
	// going back to, since the restored binary is not the one running.
	restored := ""
	if receipt, err := readInstallReceipt(path); err == nil && len(receipt.Updates) > 0 {
		restored = receipt.Updates[len(receipt.Updates)-1].From
	}
	if err := os.Rename(backup, path); err != nil {
		return a.fail(flags, exitGeneric, "update_rollback_failed", err.Error())
	}
	if err := recordRollback(path, normalizeVersion(version), restored, a.now()); err != nil {
		fmt.Fprintf(a.stderr, "Warning: rolled back, but could not record it: %v\n", err)
	}

	if restored != "" {
		fmt.Fprintf(a.stderr, "Rolled back bmcp %s -> %s at %s\n", normalizeVersion(version), restored, path)
	} else {
		fmt.Fprintf(a.stderr, "Rolled back to the previously installed bmcp at %s\n", path)
	}
	fmt.Fprintf(a.stderr, "bmcp %s will not be installed automatically again on this machine.\nRun `bmcp update --to %s` to install it anyway.\n",
		normalizeVersion(version), taggedVersion(version))
	return 0
}
