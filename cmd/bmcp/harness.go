package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type installFileResult struct {
	Path    string
	Backup  string
	Changed bool
}

type installResult struct {
	Harness string
	Scope   string
	Files   []installFileResult
}

type harness struct {
	name        string
	displayName string
	bins        []string
	userDir     string
	projectDir  string
	files       func(base string, cache *toolCache) []harnessFile
}

type harnessFile struct {
	path         string
	content      string
	appendRef    string
	managedBlock string
	legacyRefs   []string
}

var harnesses = []harness{
	{
		name: "claude-code", displayName: "Claude Code",
		bins: []string{"claude"}, userDir: ".claude",
		files: func(base string, cache *toolCache) []harnessFile {
			return []harnessFile{
				{path: filepath.Join(base, "BORIS.md"), content: borisInstructionsMarkdown(cache)},
				{path: filepath.Join(base, "CLAUDE.md"), appendRef: "@BORIS.md"},
			}
		},
	},
	{
		name: "codex", displayName: "Codex",
		bins: []string{"codex"}, userDir: ".codex",
		files: func(base string, cache *toolCache) []harnessFile {
			borisPath := filepath.Join(base, "BORIS.md")
			return []harnessFile{
				{path: borisPath, content: borisInstructionsMarkdown(cache)},
				{
					path:         filepath.Join(base, "AGENTS.md"),
					content:      borisInstructionsMarkdown(cache),
					managedBlock: "BORIS",
					legacyRefs:   []string{"@BORIS.md", "@" + borisPath},
				},
			}
		},
	},
	{
		name: "opencode", displayName: "OpenCode",
		bins: []string{"opencode"}, userDir: filepath.Join(".config", "opencode"),
		files: func(base string, cache *toolCache) []harnessFile {
			borisPath := filepath.Join(base, "BORIS.md")
			return []harnessFile{
				{path: borisPath, content: borisInstructionsMarkdown(cache)},
				{
					path:         filepath.Join(base, "AGENTS.md"),
					content:      borisInstructionsMarkdown(cache),
					managedBlock: "BORIS",
					legacyRefs:   []string{"@BORIS.md", "@" + borisPath},
				},
			}
		},
	},
	{
		name: "cursor", displayName: "Cursor",
		// projectDir is not redundant with userDir. Without it, installBase's
		// project branch falls through to bare cwd, so `--scope project` wrote
		// ./rules/boris.mdc — a path Cursor never reads, and a directory at the
		// repo root this tool has no business claiming. The install reported
		// success and the agent got no BORIS context, with nothing anywhere
		// saying why. Cursor reads project rules from .cursor/rules, so the
		// project base has to name .cursor the same way the user base does.
		bins: []string{"cursor"}, userDir: ".cursor", projectDir: ".cursor",
		files: func(base string, cache *toolCache) []harnessFile {
			return []harnessFile{
				{path: filepath.Join(base, "rules", "boris.mdc"), content: borisCursorRule(cache)},
			}
		},
	},
	{
		name: "kiro", displayName: "Kiro",
		bins: []string{"kiro-cli", "kiro"}, userDir: ".kiro", projectDir: ".kiro",
		files: func(base string, cache *toolCache) []harnessFile {
			return []harnessFile{
				{path: filepath.Join(base, "steering", "boris.md"), content: borisInstructionsMarkdown(cache)},
			}
		},
	},
}

func lookupHarness(name string) (harness, bool) {
	if name == "claude" {
		name = "claude-code"
	}
	for _, h := range harnesses {
		if h.name == name {
			return h, true
		}
	}
	return harness{}, false
}

func harnessDisplayName(name string) string {
	if h, ok := lookupHarness(name); ok {
		return h.displayName
	}
	return name
}

func (f harnessFile) install() installFileResult {
	if f.appendRef != "" {
		return appendInstructionRef(f.path, f.appendRef)
	}
	if f.managedBlock != "" {
		return writeManagedInstructionBlock(f.path, f.managedBlock, f.content, f.legacyRefs)
	}
	return writeInstructionFile(f.path, f.content)
}

func (f harnessFile) refresh() (installFileResult, bool) {
	if f.appendRef != "" || !fileExists(f.path) {
		return installFileResult{}, false
	}
	if f.managedBlock != "" {
		return refreshManagedInstructionBlock(f.path, f.managedBlock, f.content, f.legacyRefs)
	}
	return writeInstructionFile(f.path, f.content), true
}

func (a *app) promptInstallDetectedHarnesses(reader *bufio.Reader, flags globalFlags) {
	for _, h := range a.detectHarnesses() {
		if !promptYesNo(reader, a.stderr, fmt.Sprintf("Install BORIS instructions for %s? [Y/n]: ", h.displayName), true) {
			continue
		}
		result, err := a.installHarnessWithCatalog(flags, h.name, "user")
		if err != nil {
			fmt.Fprintf(a.prose(), "Could not install %s instructions: %s\n", h.displayName, err)
			continue
		}
		printInstallResult(a.prose(), result)
	}
}

func (a *app) detectHarnesses() []harness {
	var detected []harness
	for _, h := range harnesses {
		if a.hasAnyCommand(h.bins) || userDirExists(h.userDir) {
			detected = append(detected, h)
		}
	}
	return detected
}

func (a *app) hasAnyCommand(names []string) bool {
	for _, name := range names {
		if a.hasCommand(name) {
			return true
		}
	}
	return false
}

func (a *app) hasCommand(name string) bool {
	lookPath := a.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	_, err := lookPath(name)
	return err == nil
}

func userDirExists(name string) bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	info, err := os.Stat(filepath.Join(home, name))
	return err == nil && info.IsDir()
}

func promptYesNo(reader *bufio.Reader, w io.Writer, question string, defaultYes bool) bool {
	fmt.Fprint(w, question)
	line, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "" {
		return defaultYes
	}
	return answer == "y" || answer == "yes"
}

func (a *app) installHarnessWithCatalog(flags globalFlags, harness, scope string) (installResult, error) {
	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return installResult{}, err
	}
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		return installResult{}, err
	}
	return a.installHarness(harness, scope, cache)
}

func (a *app) installHarness(name, scope string, cache *toolCache) (installResult, error) {
	h, ok := lookupHarness(name)
	if !ok {
		return installResult{}, fmt.Errorf("unknown harness: %s", name)
	}
	// The same rule refreshExistingInstructions follows, for the same reason: with
	// no tools to render, these files would be written with the "no tools
	// available" placeholder in place of the catalog, spending a backup
	// generation on every run until no copy that could restore them is left.
	//
	// This path is not only reached by an explicit `bmcp install`. An all-defaults
	// interactive `bmcp init` accepts the harness prompts for you, so a machine
	// whose cache is empty would silently overwrite good instruction files without
	// the user ever typing "install".
	if cache == nil || len(cache.Tools) == 0 {
		return installResult{}, errors.New("the local tool catalog is empty, so the instructions would list no tools; run `bmcp sync` first")
	}
	base, err := installBase(scope, h.userDir, h.projectDir)
	if err != nil {
		return installResult{}, err
	}
	result := installResult{Harness: h.name, Scope: scope}
	for _, f := range h.files(base, cache) {
		result.Files = append(result.Files, f.install())
	}
	return result, firstInstallErr(result.Files)
}

func installBase(scope, userSubdir, projectSubdir string) (string, error) {
	if scope == "project" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		if projectSubdir != "" {
			return filepath.Join(cwd, projectSubdir), nil
		}
		return cwd, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, userSubdir), nil
}

func firstInstallErr(results []installFileResult) error {
	for _, r := range results {
		if r.Path == "" {
			return errors.New("install failed")
		}
	}
	return nil
}

func writeInstructionFile(path, content string) installFileResult {
	return writeFileWithBackup(path, []byte(ensureTrailingNewline(content)))
}

func ensureTrailingNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func appendInstructionRef(path, ref string) installFileResult {
	old, err := os.ReadFile(path)
	if err == nil {
		for _, line := range strings.Split(string(old), "\n") {
			if strings.TrimSpace(line) == ref {
				return installFileResult{Path: path, Changed: false}
			}
		}
		content := string(old)
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += ref + "\n"
		return writeFileWithBackup(path, []byte(content))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return installFileResult{}
	}
	return writeFileWithBackup(path, []byte(ref+"\n"))
}

func writeManagedInstructionBlock(path, name, content string, legacyRefs []string) installFileResult {
	old, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return installFileResult{}
		}
		return writeFileWithBackup(path, []byte(managedInstructionBlock(name, content)+"\n"))
	}
	next := upsertManagedInstructionBlock(string(old), name, content, legacyRefs)
	return writeFileWithBackup(path, []byte(next))
}

func refreshManagedInstructionBlock(path, name, content string, legacyRefs []string) (installFileResult, bool) {
	old, err := os.ReadFile(path)
	if err != nil {
		// "Could not read it" and "it is not ours" are different answers, and
		// collapsing them hid the case the failure report exists for: an
		// unreadable AGENTS.md — the file Codex and OpenCode auto-load — was
		// dropped before it could be counted, so a refresh that failed on exactly
		// the file that matters printed nothing at all. Only a genuine absence
		// means "not managed".
		if errors.Is(err, os.ErrNotExist) {
			return installFileResult{}, false
		}
		return installFileResult{}, true
	}
	if !hasManagedInstructionBlock(string(old), name) && !hasLegacyInstructionRef(string(old), legacyRefs) {
		return installFileResult{}, false
	}
	return writeFileWithBackup(path, []byte(upsertManagedInstructionBlock(string(old), name, content, legacyRefs))), true
}

func upsertManagedInstructionBlock(old, name, content string, legacyRefs []string) string {
	block := managedInstructionBlock(name, content)
	start, end := managedInstructionMarkers(name)
	if startIndex := strings.Index(old, start); startIndex >= 0 {
		if endIndex := strings.Index(old[startIndex:], end); endIndex >= 0 {
			endIndex += startIndex + len(end)
			next := old[:startIndex] + block + old[endIndex:]
			return ensureTrailingNewline(next)
		}
	}

	cleaned := removeLegacyInstructionRefs(old, legacyRefs)
	cleaned = strings.TrimRight(cleaned, "\n")
	if cleaned == "" {
		return block + "\n"
	}
	return cleaned + "\n\n" + block + "\n"
}

func managedInstructionBlock(name, content string) string {
	start, end := managedInstructionMarkers(name)
	return start + "\n" + strings.TrimRight(content, "\n") + "\n" + end
}

func managedInstructionMarkers(name string) (string, string) {
	return "<!-- BEGIN BMCP " + name + " -->", "<!-- END BMCP " + name + " -->"
}

func hasManagedInstructionBlock(content, name string) bool {
	start, end := managedInstructionMarkers(name)
	return strings.Contains(content, start) && strings.Contains(content, end)
}

func hasLegacyInstructionRef(content string, refs []string) bool {
	for _, line := range strings.Split(content, "\n") {
		if containsLegacyInstructionRef(line, refs) {
			return true
		}
	}
	return false
}

func removeLegacyInstructionRefs(content string, refs []string) string {
	var kept []string
	for _, line := range strings.Split(content, "\n") {
		if containsLegacyInstructionRef(line, refs) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func containsLegacyInstructionRef(line string, refs []string) bool {
	line = strings.TrimSpace(line)
	for _, ref := range refs {
		if line == ref {
			return true
		}
	}
	return false
}

// writeFileAtomic writes through a temp file in the same directory and renames
// it over the target, so a reader sees either the whole old file or the whole
// new one. An in-place write interrupted by SIGKILL, a full disk or a lost
// power rail leaves a truncated file instead, and for tools.json that is worse
// than losing it outright: readCache fails, the empty-catalog guard in
// syncTools is preconditioned on being able to read the old catalog, so it does
// not engage — and an empty tools/list is then written as the truth.
func writeFileAtomic(path string, content []byte, perm os.FileMode) error {
	staged, err := stageFileAtomic(path, content, perm)
	if err != nil {
		return err
	}
	defer staged.abandon()
	return staged.commit()
}

// stagedWrite is a temp file that already holds the new content, sitting in the
// destination's own directory and needing only a rename.
//
// The split exists for writeFileWithBackup: staging separately lets it get the
// entire new file onto disk before it rotates a .bak-, so the failure that
// actually happens — no room for the new content — happens while there is still
// nothing to leak. Writing the small backup first also spent the space the
// larger new file needed, which is the write it then failed.
type stagedWrite struct {
	path string
	tmp  string
}

// stageFileAtomic writes content to a temp file beside path and leaves it for
// commit to rename into place. The caller must call abandon or the temp file is
// left next to the good file; deferring it immediately is always correct, since
// abandon is a no-op once commit has succeeded.
func stageFileAtomic(path string, content []byte, perm os.FileMode) (staged *stagedWrite, err error) {
	path = resolveSymlink(path)
	// A file that already exists keeps the mode it has. os.WriteFile applied
	// perm only at creation, so a BORIS.md someone had tightened to 0600 stayed
	// tightened; recreating the inode on every write would otherwise reset it to
	// the constant this is called with.
	mode, preserve := perm, false
	if info, statErr := os.Stat(path); statErr == nil {
		mode, preserve = info.Mode().Perm(), true
	}
	f, tmp, createErr := createTempFile(filepath.Dir(path), "."+filepath.Base(path), mode)
	if createErr != nil {
		return nil, createErr
	}
	defer func() {
		if err == nil {
			// Staging succeeded, so the temp file is the point of the call and
			// disposing of it is the caller's to decide.
			return
		}
		f.Close()
		// What keeps a partial write from being left behind next to the good
		// file.
		os.Remove(tmp)
	}()
	if preserve {
		// The umask applied at creation may have narrowed a preserved mode, and
		// a umask has no business editing a mode the user already chose. It
		// still applies to a file being created for the first time, which is
		// what os.WriteFile did.
		if err = f.Chmod(mode); err != nil {
			return nil, err
		}
	}
	if _, err = f.Write(content); err != nil {
		return nil, err
	}
	// Sync before the rename. Without it the rename can reach disk before the
	// data does, which after a crash leaves a file that exists, has the right
	// name, and is empty — the one state the empty-catalog guard cannot see.
	if err = f.Sync(); err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	return &stagedWrite{path: path, tmp: tmp}, nil
}

// commit renames the staged file over its destination.
func (s *stagedWrite) commit() error {
	if err := os.Rename(s.tmp, s.path); err != nil {
		return err
	}
	// Best effort, and only about durability: the rename is already atomic for
	// any reader, but until the directory entry is flushed a power loss can roll
	// it back to the previous file. Losing the newer of two intact files is an
	// acceptable outcome, and not every filesystem allows this, so a failure
	// here is not worth failing the write over.
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

// abandon discards the staged file. A no-op once commit has succeeded, because
// the rename is what removed the temp name.
func (s *stagedWrite) abandon() {
	os.Remove(s.tmp)
}

// resolveSymlink returns what path ultimately names, so a write lands on the
// link's target rather than on the link.
//
// os.WriteFile opened the target and wrote through it; a rename replaces the
// link itself with a regular file, so an instruction file a dotfiles manager had
// symlinked into place would silently detach from the repo holding it. update.go
// guards the binary against exactly this, and the instruction files are the ones
// people actually symlink.
//
// Readlink rather than filepath.EvalSymlinks, which fails on a link whose target
// does not exist yet and would leave that link to be replaced — a dotfiles setup
// that symlinks a file before first writing it is the normal case, not an
// exotic one. A bounded walk, since a symlink cycle otherwise never terminates.
func resolveSymlink(path string) string {
	for i := 0; i < 16; i++ {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return path
		}
		target, err := os.Readlink(path)
		if err != nil {
			return path
		}
		if filepath.IsAbs(target) {
			path = target
		} else {
			path = filepath.Join(filepath.Dir(path), target)
		}
	}
	return path
}

// createTempFile is os.CreateTemp with a caller-chosen mode. os.CreateTemp
// hardcodes 0600, and correcting that with Chmod would bypass the umask —
// os.WriteFile honoured it, and a new file appearing more permissive than the
// user's umask allows is not a change this should make quietly.
func createTempFile(dir, prefix string, perm os.FileMode) (*os.File, string, error) {
	for i := 0; i < 1000; i++ {
		name := filepath.Join(dir, fmt.Sprintf("%s.tmp%d-%d", prefix, os.Getpid(), i))
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			return f, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("no free temp filename next to %s", filepath.Join(dir, prefix))
}

func writeFileWithBackup(path string, content []byte) installFileResult {
	result := installFileResult{Path: path}
	old, err := os.ReadFile(path)
	exists := err == nil
	if exists {
		// The load-bearing short-circuit now that renderInstructionToolList emits
		// no timestamp: a refresh against an unchanged catalog produces identical
		// bytes and returns here, so the per-session doctor refresh writes
		// nothing, rotates nothing, and touches no mtime.
		if bytes.Equal(old, content) {
			return result
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return installFileResult{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return installFileResult{}
	}
	// Staged before the backup is taken, so no .bak- exists yet for any failure
	// up to this point — a read-only mount, a full disk, a target that is not
	// writable. Taking it first left one behind on every such write, and the
	// target was unchanged, so the next run took another: one orphan per agent
	// session on a machine where the write kept failing, unbounded, because
	// pruning is what never ran. backupGenerations does not bound that.
	staged, err := stageFileAtomic(path, content, 0o644)
	if err != nil {
		return installFileResult{}
	}
	defer staged.abandon()
	if exists {
		backup := backupPath(path)
		if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
			return installFileResult{}
		}
		if err := writeFileAtomic(backup, old, 0o600); err != nil {
			return installFileResult{}
		}
		result.Backup = backup
	}
	if err := staged.commit(); err != nil {
		// The rename is a short window but not an empty one: an immutable
		// target, or a path that became a directory, fails here with the backup
		// already taken. Removing the copy this call made restores the state
		// before it exactly — the target was never replaced, so the copy
		// duplicates a file that is still there — and leaves the generation
		// count untouched rather than spending one on a write that never
		// happened.
		if result.Backup != "" {
			os.Remove(result.Backup)
		}
		return installFileResult{}
	}
	// Pruning only after the target is actually replaced. Doing it beside the
	// backup spent a generation on a write that then failed — ENOSPC part-way
	// through, since the small backup fits where the larger new file does not —
	// which deletes a good restore point in exchange for nothing, and breaks the
	// README's promise that a backup rotates "when a file changes".
	if result.Backup != "" {
		pruneOldBackups(path, result.Backup)
	}
	result.Changed = true
	return result
}

func backupPath(path string) string {
	// Nanosecond resolution, fixed width. A one-second stamp let two writes
	// inside the same second land on the same name, so the second overwrote the
	// backup the first had just taken — collapsing two generations into one and,
	// when the first write was the good one, destroying exactly the copy worth
	// keeping. Probing for a free name instead would break the other property
	// pruneOldBackups depends on: it reuses a slot that pruning just freed, so
	// the lexically smallest name ends up holding the newest content and the
	// oldest-first sort starts deleting the wrong file.
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	return fmt.Sprintf("%s.bak-%s", path, stamp)
}

// backupGenerations is how many .bak-* copies survive a write. One is not
// enough: the first bad write backs up the good file, the second backs up the
// damaged file and deletes the good one, so two consecutive bad writes leave no
// restore point at all. That amplifier is what turned #14 from recoverable into
// permanent data loss. The files are a few KB.
//
// Five is only enough because rotations are rare, and they are rare only
// because renderInstructionToolList is a pure function of the catalog. It used
// to embed a sync timestamp, which made every render unique and every refresh a
// rotation — tolerable when only `bmcp sync` refreshed, fatal once `bmcp doctor`
// does it every agent session. Anything time-varying put back into that render
// re-arms it.
const backupGenerations = 5

func pruneOldBackups(path, keep string) {
	// Listed and prefix-matched rather than globbed. filepath.Glob reads `[`, `*`
	// and `?` in the path as pattern syntax, so a project directory named
	// something like `service[1]` made the pattern match nothing and returned no
	// error — pruning silently became a no-op and the .bak-* set grew without
	// bound, in the one place a silent no-op is hardest to notice.
	dir, base := filepath.Split(path)
	listDir := dir
	if listDir == "" {
		listDir = "."
	}
	entries, err := os.ReadDir(listDir)
	if err != nil {
		return
	}
	// keep is held back rather than sorted with the rest: it is the newest by
	// construction, but a backup written under a skewed clock could sort after
	// it, and pruning the copy this write just took would defeat the point.
	//
	// Ordered by mtime, not by the timestamp in the name. The name is only as
	// honest as the clock that wrote it, and a backup stamped with a future date
	// — a clock that jumped forward and came back — sorts last by name forever.
	// It then survives every prune while the genuinely recent copies below it
	// are deleted as "oldest", which is precisely the two-bad-writes loss this
	// retention exists to prevent. mtime is what the filesystem observed.
	prefix := base + ".bak-"
	type backup struct {
		path string
		at   time.Time
	}
	others := make([]backup, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		if full == keep {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		others = append(others, backup{path: full, at: info.ModTime()})
	}
	sort.Slice(others, func(i, j int) bool {
		if others[i].at.Equal(others[j].at) {
			return others[i].path < others[j].path
		}
		return others[i].at.Before(others[j].at)
	})
	for i := 0; i < len(others)-(backupGenerations-1); i++ {
		_ = os.Remove(others[i].path)
	}
}

func printInstallResult(w io.Writer, result installResult) {
	fmt.Fprintf(w, "Installed BORIS instructions for %s (%s scope):\n", harnessDisplayName(result.Harness), result.Scope)
	for _, file := range result.Files {
		if file.Changed {
			fmt.Fprintf(w, "  wrote %s\n", file.Path)
			if file.Backup != "" {
				fmt.Fprintf(w, "  backup %s\n", file.Backup)
			}
		} else {
			fmt.Fprintf(w, "  unchanged %s\n", file.Path)
		}
	}
}

func printRefreshResult(w io.Writer, result installResult) {
	changed := false
	failed := 0
	for _, file := range result.Files {
		// writeFileWithBackup discards the path on every error return, so a failed
		// write is indistinguishable from any other failed write here. Reporting
		// the count is still the difference between a refresh that quietly did
		// nothing and one an operator can act on: these files are what agents read
		// to learn which tools exist, and a stale catalog sends them at tools that
		// no longer exist.
		if file.Path == "" {
			failed++
			continue
		}
		changed = changed || file.Changed
	}
	if failed > 0 {
		// No "run `bmcp sync` to retry": sync writes through this same function
		// and fails the same way, and doctor runs every agent session, so that
		// advice would be a per-session instruction to do something that cannot
		// work. Name the consequence instead — a stale tool list is the thing the
		// reader has to weigh — and let them decide.
		fmt.Fprintf(w, "Could not write %d BORIS instruction file(s) for %s (%s scope); agents there keep reading the previous tool list.\n",
			failed, harnessDisplayName(result.Harness), result.Scope)
	}
	if !changed {
		return
	}
	fmt.Fprintf(w, "Refreshed BORIS instructions for %s (%s scope):\n", harnessDisplayName(result.Harness), result.Scope)
	for _, file := range result.Files {
		if !file.Changed {
			continue
		}
		fmt.Fprintf(w, "  wrote %s\n", file.Path)
		if file.Backup != "" {
			fmt.Fprintf(w, "  backup %s\n", file.Backup)
		}
	}
}

// refreshExistingInstructions rewrites instruction files that already exist.
//
// includeProject decides whether the current working directory is in scope, and
// the two callers answer differently on purpose. `bmcp sync` is typed by a human
// who knows which directory they are standing in, so it refreshes what it finds
// there. `bmcp doctor` is what the generated instructions tell every agent to
// run before its first BORIS call, from whatever repository the agent happens to
// be working in — so for doctor the answer is no. Project-scope refresh stays
// the explicit act it has always been.
//
// The distinction matters because a project-scope file is claimed by filename
// alone. `BORIS.md` and `.kiro/steering/boris.md` are rewritten whole, with no
// marker proving bmcp wrote them, so an unrelated file of that name in someone's
// repository is indistinguishable from one of ours. Under `sync` that costs a
// user who ran the wrong command in the wrong directory one file and leaves a
// .bak- beside it. Under `doctor` it would be every agent session, unattended,
// everywhere.
func refreshExistingInstructions(cache *toolCache, includeProject bool) []installResult {
	// Belt and braces behind the syncTools guard. With no tools to render, every
	// managed file would be rewritten with renderInstructionToolList's "no tools
	// available" placeholder in place of the catalog, spending a backup
	// generation on every run until no copy that could restore them is left. A
	// catalog that cannot improve these files must not be able to damage them,
	// however the empty cache arrived — including one an older binary already
	// wrote before that guard existed.
	if cache == nil || len(cache.Tools) == 0 {
		return nil
	}
	var results []installResult
	seen := map[string]bool{}
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	scopes := []struct {
		name string
		base func(h harness) string
	}{
		{"user", func(h harness) string {
			if home == "" {
				return ""
			}
			return filepath.Join(home, h.userDir)
		}},
		{"project", func(h harness) string {
			if cwd == "" || !includeProject {
				return ""
			}
			if h.projectDir != "" {
				return filepath.Join(cwd, h.projectDir)
			}
			return cwd
		}},
	}
	for _, scope := range scopes {
		for _, h := range harnesses {
			base := scope.base(h)
			if base == "" {
				continue
			}
			var files []installFileResult
			for _, f := range h.files(base, cache) {
				if seen[f.path] {
					continue
				}
				if r, refreshed := f.refresh(); refreshed {
					seen[f.path] = true
					files = append(files, r)
				}
			}
			if len(files) > 0 {
				results = append(results, installResult{Harness: h.name, Scope: scope.name, Files: files})
			}
		}
	}
	return results
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func borisInstructionsMarkdown(cache *toolCache) string {
	return `# BORIS MCP Infrastructure Context

Use the local ` + "`bmcp`" + ` CLI when a task needs live context about infrastructure, deployed resources, repository/code relationships, dependencies, topology, or prior decisions and memory. Do not use it for general cloud or programming knowledge when the answer does not depend on this environment.

Before the first BORIS call in a session, run:

` + "```bash" + `
bmcp doctor
` + "```" + `

This is a local check: while the cached tool catalog is fresh it authenticates nothing and reaches no BORIS server, so it is cheap enough to run every session. (It may still contact GitHub for its own update check, at most once a day.) If it fails on config, tell the user to run ` + "`bmcp init`" + `.

**Never shorten ` + "`bmcp`" + ` output to a fixed number of lines, bytes, or records.** The cut leaves no marker, so a partial answer looks exactly like a complete one. If a result is too large: filter by scope (account, region, namespace, selector) first, then ` + "`bmcp --max-bytes <n>`" + `, the one cut that marks what it dropped — and a count cap like ` + "`max_results`" + ` only last, because that one may leave no marker at all. A result is not complete if ` + "`truncated`" + ` or ` + "`has_more`" + ` is set, or a count cap applied — yours, or the tool's own default.

If a tool call later fails on authentication or connectivity, run ` + "`bmcp doctor --deep`" + `, which checks credentials, the server and the live catalog for real, and says which of them is at fault. The BORIS MCP server requires AWS credentials for any account in the AWS Organization; if auth is unavailable, use the normal environment credential workflow available in this harness or explain the credential requirement to the user.

Useful commands:

- ` + "`bmcp list`" + `: list remote tools as NDJSON, one object per line: ` + "`name`" + ` (full name, always callable), ` + "`display_name`" + `, ` + "`description`" + `, ` + "`last_sync`" + `. Call tools by ` + "`name`" + `. Add ` + "`--format human`" + ` for indented text, or ` + "`--format json`" + ` for one document whose ` + "`count`" + ` says how many records it should hold.
- ` + "`bmcp list --schemas`" + `: the same records with each tool's ` + "`input_schema`" + ` included. Prefer this when you intend to call a tool: it answers "which tools exist" and "how do I call them" in one local invocation, with no per-tool ` + "`describe`" + ` round trip.
- ` + "`bmcp describe <tool>`" + `: show one tool's schema and examples as indented text.
- ` + "`bmcp <tool> --arg value`" + `: call a tool with CLI flags.
- ` + "`bmcp call <tool> '{\"arg\":\"value\"}'`" + `: call a tool with JSON.
- ` + "`bmcp --pretty <tool> ...`" + `: pretty-print JSON output when the tool returns JSON. Not needed under ` + "`--format json`" + `.
- ` + "`bmcp --raw <tool> ...`" + `: show the original MCP tool envelope for debugging.

Output format: pass ` + "`--format human|json|ndjson`" + ` to any command to get the machine-output contract. Prefer ` + "`--format json`" + ` (or ` + "`--format ndjson`" + ` for ` + "`bmcp list`" + `) for anything you intend to parse. Without it each command keeps its older output, which is not a contract — ` + "`--output`" + ` and ` + "`--json`" + ` are the legacy flags and are deprecated.

**Put ` + "`--format`" + ` and ` + "`--max-bytes`" + ` before the tool name**, as in ` + "`bmcp --format json <tool> --arg value`" + `. Everything after the tool name is parsed as that tool's own arguments, so a trailing ` + "`--format json`" + ` is rejected as an unknown tool argument — and on a tool that declares no arguments it is not rejected but **sent to the server as an argument named ` + "`format`" + `**. The same applies to ` + "`bmcp install`" + ` and ` + "`bmcp version`" + `, which take their arguments verbatim.

Under ` + "`--format json`" + ` or ` + "`--format ndjson`" + ` the rules are the same for every command, so no output plumbing is needed:

- stdout carries one JSON document and nothing else. ` + "`bmcp list --format ndjson`" + ` is the exception by design: one object per line, and empty stdout for an empty catalog. Progress prose is not written at all, so ` + "`2>&1`" + ` is safe. Merging is also the only way to capture both outcomes in one variable, because the failure document is on stderr.
- A failure writes ` + "`{\"ok\":false,\"command\":…,\"error\":…,\"message\":…,\"exit_code\":…}`" + ` to stderr as a single line, whichever format was selected, and leaves stdout empty. Read ` + "`ok`" + ` to tell the two apart, and ` + "`exit_code`" + ` if a pipeline swallowed the real exit status.
- Two exceptions to that failure rule. ` + "`bmcp doctor`" + ` reports failing checks in its ordinary report on stdout with ` + "`\"ok\": false`" + ` and exits 1 — it is a diagnostic, so a failing check is its answer rather than an error. And ` + "`--help`" + ` prints human text in every format; do not parse it. Adding ` + "`--verbose`" + ` also puts progress prose back on stderr, so do not combine it with ` + "`2>&1`" + `.
- A tool call answers with ` + "`{\"ok\":true,\"tool\":…,\"result\":…,\"result_bytes\":…,\"truncated\":…}`" + `. A non-JSON payload arrives in ` + "`result_text`" + ` instead of ` + "`result`" + `.
- ` + "`bmcp --max-bytes <n> <tool> ...`" + ` caps a large result: the document stays parseable, sets ` + "`truncated`" + `, reports the full ` + "`result_bytes`" + `, and puts the kept prefix in ` + "`result_excerpt`" + `. It goes before the tool name, as above.

Tools available when these instructions were generated (short display names; ` + "`bmcp list`" + ` prints the full ` + "`name`" + ` for each):

` + renderInstructionToolList(cache) + `

To refresh this tool list after BORIS changes, run:

` + "```bash" + `
bmcp sync
` + "```" + `

` + "`bmcp sync`" + ` refreshes the local tool cache and updates any existing BORIS instruction files it finds.

BORIS unwraps MCP text envelopes internally, so normal tool calls print the useful payload directly. Summarize the relevant facts and mention if the tool returned an error.`
}

func renderInstructionToolList(cache *toolCache) string {
	if cache == nil || len(cache.Tools) == 0 {
		return "- No tools were available in the local BORIS cache. Run `bmcp sync`, then reinstall or sync instructions."
	}
	// No sync timestamp. It used to head this list, and it made every render
	// unique: the same catalog produced different bytes on every sync, so
	// writeFileWithBackup's bytes.Equal short-circuit never fired and each
	// refresh rotated a backup generation. That was survivable while only `bmcp
	// sync` refreshed these files; once `bmcp doctor` does it, it is once per
	// agent session, and five sessions evict every restore point.
	//
	// Suppressing the backup for a stamp-only rewrite was the obvious repair and
	// the wrong one: it needs a matcher that decides whether two documents differ
	// "only in the stamp", and every way that matcher can be fooled is a real
	// content change that silently loses its restore point. Deleting the input
	// deletes the question. An unchanged catalog now renders byte-identical and
	// is not written at all.
	//
	// Freshness did not live here anyway: `bmcp list` reports last_sync and
	// `bmcp doctor` reports the cache age, both from tools.json, which is the
	// authority.
	var b strings.Builder
	for _, t := range cache.Tools {
		desc := normalizeWhitespace(t.Description)
		if desc == "" {
			fmt.Fprintf(&b, "- `%s`\n", displayToolName(t.Name))
			continue
		}
		fmt.Fprintf(&b, "- `%s`: %s\n", displayToolName(t.Name), desc)
	}
	return strings.TrimRight(b.String(), "\n")
}

func borisCursorRule(cache *toolCache) string {
	return `---
description: Use BORIS for infrastructure, code, dependency, and memory context
alwaysApply: true
---

` + borisInstructionsMarkdown(cache)
}
