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
		name: "cursor", displayName: "Cursor",
		bins: []string{"cursor"}, userDir: ".cursor",
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
			fmt.Fprintf(a.stderr, "Could not install %s instructions: %s\n", h.displayName, err)
			continue
		}
		printInstallResult(a.stderr, result)
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
		return installFileResult{}, false
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

func writeFileWithBackup(path string, content []byte) installFileResult {
	result := installFileResult{Path: path}
	old, err := os.ReadFile(path)
	if err == nil {
		if bytes.Equal(old, content) {
			return result
		}
		backup := backupPath(path)
		if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
			return installFileResult{}
		}
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return installFileResult{}
		}
		pruneOldBackups(path, backup)
		result.Backup = backup
	} else if !errors.Is(err, os.ErrNotExist) {
		return installFileResult{}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return installFileResult{}
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		return installFileResult{}
	}
	result.Changed = true
	return result
}

func backupPath(path string) string {
	stamp := time.Now().UTC().Format("20060102T150405Z")
	return fmt.Sprintf("%s.bak-%s", path, stamp)
}

func pruneOldBackups(path, keep string) {
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		return
	}
	for _, match := range matches {
		if match == keep {
			continue
		}
		_ = os.Remove(match)
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
	for _, file := range result.Files {
		changed = changed || file.Changed
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

func refreshExistingInstructions(cache *toolCache) []installResult {
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
			if cwd == "" {
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

If ` + "`doctor`" + ` fails on config, tell the user to run ` + "`bmcp init`" + `. The BORIS MCP server requires AWS credentials for any account in the AWS Organization; if auth is unavailable, use the normal environment credential workflow available in this harness or explain the credential requirement to the user.

Useful commands:

- ` + "`bmcp list`" + `: list available remote tools.
- ` + "`bmcp describe <tool>`" + `: show tool schema and examples.
- ` + "`bmcp <tool> --arg value`" + `: call a tool with CLI flags.
- ` + "`bmcp call <tool> '{\"arg\":\"value\"}'`" + `: call a tool with JSON.
- ` + "`bmcp --pretty <tool> ...`" + `: pretty-print JSON output when the tool returns JSON.
- ` + "`bmcp --raw <tool> ...`" + `: show the original MCP tool envelope for debugging.

Tools available when these instructions were generated:

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
	var b strings.Builder
	if !cache.LastSync.IsZero() {
		fmt.Fprintf(&b, "_Synced: %s_\n\n", cache.LastSync.UTC().Format(time.RFC3339))
	}
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
