# bmcp binary distribution — agent handoff

**Status:** Phases 1–3 implemented; Phase 0 (Apple signing) and Phase 4 (first release) pending  
**Last updated:** 2026-06-07  
**Repo:** `github.com/sirob-tech/boris-mcp-cli` (currently private; make public before first customer release)

This document captures research, stakeholder decisions, and an implementation plan for distributing pre-built `bmcp` binaries on macOS and Linux via GitHub Releases, Homebrew, and a curl installer. A prior agent session explored [rtk-ai/rtk](https://github.com/rtk-ai/rtk) as a reference and aligned with the product owner through structured interviews.

---

## Goal

Ship installable `bmcp` binaries for **external customers/partners** through:

1. **GitHub Releases** — downloadable tarballs + `checksums.txt`
2. **Homebrew** — Formula in this repo (`Formula/bmcp.rb`)
3. **`install.sh`** — RTK-style `curl | sh` installer

Build and release automation: **GoReleaser OSS** + **release-please** on `main`.

---

## Project context

| Item | Value |
|------|-------|
| Module | `github.com/sirob-tech/boris-mcp-cli` |
| Binary | `bmcp` (built from `./cmd/bmcp`) |
| Language | Go 1.24, pure Go (`CGO_ENABLED=0` viable) |
| License | Apache-2.0 |
| Current version | `0.1.0` hardcoded in `cmd/bmcp/main.go` |
| Build metadata | `buildCommit`, `buildDate` vars (default `"unknown"`) |
| CI/CD today | **None** — no `.github/`, no `.goreleaser.yaml` |
| Config at runtime | `bmcp init` — no secrets baked into binary |

`bmcp version` prints version, commit, and build date (`cmd/bmcp/commands.go`).

---

## Reference: how RTK distributes (rtk-ai/rtk)

RTK is **Rust**, not Go, and does **not** use GoReleaser. Still useful as a distribution pattern reference.

### What RTK does

- **Custom GitHub Actions** (`release.yml`): `cargo` cross-compile matrix, package tarballs/zip, `checksums.txt`, GitHub Release upload
- **Platforms:** `darwin` amd64/arm64, `linux` musl amd64, `linux` gnu arm64, `windows` amd64
- **No macOS code signing** in their pipeline
- **`install.sh`:** OS/arch detection, download from releases, path-traversal checks, install to `~/.local/bin`
- **Homebrew:** separate repo `rtk-ai/homebrew-tap` with a **Formula** (not Cask) that downloads pre-built binaries + sha256 from GitHub releases; updated automatically post-release via `gh api`
- **Versioning:** release-please on `master`; RC pre-releases from `develop` (we are **not** doing this)

### Key files to read on RTK

- `.github/workflows/release.yml` — build matrix, checksums, homebrew formula generation
- `.github/workflows/CICD.md` — flow diagrams
- `install.sh` — installer script
- `Formula/rtk.rb` — template formula (placeholders replaced in CI)

### What we adopt from RTK

- Pre-built binary releases + `checksums.txt`
- `install.sh` pattern
- Homebrew **Formula** pointing at release artifacts (not Cask)
- release-please for versioning (stable-only, no develop RC track)

### What we do differently

- **GoReleaser** instead of custom cargo CI
- **macOS sign + notarize** from v0.1.0 (customer-facing)
- **Formula in same repo** (`Formula/bmcp.rb`) — see open question #1
- **Fewer platforms** (no Windows in v1)
- **Fully static Linux** builds (both amd64 and arm64)

---

## Signing requirements (research summary)

### macOS — YES, sign and notarize

| Channel | Signing needed? | Notes |
|---------|-----------------|-------|
| GitHub release download | **Yes** | Quarantine + Gatekeeper friction on unsigned binaries; Apple Silicon is strict |
| `curl \| sh` installer | **Yes** | Same as direct download |
| Homebrew Formula (our model) | Not enforced by Homebrew | Sept 2026 Gatekeeper crackdown targets **Casks**, not Formulas. Signing still improves UX for binaries inside the tarball. |
| GoReleaser `homebrew_casks` | Would expect signing | We chose **Formula** (`brews`), not Cask — RTK model |

**Implementation:** GoReleaser OSS `notarize.macos` block with secrets (Charmbracelet pattern):

- `MACOS_SIGN_P12` (base64 Developer ID Application `.p12`)
- `MACOS_SIGN_PASSWORD`
- `MACOS_NOTARY_ISSUER_ID`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_KEY` (notarytool API)

Reference: `https://raw.githubusercontent.com/charmbracelet/meta/main/notarize.yaml`

**Cost:** Apple Developer Program ~$99/year. **Stakeholder said certs need full setup** — not yet enrolled.

**CI note:** Notarization must run on a **macOS** GitHub Actions runner.

### Linux — NO OS-level signing

- No Gatekeeper equivalent
- **sha256 `checksums.txt` only** (stakeholder decision; no GPG/cosign in v1)
- Static binaries (`CGO_ENABLED=0`) for amd64 + arm64

---

## Locked-in stakeholder decisions

| Topic | Decision |
|-------|----------|
| Audience | External customers/partners |
| Repo visibility | **Public before first release** |
| Platforms | `darwin` amd64 + arm64, `linux` amd64 + arm64 |
| Linux linking | Fully static (`CGO_ENABLED=0`) |
| Release tooling | GoReleaser **OSS** |
| Versioning | **release-please** on `main`, **stable only** (no develop RC track) |
| Homebrew | **Formula** in `Formula/bmcp.rb` (same repo) |
| macOS signing | **Yes, from v0.1.0** |
| Checksum signing | sha256 only (`checksums.txt`) |
| Extra channel | `install.sh` |
| Windows | **Not in v1** (implicit from platform choice) |
| Apple certs | **Need setup** — enrollment + secrets |

---

## release-please flow (chosen strategy)

```text
Developer merges conventional commit to main
  → release-please workflow opens/updates "chore(main): release X.Y.Z" PR
    (bumps version, updates CHANGELOG)
  → Human merges Release PR
    → release-please creates git tag vX.Y.Z
      → tag push triggers GoReleaser release workflow
        → build, sign (macOS), notarize, upload artifacts, update Formula/
```

**Conventional commit bumps:**

- `feat:` → minor
- `fix:` → patch
- `feat!:` or `BREAKING CHANGE:` → major
- `chore:`, `docs:`, `ci:` → typically no release (configurable)

**release-please does not build binaries.** GoReleaser runs on the tag.

---

## Implementation plan (for next agent)

### Phase 0 — Apple Developer (blocker for signed macOS)

1. Enroll org/personal in Apple Developer Program
2. Create **Developer ID Application** certificate → export `.p12`
3. App Store Connect → create **notarytool** API key → `.p8`
4. Add GitHub Actions secrets (see Signing section above)

**Open:** Personal vs Sirob org account — affects cert identity string.

### Phase 1 — Version + build plumbing

**Files to create/modify:**

| File | Purpose |
|------|---------|
| `cmd/bmcp/main.go` | Keep `version` injectable via `-ldflags -X main.version=...` (may stay `const` or become `var` — GoReleaser commonly uses `var`) |
| `.goreleaser.yaml` | Builds, archives, checksums, notarize, brews |
| `release-please-config.json` | Configure version bump targets |
| `.release-please-manifest.json` | Current version `0.1.0` |

**GoReleaser build sketch:**

```yaml
version: 2
before:
  hooks: [go mod tidy]
builds:
  - main: ./cmd/bmcp
    binary: bmcp
    env: [CGO_ENABLED=0]
    goos: [darwin, linux]
    goarch: [amd64, arm64]
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.buildCommit={{.Commit}}
      - -X main.buildDate={{.Date}}
archives:
  - format: tar.gz
    name_template: "{{ .ProjectName }}-{{ .Arch }}-{{ .Os }}"
checksum:
  name_template: checksums.txt
notarize:
  macos:
    - enabled: '{{ isEnvSet "MACOS_SIGN_P12" }}'
      sign:
        certificate: "{{.Env.MACOS_SIGN_P12}}"
        password: "{{.Env.MACOS_SIGN_PASSWORD}}"
      notarize:
        issuer_id: "{{.Env.MACOS_NOTARY_ISSUER_ID}}"
        key_id: "{{.Env.MACOS_NOTARY_KEY_ID}}"
        key: "{{.Env.MACOS_NOTARY_KEY}}"
brews:
  - name: bmcp
    repository:
      owner: sirob-tech
      name: boris-mcp-cli
      token: "{{ .Env.GITHUB_TOKEN }}"
    directory: Formula
    homepage: https://github.com/sirob-tech/boris-mcp-cli
    description: BORIS MCP to CLI converter
    license: Apache-2.0
    install: |
      bin.install "bmcp"
    test: |
      system "#{bin}/bmcp", "version"
release:
  github:
    owner: sirob-tech
    name: boris-mcp-cli
```

**Note on `brews` deprecation:** GoReleaser soft-deprecates `brews` in favor of `homebrew_casks`. Stakeholder explicitly chose **Formula + prebuilt binary** (RTK model). `brews` is correct for now; watch GoReleaser v3. Alternative: RTK-style manual formula commit in CI (shell heredoc) for more control.

**Archive naming:** Align with `install.sh` expectations. RTK uses `{binary}-{target}.tar.gz` (e.g. `rtk-aarch64-apple-darwin.tar.gz`). GoReleaser default may differ — pick one convention and use it consistently in `install.sh` and Formula.

### Phase 2 — CI workflows

| Workflow | Trigger | Action |
|----------|---------|--------|
| `.github/workflows/ci.yml` | PR + push to `main` | `go test ./...` |
| `.github/workflows/release-please.yml` | push to `main` | `googleapis/release-please-action` |
| `.github/workflows/release.yml` | tag `v*` | `goreleaser/goreleaser-action` on **`macos-latest`** |

**Permissions for release workflow:**

- `contents: write` (releases, formula commit)
- `id-token: write` only if cosign added later (not in v1)

**Local smoke test before first release:**

```bash
goreleaser release --snapshot --clean
# unsigned locally if MACOS_SIGN_* not set; notarize block should be disabled via isEnvSet
```

### Phase 3 — Distribution artifacts

**Expected GitHub Release assets:**

```text
bmcp-darwin-amd64.tar.gz    # or aligned naming — see above
bmcp-darwin-arm64.tar.gz
bmcp-linux-amd64.tar.gz
bmcp-linux-arm64.tar.gz
checksums.txt
```

**`install.sh`** (new file at repo root):

- Port patterns from RTK `install.sh`: OS/arch detect, latest version via redirect (avoid API rate limits), `RTK_VERSION`-style pin via `BMCP_VERSION`, path traversal check on tarball, install to `~/.local/bin`, verify with `bmcp version`
- Support `BMCP_INSTALL_DIR` env override

**Homebrew install UX (after tap):**

```bash
brew install sirob-tech/boris-mcp-cli/bmcp
# or
brew tap sirob-tech/boris-mcp-cli && brew install bmcp
```

**README updates:** Add Install section (Homebrew primary, curl script, manual download). Keep existing build-from-source as dev option.

### Phase 4 — First release checklist

- [ ] Apple secrets in GitHub Actions
- [ ] CI green
- [ ] `goreleaser release --snapshot --clean` succeeds locally
- [ ] Repo made public
- [ ] Merge first release-please PR → tag `v0.1.0`
- [ ] Verify macOS arm64: brew, curl installer, direct download
- [ ] Verify linux amd64 + arm64
- [ ] Customer-facing install docs

---

## Open questions (unresolved — ask stakeholder if needed)

### 1. Formula commit strategy (same repo)

GoReleaser `brews` typically commits `Formula/bmcp.rb` to `main` **after** the release tag, creating a post-tag commit. RTK avoids this with a **separate** `homebrew-tap` repo.

Stakeholder chose same-repo Formula. Confirm they accept post-release commits on `main`, or switch to `sirob-tech/homebrew-tap`.

### 2. Windows

Explicitly out of v1. Confirm no customer need before adding `windows/amd64`.

### 3. Universal vs customer-specific builds

One universal binary (URL configured at `bmcp init`) is assumed. Confirm no per-customer default URL or build tags.

### 4. GoReleaser `brews` vs manual Formula

Stakeholder prefers GoReleaser OSS with `brews`. Fallback: RTK-style formula generation in `release.yml` if `brews` deprecation or same-repo commit behavior is problematic.

### 5. Apple Developer account owner

Org vs personal enrollment — affects `Developer ID Application: ...` identity in CI logs and user trust prompts.

---

## GoReleaser vs Homebrew model notes

- **`brews` → Formula:** installs pre-built binary from GitHub release URL + sha256. Matches RTK. Works on macOS and Linux.
- **`homebrew_casks` → Cask:** Homebrew’s newer path for pre-built binaries; expects signed macOS binaries for official tap compliance by Sept 2026. We are **not** using Casks for v1.
- **homebrew-core:** eventual aspiration possible; core prefers build-from-source. Out of scope for v1.

Useful links:

- GoReleaser notarize: https://goreleaser.com/customization/sign/notarize/
- GoReleaser homebrew_casks (for context): https://goreleaser.com/customization/publish/homebrew_casks/
- GoReleaser deprecations (`brews`): https://goreleaser.com/resources/deprecations/
- Homebrew 5.0 / Gatekeeper (Casks only): https://workbrew.com/blog/homebrew-5-0-0

---

## Files that do not exist yet (create these)

```text
.goreleaser.yaml
.github/workflows/ci.yml
.github/workflows/release-please.yml
.github/workflows/release.yml
release-please-config.json
.release-please-manifest.json
Formula/bmcp.rb          # generated/managed by GoReleaser on first release
install.sh
CHANGELOG.md             # created by release-please on first run
docs/DISTRIBUTION_HANDOFF.md  # this file
```

---

## Suggested order of work for next agent

1. Resolve open question #1 (same-repo Formula commits vs separate tap) if blocking
2. Phase 1: `.goreleaser.yaml`, version ldflags, release-please config
3. Phase 2: CI workflows (ci + release-please + release)
4. Phase 3: `install.sh`, README install section
5. Document Apple setup steps in README or `docs/APPLE_SIGNING.md` (optional)
6. Phase 0 can run in parallel with 1–4 if secrets not ready — use `enabled: '{{ isEnvSet "MACOS_SIGN_P12" }}'` so unsigned snapshot builds work
7. First release only after Apple secrets + repo public

---

## Testing commands

```bash
# Dev build (existing)
go build -o bmcp ./cmd/bmcp

# After GoReleaser added
goreleaser build --snapshot --clean
goreleaser release --snapshot --clean

# After install.sh added
curl -fsSL https://raw.githubusercontent.com/sirob-tech/boris-mcp-cli/main/install.sh | sh

# After Formula published
brew install sirob-tech/boris-mcp-cli/bmcp
bmcp version
bmcp doctor
```

---

## Conversation reference

Planning session: stakeholder interview via Cursor agent, 2026-06-07. RTK exploration via GitHub API and raw workflow files on `develop` branch.
