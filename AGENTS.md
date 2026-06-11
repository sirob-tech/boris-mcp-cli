# Agent guidance for boris-mcp-cli

## Commit messages

All commits to `main` must use [Conventional Commits](https://www.conventionalcommits.org/) prefixes. release-please parses these to compute the next version bump and update `CHANGELOG.md`.

Prefixes that trigger a release:

- `feat: ...` → minor bump (`0.1.x` → `0.2.0`)
- `fix: ...` → patch bump (`0.1.0` → `0.1.1`)
- `feat!: ...` or any commit body with `BREAKING CHANGE:` → major bump (`0.x.y` → `1.0.0`)

Prefixes that do **not** trigger a release (still required for clean history):

- `chore:`, `docs:`, `ci:`, `refactor:`, `test:`, `style:`, `perf:`, `build:`

Without a recognised prefix, release-please ignores the commit — the change ships in the source tree but no version PR opens. Always pick the closest-fitting prefix.

## Release flow

1. Merge conventional commits to `main`.
2. `release-please` opens/updates a `chore(main): release X.Y.Z` PR with version bump + CHANGELOG.
3. Merging that PR creates a `vX.Y.Z` tag.
4. The tag triggers `.github/workflows/release.yml` on `macos-latest`:
   - GoReleaser builds darwin/linux × amd64/arm64
   - macOS binaries are signed (Developer ID) and notarized (Apple notarytool, `wait: true`)
   - Tarballs + `checksums.txt` upload to GitHub Releases
   - Homebrew formula pushed to `sirob-tech/homebrew-tap/Formula/bmcp.rb` via a GitHub App installation token (no PAT)

Do not hand-tag releases unless recovering from a broken release-please state.
