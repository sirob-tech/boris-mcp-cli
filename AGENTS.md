# Agent guidance for boris-mcp-cli

## Commit messages

All commits to `main` must use [Conventional Commits](https://www.conventionalcommits.org/) prefixes. release-please parses these to compute the next version bump and update `CHANGELOG.md`.

Prefixes that trigger a release:

- `feat: ...` → minor bump (`0.1.x` → `0.2.0`)
- `fix: ...` → patch bump (`0.1.0` → `0.1.1`)
- `feat!: ...` or any commit body with `BREAKING CHANGE:` → minor bump while the
  version is below 1.0.0 (`0.3.0` → `0.4.0`), major bump after that (`1.2.3` →
  `2.0.0`). `bump-minor-pre-major` in `release-please-config.json` is what holds
  0.x back from jumping straight to 1.0.0.

Prefixes that do **not** trigger a release (still required for clean history):

- `chore:`, `docs:`, `ci:`, `refactor:`, `test:`, `style:`, `perf:`, `build:`

Without a recognised prefix, release-please ignores the commit — the change ships in the source tree but no version PR opens. Always pick the closest-fitting prefix.

## Release flow

1. Merge conventional commits to `main`.
2. `release-please` opens/updates a `chore(main): release X.Y.Z` PR with version bump + CHANGELOG.
3. Merging that PR creates the `vX.Y.Z` tag **and the GitHub release object**.
4. The tag triggers `.github/workflows/release.yml` on `macos-latest`:
   - GoReleaser builds darwin/linux × amd64/arm64
   - macOS binaries are signed (Developer ID) and notarized (Apple notarytool, `wait: true`)
   - Tarballs + `checksums.txt` upload to GitHub Releases
   - Homebrew formula pushed to `sirob-tech/homebrew-tap/Formula/bmcp.rb` via a GitHub App installation token (no PAT)
5. `smoke` installs the published release through `install.sh` on Linux and macOS.
6. `publication-state` promotes the release to Latest, or marks it prerelease if
   anything above failed.

Do not hand-tag releases unless recovering from a broken release-please state.

### Why steps 5 and 6 exist

release-please publishes the release object *before* GoReleaser has anything to
put in it. Between those two moments the release is real, it is what
`/releases/latest` resolves to, and it contains nothing — so `curl … | sh`
returns 404 for everyone. If GoReleaser then fails, that state is permanent.
This is how `v0.4.0` shipped: Apple rejected notarization with
`FORBIDDEN.REQUIRED_AGREEMENTS_MISSING_OR_EXPIRED`, and installs stayed broken
because no job checked whether the release was installable.

`publication-state` bounds that window to the length of one workflow run.
`smoke` is what tells it which way to go, and it tests over the public download
URLs — an authenticated check would pass on a release the public cannot fetch.

### Before releasing

`.github/workflows/release-preflight.yml` runs the whole signing and
notarization path against real Apple servers and stops short of publishing. It
runs automatically on every release-please PR, weekly on a schedule, and on
demand:

```sh
gh workflow run release-preflight.yml
```

Run it if a release has not gone out in a while. Signing depends on an Apple
agreement, a certificate, and an App Store Connect key — all of which expire
outside this repository, and none of which anything else notices.

### Recovering a broken release

Re-run the release **from the default branch**, passing the tag:

```sh
gh workflow run release.yml --ref main -f tag=vX.Y.Z
```

Do not use GitHub's "re-run jobs" button. It replays the workflow as it existed
at the tag, so a release broken by a pipeline bug gets retried by the same
broken pipeline. Uploads are idempotent (`replace_existing_artifacts`), and a
successful run promotes the tag back to Latest — no deleting or re-tagging.

## Releases reach machines by themselves

Installed binaries self-update, so a release is not a thing users opt into — it
propagates on its own the next time any machine runs `bmcp doctor`, `bmcp sync`,
or `bmcp init`. Two consequences worth holding onto:

- **Signing is a precondition, not a nicety.** `.goreleaser.yaml` signs
  unconditionally and `release.yml` refuses to publish without the signing
  secrets. An unsigned release is one that macOS clients will eventually refuse
  to install, once `codesignFailClosed` is enabled in `cmd/bmcp/update.go`.
- **`bump-minor-pre-major: true` means breaking changes are minor bumps**, so
  no semver gate can express "safe to apply unattended". A `feat!:` merged today
  reaches every machine automatically. If a change would break a caller's
  scripts, say so in the release notes and consider whether it should wait.

The blast radius of a bad release is quiet: if it makes `bmcp doctor` exit
non-zero, agents read that as "BORIS is broken" and simply stop using it. No
pipeline turns red. `bmcp update --rollback` restores the previous binary on a
single machine; marking a release `prerelease: true` stops it spreading further
but does not heal machines that already took it.
