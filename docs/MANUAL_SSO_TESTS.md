# Manual tests for SSO login and credential stores

CI covers the login, refresh, locking and store logic against a fake IAM
Identity Center. It cannot cover what depends on a real machine: Keychain
access lists, Secret Service on a real session bus, a real Identity Center, and
a browser. Run this checklist before merging a change to `ssologin.go`,
`ssoprovider.go`, `sessionlock.go` or `credstore*.go`, and on the first release
after such a change.

You need an SSO profile in `~/.aws/config` and a working `~/.bmcp/config.toml`.
Every login step needs a person at the browser: a device code expires after 10
minutes.

## macOS: use signed builds

The Keychain trusts an item's creator by its code signature, so unsigned local
builds show different behaviour: prompts in a terminal, `store_locked` under
agents. Use the signed preflight builds instead.

1. Run the preflight on the branch twice, waiting for the first to finish (a
   second run on the same ref cancels the first):
   `gh workflow run release-preflight.yml --ref <branch>`
2. Download both: `gh run download <run-id>`. Each holds
   `bmcp-darwin-{arm64,amd64}.tar.gz`, versioned `0.0.0-preflight.<run>.<attempt>`.
3. Unpack build 1 to a scratch path, e.g. `/tmp/bmcp-test/bin/bmcp`.
4. Set `BMCP_AUTO_UPDATE=false` for every command. Preflight builds are version
   0.0.0, so the update check would replace them with the latest release.

Avoid `bmcp doctor` and `bmcp sync` with these builds. A completed sync
rewrites your agent instruction files from the build's template. If it happens,
run your installed `bmcp doctor` to put them back.

| Check | How | Expected |
|---|---|---|
| Native login into the Keychain | `bmcp login` with build 1 | Browser opens; output says `Stored in the keychain credential store; refreshable: yes` |
| Other programs are prompted | `security find-generic-password -s bmcp -w` in a terminal | A Keychain dialog. **Click Deny**: allowing prints a live token. `security dump-keychain -a` shows the item's access list with no secrets: one trusted app, matched by the `bmcp` designated requirement, and a `teamid:` partition |
| Role credentials cached | Any tool call, then count items: `security dump-keychain \| grep -c '"svce"<blob>="bmcp"'` | Two items: the SSO token and one role credential |
| Trust survives a new build | Copy build 2 over build 1 at the same path, then `bmcp --format json --non-interactive <tool>` | `ok: true`. A prompt would surface as `store_locked`, because `--non-interactive` forbids UI |
| One login for parallel callers | `bmcp clear`; start `bmcp login`; while it waits, run 8 `bmcp --format json <tool>` in parallel | One browser approval; all 8 exit 0 |
| Silent refresh | Wait until the token is within 15 minutes of expiry, then `bmcp login` | `Refreshed the AWS SSO session …` with a later expiry, no browser |
| Clear | `bmcp clear` | No `bmcp` items left in the Keychain |

## Linux: run in containers

Build a static binary: `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/bmcp-linux ./cmd/bmcp`.
Mount into `debian:stable-slim`, read-only:
- the binary;
- a copy of `~/.aws/config` holding only the test profile;
- `~/.bmcp/config.toml`, at `/root/.bmcp/config.toml`;
- on macOS hosts, `/etc/ssl/cert.pem` at `/etc/ssl/certs/ca-certificates.crt`, since the slim image has no CA bundle.

Pass `-e BMCP_AUTO_UPDATE=false`.

| Check | Setup | Expected |
|---|---|---|
| No D-Bus | Plain container; `bmcp login --device-code`, a tool call, `bmcp doctor` | `doctor` shows `backend ok aws-cli-cache (plaintext, auto)`; token in `~/.aws/sso/cache` and role credentials in `~/.cache/bmcp/creds`, both `0600` |
| GNOME Keyring | `apt-get install dbus gnome-keyring libsecret-tools ca-certificates`, then inside `dbus-run-session`: `printf pw \| gnome-keyring-daemon --unlock --components=secrets`, then the same commands | `doctor` shows `secret-service (auto)`; no plaintext files; `secret-tool search --all application bmcp` lists two items, none after `bmcp clear` |
| SSH picks device code | `-e SSH_CONNECTION="10.0.0.1 50000 10.0.0.2 22"`, `bmcp login` without `--device-code` | The printed URL is a `device?user_code=` link, not `/authorize` |

## After the first release

These need a real release and cannot be checked earlier. Run them on a Mac
holding a Keychain token from the previous release.
- `bmcp update`: the next call reads the Keychain with no prompt.
- `brew upgrade bmcp`: the next call reads the Keychain with no prompt.

## Cleanup

Run `bmcp clear` with the build under test. If a token was printed anywhere,
also sign out of the AWS access portal: `clear` deletes only local copies, and
the refresh token stays valid until the session ends.
