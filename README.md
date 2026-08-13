# bmcp

B.O.R.I.S. MCP to CLI converter.

`bmcp` lets local AI coding agents query the remote BORIS MCP server hosted
on AWS AgentCore through a regular CLI. It handles SigV4 auth, tool discovery,
schema caching, validation, and MCP text-envelope unwrapping.

## Why this exists

The MCP protocol is brittle in real-world use, especially when the server is
behind real auth. Wrapping the remote MCP server as a CLI bypasses several
rough edges at once:

- **Auth and transport are handled once, in one place.** SigV4 signing, region
  inference, and the AWS credential chain live in this binary instead of
  inside each harness's MCP client.
- **One-step config and install.** `bmcp init` saves config; `bmcp install
  <claude-code|codex|opencode|cursor|kiro|all>` drops a small instructions file
  into each harness. No per-harness MCP server registration to maintain.
- **No separate skill to distribute.** The installer emits a single `BORIS.md`
  whose contents are generated from the live tool catalog, so updating agent
  guidance for a new tool is `bmcp sync` — not a new release of a Claude
  skill, Cursor rule, or Codex prompt.
- **Cheaper context.** Native MCP clients load every tool's full JSON schema
  into the agent's context on every turn. With `bmcp` the agent sees a short
  tool list up front and calls `bmcp describe <tool>` only when it actually
  needs the schema — one tool at a time, on demand.

## Install

### Install script (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/sirob-tech/boris-mcp-cli/main/install.sh | sh
```

Pin a version with `BMCP_VERSION=v0.1.0` or choose an install directory with
`BMCP_INSTALL_DIR=/usr/local/bin`. The script verifies the download against the
release `checksums.txt` before installing.

This is the recommended path because it is the only one that can keep itself
current — see [Keeping bmcp current](#keeping-bmcp-current). `bmcp` is driven
mostly by AI coding agents, which will not act on a "please upgrade" message,
so a stale binary tends to stay stale.

### Homebrew

```bash
brew install sirob-tech/tap/bmcp
```

Or tap first:

```bash
brew tap sirob-tech/tap
brew install bmcp
```

Homebrew installs cannot update themselves: replacing a binary under
Homebrew's prefix leaves its metadata describing a version that is no longer
there. `bmcp` detects this and tells you to run `brew upgrade` instead. The
same applies to any layout that stores the binary under a directory named after
its version — mise, asdf, Nix, MacPorts — which `bmcp` also refuses to replace
in place. Upgrade Homebrew installs with:

```bash
brew upgrade sirob-tech/tap/bmcp
```

### Avoid conflicting installations

Use either Homebrew or the install script for routine upgrades. The install
script defaults to `~/.local/bin`, while Homebrew installs under its own prefix.
If both exist, whichever directory appears first on `PATH` wins, so a successful
Homebrew upgrade may still leave an older install-script binary active.

Check all installed copies and the active version with:

```bash
which -a bmcp
bmcp version
```

When switching to Homebrew, remove a previous install-script copy and clear the
shell command cache:

```bash
rm ~/.local/bin/bmcp
hash -r
```

Only remove that path after confirming it is the old install-script copy. The
install script verifies the exact binary it writes and warns when another copy
takes precedence on `PATH`.

### Manual download

Download the tarball for your platform from
[GitHub Releases](https://github.com/sirob-tech/boris-mcp-cli/releases) and
verify it against `checksums.txt`:

```text
bmcp-darwin-amd64.tar.gz
bmcp-darwin-arm64.tar.gz
bmcp-linux-amd64.tar.gz
bmcp-linux-arm64.tar.gz
```

Extract and place `bmcp` on your `PATH`.

## Build from source

For development:

```bash
go build -o bmcp ./cmd/bmcp
```

Put the binary somewhere on `PATH`, for example:

```bash
ln -s "$(pwd)/bmcp" ~/.local/bin/bmcp
```

Source builds never self-update — there is no release that corresponds to them.

## Keeping bmcp current

`bmcp` keeps itself up to date. It checks for a new release, and installs one,
only when you run `bmcp doctor`, `bmcp sync`, or `bmcp init`. Tool calls never
check for updates and never pay for a network round trip.

After a successful update the current command finishes on the version it
already loaded; the new one takes effect on the next invocation.

What is verified before a downloaded binary replaces the running one:

- Its SHA-256 is checked against the release `checksums.txt`, which fails
  closed — a missing file, or one with no line for this platform's asset, aborts
  the update rather than skipping the check. `checksums.txt` comes from the same
  GitHub release as the archive, so this establishes that the bytes arrived
  intact, not that they came from us.
- The bytes are read back off disk after staging and re-hashed, so a short or
  truncated write cannot be committed over a working binary.
- On macOS the Developer ID signature is verified with `codesign`. **This is
  currently advisory: a failure warns and the update proceeds.** It stays that
  way for one release, because a fleet that refuses every update cannot receive
  the fix for whatever made it refuse. On Linux there is no signature check at
  all — the release artifacts are not signed for that platform.

The practical consequence: today the trust root is GitHub. Anything able to
replace a published release asset can reach installed binaries. If that is
outside your risk tolerance, set `auto_update = "false"` and upgrade
deliberately.

```bash
bmcp update              # update to the latest release
bmcp update --check      # report what is available, change nothing
bmcp update --to v0.4.0  # move to an exact version, downgrading if needed
bmcp update --rollback   # restore the binary the last update replaced
```

`bmcp doctor` reports the version state on its own line, and never fails
because of it — a GitHub outage is not a BORIS outage.

### Turning auto-update off

Any one of these disables automatic updates and prints a one-line nudge
instead. Precedence is flag, then environment, then config file.

```bash
bmcp doctor --no-auto-update        # this command only
export BMCP_AUTO_UPDATE=false       # this shell
```

```toml
# ~/.bmcp/config.toml
auto_update = "false"
```

Three things worth knowing:

- `auto_update` lives under `BMCP_HOME`, which can vary per project, while the
  binary is machine-wide. One project opting out does not stop another
  invocation from updating the shared binary. The environment variable and the
  flag are the reliable levers.
- Turning auto-update off stops the *install*, not the *check* — the nudge has
  to know a new version exists in order to mention it. In an egress-restricted
  environment `bmcp doctor` will therefore spend up to 15s failing to reach
  GitHub before continuing; it never changes doctor's exit code.
- Setting `BMCP_VERSION` pins a version. `bmcp update` then converges to
  exactly that version, downgrading if needed, so a machine carrying a bad
  release can be healed rather than frozen on it. Auto-update stands down
  entirely while a pin is set — it will report the gap but never downgrade you
  unattended.

### If an update goes wrong

```bash
bmcp update --rollback
```

That restores the binary the last update replaced, and puts a hold on the
version you rolled back from so the next `bmcp doctor` does not simply install
it again. The hold is per-machine and is lifted as soon as you ask for that
version explicitly (`bmcp update --to vX.Y.Z`) or a newer release appears.

If there is no backup, or the install is otherwise broken, reinstall a
known-good version:

```bash
BMCP_VERSION=v0.3.0 curl -fsSL https://raw.githubusercontent.com/sirob-tech/boris-mcp-cli/main/install.sh | sh
```

`bmcp version` prints the last update it applied, which is the first thing to
check when something worked yesterday and does not today.

## Configure

Run first-time setup:

```bash
bmcp init --url <url> --profile <aws-profile>
```

`--profile` is optional; if omitted, the AWS SDK default credential chain is
used. The BORIS MCP server requires AWS credentials for any account in the AWS
Organization. `init` saves config, syncs the remote tool catalog, and in
interactive sessions offers to install agent instructions for detected
harnesses.

Harness detection checks for a known executable on `PATH` or an existing config
directory such as `~/.claude`, `~/.codex`, `~/.config/opencode`, `~/.cursor`,
or `~/.kiro`. Kiro is detected from either `kiro-cli` or `kiro` on `PATH`. Each detected harness is
prompted separately and defaults to yes. Use `--non-interactive` to disable
prompts.

Additional configuration flags:

- `--region <region>`: override the SigV4 region.
- `--service <service>`: override the SigV4 service.
- `--allow-http`: allow non-localhost `http://` BORIS URLs.
- `--no-auto-update`: do not update automatically during this command.

Update-related settings, in precedence order (flag, environment, config file):

| Setting | Where | Meaning |
| --- | --- | --- |
| `--no-auto-update` | flag | Disable automatic updates for this command |
| `BMCP_AUTO_UPDATE` | environment | `false` disables automatic updates |
| `auto_update` | `config.toml` | `"false"` disables automatic updates |
| `BMCP_VERSION` | environment | Pin a version; `bmcp update` converges to it |

A value that is neither true nor false is reported and ignored rather than
treated as "off", so a typo cannot silently stop a machine receiving updates.

Check setup:

```bash
bmcp doctor
```

## Install Agent Instructions

The installer does not register BORIS as a local MCP server. It writes
instructions that teach agents to call the existing `bmcp` CLI and include
the currently synced BORIS tool catalog. Run `bmcp init` first so the
installer has config and a tool catalog to read.

User-global install is the default:

```bash
bmcp install claude-code
bmcp install codex
bmcp install opencode
bmcp install cursor
bmcp install kiro
bmcp install all
```

Project-local install:

```bash
bmcp install claude-code --scope project
bmcp install codex --scope project
bmcp install opencode --scope project
bmcp install cursor --scope project
bmcp install kiro --scope project
```

User-scope targets:

- Claude Code: `~/.claude/BORIS.md`, referenced from `~/.claude/CLAUDE.md`
- Codex: `~/.codex/BORIS.md`, inlined into a managed block in `~/.codex/AGENTS.md`
- OpenCode: `~/.config/opencode/BORIS.md`, inlined into a managed block in
  `~/.config/opencode/AGENTS.md`
- Cursor: `~/.cursor/rules/boris.mdc`
- Kiro: `~/.kiro/steering/boris.md`

Project-scope targets:

- Claude Code: `./BORIS.md`, referenced from `./CLAUDE.md`
- Codex: `./BORIS.md`, inlined into a managed block in `./AGENTS.md`
- OpenCode: `./BORIS.md`, inlined into a managed block in `./AGENTS.md`
  (shared with Codex)
- Cursor: `./.cursor/rules/boris.mdc`
- Kiro: `./.kiro/steering/boris.md`

Existing files are modified in place. When a file changes, a timestamped
`.bak-<timestamp>` backup is created and printed.

Refresh tools and installed instructions:

```bash
bmcp sync
```

`sync` refreshes the local tool cache and updates any existing BORIS instruction
files it finds, without installing new harnesses.

## Use

```bash
bmcp list
bmcp describe <tool>
bmcp <tool> --arg value
bmcp call <tool> '{"arg":"value"}'
bmcp update
```

Successful tool calls unwrap MCP text envelopes internally and print the useful
payload directly. Use `--pretty` to format JSON payloads and `--raw` to inspect
the original MCP envelope.

### `bmcp list` output

`list` writes NDJSON to stdout — one JSON object per line, nothing else. The
`%d tools synced <timestamp>` header goes to stderr, so stdout stays parseable
even when piped through `head`, and an empty catalog is empty stdout with
exit 0.

```json
{"name":"tools___search_infrastructure_graph","display_name":"search_infrastructure_graph","description":"Multi-hop, aggregation…","last_sync":"2026-08-13T16:44:41Z"}
```

| Field | Meaning |
|---|---|
| `name` | Full tool name. Always callable — use this to call the tool. Also the only unique key: two namespaces can share a `display_name`. |
| `display_name` | Short alias with the namespace prefix stripped. Convenience only. |
| `description` | Verbatim, including authored newlines (JSON-escaped, so one record stays one line). Always present, empty string when the tool has none. |
| `last_sync` | Catalog sync time in RFC 3339. Omitted when the cache has no timestamp. |

Descriptions are not HTML-escaped, so grepping raw lines for `<region>` works.
Parse the lines as JSON rather than matching on field or column positions.

Two things worth knowing when consuming this:

- **`head` truncates safely but silently.** Every line is a complete record, so
  `head -5` never yields invalid JSON — but it does hide tools, without any
  marker in stdout. The total count is on stderr; compare it if completeness
  matters.
- **Pipe records, do not `echo` them.** `echo "$line" | jq` expands the `\n`
  escapes inside a description and corrupts the JSON. Use `printf '%s'` or feed
  `jq` the stream directly.

For a human-readable catalog, pass `--output human` — each name flush left with
its description indented two spaces:

```bash
bmcp list --output human
```

`--output` accepts `ndjson` (default), `json` as an alias for it, and `human`.
Any other value, including an empty `--output=`, exits 5; omitting the value
(`bmcp list --output`) is a flag-parse error and exits 1, like every other
value-taking flag.

Only `list` reads it — other commands accept and ignore it. As a global flag it
always works before the command name. After the command name, `help`, `version`
and `install` take their arguments verbatim (`install` rejects it outright), as
does the tool in the `bmcp <tool> --arg value` form. Putting `--output` first is
always safe.
