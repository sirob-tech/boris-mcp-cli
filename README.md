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
- On macOS the Developer ID signature is verified with `codesign` against a
  pinned Team ID, and **a failure aborts the update** — the staged binary is
  discarded and the running one is left untouched. This was advisory for one
  release (v0.5.0, the first shipped under fail-closed signing), because a fleet
  that refuses every update cannot receive the fix for whatever made it refuse.
  On Linux there is no signature check at all — the release artifacts are not
  signed for that platform.

The practical consequence: on Linux the trust root is GitHub, so anything able
to replace a published release asset can reach installed binaries. On macOS a
substituted asset is rejected unless it also carries a valid Developer ID
signature from the pinned team. If that is outside your risk tolerance, set
`auto_update = "false"` and upgrade deliberately.

```bash
bmcp update              # update to the latest release
bmcp update --check      # report what is available, change nothing
bmcp update --to v0.4.0  # move to an exact version, downgrading if needed
bmcp update --rollback   # restore the binary the last update replaced
```

`bmcp doctor` reports the version state on its own line, and a failed update
check never changes its exit code — a GitHub outage is not a BORIS outage. The
one exception is an update that left no working binary at the install path:
doctor reports that as a failing check, because exiting 0 on it would be a lie.

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
used. `init` saves config, syncs the remote tool catalog, and in interactive
sessions offers to install agent instructions for detected harnesses.

### Which AWS credentials are used

The BORIS MCP server requires AWS credentials for any account in the AWS
Organization. `bmcp` resolves them in this order:

1. `--profile <name>`, or `BMCP_PROFILE` — a profile named for this
   invocation. Applied ahead of anything in the environment, because asking
   for a profile now is an instruction rather than a default.
2. Credentials the environment carries: `AWS_ACCESS_KEY_ID` with
   `AWS_SECRET_ACCESS_KEY` (what `aws-vault exec` and most CI runners inject),
   or `AWS_WEB_IDENTITY_TOKEN_FILE` with `AWS_ROLE_ARN` (IRSA).
3. `AWS_PROFILE` or `AWS_DEFAULT_PROFILE`, then `aws_profile` in `config.toml`.
4. Whatever that profile resolves through — SSO, `credential_process`,
   `source_profile`, `AWS_CONTAINER_CREDENTIALS_*`, an instance role — or, with
   no profile at all, the SDK's default chain.

So `aws-vault exec <profile> -- bmcp ...` works, and so does a CI runner that
injects credentials into the environment, with an `aws_profile` still sitting in
`config.toml` from `bmcp init`. Pass `--profile` when you want the profile to
win instead.

Only the two sources in step 2 outrank a profile, because they are the only two
the AWS SDK itself places above one. `AWS_CONTAINER_CREDENTIALS_*` is not among
them — in the SDK it is a *profile's* fallback, tried after that profile's own
SSO, static keys and `credential_process` — so on ECS or EKS Pod Identity, leave
`aws_profile` out of `config.toml` rather than expecting the task role to
displace it.

Because `BMCP_PROFILE` counts as naming a profile for the invocation, exporting
it from a shell profile will quietly defeat `aws-vault exec` for every later
call. Prefer `aws_profile` in `config.toml` for a standing default, and keep
`BMCP_PROFILE` for a shell where you mean it.

One exception to step 2, and the only case where `bmcp` departs from this order
on its own: environment credentials stamped with an `AWS_CREDENTIAL_EXPIRATION`
that has already passed — a lapsed `aws-vault exec` shell — are treated as
absent, so the profile from step 3 wins after all. The AWS SDK does not read
that variable, so without this those credentials are inescapable: it sees static
keys it believes cannot expire, signs with them, and every request is rejected
while no `aws_profile` in `config.toml` can take over. Credentials naming no
expiration, one still in the future, or one that does not parse as RFC 3339 are
all untouched — an unrecognised stamp is evidence of a wrapper `bmcp` does not
understand, not evidence that the keys are dead. The demotion is also withheld
when the environment carries `AWS_WEB_IDENTITY_TOKEN_FILE`, because handing the
SDK a profile steps over its whole environment tier and would authenticate an
IRSA pod as the profile instead of as its own role.

One caveat, because it decides an identity: nothing binds `AWS_CREDENTIAL_EXPIRATION`
to the keys beside it. A shell where the keys were refreshed but that variable
was left behind, or a CI step that replaces the credential variables without
replacing it, will have working credentials passed over in favour of the
profile — a different account, quietly. Every message `bmcp` prints in that case
says so, naming the expiry it acted on, and `--profile <name>` overrides the
choice for one call. If a wrapper leaves a stale stamp behind, unset the
variable or drop `aws_profile` from `config.toml`.

Every `bmcp doctor` reports a `credentials` row naming the source a call would
use, and an authentication failure names the one it tried — so a failure never
sends you to repair a profile the call never consulted. That row ends in
`— found, not verified`: it says what resolved locally, having contacted
nothing. A run that goes remote is what tests them — `bmcp doctor --deep`, or a
plain `bmcp doctor` whose cached catalog is missing, unreadable or stale — and
its `auth` and `remote` rows then come from that one attempt. `auth` fails only
when `bmcp` never produced a signed request, in which case no `remote` row is
emitted at all, or when the BORIS gateway refused the request it did sign; a
connection that never arrives fails `remote` alone.

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
installer has config and a tool catalog to read. To register bmcp itself as
a server instead, see [Run as an MCP server](#run-as-an-mcp-server).

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
`.bak-<timestamp>` backup is created and printed. The five most recent backups
of a file are kept, so a bad write is still recoverable after a later one has
happened. A write that fails leaves neither: the new content is staged in full
before any backup is rotated, so a read-only mount or a full disk leaves the
file it could not replace exactly as it was, with nothing beside it. The
generated content is a pure function of the tool catalog, so a
refresh against an unchanged catalog writes nothing at all — no backup, no
mtime change — and the routine refresh below cannot age genuine restore points
out of the set.

Refresh tools and installed instructions:

```bash
bmcp sync
```

`sync` refreshes the local tool cache and updates any existing BORIS instruction
files it finds, without installing new harnesses.

`doctor` refreshes the **user-scope** files whenever it reaches the server, so
the tool list agents read stays current without anyone running `sync` by hand.
Like `sync`, it installs no new harnesses — it only rewrites files that already
exist.

Project-scope files stay `sync`'s job. A project file is claimed by filename
alone — nothing inside a `BORIS.md` marks it as generated — and `doctor` is what
agents run every session from whatever repository they happen to be working in.
Refreshing project scope from there would rewrite an unrelated file of that name
in someone else's repository. `sync` is typed by a person who knows which
directory they are standing in, so it still refreshes both.

This is what keeps the catalog honest across a self-update. The run that applies
an update finishes on the binary it already loaded, so it writes that binary's
instructions; the next `doctor` run is the new binary and installs the new
ones.

## Run as an MCP server

`bmcp serve` speaks MCP over stdin and stdout, so a client can call BORIS
directly instead of shelling out to the CLI. It re-exports the synced catalog
under the same fully-qualified tool names and proxies each call to the endpoint
`bmcp <tool>` already uses. Run `bmcp init` first: `serve` answers `tools/list`
from the local catalog rather than syncing on every call, and loads that catalog
once at startup.

Which config file you register it in decides whether pictures appear. Only the
client that owns the connection can negotiate MCP Apps, and for the Claude
desktop app that is the app itself — for servers listed in its own config, or
installed as an extension. A server registered with the Claude Code CLI
(`claude mcp add`, `~/.claude.json`, `.mcp.json`) is spawned by the CLI instead,
which does not implement the extension: the tools work and no picture is ever
drawn.

To get pictures, register with the app. On macOS, in
`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "boris": {
      "command": "/absolute/path/to/bmcp",
      "args": ["serve"]
    }
  }
}
```

Use an absolute path: the app does not inherit a shell's `PATH`. Restart the
client afterwards — MCP servers are read at startup. The tools then appear in
every tab, pictures included.

It belongs in a client's server list, not in a terminal: stdout carries JSON-RPC
frames and nothing else, and the process runs until the client closes the pipe.

### Where to register it

The tools work in every client below. Pictures need a client that implements
MCP Apps, and need the server registered with the process that owns the
connection — for Claude and Codex that is the desktop app, not the terminal.

| Client | Pictures | Register in |
| --- | --- | --- |
| Claude desktop app | yes | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | yes | `~/.cursor/mcp.json`, or `<project>/.cursor/mcp.json` |
| Codex desktop | yes, with `features.enable_mcp_apps = true` | `~/.codex/config.toml` |
| Claude Code CLI | no | `claude mcp add`, `~/.claude.json`, `.mcp.json` |
| Codex CLI | no | `~/.codex/config.toml` |
| Kiro | no | `~/.kiro/settings/mcp.json` (JSONC) |
| OpenCode | no | `~/.config/opencode/opencode.json` |

Two want a shape other than `mcpServers`:

```toml
# ~/.codex/config.toml
[mcp_servers.boris]
command = "/absolute/path/to/bmcp"
args = ["serve"]
```

```json
// ~/.config/opencode/opencode.json — the key is "mcp", and command is an array
{ "mcp": { "boris": { "type": "local", "command": ["/absolute/path/to/bmcp", "serve"], "enabled": true } } }
```

### Graph pictures

The two resource finders, `search_infrastructure_by_description` and
`search_infrastructure_relationships`, also draw their answer as a graph. Under
`serve` the drawing is offered to the client as an MCP Apps UI resource
(`ui://boris/graph.html`), so a person can see it inline while the model
receives the same text answer as before with no markup in it. A client that does
not implement MCP Apps — including a `bmcp serve` registered with the Claude
Code CLI rather than with the app — never reads the resource and sees no
change.

Called as a CLI, the same two tools write the drawing to
`$BMCP_HOME/last-graph.svg` and replace it with a `picture` field naming that
path. The filename is stable so a viewer left open on it follows along.

Either way the picture is a decoration: if drawing it fails the tool still
answers, and `BMCP_RENDER` turns it off — `off`, `false`, `0` or `no`, the
same spellings every other switch here accepts.

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

### Machine output

`--format` opts a command into the machine-output contract:

| Format | stdout |
|---|---|
| `human` | prose |
| `json` | exactly one indented JSON document per invocation |
| `ndjson` | the same document compacted onto one line — except `list`, which is one bare tool record per line |

**Without `--format`, nothing changes.** Every command keeps the output it had
before this flag existed, which is what makes a release safe to apply
unattended on a binary that self-updates. `--output` (read by `list` alone,
where `json` still means `ndjson`) and `--json` (structured errors, plus
doctor's report) are the legacy flags. Both still work, both are deprecated,
and `--format` supersedes them wherever they appear together.

`--pretty` is a legacy convenience: `--format json` is already indented, and
`ndjson` must stay on one line, so it is not consulted under either.

Under `--format json` or `--format ndjson`, three rules hold for every command:

- **stdout carries the document and nothing else.** Progress prose is not
  redirected but suppressed, so `bmcp … --format json 2>&1 | jq` is safe —
  exactly one JSON document reaches the merged stream. `--verbose` puts the
  prose back on stderr when you are debugging, so do not combine it with `2>&1`.
- **Failures are one document on stderr**, with stdout left empty:

  ```json
  {"ok":false,"command":"call","error":"tool_validation_failed","message":"…","exit_code":5}
  ```

  Read `ok` to tell success from failure on a merged stream. `exit_code`
  repeats bmcp's own exit status, which is worth reading when a pipeline has
  replaced it with its own. `error` and `exit_code` always agree about the same
  cause: credentials that never produced a signed request and a request the
  BORIS gateway refused both report `auth_failure` with exit 3, on every command
  that can meet them — `sync`, `list`, `describe`, `serve` and a tool call
  alike. The document is always a **single line**, in both
  machine formats — the one place the output does not follow `--format` — so
  `tail -1` and `read -r line` keep working on it.

  Because failures are on stderr, `out=$(bmcp … --format json)` captures
  nothing when the command fails. Merge the streams if you want one capture
  that holds either outcome.

  Two commands are exceptions. `doctor` reports failing checks in its ordinary
  report on stdout with `"ok": false` and exits 1 — a failing check is its
  answer, not an error about it — so its report carries `exit_code` too.
  `--help` prints human text in every format.
- **Success documents carry `ok` and `command`**, then whatever that command
  answers with.
- **Nothing prompts.** No first-run wizard, no URL or profile question, no
  `aws sso login` shell-out — each returns an actionable error instead.

A tool call answers like this:

```json
{
  "ok": true,
  "command": "call",
  "tool": "tools___search_infrastructure_graph",
  "display_name": "search_infrastructure_graph",
  "result": { "nodes": [] },
  "result_bytes": 17,
  "truncated": false
}
```

`result` holds the payload as JSON when it parses as JSON; a text payload
arrives in `result_text` instead, so the type of `result` never depends on what
the server chose to return.

`--max-bytes <n>` caps a large result. The document stays parseable, sets
`truncated`, reports the full `result_bytes`, and puts the kept prefix in
`result_excerpt` — as text, because a prefix of a JSON document is not a JSON
document. Prefer it to `head -c`, which cuts the payload without leaving
anything in the output that says so. Without `--format` it truncates stdout and
says so on stderr.

The excerpt cuts on a rune boundary, and it is text rather than a byte-exact
prefix: JSON encoding replaces invalid UTF-8 with U+FFFD, so a payload carrying
raw bytes reads back with those substituted. That applies to `result_text` too,
so no machine field preserves them — read the payload without `--format`, where
it is written to stdout verbatim, if you need the exact bytes.

Like `--pretty` and `--raw`, `--max-bytes` and `--format` must precede the tool
name in the `bmcp <tool> --arg value` form — everything after the tool name is
parsed as that tool's arguments, so a trailing `--format json` is rejected as an
unknown tool argument, and on a tool that declares no arguments it is sent to
the server as an argument named `format`.

### `bmcp list` output

`list` writes NDJSON to stdout — one JSON object per line, nothing else, and an
empty catalog is empty stdout with exit 0. The `%d tools synced <timestamp>`
header goes to stderr, so stdout stays parseable. Under `--format json` or
`--format ndjson` that header is suppressed rather than redirected, so merging
the streams is safe.

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

- **`head` hides tools and leaves no marker.** Every line is a complete record,
  so `head -5` never yields invalid JSON — which is the problem: a shortened
  catalog reads exactly like a small one. Use `--format json` when completeness
  matters: that document carries `count`, which a stream cut short cannot report
  about itself. The total is also on stderr without `--format`.
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
value-taking flag. `--format` accepts `human`, `json` and `ndjson` — three
distinct formats — and is the one to reach for; `--output` is kept for callers
that already use it and is read by `list` alone.

As a global flag `--output` always works before the command name. After the
command name, `help`, `version` and `install` take their arguments verbatim
(`install` rejects it outright), as does the tool in the `bmcp <tool> --arg
value` form. Putting `--output` first is always safe.

### `bmcp doctor` JSON output

`doctor --json` — or `doctor --format json`, which adds `command` and
`exit_code` — writes its report as one JSON document to stdout, so it can be
piped straight into a parser:

```bash
bmcp doctor --json | jq '.checks[] | select(.ok == false)'
```

Progress prose such as `Syncing tools...` goes to stderr under `--json`, and is
suppressed entirely under `--format`; `--verbose` restores it there.

The document carries `ok` and a `checks` array, plus an `update` object whenever
the pre-command update inspection ran — which is not the same as a network check
having happened. Read `update.checked` for that, and `update.kind`, which is
`source` for a build that cannot self-update at all.

Two things worth knowing when consuming it:

- **Check the exit code, not just stdout.** A failure *before* doctor produces a
  report — an unparseable flag, a bad `--output`, an extra argument — writes
  `{"ok":false,"error":…,"exit_code":…}` to stderr and leaves stdout empty, as
  every other command does. The pipeline above then prints nothing and `jq`
  exits 0, which reads as "no failing checks" from a command that never ran one.
  Use `set -o pipefail`, test bmcp's own exit code, or merge the streams — in a
  machine format `2>&1` yields exactly one document either way, and `ok` says
  which.
- **`ok` is false exactly when the command exits 1.** A failed update *check*
  stays outside `checks` and never gets there: a GitHub outage is not a BORIS
  outage. The single exception is an update that left no working binary at the
  install path — that appears in `checks` as `update` and does fail doctor.
