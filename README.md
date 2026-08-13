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

### Homebrew

```bash
brew install sirob-tech/tap/bmcp
```

Or tap first:

```bash
brew tap sirob-tech/tap
brew install bmcp
```

### Install script

```bash
curl -fsSL https://raw.githubusercontent.com/sirob-tech/boris-mcp-cli/main/install.sh | sh
```

Pin a version with `BMCP_VERSION=v0.1.0` or choose an install directory with
`BMCP_INSTALL_DIR=/usr/local/bin`.

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
| `name` | Full tool name. Always callable — use this to call the tool. |
| `display_name` | Short alias with the namespace prefix stripped. Convenience only. |
| `description` | Verbatim, including authored newlines (JSON-escaped, so one record stays one line). |
| `last_sync` | Catalog sync time in RFC 3339. Omitted when the cache has no timestamp. |

Descriptions are not HTML-escaped, so grepping raw lines for `<region>` works.
Field order is stable, but parse the lines as JSON rather than matching on
column positions.

For a human-readable catalog, pass `--output human` — each name flush left with
its description indented two spaces:

```bash
bmcp list --output human
```

`--output` accepts `ndjson` (default), `json` as an alias for it, and `human`.
It applies to `list`; other commands accept it and ignore it. It is a global
flag, so it must come before the tool name in the `bmcp <tool> --arg value`
form, which passes everything after the tool name to the tool itself.
