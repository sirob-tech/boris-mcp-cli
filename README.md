# boris-mcp

B.O.R.I.S. MCP to CLI converter.

`boris-mcp` lets local AI coding agents query the remote BORIS MCP server hosted
on AWS AgentCore through a regular CLI. It handles SigV4 auth, tool discovery,
schema caching, validation, and MCP text-envelope unwrapping.

## Build

```bash
go build -o boris-mcp ./cmd/boris-mcp
```

Put the binary somewhere on `PATH`, for example:

```bash
ln -s "$(pwd)/boris-mcp" ~/.local/bin/boris-mcp
```

## Configure

Run first-time setup:

```bash
boris-mcp init --url <boris-mcp-url> --profile <aws-profile>
```

`--profile` is optional; if omitted, the AWS SDK default credential chain is
used. The BORIS MCP server requires AWS credentials for any account in the AWS
Organization. `init` saves config, syncs the remote tool catalog, and in
interactive sessions offers to install agent instructions for detected
harnesses.

Harness detection checks for a known executable on `PATH` or an existing config
directory such as `~/.claude`, `~/.codex`, or `~/.cursor`. Each detected harness
is prompted separately and defaults to yes. Use `--non-interactive` to disable
prompts.

Additional configuration flags:

- `--region <region>`: override the SigV4 region.
- `--service <service>`: override the SigV4 service.
- `--allow-http`: allow non-localhost `http://` BORIS URLs.

Check setup:

```bash
boris-mcp doctor
```

## Install Agent Instructions

The installer does not register BORIS as a local MCP server. It writes
instructions that teach agents to call the existing `boris-mcp` CLI and include
the currently synced BORIS tool catalog. Run `boris-mcp init` first so the
installer has config and a tool catalog to read.

User-global install is the default:

```bash
boris-mcp install claude-code
boris-mcp install codex
boris-mcp install cursor
boris-mcp install all
```

Project-local install:

```bash
boris-mcp install claude-code --scope project
boris-mcp install codex --scope project
boris-mcp install cursor --scope project
```

User-scope targets:

- Claude Code: `~/.claude/BORIS.md`, referenced from `~/.claude/CLAUDE.md`
- Codex: `~/.codex/BORIS.md`, referenced from `~/.codex/AGENTS.md`
- Cursor: `~/.cursor/rules/boris.mdc`

Project-scope targets:

- Claude Code: `./BORIS.md`, referenced from `./CLAUDE.md`
- Codex: `./BORIS.md`, referenced from `./AGENTS.md`
- Cursor: `./.cursor/rules/boris.mdc`

Existing files are modified in place. When a file changes, a timestamped
`.bak-<timestamp>` backup is created and printed.

Refresh tools and installed instructions:

```bash
boris-mcp sync
```

`sync` refreshes the local tool cache and updates any existing BORIS instruction
files it finds, without installing new harnesses.

## Use

```bash
boris-mcp list
boris-mcp describe <tool>
boris-mcp <tool> --arg value
boris-mcp call <tool> '{"arg":"value"}'
```

Successful tool calls unwrap MCP text envelopes internally and print the useful
payload directly. Use `--pretty` to format JSON payloads and `--raw` to inspect
the original MCP envelope.
