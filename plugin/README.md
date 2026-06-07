# boris-mcp plugin

A Claude Code plugin that teaches agents how to use the `boris-mcp` CLI to
fetch AWS infrastructure context — account topology, deployed resources,
relationships, and accumulated organizational memory — from the remote BORIS
MCP server hosted on AWS AgentCore.

The plugin ships **one skill**: `infra-context`. Claude will load it
automatically when the active task needs facts about *this* AWS environment
(as opposed to general AWS knowledge).

## Prerequisites

This plugin assumes the `boris-mcp` binary is installed and on `PATH`. Build
it from the parent repo and link it however you prefer, e.g.:

```bash
go build -o boris-mcp ./cmd/boris-mcp
ln -s "$(pwd)/boris-mcp" ~/.local/bin/boris-mcp
boris-mcp init        # one-time interactive setup
boris-mcp doctor      # confirm config + auth + remote reachability
```

The plugin does **not** install or configure the binary.

## Install (local development)

From any Claude Code session:

```
/plugin add /path/to/boris-mcp/plugin
```

## Install (via marketplace)

Publish the parent repo as a marketplace entry pointing at this subdirectory
(`source: { path: "plugin" }`) and `/plugin install boris-mcp@<marketplace>`.

## What's in the box

- `.claude-plugin/plugin.json` — manifest.
- `skills/infra-context/SKILL.md` — the agent-facing skill: when to invoke
  which BORIS tool, how to unwrap MCP envelopes, common workflows, gotchas.

## Tools surfaced (read-only)

| Tool | Purpose |
|---|---|
| `get_aws_org_config` | AWS Organization tree, accounts, OUs, delegated admins |
| `search_aws` | Semantic search across indexed AWS resources |
| `aws_resource_explorer` | List resources by type/filter via AWS Resource Explorer |
| `graph_query` | Read-only Cypher against the Memgraph topology graph |
| `memory_kb_search` | Prior decisions, gotchas, preferences (Bedrock KB) |
| `read_only_aws_access` | Direct boto3 calls (read-only IAM role) |
| `ask_boris_for_context` | NL meta-query (currently may report not-registered) |
| `x_amz_bedrock_agentcore_search` | AgentCore-side tool narrowing |

See the skill for argument shapes and recommended sequencing.
