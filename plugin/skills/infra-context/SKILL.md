---
name: infra-context
description: Query the BORIS MCP server via the local `boris-mcp` CLI for AWS infrastructure context — account/org topology, deployed resources, resource relationships, and prior decisions/memory. Use BEFORE making infra changes or investigating production, whenever you need to understand what exists, how services are deployed, which account owns something, what depends on what, or recall past decisions and incidents. Not for general AWS knowledge questions; only when you need facts about *this* environment.
allowed-tools:
  - Bash(boris-mcp *)
  - Bash(jq *)
---

# infra-context — Pull AWS infra context from BORIS

`boris-mcp` is a local CLI that fronts a remote BORIS MCP server hosted on AWS
AgentCore. It exposes **8 read-only tools** for querying AWS topology,
resources, relationships, and accumulated organizational memory. Output is
deterministic JSON suitable for piping through `jq`. Use this skill when you
need ground truth about the environment instead of guessing.

## Prerequisites

The skill calls `boris-mcp` from PATH. If you get `command not found`, stop
and tell the user — do not try to install or symlink the binary on their
behalf. The user can symlink the built binary into a PATH directory, e.g.:

```bash
ln -s "$(pwd)/boris-mcp" ~/.local/bin/boris-mcp   # from inside the repo
```

Before the first call in a session, sanity-check the connection:

```bash
boris-mcp doctor
```

If `doctor` fails on `config`, the user needs `boris-mcp init`. If it fails on
`auth`, they need to refresh AWS SSO. Report the failure and stop — do not
try to fix auth yourself.

## When to invoke each tool

Pick the most specific tool for the question. In rough order of preference:

| Question shape | Tool |
|---|---|
| "What accounts/OUs do we have? Which is mgmt, which is prod?" | `get_aws_org_config` |
| "Find a resource — I don't know the ID, just describe it in words" | `search_aws` (semantic) |
| "List every resource of type X across accounts" | `aws_resource_explorer` |
| "What does X depend on / what's in account Y / who connects to Z" | `graph_query` (Cypher) |
| "Have we decided / learned / been burned by something like this before?" | `memory_kb_search` |
| "I know the exact boto3 call I want to run" | `read_only_aws_access` |
| "Give me a high-level natural-language answer" | `ask_boris_for_context` *(may be flaky — see Gotchas)* |
| "Narrow down which tools are relevant to my query" | `x_amz_bedrock_agentcore_search` *(rarely needed — only 8 tools)* |

For schemas and exact arg shapes, run `boris-mcp describe <tool>`.

## Output handling

Every tool returns the MCP envelope:

```json
{"isError": false, "content": [{"type": "text", "text": "<inner json string>"}]}
```

Unwrap with `jq` before reading:

```bash
boris-mcp <tool> ... | jq -r '.content[0].text' | jq .
```

If `isError` is `true`, the inner `text` is an error payload — don't treat it
as a successful result. Tool-side errors surface with exit code `6`; CLI-side
errors use other non-zero codes (see `boris-mcp help` and the design spec).

## Agent invocation pattern

When called by an agent (non-TTY), pass `--non-interactive` so the CLI never
prompts and fails fast with actionable instructions instead:

```bash
boris-mcp --non-interactive <tool> ...
```

Use `--json` to get structured CLI error objects on stderr (separate from
upstream tool errors).

## Common workflows

### Map the AWS organization

```bash
boris-mcp get_aws_org_config | jq -r '.content[0].text' | jq -r '.result.content'
```

Returns markdown with management account, OUs, delegated admins, and every
member account ID + name. Cache this in your working memory for the session —
it rarely changes mid-task.

### Find a resource by description

```bash
boris-mcp search_aws --action search --query "payment service ECS" --limit 10 \
  | jq -r '.content[0].text' | jq .
```

For paginated drill-down, pass the returned `next_token`. To see what
resource types are indexed:

```bash
boris-mcp search_aws --action list_types | jq -r '.content[0].text' | jq -r '.result.data.resource_types[]'
```

### List all resources of a known type

```bash
boris-mcp aws_resource_explorer \
  --action list_resources \
  --resource_type ecs:service \
  --account_ids 637423600426 --account_ids 918349930392 \
  --filter_string "tag:Environment=prod"
```

`account_ids` is required and repeated per account. Use `action=check_indexes`
first if a query returns nothing — Resource Explorer needs an aggregator
index per account.

### Explore relationships in the graph

The graph is a single label `Resource` (read-only Memgraph). Useful for
"what's wired to what":

```bash
# List resource types in the graph
boris-mcp graph_query --cypher \
  "MATCH (n:Resource) RETURN DISTINCT n.type AS type, count(*) AS cnt ORDER BY cnt DESC"

# Find what connects to a specific resource (replace ARN)
boris-mcp graph_query --cypher \
  "MATCH (a:Resource)-[r]-(b:Resource) WHERE a.arn = 'arn:...' RETURN type(r), b.type, b.name LIMIT 50"
```

Only read-only Cypher is accepted. Keep queries bounded — add `LIMIT`.

### Recall prior decisions / gotchas / preferences

```bash
boris-mcp memory_kb_search --action search --query "drift between dev and prod" --limit 5 \
  | jq -r '.content[0].text' | jq -r '.result.data.results[] | "\(.metadata.memory_type): \(.content)"'
```

Filter by type when you know what you want: `--memory_type gotcha`, `decision`,
`pattern`, `preference`, or `knowledge`. Always check memory before proposing
something that "feels" novel — the user may have already settled the question.

### Run a specific boto3 call cross-account

```bash
boris-mcp read_only_aws_access \
  --account_id 637423600426 \
  --region us-east-1 \
  --service_name ecs \
  --operation_name list_clusters
```

For parameterized calls, pass `--parameters '{"Bucket":"my-bucket"}'`. The
IAM role enforces read-only, so write ops will hard-fail — that's expected,
not a bug to work around.

## Recommended sequence for "I need infra context"

1. `boris-mcp doctor` — confirm setup once per session.
2. `boris-mcp list` if you've forgotten what's available (otherwise skip).
3. **Memory first**: `memory_kb_search` for the topic. Prior decisions trump
   live discovery — they often explain *why* something looks the way it does.
4. **Topology**: `get_aws_org_config` if you don't already know which account
   to target.
5. **Find resources**: `search_aws` (don't know IDs) or `aws_resource_explorer`
   (know type, want a list).
6. **Relationships**: `graph_query` only when you need edges between
   resources, not just a list.
7. **Precise lookups**: `read_only_aws_access` for boto3 calls you know
   exactly how to formulate.

Don't run all of these — stop as soon as you have enough to answer.

## Gotchas

- **`ask_boris_for_context` may currently return `UnknownToolError: tool
  'ask_boris_for_context' is not registered`** even though it's listed by
  `boris-mcp list`. The schema is cached locally; server-side registration
  can lag. If it errors, fall back to the direct tools (it's a convenience
  wrapper, not load-bearing). Mention this to the user once if it happens.
- **Read-only by design.** No tool mutates AWS. If you need to *change*
  something, use the user's normal deployment path — never try to coax a
  mutation through `read_only_aws_access`.
- **Stale tool cache** if schemas drift: `boris-mcp sync` forces a refresh.
  A tool call that hits a schema change aborts with a semantic diff (exit
  code `4`) — re-read the description and retry with corrected args.
- **Account IDs as strings.** `aws_resource_explorer` and `read_only_aws_access`
  want quoted account IDs (leading zeros matter for some, e.g.
  `"016491065510"`). Don't let JSON parsers strip them.
- **Don't print credentials.** The CLI already redacts AWS keys, session
  tokens, and signed headers from diagnostics. Don't pipe `--verbose` output
  into anywhere that gets persisted.
- **Don't paste raw tool output to the user.** It's wrapped JSON. Always
  unwrap and summarize — the user wants the answer, not the envelope.

## Reference

- CLI design spec: `boris-mcp-cli-design-spec.md` in the boris-mcp repo.
- Exit codes: `0` ok, `2` config, `3` auth, `4` sync/schema, `5` validation,
  `6` upstream tool failure.
