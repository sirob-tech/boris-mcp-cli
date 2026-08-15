package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// The machine-output contract.
//
// Three controls used to decide what BMCP wrote and where, each with a different
// scope: --output formatted `list` alone, --json restructured errors and doctor,
// and --pretty reformatted successful tool payloads. `describe` had no machine
// form at all, tool calls emitted the server's payload shape directly, and
// progress prose went to stderr on every path including the machine ones.
//
// The cost of that showed up as plumbing. In the transcript audit 322 of 907
// operational shell calls post-processed BMCP output by hand, every Claude
// session wrapped BMCP in head/tail/jq or a text filter, and the merge agents
// reached for to keep errors — `2>&1` — is exactly what made the valid payloads
// unparseable: one line of prose in the stream and the document is gone.
//
// The contract is --format, and one rule per value:
//
//   - human   prose on stdout, progress and errors on stderr.
//   - json    exactly one indented JSON document on stdout per invocation.
//   - ndjson  the same document compacted onto one line, except for `list`,
//     whose stream is one bare tool record per line so that `head` cannot
//     split one.
//
// Under json and ndjson stdout carries machine data and nothing else, progress
// prose is suppressed rather than merely redirected — see app.prose — and
// nothing prompts. That is what makes `bmcp … --format json 2>&1 | jq` safe:
// exactly one JSON document appears on the merged stream, the success document
// on stdout or the failure document on stderr, and `ok` says which. Errors stay
// on stderr because that is where a shell expects them; suppressing the prose is
// what removes the reason agents were merging the streams in the first place.
//
// --format is a new flag rather than a new meaning for --output, and that is the
// load-bearing decision here. Installed binaries self-update (see AGENTS.md), so
// redefining --output would have changed `bmcp list --output json` from a record
// stream to a document on every machine in the fleet, with no version gate able
// to express "do not apply unattended". So --output stays list-only with json an
// alias for ndjson, --json stays errors-plus-doctor, both are deprecated in
// documentation only, and --format supersedes them wherever they appear together.
// TestLegacyFlagsKeepTheirExactOutput pins each frozen output.
//
// Two consequences worth holding onto when editing this file:
//
//   - Read the format from flags.contract(), never from flags.output. The latter
//     is the legacy flag, seeded to ndjson and normalized so that it can never
//     hold "json" — threading it into encodeMachineDoc made --format json emit
//     compact output for every command but list and doctor, which is exactly the
//     distinction --format was added to create.
//   - --pretty and --raw keep their meanings. --raw still selects the
//     unwrapped-or-not payload; --pretty is a legacy convenience and is not
//     consulted under --format, whose json is already indented and whose ndjson
//     must stay on one line.
const (
	outputHuman  = "human"
	outputJSON   = "json"
	outputNDJSON = "ndjson"
)

// machineFormat reports whether stdout carries JSON for this format. It is the
// single test every command uses to decide between its two renderings, so that
// adding a format cannot leave one command answering in prose.
func machineFormat(format string) bool {
	return format == outputJSON || format == outputNDJSON
}

// encodeMachineDoc writes one document in the given machine format: indented for
// json, compacted onto a single line for ndjson.
//
// HTML escaping is off for the same reason writeToolRecords turns it off — tool
// descriptions and results contain <, > and &, and escaping them hides those
// bytes from a caller grepping the raw output.
func encodeMachineDoc(w io.Writer, format string, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if format == outputJSON {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

// errorDoc is the failure shape, identical across every command and every error
// source. exit_code is in the document because the audit found 11 locally
// rejected calls that read as successes to the agent: a following pipeline
// command replaced BMCP's exit status with its own, and nothing in the output
// said otherwise. A caller that lost the status can still read it here.
//
// tool and changes are only set by the schema-change refusal, which is the one
// failure carrying structured detail. #40 is where retryability and request
// correlation join this shape.
type errorDoc struct {
	OK       bool                `json:"ok"`
	Command  string              `json:"command"`
	Error    string              `json:"error"`
	Message  string              `json:"message"`
	ExitCode int                 `json:"exit_code"`
	Tool     string              `json:"tool,omitempty"`
	Changes  []map[string]string `json:"changes,omitempty"`
}

// listDoc is `list --format json`. count is what ndjson cannot report: a stream
// piped through `head` is silently short, and comparing a line count against
// this field is how a caller tells a truncated catalog from a small one.
type listDoc struct {
	OK       bool         `json:"ok"`
	Command  string       `json:"command"`
	Count    int          `json:"count"`
	LastSync string       `json:"last_sync,omitempty"`
	Tools    []toolRecord `json:"tools"`
	Warnings []string     `json:"warnings,omitempty"`
}

// describeDoc is `describe --format json`: one tool, schema included, in the
// same record shape `list --schemas` emits. Same shape on purpose — an agent
// that parsed one catalog record can parse this without a second reader.
type describeDoc struct {
	OK       bool       `json:"ok"`
	Command  string     `json:"command"`
	Tool     toolRecord `json:"tool"`
	Warnings []string   `json:"warnings,omitempty"`
}

// callDoc is a tool call in a machine format.
//
// The payload lands in exactly one of two fields: result when it parses as JSON,
// result_text when it does not. Splitting them keeps result typed — a consumer
// can index into it — without forcing a text payload to masquerade as a JSON
// string, and without the shape of `result` depending on what the server chose
// to return.
//
// result_bytes and truncated answer the completeness half of the contract. They
// are always present, so "was this all of it" is a field read rather than an
// inference from length: 210 results in the audit were larger than the reading
// agent's excerpt budget, and nothing in the output distinguished a complete
// small answer from a clipped large one.
type callDoc struct {
	OK          bool            `json:"ok"`
	Command     string          `json:"command"`
	Tool        string          `json:"tool"`
	DisplayName string          `json:"display_name"`
	Result      json.RawMessage `json:"result,omitempty"`
	ResultText  *string         `json:"result_text,omitempty"`
	ResultBytes int             `json:"result_bytes"`
	Truncated   bool            `json:"truncated"`
	// Excerpt carries the kept prefix when --max-bytes clipped the payload, as
	// text rather than JSON: a prefix of a JSON document is not a JSON document,
	// and presenting it as one would put a parse error in the consumer's lap
	// instead of a truncation flag.
	//
	// A pointer so that it is present whenever Truncated is, including when it is
	// empty — a cap smaller than the payload's first rune keeps no bytes, and a
	// missing key there reads as a different kind of answer than an empty one.
	//
	// It is text, not a byte-exact prefix: encoding/json replaces invalid UTF-8
	// with U+FFFD, so a payload carrying raw bytes — which --raw and an
	// unrecognised envelope both pass through verbatim — reads back with those
	// bytes substituted. Correct for the excerpt's purpose, which is to show what
	// was there; result_text cannot preserve them either, so a caller needing the
	// exact bytes should read the payload without --format, where it is written to
	// stdout verbatim.
	Excerpt *string `json:"result_excerpt,omitempty"`
	// Warnings carries any degradation this invocation hit — a stale catalog, a
	// server that listed no tools. Without it a machine caller reads ok:true on a
	// result the human form flags as suspect, since the prose saying so is
	// discarded under the contract.
	Warnings []string `json:"warnings,omitempty"`
}

// newCallDoc places the payload into whichever field fits, applying maxBytes.
func newCallDoc(name string, result []byte, maxBytes int, warnings []string) callDoc {
	doc := callDoc{
		OK:          true,
		Command:     "call",
		Tool:        name,
		DisplayName: displayToolName(name),
		ResultBytes: len(result),
		Warnings:    warnings,
	}
	if maxBytes > 0 && len(result) > maxBytes {
		excerpt := string(truncateBytes(result, maxBytes))
		doc.Truncated = true
		doc.Excerpt = &excerpt
		return doc
	}
	if json.Valid(result) {
		doc.Result = json.RawMessage(result)
		return doc
	}
	text := string(result)
	doc.ResultText = &text
	return doc
}

type versionDoc struct {
	OK      bool         `json:"ok"`
	Command string       `json:"command"`
	Version string       `json:"version"`
	Commit  string       `json:"commit"`
	Built   string       `json:"built"`
	Updated *updatedFrom `json:"updated,omitempty"`
}

type updatedFrom struct {
	From string `json:"from"`
	To   string `json:"to"`
	At   string `json:"at"`
}

// initDoc reports what init decided, not what the sync it triggers found: the
// tool catalog is `sync`'s document to emit, and one invocation writes one.
// The URL is sanitized for the same reason doctor sanitizes it.
type initDoc struct {
	OK         bool     `json:"ok"`
	Command    string   `json:"command"`
	ConfigPath string   `json:"config_path"`
	URL        string   `json:"url"`
	Warnings   []string `json:"warnings,omitempty"`
}

// updateDoc is what `bmcp update` answers with in a machine format, on every
// path that exits 0 — not only --check, which was the one converted first and
// left the other four writing prose into io.Discard.
//
// outcome is the field to branch on, because "exit 0" covers five different
// things here: a check that found something, a machine already current, a
// machine ahead of the latest release, an applied update and a rollback.
//
// The update state is nested rather than merged into this object. Merged, its
// own `error` key — always present, null on this path — sat at top level beside
// the `error` the failure document uses for the error *name*, so a consumer
// branching on the presence of `error` got the wrong answer.
type updateDoc struct {
	OK       bool           `json:"ok"`
	Command  string         `json:"command"`
	Outcome  string         `json:"outcome"`
	Path     string         `json:"path,omitempty"`
	From     string         `json:"from,omitempty"`
	To       string         `json:"to,omitempty"`
	Update   map[string]any `json:"update,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

const (
	updateOutcomeChecked    = "checked"
	updateOutcomeCurrent    = "current"
	updateOutcomeAhead      = "ahead"
	updateOutcomeApplied    = "applied"
	updateOutcomeRolledBack = "rolled_back"
)

type syncDoc struct {
	OK           bool            `json:"ok"`
	Command      string          `json:"command"`
	Count        int             `json:"count"`
	ToolsPath    string          `json:"tools_path"`
	Instructions *refreshSummary `json:"instructions,omitempty"`
	Warnings     []string        `json:"warnings,omitempty"`
}

// installDoc reports every file each harness install touched, which the prose
// form already listed and no machine caller could read.
type installDoc struct {
	OK        bool           `json:"ok"`
	Command   string         `json:"command"`
	Scope     string         `json:"scope"`
	Harnesses []harnessDoc   `json:"harnesses"`
	Files     []installedDoc `json:"files"`
	Warnings  []string       `json:"warnings,omitempty"`
}

type harnessDoc struct {
	Harness string `json:"harness"`
	Scope   string `json:"scope"`
}

type installedDoc struct {
	Harness string `json:"harness"`
	Path    string `json:"path"`
	Backup  string `json:"backup,omitempty"`
	Changed bool   `json:"changed"`
	// Failed marks a file the install could not write. printInstallResult reports
	// these as prose and the exit code ignores them, so without the field a
	// machine caller would read a partial install as a complete one.
	Failed bool `json:"failed,omitempty"`
}

// truncateBytes cuts b to at most max bytes without splitting a UTF-8 rune.
// Splitting one would put a replacement character into the excerpt and, worse,
// make the excerpt disagree with the prefix of the real payload it claims to be.
//
// It backs off to the nearest rune start, which is at most three bytes and never
// depends on the rest of the payload. Validating the whole prefix instead —
// shortening while !utf8.Valid(cut) — was both quadratic and wrong: one invalid
// byte anywhere before the cut, which a --raw payload or an unrecognised
// envelope passes through verbatim, walked the excerpt all the way back to
// empty, and did it in seconds for a multi-megabyte cap.
func truncateBytes(b []byte, max int) []byte {
	if max <= 0 || len(b) <= max {
		return b
	}
	cut := max
	// b[cut] is the first dropped byte. If it continues a rune, that rune spans
	// the cut and the whole of it goes.
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}

// parseMaxBytes validates --max-bytes, and is only reached when the flag was
// given: an absent one leaves the cap at zero, which is what "no limit" is
// spelled as internally. Zero is not an accepted *value* for the same reason —
// a caller that wants none of the result wants no call, and accepting it would
// make `--max-bytes 0` silently empty every payload.
func parseMaxBytes(v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid --max-bytes value: %q\nExpected a positive whole number of bytes, for example --max-bytes 8192", v)
	}
	return n, nil
}
