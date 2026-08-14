package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type serverInfo struct {
	Name            string `json:"name,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	Instructions    string `json:"instructions,omitempty"`
}

type toolCache struct {
	Version  int        `json:"version"`
	URL      string     `json:"url"`
	LastSync time.Time  `json:"last_sync"`
	Server   serverInfo `json:"server"`
	Tools    []tool     `json:"tools"`
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	SchemaHash  string          `json:"schema_hash"`
}

type schemaObject struct {
	Type       any                       `json:"type,omitempty"`
	Properties map[string]schemaProperty `json:"properties,omitempty"`
	Required   []string                  `json:"required,omitempty"`
}

type schemaProperty struct {
	Type        any                       `json:"type,omitempty"`
	Description string                    `json:"description,omitempty"`
	Items       *schemaProperty           `json:"items,omitempty"`
	Properties  map[string]schemaProperty `json:"properties,omitempty"`
	// Required is a nested object's own required list. Only added for rendering:
	// without it every sub-field would be marked optional, which for a required
	// one is not a gap in the output but a wrong statement in it.
	Required []string `json:"required,omitempty"`
	// Enum and Const let a generated example name a value the schema accepts. A
	// type placeholder in a field constrained to `["a","b"]` is valid JSON that the
	// server still rejects, which for a copy-pasteable example is not much better
	// than being unparseable.
	Enum  []any `json:"enum,omitempty"`
	Const any   `json:"const,omitempty"`
}

// catalogIsFresh reports whether the cache on disk is the catalog a tool call at
// this instant would actually use: readable, belonging to this server, and inside
// the TTL.
//
// cacheForCatalog inverts it to decide whether to sync, and cmdDynamic requires it
// before answering an unknown name locally. Both callers must agree, or a local
// answer could contradict the one the normal path would give after syncing —
// which is how a tool the server had but the cache did not became unreachable.
func (a *app) catalogIsFresh(cfg effectiveConfig, cache *toolCache, cacheErr error) bool {
	// Guarded first: readCache returns a nil cache alongside its error, so every
	// field access below depends on this.
	if cacheErr != nil {
		return false
	}
	return cache.URL == cfg.URL && cfg.SyncTTL != 0 && a.now().Sub(cache.LastSync) <= cfg.SyncTTL
}

func (a *app) cacheForCatalog(flags globalFlags, cfg effectiveConfig, allowStale bool) (*toolCache, error) {
	cache, cacheErr := readCache(cfg.ToolsPath)
	due := !a.catalogIsFresh(cfg, cache, cacheErr)
	// A refusal earlier in this run already established that upstream is listing
	// nothing and that the cache on disk is the last known-good catalog. Asking
	// again in the same process cannot produce a better answer, and the second ask
	// is a full handshake against a server that is already struggling.
	//
	// sameServer is re-checked rather than assumed: `due` can also be true because
	// the cache belongs to a different URL, and serving a mismatched catalog
	// without syncing would be worse than the round trip this saves. The single
	// real caller keeps one config for the whole command, so this only guards
	// against a future one that does not.
	if due && a.refusedEmptyCatalog && cacheErr == nil && sameServer(cache.URL, cfg.URL) {
		return cache, nil
	}
	if due {
		newCache, err := a.syncTools(context.Background(), cfg)
		if err != nil {
			// errEmptyCatalog is a refusal to overwrite, not a failure to reach the
			// server, so the cache on disk is still the last known-good catalog —
			// usable even where a merely stale one would be refused, because a tool
			// call should not start failing because upstream briefly listed no
			// tools.
			//
			// cacheErr == nil is load-bearing, not belt and braces: syncTools also
			// returns errEmptyCatalog when the cache exists but could not be parsed,
			// which is precisely the case with nothing to serve. readCache returns
			// (nil, err) there, so dropping the conjunct would return (nil, nil) and
			// cmdList would dereference it.
			if errors.Is(err, errEmptyCatalog) && cacheErr == nil {
				a.refusedEmptyCatalog = true
				fmt.Fprintf(a.stderr, "Warning: %s\n", err)
				return cache, nil
			}
			if allowStale && cacheErr == nil {
				fmt.Fprintf(a.stderr, "Warning: sync failed, using stale cache: %s\n", err)
				return cache, nil
			}
			return nil, err
		}
		// The catalog on disk just changed, which makes the tool list embedded in
		// every installed instruction file the stale copy — and that list, not
		// tools.json, is what agents actually read.
		//
		// This used to be doctor's job, on the reasoning that BORIS.md tells agents
		// to run doctor before their first call. Doctor no longer syncs when local
		// state is fresh, so hanging the refresh off doctor would mean hanging it
		// off nothing. Here it is bounded by the same TTL that bounds syncing, and
		// it fires on the run that learned the catalog changed rather than on some
		// later diagnostic.
		//
		// User scope only, for the reason refreshExistingInstructions gives: this
		// path runs unattended from whatever directory an agent is working in, and
		// a project-scope file is claimed by filename alone. An unchanged catalog
		// renders byte-identical and is not written at all.
		a.refreshInstructions(newCache, false)
		return newCache, nil
	}
	return cache, nil
}

func readCache(path string) (*toolCache, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c toolCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func writeCache(path string, cache *toolCache) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(b, '\n'), 0o600)
}

func schemaHash(raw json.RawMessage) string {
	var v any
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	_ = json.Unmarshal(raw, &v)
	canonical := canonicalJSON(v)
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalJSON(v any) string {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.WriteString(canonicalJSON(x[k]))
		}
		b.WriteByte('}')
		return b.String()
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(canonicalJSON(item))
		}
		b.WriteByte(']')
		return b.String()
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func nonEmptySchema(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return raw
}

func (t tool) schema() schemaObject {
	var s schemaObject
	_ = json.Unmarshal(nonEmptySchema(t.InputSchema), &s)
	if s.Properties == nil {
		s.Properties = map[string]schemaProperty{}
	}
	return s
}

func (t tool) Validate(input map[string]any) error {
	s := t.schema()
	for _, r := range s.Required {
		if _, ok := input[r]; !ok {
			return fmt.Errorf("Missing required argument: %s\nExpected type: %s\nExample: bmcp call %s '{\"%s\":...}'", r, typeName(s.Properties[r].Type), displayToolName(t.Name), r)
		}
	}
	for name, val := range input {
		prop, ok := s.Properties[name]
		if !ok && len(s.Properties) > 0 {
			return fmt.Errorf("Unknown argument: --%s\n%sThe tool was not called.", name, suggestion(name, propertyNames(s.Properties)))
		}
		if ok && !valueMatchesType(val, prop) {
			return fmt.Errorf("Invalid argument: %s expected %s", name, typeName(prop.Type))
		}
	}
	return nil
}

func (t tool) ParseFlags(args []string) (map[string]any, error) {
	s := t.schema()
	input := map[string]any{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			if trimmed := strings.TrimSpace(arg); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				return nil, fmt.Errorf("unexpected JSON positional argument: %s\nTo pass JSON args, use the call subcommand:\n  bmcp call %s '%s'", arg, displayToolName(t.Name), arg)
			}
			return nil, fmt.Errorf("unexpected positional argument: %s", arg)
		}
		raw := strings.TrimPrefix(arg, "--")
		name, value, hasValue := strings.Cut(raw, "=")
		prop, known := s.Properties[name]
		if !known && len(s.Properties) > 0 {
			return nil, fmt.Errorf("Unknown argument: --%s\n%sThe tool was not called.", name, suggestion(name, propertyNames(s.Properties)))
		}
		if !hasValue {
			if typeName(prop.Type) == "boolean" {
				value = "true"
				hasValue = true
			} else {
				if i+1 >= len(args) {
					return nil, fmt.Errorf("--%s requires a value", name)
				}
				i++
				value = args[i]
			}
		}
		parsed, err := parseFlagValue(value, prop)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", name, err)
		}
		if typeName(prop.Type) == "array" {
			input[name] = appendValue(input[name], parsed)
		} else {
			input[name] = parsed
		}
	}
	if err := t.Validate(input); err != nil {
		return nil, err
	}
	return input, nil
}

func parseFlagValue(raw string, prop schemaProperty) (any, error) {
	switch typeName(prop.Type) {
	case "boolean":
		return strconv.ParseBool(raw)
	case "integer":
		return strconv.ParseInt(raw, 10, 64)
	case "number":
		return strconv.ParseFloat(raw, 64)
	case "array":
		if strings.HasPrefix(strings.TrimSpace(raw), "[") {
			var v any
			if err := json.Unmarshal([]byte(raw), &v); err != nil {
				return nil, err
			}
			return v, nil
		}
		if prop.Items != nil {
			return parseFlagValue(raw, *prop.Items)
		}
		return raw, nil
	case "object":
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		if strings.HasPrefix(strings.TrimSpace(raw), "{") || strings.HasPrefix(strings.TrimSpace(raw), "[") {
			var v any
			if json.Unmarshal([]byte(raw), &v) == nil {
				return v, nil
			}
		}
		return raw, nil
	}
}

func appendValue(existing any, parsed any) []any {
	var out []any
	if arr, ok := existing.([]any); ok {
		out = arr
	}
	if parsedArr, ok := parsed.([]any); ok {
		return append(out, parsedArr...)
	}
	return append(out, parsed)
}

func valueMatchesType(val any, prop schemaProperty) bool {
	switch typeName(prop.Type) {
	case "", "any":
		return true
	case "string":
		_, ok := val.(string)
		return ok
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "integer":
		switch val.(type) {
		case int, int64, float64:
			f, _ := toFloat(val)
			return f == float64(int64(f))
		default:
			return false
		}
	case "number":
		_, ok := toFloat(val)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	case "object":
		_, ok := val.(map[string]any)
		return ok
	default:
		return true
	}
}

func typeName(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		if len(x) > 0 {
			if s, ok := x[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

func (t tool) Describe(w io.Writer) {
	s := t.schema()
	fmt.Fprintf(w, "%s\n", displayToolName(t.Name))
	if t.Description != "" {
		fmt.Fprintf(w, "%s\n", t.Description)
	}
	fmt.Fprintln(w, "\nArguments:")
	if len(s.Properties) == 0 {
		fmt.Fprintln(w, "  none")
	} else {
		req := set(s.Required)
		for _, name := range propertyNames(s.Properties) {
			describeProperty(w, "  ", name, s.Properties[name], req[name])
		}
	}
	displayName := displayToolName(t.Name)
	fmt.Fprintf(w, "\nJSON call:\n  bmcp call %s '{%s}'\n", displayName, exampleJSONArgs(s))
	fmt.Fprintf(w, "\nSubcommand:\n  bmcp %s%s\n", displayName, exampleFlags(s))
}

// describeProperty renders one argument and, indented under it, the fields a
// structured argument is made of.
//
// Rendering only the top level showed an object argument with no fields at all,
// so the only shape guidance a caller got was the `{"Key":"value"}` placeholder
// in the examples below — which Validate accepts, because it checks an object
// argument for being a map and nothing else. `Key` then reached the server as a
// filter key that does not exist, and the call succeeded.
func describeProperty(w io.Writer, indent, name string, p schemaProperty, required bool) {
	marker := "optional"
	if required {
		marker = "required"
	}
	// Collapsed, not printed verbatim: the indentation is now semantic, so a
	// newline inside a description would put continuation text at column 0 where
	// it reads as another argument. Tool-level descriptions in this catalog
	// already contain newlines, so a property one is a question of when.
	desc := normalizeWhitespace(p.Description)
	if desc != "" {
		desc = " - " + desc
	}
	fmt.Fprintf(w, "%s%s (%s, %s)%s\n", indent, name, argTypeName(p), marker, desc)
	fields, fieldsRequired := nestedProperties(p)
	req := set(fieldsRequired)
	for _, sub := range propertyNames(fields) {
		describeProperty(w, indent+"  ", sub, fields[sub], req[sub])
	}
}

// nestedProperties returns the fields a caller has to fill in for a structured
// argument, plus that level's own required list. Array items are followed as well
// as object properties, because both hide a shape the caller must produce.
//
// The recursion in describeProperty terminates on this: the tree comes from an
// unmarshalled schema, so however deep it nests it is finite — a `$ref` cycle is
// not representable in it, because nothing here resolves `$ref` at all.
func nestedProperties(p schemaProperty) (map[string]schemaProperty, []string) {
	// The declared type decides which keyword applies. JSON Schema reads `items` for
	// an array and `properties` for an object, so a schema carrying both is not
	// licence to pick whichever is present: preferring `properties` on a declared
	// array printed fields the array does not have while the heading, taken from
	// `items`, described the ones it does.
	//
	// Array levels are followed as deep as they nest, so an array of arrays of
	// objects still reaches the fields, and argTypeName names every level it
	// descends so the heading stays attributable to them.
	if typeName(p.Type) == "array" {
		if p.Items != nil {
			return nestedProperties(*p.Items)
		}
		return nil, nil
	}
	if len(p.Properties) > 0 {
		return p.Properties, p.Required
	}
	// No declared type: presence is the only evidence of shape.
	if p.Items != nil {
		return nestedProperties(*p.Items)
	}
	return nil, nil
}

// argTypeName spells an array of typed items as "array of object" rather than
// "array". For the structured case that is what attributes the fields indented
// underneath to the items instead of to the array itself.
func argTypeName(p schemaProperty) string {
	name := typeName(p.Type)
	if name == "" {
		// No declared type: infer from whichever shape keyword is present, in the same
		// order nestedProperties uses, so the heading always describes the fields
		// printed beneath it. An items schema declaring properties and no type used to
		// render as a bare "array" with its fields indented under it, which is the
		// exact ambiguity this function exists to remove.
		switch {
		case len(p.Properties) > 0:
			name = "object"
		case p.Items != nil:
			name = "array"
		}
	}
	if name == "array" && p.Items != nil {
		if inner := argTypeName(*p.Items); inner != "" {
			return "array of " + inner
		}
	}
	return name
}

// toolRecord is one line of `bmcp list` output. It is deliberately separate from
// tool: tool is the on-disk cache format, so retagging it would rewrite
// tools.json.
// name, display_name and description are always present, so a caller can rely
// on the shape of every record; only last_sync drops out, and only when the
// cache has no timestamp to report.
type toolRecord struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	LastSync    string `json:"last_sync,omitempty"`
}

// writeToolRecords emits NDJSON: one record per line, descriptions verbatim.
// Authored newlines survive as JSON escapes, so a record never spans two lines
// and `head` can never split one.
func writeToolRecords(w io.Writer, tools []tool, lastSync time.Time) error {
	stamp := ""
	if !lastSync.IsZero() {
		stamp = lastSync.UTC().Format(time.RFC3339)
	}
	enc := json.NewEncoder(w)
	// Descriptions contain <, > and &; escaping them would hide those bytes
	// from a caller grepping the raw lines.
	enc.SetEscapeHTML(false)
	for _, t := range tools {
		record := toolRecord{
			Name:        t.Name,
			DisplayName: displayToolName(t.Name),
			Description: t.Description,
			LastSync:    stamp,
		}
		if err := enc.Encode(record); err != nil {
			return fmt.Errorf("write record for %s: %w", t.Name, err)
		}
	}
	return nil
}

// renderToolList is the --output human view: names flush left, every
// description line indented by two spaces. No wrapping — terminal width is
// unknowable here, and rune counts are not display columns. Write errors are
// returned rather than dropped, so a truncated catalog cannot exit 0.
func renderToolList(w io.Writer, tools []tool) error {
	for _, t := range tools {
		if _, err := fmt.Fprintf(w, "%s\n", displayToolName(t.Name)); err != nil {
			return err
		}
		// Whitespace-only descriptions have nothing to show. The wrapping
		// renderer collapsed them away via normalizeWhitespace; without this
		// guard they would print as indented runs of spaces.
		if strings.TrimSpace(t.Description) == "" {
			continue
		}
		// Trailing newlines are dropped — keeping them would put a blank line
		// under every tool whose description ends in one. An interior blank line
		// stays blank rather than becoming two spaces: there is nothing to indent,
		// and trailing whitespace is noise in a terminal and in a diff.
		for _, line := range strings.Split(strings.TrimRight(t.Description, "\r\n"), "\n") {
			line = strings.TrimRight(line, "\r")
			if line == "" {
				if _, err := fmt.Fprintln(w); err != nil {
					return err
				}
				continue
			}
			if _, err := fmt.Fprintf(w, "  %s\n", line); err != nil {
				return err
			}
		}
	}
	return nil
}

func displayToolName(name string) string {
	if _, suffix, ok := strings.Cut(name, "___"); ok && suffix != "" {
		return suffix
	}
	return name
}

func (oldTool tool) Diff(newTool tool) []map[string]string {
	oldS, newS := oldTool.schema(), newTool.schema()
	oldReq, newReq := set(oldS.Required), set(newS.Required)
	var changes []map[string]string
	for name := range oldReq {
		if !newReq[name] {
			changes = append(changes, map[string]string{"kind": "removed_required_arg", "name": name, "message": "removed required arg: " + name})
		}
	}
	for name := range newReq {
		if !oldReq[name] {
			changes = append(changes, map[string]string{"kind": "added_required_arg", "name": name, "message": "added required arg: " + name})
		}
	}
	for name, oldProp := range oldS.Properties {
		if newProp, ok := newS.Properties[name]; ok && typeName(oldProp.Type) != typeName(newProp.Type) {
			changes = append(changes, map[string]string{"kind": "changed_type", "name": name, "message": fmt.Sprintf("changed type: %s %s -> %s", name, typeName(oldProp.Type), typeName(newProp.Type))})
		}
	}
	if len(changes) == 0 {
		changes = append(changes, map[string]string{"kind": "schema_hash_changed", "name": newTool.Name, "message": "input schema hash changed"})
	}
	return changes
}

func findTool(cache *toolCache, name string) (tool, bool) {
	if cache == nil {
		return tool{}, false
	}
	for _, t := range cache.Tools {
		if t.Name == name {
			return t, true
		}
	}
	return tool{}, false
}

func resolveTool(cache *toolCache, name string) (tool, error) {
	if t, ok := findTool(cache, name); ok {
		return t, nil
	}
	if cache == nil {
		return tool{}, newUnknownToolError(cache, name)
	}
	var matches []tool
	for _, t := range cache.Tools {
		if displayToolName(t.Name) == name {
			matches = append(matches, t)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		fullNames := make([]string, 0, len(matches))
		for _, t := range matches {
			fullNames = append(fullNames, t.Name)
		}
		sort.Strings(fullNames)
		return tool{}, fmt.Errorf("Ambiguous tool alias: %s\nUse the full tool name: %s", name, strings.Join(fullNames, ", "))
	}
	return tool{}, newUnknownToolError(cache, name)
}

// unknownToolError is returned when a name matched nothing in the catalog. It is a
// type rather than a formatted string so that a caller which also has the local
// command table behind it — cmdDynamic, for a first token — can add that near miss
// to the same message, while callers where the name can only be a tool (describe,
// call) leave it empty. Assembling the lines in one place is what keeps the
// recovery hint last no matter which suggestions are present.
type unknownToolError struct {
	name        string
	nearTool    string
	nearCommand string
}

func newUnknownToolError(cache *toolCache, name string) *unknownToolError {
	return &unknownToolError{name: name, nearTool: nearestToolName(cache, name)}
}

// withCommand returns a copy naming the nearest local command as well. The two
// near misses stay on separate labelled lines because they call for different next
// moves: one is a different spelling of something bmcp does locally, the other is a
// different tool on the server.
func (e *unknownToolError) withCommand(near string) *unknownToolError {
	out := *e
	out.nearCommand = near
	return &out
}

func (e *unknownToolError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Unknown command or tool: %s", e.name)
	if e.nearCommand != "" {
		fmt.Fprintf(&b, "\nDid you mean the command: bmcp %s?", e.nearCommand)
	}
	if e.nearTool != "" {
		fmt.Fprintf(&b, "\nDid you mean the tool: %s?", e.nearTool)
	}
	// Unconditional. The least-informed failure — nothing close enough to suggest —
	// is the one that most needs a next step, and it used to be the only one that
	// got none.
	b.WriteString("\nRun `bmcp --help` for commands, `bmcp list` for the current tool catalog.")
	return b.String()
}

// nearestToolName matches both spellings of every tool, because both are things a
// caller types: the display name is what the generated instructions show, and the
// full namespaced name is what a copy out of the catalog gives. Matching only the
// display form left a typo in the full name unsuggestable, since the `tools___`
// prefix alone puts the distance past the threshold.
//
// The answer is always the display name — the shorter spelling that also resolves.
// Sorted, so a tie between two equally distant names resolves the same way on every
// run.
func nearestToolName(cache *toolCache, name string) string {
	if cache == nil {
		return ""
	}
	displayFor := make(map[string]string, len(cache.Tools)*2)
	spellings := make([]string, 0, len(cache.Tools)*2)
	for _, t := range cache.Tools {
		display := displayToolName(t.Name)
		for _, spelling := range []string{display, t.Name} {
			if _, seen := displayFor[spelling]; seen {
				continue
			}
			displayFor[spelling] = display
			spellings = append(spellings, spelling)
		}
	}
	sort.Strings(spellings)
	// A miss yields "", which is also what an absent key returns.
	return displayFor[nearest(name, spellings)]
}

func propertyNames(props map[string]schemaProperty) []string {
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func suggestion(name string, candidates []string) string {
	if best := nearest(name, candidates); best != "" {
		return fmt.Sprintf("Did you mean: --%s?\n", best)
	}
	return ""
}

// nearest returns the closest candidate within an edit distance of 3, or "" when
// nothing is close enough. Ties go to the earliest candidate, so callers that
// want a deterministic answer pass a sorted list.
func nearest(name string, candidates []string) string {
	best, dist := "", 4
	for _, c := range candidates {
		if d := editDistance(name, c); d < dist {
			best, dist = c, d
		}
	}
	return best
}

// editDistance is Damerau-Levenshtein restricted to adjacent transpositions: a
// swap of two neighbouring characters costs one edit, not two.
//
// That distinction carries real weight against short command names. Transposition
// is one of the most common ways to mistype a word, and under plain Levenshtein
// `lsit`, `snyc`, `inti` and `clal` all cost two — out of reach of the tight
// threshold that four-letter command names need to avoid swallowing unrelated
// tokens. Counting the swap as one edit covers them without loosening anything
// else.
func editDistance(a, b string) int {
	// Two previous rows, because a transposition reaches back two positions in
	// both strings.
	prev2 := make([]int, len(b)+1)
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			// The two characters just consumed are the same pair in the opposite
			// order, so one swap explains them.
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				if swapped := prev2[j-2] + 1; swapped < cur[j] {
					cur[j] = swapped
				}
			}
		}
		prev2, prev = prev, cur
	}
	return prev[len(b)]
}

func set(vals []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range vals {
		m[v] = true
	}
	return m
}

func exampleJSONArgs(s schemaObject) string {
	parts := []string{}
	for _, name := range propertyNames(s.Properties) {
		parts = append(parts, fmt.Sprintf("%q:%s", name, exampleValue(s.Properties[name])))
	}
	return strings.Join(parts, ",")
}

func exampleFlags(s schemaObject) string {
	parts := []string{}
	for _, name := range propertyNames(s.Properties) {
		parts = append(parts, fmt.Sprintf(" --%s %s", name, exampleFlagValue(s.Properties[name])))
	}
	return strings.Join(parts, "")
}

// exampleFlagValue renders a shell-safe placeholder for the --flag form.
// Object/array values must be single-quoted JSON so the example is
// copy-pasteable (an unquoted "{}" is mangled by the shell).
func exampleFlagValue(p schemaProperty) string {
	switch typeName(p.Type) {
	case "object":
		if len(p.Properties) == 0 {
			return `'{"Key":"value"}'`
		}
		return "'" + exampleObject(p) + "'"
	case "array":
		return "'" + exampleArray(p) + "'"
	default:
		return exampleValue(p)
	}
}

func exampleValue(p schemaProperty) string {
	// A schema that names its accepted values is the best example available: a type
	// placeholder in a constrained field parses and is then rejected upstream.
	if p.Const != nil {
		if b, err := json.Marshal(p.Const); err == nil {
			return string(b)
		}
	}
	for _, v := range p.Enum {
		if b, err := json.Marshal(v); err == nil {
			return string(b)
		}
	}
	switch typeName(p.Type) {
	case "string":
		return `"value"`
	case "boolean":
		return "true"
	case "integer":
		return "1"
	case "number":
		return "1.0"
	case "array":
		return exampleArray(p)
	case "object":
		// An object with no declared fields keeps `{}`: there is no real key to
		// name, and `{}` at least sends nothing rather than sending a wrong key.
		if len(p.Properties) == 0 {
			return "{}"
		}
		return exampleObject(p)
	default:
		// Quoted, so the result is still valid JSON. A bare `...` was tolerable
		// when it could only appear at the top level of a rendered example; nested
		// inside an object or array it makes the whole example unparseable, and the
		// CLI then rejects its own printed example.
		return `"..."`
	}
}

// exampleArray shows one element whenever the schema says what an element looks
// like. `[]` passes Validate — which checks only that the value is a list — and
// then reaches the server missing whatever the items require, which is the same
// wrong-payload harm the object examples exist to remove.
func exampleArray(p schemaProperty) string {
	if p.Items == nil {
		return "[]"
	}
	return "[" + exampleValue(*p.Items) + "]"
}

// exampleObject names a field the schema actually declares. The `Key` placeholder
// it replaces was not merely unhelpful: local validation accepts it, so the
// example was a copy-pasteable way to send the server a key that does not exist
// and get a plausible answer back. Callers must check len(p.Properties) first.
func exampleObject(p schemaProperty) string {
	parts := []string{}
	for _, name := range exampleFieldNames(p) {
		parts = append(parts, fmt.Sprintf("%q:%s", name, exampleValue(p.Properties[name])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// exampleFieldNames returns every required field, not just one: an example naming a
// single field of two required ones is a payload the server rejects for a missing
// key, which is the same class of unusable example as an empty array.
//
// With nothing required it returns the first field alone — naming one is what
// teaches the shape, and naming all of them would bury it. propertyNames sorts, so
// both cases are stable across runs. Callers must check len(p.Properties) first.
func exampleFieldNames(p schemaProperty) []string {
	names := propertyNames(p.Properties)
	required := set(p.Required)
	var out []string
	for _, n := range names {
		if required[n] {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = names[:1]
	}
	return out
}

func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	default:
		return 0, false
	}
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}
