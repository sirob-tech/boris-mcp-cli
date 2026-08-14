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
}

func (a *app) cacheForCatalog(flags globalFlags, cfg effectiveConfig, allowStale bool) (*toolCache, error) {
	cache, cacheErr := readCache(cfg.ToolsPath)
	due := cacheErr != nil || cache.URL != cfg.URL || cfg.SyncTTL == 0 || a.now().Sub(cache.LastSync) > cfg.SyncTTL
	// A refusal earlier in this run already established that upstream is listing
	// nothing and that the cache on disk is the last known-good catalog. Asking
	// again in the same process cannot produce a better answer, and the second ask
	// is a full handshake against a server that is already struggling.
	if due && a.refusedEmptyCatalog && cacheErr == nil {
		return cache, nil
	}
	if due {
		newCache, err := a.syncTools(context.Background(), cfg)
		if err != nil {
			// errEmptyCatalog is a refusal to overwrite, not a failure to reach the
			// server: syncTools only returns it when the cache in hand is non-empty
			// and belongs to this URL. That makes it the last known-good catalog,
			// usable even where a merely stale one would be refused — a tool call
			// should not start failing because upstream briefly listed no tools.
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
	return os.WriteFile(path, append(b, '\n'), 0o600)
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
		req := map[string]bool{}
		for _, r := range s.Required {
			req[r] = true
		}
		for _, name := range propertyNames(s.Properties) {
			marker := "optional"
			if req[name] {
				marker = "required"
			}
			p := s.Properties[name]
			desc := p.Description
			if desc != "" {
				desc = " - " + desc
			}
			fmt.Fprintf(w, "  %s (%s, %s)%s\n", name, typeName(p.Type), marker, desc)
		}
	}
	displayName := displayToolName(t.Name)
	fmt.Fprintf(w, "\nJSON call:\n  bmcp call %s '{%s}'\n", displayName, exampleJSONArgs(s))
	fmt.Fprintf(w, "\nSubcommand:\n  bmcp %s%s\n", displayName, exampleFlags(s))
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
		return tool{}, fmt.Errorf("Unknown command or tool: %s", name)
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
	return tool{}, fmt.Errorf("Unknown command or tool: %s", name)
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
	best, dist := "", 99
	for _, c := range candidates {
		if d := levenshtein(name, c); d < dist {
			best, dist = c, d
		}
	}
	if best != "" && dist <= 3 {
		return fmt.Sprintf("Did you mean: --%s?\n", best)
	}
	return ""
}

func levenshtein(a, b string) int {
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
		}
		prev = cur
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
		return `'{"Key":"value"}'`
	case "array":
		return `'[]'`
	default:
		return exampleValue(p)
	}
}

func exampleValue(p schemaProperty) string {
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
		return "[]"
	case "object":
		return "{}"
	default:
		return "..."
	}
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
