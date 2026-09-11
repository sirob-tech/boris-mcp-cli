package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// bmcp as an MCP server: it re-exports the remote catalog over stdio so an IDE
// can call BORIS directly, and serves the rendered graph as an MCP Apps UI
// resource so a person sees the picture inline. The markup rides the result's
// own _meta, which a host forwards to the widget and the CLI keeps out of the
// model's request, so no model carries it.
const (
	widgetURI  = "ui://boris/graph.html"
	widgetMIME = "text/html;profile=mcp-app"
	// The version to answer with when a client sends none. A client that names
	// one gets its own back: the methods below are common to every revision the
	// client half of this binary speaks.
	serveProtocolVersion = "2025-06-18"
	uiExtensionID        = "io.modelcontextprotocol/ui"
)

type serveRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type serveTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Meta        map[string]any  `json:"_meta,omitempty"`
}

type server struct {
	a     *app
	flags globalFlags
	cfg   effectiveConfig
	cache *toolCache

	// apps records whether the client negotiated MCP Apps at initialize. Nothing
	// about the picture is offered without it, since no widget can mount to
	// receive it.
	apps bool
}

// cmdServe speaks MCP over stdin and stdout until the client closes the pipe.
func (a *app) cmdServe(flags globalFlags, args []string) int {
	if len(args) > 0 {
		return a.fail(flags, exitValidation, "unexpected_argument",
			fmt.Sprintf("serve takes no arguments, got %q", args[0]))
	}
	// stdin is the transport from here on. All three gates are needed: the
	// first-run wizard is refused on a non-interactive app, `aws sso login` on a
	// machine one, and a credential_process helper on one that owns stdin — no
	// flag covers the others, and each of the three would otherwise read the
	// frames the client is sending.
	//
	// The helper is the one that had no gate before. `serve` resolves credentials
	// per tools/call, so a helper spawned mid-session inherited the live protocol
	// stream and shared its offset: frames the client had already sent could be
	// eaten by a subprocess, and the client would see a request simply never
	// answered. Same defect as #65, on a descriptor carrying rather more.
	a.interactive = func() bool { return false }
	a.machine = true
	a.quiet = true
	a.ownsStdin = true

	cfg, _, err := a.requireConfig(flags)
	if err != nil {
		return a.fail(flags, exitConfig, "not_configured", err.Error())
	}
	// Loaded once. Syncing per call would re-render the installed harness files
	// underneath a running IDE, several times a session.
	cache, err := a.cacheForCatalog(flags, cfg, true)
	if err != nil {
		code := exitSync
		if isCredentialFailure(err) {
			code = exitAuth
		}
		return a.fail(flags, code, errorName(err), err.Error())
	}

	s := &server{a: a, flags: flags, cfg: cfg, cache: cache}
	if err := s.run(a.stdin, a.stdout); err != nil {
		return a.fail(flags, exitGeneric, "serve_failed", err.Error())
	}
	return 0
}

func (s *server) run(stdin io.Reader, stdout io.Writer) error {
	in := bufio.NewScanner(stdin)
	in.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := bufio.NewWriter(stdout)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var req serveRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}
		result, rpcErr := s.handle(req)
		// A notification carries no id and takes no reply, whatever it produced.
		if len(req.ID) == 0 {
			continue
		}
		reply := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rpcErr != nil {
			reply["error"] = rpcErr
		} else {
			reply["result"] = result
		}
		encoded, err := json.Marshal(reply)
		if err != nil {
			return err
		}
		if _, err := out.Write(append(encoded, '\n')); err != nil {
			return err
		}
		if err := out.Flush(); err != nil {
			return err
		}
	}
	return in.Err()
}

func (s *server) handle(req serveRequest) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
			Capabilities    struct {
				Extensions map[string]json.RawMessage `json:"extensions"`
			} `json:"capabilities"`
		}
		_ = json.Unmarshal(req.Params, &params)
		_, s.apps = params.Capabilities.Extensions[uiExtensionID]
		if params.ProtocolVersion == "" {
			params.ProtocolVersion = serveProtocolVersion
		}
		capabilities := map[string]any{"tools": map[string]any{}}
		// Declared only to a client that negotiated MCP Apps. Some clients turn
		// the resources capability alone into a model-facing read tool that is
		// not restricted to listed resources, which would let a model pull the
		// widget's markup into its own context by guessing the URI.
		if s.apps {
			capabilities["resources"] = map[string]any{}
		}
		return map[string]any{
			"protocolVersion": params.ProtocolVersion,
			"capabilities":    capabilities,
			"serverInfo":      map[string]any{"name": "bmcp", "version": version},
		}, nil

	case "ping":
		return map[string]any{}, nil

	case "tools/list":
		return map[string]any{"tools": s.tools()}, nil

	case "tools/call":
		return s.callTool(req.Params)

	case "resources/list":
		// Deliberately empty. A host reaches the widget through the tool's
		// resourceUri; listing it as well only publishes a route for a model
		// with resource access to read the markup for itself.
		return map[string]any{"resources": []any{}}, nil

	case "resources/read":
		return s.readResource(req.Params)

	case "resources/templates/list":
		return map[string]any{"resourceTemplates": []any{}}, nil

	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	}

	if len(req.ID) == 0 {
		return nil, nil
	}
	return nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
}

// tools re-exports the cached catalog under its fully-qualified names, which are
// the only unique key — two namespaces may share a display name.
func (s *server) tools() []serveTool {
	out := make([]serveTool, 0, len(s.cache.Tools)+1)
	for _, t := range s.cache.Tools {
		entry := serveTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: objectSchema(t.InputSchema),
		}
		if s.apps && wantsPicture(t.Name) {
			entry.Meta = map[string]any{"ui": map[string]any{"resourceUri": widgetURI}}
		}
		out = append(out, entry)
	}
	return out
}

func objectSchema(raw json.RawMessage) json.RawMessage {
	if schema := nonEmptySchema(raw); schema != nil {
		return schema
	}
	return json.RawMessage(`{"type":"object","properties":{}}`)
}

func (s *server) callTool(raw json.RawMessage) (any, *rpcError) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	t, err := resolveTool(s.cache, params.Name)
	if err != nil {
		return nil, &rpcError{Code: -32602, Message: err.Error()}
	}
	input := params.Arguments
	if input == nil {
		input = map[string]any{}
	}
	if err := t.Validate(input); err != nil {
		return toolFailure(err.Error()), nil
	}
	// Asked for after Validate, which runs against the advertised schema and
	// does not declare the marker.
	drawing := s.apps && wantsPicture(t.Name)
	if drawing {
		input = withPictureRequest(input)
	}
	result, err := s.a.callTool(context.Background(), s.cfg, t.Name, input)
	if err != nil {
		// An upstream failure carries the whole remote body in its message, so
		// it is a markup path like any other.
		return toolFailure(scrubMarkup(err.Error())), nil
	}
	result = unwrapMCPTextEnvelope(result)
	// Stripped unconditionally, not only for the tools this build expects to
	// render: the field is the gateway's to send, and the list here is a guess.
	stripped, svg := stripPicture(result)
	if stripped == nil {
		return toolFailure("the answer carried a graph picture that could not be separated from it"), nil
	}
	answer := map[string]any{
		"content": []any{map[string]any{"type": "text", "text": string(stripped)}},
	}
	// A host reads the ui:// resource before this call is dispatched, so a
	// drawing inlined there is always the previous call's; the result's own
	// _meta arrives with the call it belongs to and is kept out of the model's
	// request. The result's _meta, never a content block's — that one does
	// reach the model.
	if drawing && svg != "" {
		answer["_meta"] = map[string]any{pictureField: fitWithinPanel(svg)}
	}
	return answer, nil
}

func toolFailure(msg string) any {
	return map[string]any{
		"isError": true,
		"content": []any{map[string]any{"type": "text", "text": msg}},
	}
}

func (s *server) readResource(raw json.RawMessage) (any, *rpcError) {
	var params struct {
		URI string `json:"uri"`
	}
	_ = json.Unmarshal(raw, &params)
	if !s.apps || (params.URI != "" && params.URI != widgetURI) {
		return nil, &rpcError{Code: -32602, Message: "unknown resource: " + params.URI}
	}
	return map[string]any{"contents": []any{map[string]any{
		"uri":      widgetURI,
		"mimeType": widgetMIME,
		"text":     widgetHTML(),
		// csp and permissions belong on the resource; a host is told to ignore
		// them on the tool.
		"_meta": map[string]any{"ui": map[string]any{
			"permissions":   map[string]any{},
			"prefersBorder": false,
		}},
	}}}, nil
}

// stripPicture removes the render field from wherever it appears in a payload
// and returns the markup it carried. A payload without the field comes back
// byte-for-byte; one that has it is always rebuilt, and a nil payload means the
// answer could not be made safe. Nothing returns the original once the field is
// known to be there, which is what would put the markup in front of a model.
func stripPicture(raw []byte) ([]byte, string) {
	// The bare name, not the quoted key: an answer the gateway encoded twice
	// spells it \"_svg\", so looking for the quoted form steps past it.
	if !bytes.Contains(raw, []byte(renderField)) {
		return raw, ""
	}
	// UseNumber so re-encoding cannot reformat a number the caller then reads
	// as a different value.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var doc any
	if err := decoder.Decode(&doc); err != nil {
		return nil, ""
	}
	cleaned, svg := withoutRenderField(doc)
	if svg != "" {
		if object, ok := cleaned.(map[string]any); ok {
			if inner, ok := object["result"].(map[string]any); ok {
				inner[pictureField] = "shown to the user"
			}
		}
	}
	rewritten, err := json.Marshal(cleaned)
	if err != nil {
		return nil, svg
	}
	return rewritten, svg
}

// withoutRenderField deletes the render field at every depth, returning the
// first markup string it found.
func withoutRenderField(node any) (any, string) {
	found := ""
	switch value := node.(type) {
	case map[string]any:
		if blob, ok := value[renderField]; ok {
			if markup, isString := blob.(string); isString {
				found = markup
			}
			delete(value, renderField)
		}
		for key, child := range value {
			cleaned, svg := withoutRenderField(child)
			value[key] = cleaned
			if found == "" {
				found = svg
			}
		}
		return value, found
	case []any:
		for i, child := range value {
			cleaned, svg := withoutRenderField(child)
			value[i] = cleaned
			if found == "" {
				found = svg
			}
		}
		return value, found
	case string:
		// A string can be a JSON document in its own right — an unwrapped MCP
		// envelope, or an answer the gateway encoded twice. Walking only decoded
		// values would step straight past the field.
		if !strings.Contains(value, renderField) {
			return value, ""
		}
		if cleaned, svg := stripPicture([]byte(value)); cleaned != nil {
			return string(cleaned), svg
		}
		return "(a graph picture was removed from this message)", ""
	}
	return node, ""
}

// scrubMarkup keeps the render field out of a message that is prose wrapped
// around a JSON body, which is how an upstream failure arrives.
func scrubMarkup(text string) string {
	if !strings.Contains(text, renderField) {
		return text
	}
	const withheld = "(a graph picture was removed from this message)"
	start := strings.Index(text, "{")
	if start < 0 {
		return withheld
	}
	if cleaned, _ := stripPicture([]byte(text[start:])); cleaned != nil {
		return text[:start] + string(cleaned)
	}
	return text[:start] + withheld
}
