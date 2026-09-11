package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// callRecorder keeps the arguments of the last tools/call so a test can assert
// what actually went upstream, which fakeMCP alone does not expose.
type callRecorder struct {
	*fakeMCP
	lastArgs map[string]any
}

func (r *callRecorder) Do(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
		var rpc jsonRPCRequest
		if json.Unmarshal(body, &rpc) == nil && rpc.Method == "tools/call" {
			var params struct {
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(rpc.Params, &params)
			r.lastArgs = params.Arguments
		}
	}
	return r.fakeMCP.Do(req)
}

const (
	finderTool   = "tools___search_infrastructure_by_description"
	plainTool    = "tools___list_aws_resources"
	initWithUI   = `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{"extensions":{"io.modelcontextprotocol/ui":{"mimeTypes":["text/html;profile=mcp-app"]}}}}}`
	initPlainRPC = `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`
)

func finderCatalog() []tool {
	return []tool{
		{
			Name:        finderTool,
			Description: "Find a resource by description.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}}}`),
		},
		{Name: plainTool, Description: "Enumerate resources."},
	}
}

// upstreamAnswer wraps a finder payload the way the gateway does: the answer is
// a JSON document inside the MCP envelope's first text block.
func upstreamAnswer(payload map[string]any) []byte {
	inner, err := json.Marshal(map[string]any{"result": payload})
	if err != nil {
		panic(err)
	}
	return mcpEnvelope(string(inner), false)
}

func mcpEnvelope(text string, isError bool) []byte {
	envelope, err := json.Marshal(map[string]any{
		"isError": isError,
		"content": []any{map[string]any{"type": "text", "text": text}},
	})
	if err != nil {
		panic(err)
	}
	return envelope
}

func serveConfiguredHome(t *testing.T, doer httpDoer) {
	t.Helper()
	t.Setenv("BMCP_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	// wantsPicture reads this from the process environment, so a developer or
	// runner with it set would otherwise silently disarm half this file.
	t.Setenv("BMCP_RENDER", "")

	var stdout, stderr bytes.Buffer
	setup := &app{
		stdin: strings.NewReader(""), stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: doer, credentials: staticCreds(),
		lookPath: func(string) (string, error) { return "", os.ErrNotExist },
	}
	if code := setup.run([]string{"init", "--url", "http://localhost:8787/mcp"}); code != 0 {
		t.Fatalf("init exit code %d, stderr: %s", code, stderr.String())
	}
}

// serveLines runs one serve session over the frames and returns the raw lines it
// wrote to stdout. Assertions about markup must use these, not a re-marshalled
// map: encoding/json escapes "<" to "<", so searching a re-marshalled
// payload for "<svg" can never match whatever the server actually sent.
func serveLines(t *testing.T, doer httpDoer, frames ...string) []string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	a := &app{
		stdin:  strings.NewReader(strings.Join(frames, "\n") + "\n"),
		stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: doer, credentials: staticCreds(),
		lookPath: func(string) (string, error) { return "", os.ErrNotExist },
	}
	if code := a.run([]string{"serve"}); code != 0 {
		t.Fatalf("serve exit code %d, stderr: %s", code, stderr.String())
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// serveFrames configures a home, negotiates MCP Apps, then returns the replies
// to the caller's frames alongside the raw lines that carried them.
func serveFrames(t *testing.T, doer httpDoer, frames ...string) ([]map[string]any, []string) {
	t.Helper()
	serveConfiguredHome(t, doer)
	lines := serveLines(t, doer, append([]string{initWithUI}, frames...)...)
	if len(lines) == 0 {
		t.Fatal("serve wrote nothing at all")
	}
	replies := make([]map[string]any, 0, len(lines)-1)
	for _, line := range lines[1:] {
		var reply map[string]any
		if err := json.Unmarshal([]byte(line), &reply); err != nil {
			t.Fatalf("reply is not JSON: %s", line)
		}
		replies = append(replies, reply)
	}
	return replies, lines[1:]
}

func resultOf(t *testing.T, reply map[string]any) map[string]any {
	t.Helper()
	if errObj, bad := reply["error"]; bad {
		t.Fatalf("expected a result, got error: %v", errObj)
	}
	result, ok := reply["result"].(map[string]any)
	if !ok {
		t.Fatalf("reply carries no result object: %v", reply)
	}
	return result
}

// assertNoMarkup checks the bytes the server actually wrote, in both the plain
// and the JSON-escaped spelling.
func assertNoMarkup(t *testing.T, what, line string) {
	t.Helper()
	for _, needle := range []string{renderField, "<svg", `u003csvg`} {
		if strings.Contains(line, needle) {
			t.Fatalf("%s: %q reached the model:\n%s", what, needle, line)
		}
	}
}

func callFrame(id int, name, args string) string {
	return `{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

func itoa(n int) string {
	out, _ := json.Marshal(n)
	return string(out)
}

func TestServeMarksOnlyTheFindersWithTheWidget(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	replies, _ := serveFrames(t, doer, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	tools, _ := resultOf(t, replies[0])["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("tools/list returned nothing, so nothing below is being tested")
	}
	widget := map[string]bool{}
	visibility := map[string]string{}
	for _, entry := range tools {
		tool := entry.(map[string]any)
		name := tool["name"].(string)
		meta, _ := tool["_meta"].(map[string]any)
		ui, _ := meta["ui"].(map[string]any)
		if ui["resourceUri"] == widgetURI {
			widget[name] = true
		}
		if v, ok := ui["visibility"]; ok {
			encoded, _ := json.Marshal(v)
			visibility[name] = string(encoded)
		}
		if tool["inputSchema"] == nil {
			t.Errorf("%s advertises no input schema", name)
		}
	}
	if !widget[finderTool] {
		t.Error("the finder must carry the widget's resourceUri")
	}
	if widget[plainTool] {
		t.Error("a tool that draws no picture must not mount the widget")
	}
	if visibility[pictureToolName] != `["app"]` {
		t.Errorf("picture tool visibility = %s, want [\"app\"]", visibility[pictureToolName])
	}
}

func TestServeOffersNoPictureWithoutMCPApps(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	serveConfiguredHome(t, doer)
	// A client that never advertised the extension cannot mount a widget, so
	// the tool would only be a way for a model to fetch the markup itself.
	lines := serveLines(t, doer, initPlainRPC,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		callFrame(2, pictureToolName, "{}"),
	)
	if strings.Contains(lines[1], pictureToolName) {
		t.Errorf("the picture tool must not be advertised:\n%s", lines[1])
	}
	if strings.Contains(lines[1], widgetURI) {
		t.Errorf("the widget must not be advertised:\n%s", lines[1])
	}
	var reply map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &reply); err != nil {
		t.Fatal(err)
	}
	if _, bad := reply["error"]; !bad {
		t.Errorf("calling the picture tool must fail on such a client: %s", lines[2])
	}
}

func TestServeDoesNotListTheWidgetResource(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	replies, _ := serveFrames(t, doer, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`)
	resources, _ := resultOf(t, replies[0])["resources"].([]any)
	if len(resources) != 0 {
		t.Errorf("listing the widget publishes a route to the markup: %v", resources)
	}
}

func TestServeKeepsTheMarkupOutOfTheToolResult(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{
		tools: finderCatalog(),
		callResult: upstreamAnswer(map[string]any{
			"status": "success",
			"data":   []any{map[string]any{"id": "vpc-1"}},
			"_svg":   "<svg>the picture</svg>",
		}),
	}}
	replies, lines := serveFrames(t, doer,
		callFrame(1, finderTool, `{"query":"the shared vpc"}`),
		callFrame(2, pictureToolName, "{}"),
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"`+widgetURI+`"}}`,
	)
	if len(replies) != 3 {
		t.Fatalf("expected 3 replies, got %d", len(replies))
	}

	assertNoMarkup(t, "finder answer", lines[0])
	if !strings.Contains(lines[0], "vpc-1") {
		t.Errorf("the finder's own answer must survive: %s", lines[0])
	}
	if doer.lastArgs[renderMarker] != true {
		t.Errorf("the render marker was not sent upstream: %v", doer.lastArgs)
	}
	if doer.lastArgs["query"] != "the shared vpc" {
		t.Errorf("declared arguments must survive: %v", doer.lastArgs)
	}

	meta, ok := resultOf(t, replies[1])["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("the picture tool returned no _meta: %v", replies[1])
	}
	svg, _ := meta["svg"].(string)
	if !strings.Contains(svg, "the picture") {
		t.Errorf("picture tool returned %q", svg)
	}

	contents, _ := resultOf(t, replies[2])["contents"].([]any)
	if len(contents) != 1 {
		t.Fatalf("expected one resource content, got %v", contents)
	}
	content := contents[0].(map[string]any)
	if content["mimeType"] != widgetMIME {
		t.Errorf("resource mimeType = %v", content["mimeType"])
	}
	if !strings.Contains(content["text"].(string), "the picture") {
		t.Error("the widget must carry the picture the resource was read for")
	}
}

func TestServeStripsMarkupFromAnyShapeTheGatewaySends(t *testing.T) {
	cases := map[string][]byte{
		"nested in an array": upstreamAnswer(map[string]any{
			"data": []any{map[string]any{"id": "vpc-1", "_svg": "<svg>nested</svg>"}},
		}),
		"no result wrapper": mcpEnvelope(`{"status":"ok","_svg":"<svg>top level</svg>"}`, false),
		"not a string":      upstreamAnswer(map[string]any{"status": "ok", "_svg": map[string]any{"nested": true}}),
	}
	for name, callResult := range cases {
		t.Run(name, func(t *testing.T) {
			doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog(), callResult: callResult}}
			_, lines := serveFrames(t, doer, callFrame(1, finderTool, `{"query":"x"}`))
			assertNoMarkup(t, name, lines[0])
		})
	}
}

func TestServeStripsMarkupEvenFromAToolItDidNotAskToRender(t *testing.T) {
	// The field is the gateway's to send; the client-side list of renderable
	// tools is only a guess about which answers will carry one.
	doer := &callRecorder{fakeMCP: &fakeMCP{
		tools:      finderCatalog(),
		callResult: upstreamAnswer(map[string]any{"status": "success", "_svg": "<svg>unasked</svg>"}),
	}}
	_, lines := serveFrames(t, doer, callFrame(1, plainTool, "{}"))
	assertNoMarkup(t, plainTool, lines[0])
}

func TestServeScrubsMarkupFromAnUpstreamFailure(t *testing.T) {
	// An upstream isError puts the entire remote body in the error message.
	doer := &callRecorder{fakeMCP: &fakeMCP{
		tools:      finderCatalog(),
		callResult: mcpEnvelope(`{"result":{"status":"partial","_svg":"<svg>the picture</svg>"}}`, true),
	}}
	replies, lines := serveFrames(t, doer, callFrame(1, finderTool, `{"query":"x"}`))
	assertNoMarkup(t, "upstream failure", lines[0])
	if resultOf(t, replies[0])["isError"] != true {
		t.Errorf("an upstream failure must stay an error: %s", lines[0])
	}
}

func TestServeReportsARejectedArgumentLocally(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	replies, _ := serveFrames(t, doer, callFrame(1, finderTool, `{"unknown":1}`))
	result := resultOf(t, replies[0])
	if result["isError"] != true {
		t.Fatalf("a rejected argument must come back as a tool error: %v", result)
	}
	if doer.lastArgs != nil {
		t.Errorf("validation must fail before anything goes upstream: %v", doer.lastArgs)
	}
}

func TestServeAnswersNothingForANotification(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	replies, _ := serveFrames(t, doer,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
	)
	if len(replies) != 1 {
		t.Fatalf("a notification must draw no reply, got %d replies", len(replies))
	}
	if replies[0]["id"] != float64(1) {
		t.Errorf("the reply must belong to the ping, got %v", replies[0])
	}
}

func TestServeEchoesTheClientsRequestID(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	// A string id is legal JSON-RPC and the client half of this binary cannot
	// represent one, so the server needs its own wire type.
	replies, _ := serveFrames(t, doer, `{"jsonrpc":"2.0","id":"abc","method":"tools/list"}`)
	if replies[0]["id"] != "abc" {
		t.Errorf("id = %v, want \"abc\"", replies[0]["id"])
	}
}

func TestServeRejectsAResourceItDoesNotServe(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	replies, _ := serveFrames(t, doer,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"ui://somewhere/else"}}`,
	)
	if _, bad := replies[0]["error"]; !bad {
		t.Fatalf("an unknown resource must be an error: %v", replies[0])
	}
}

func TestServeDoesNotPromptOnAnUnconfiguredHome(t *testing.T) {
	t.Setenv("BMCP_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("BMCP_RENDER", "")
	frame := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	stdin := strings.NewReader(frame + "\n")

	var stdout, stderr bytes.Buffer
	a := &app{
		stdin: stdin, stdout: &stdout, stderr: &stderr, now: time.Now,
		httpClient: &fakeMCP{tools: finderCatalog()}, credentials: staticCreds(),
		lookPath: func(string) (string, error) { return "", os.ErrNotExist },
		// A terminal-launched server would otherwise reach the first-run wizard,
		// which reads the frames the client is sending.
		interactive: func() bool { return true },
	}
	if code := a.run([]string{"serve"}); code == 0 {
		t.Fatal("an unconfigured home must fail, not proceed")
	}
	if left, _ := io.ReadAll(stdin); len(left) != len(frame)+1 {
		t.Errorf("the transport was read from: %d of %d bytes left", len(left), len(frame)+1)
	}
	if strings.Contains(stderr.String(), "BORIS MCP URL") {
		t.Errorf("the wizard prompted on the transport:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must carry JSON-RPC only, got: %s", stdout.String())
	}
}

func TestStripPictureAlwaysRemovesTheMarkupOnceItIsFound(t *testing.T) {
	cases := map[string]string{
		"a string":          `{"result":{"status":"ok","_svg":"<svg/>"}}`,
		"not a string":      `{"result":{"status":"ok","_svg":{"nested":true}}}`,
		"empty":             `{"result":{"status":"ok","_svg":""}}`,
		"no result wrapper": `{"status":"ok","_svg":"<svg/>"}`,
		"inside an array":   `{"result":{"data":[{"status":"ok","_svg":"<svg/>"}]}}`,
		"two levels deep":   `{"result":{"a":{"b":{"status":"ok","_svg":"<svg/>"}}}}`,
	}
	for name, payload := range cases {
		out, _ := stripPicture([]byte(payload))
		if out == nil {
			t.Errorf("%s: the answer was withheld entirely", name)
			continue
		}
		if bytes.Contains(out, []byte(renderField)) {
			t.Errorf("%s: the render field survived: %s", name, out)
		}
		if !bytes.Contains(out, []byte(`"status":"ok"`)) {
			t.Errorf("%s: the answer was lost: %s", name, out)
		}
	}
}

func TestStripPictureLeavesEverythingElseAlone(t *testing.T) {
	// Each must come back byte-for-byte: a decoration may never cost the caller
	// the answer it asked for.
	cases := map[string]string{
		"no picture":    `{"result":{"status":"success","data":[]}}`,
		"no result key": `{"error":"TypeError: tool invocation failed"}`,
		"not an object": `[1,2,3]`,
		"not json":      `# AWS Organization`,
	}
	for name, payload := range cases {
		out, svg := stripPicture([]byte(payload))
		if string(out) != payload {
			t.Errorf("%s: payload changed\n got %s\nwant %s", name, out, payload)
		}
		if svg != "" {
			t.Errorf("%s: reported a picture it did not have: %q", name, svg)
		}
	}
}

func TestStripPictureKeepsNumbersExact(t *testing.T) {
	// Re-encoding through float64 would turn a long score into 0.68597102165222,
	// and a large integer into 1e+06.
	payload := `{"result":{"score":0.6859710216522217,"count":1000000,"_svg":"<svg/>"}}`
	out, _ := stripPicture([]byte(payload))
	for _, want := range []string{"0.6859710216522217", "1000000"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("number %s was reformatted: %s", want, out)
		}
	}
}

func TestStripPictureWithholdsAnAnswerItCannotRebuild(t *testing.T) {
	// Not valid JSON, but it carries the field: there is no way to hand this on
	// without handing on the markup too.
	out, _ := stripPicture([]byte(`{"result":{"_svg":"<svg/>" truncated`))
	if out != nil {
		t.Errorf("an unparseable payload carrying markup must be withheld, got %s", out)
	}
}

func TestScrubMarkupCleansProseWrappedAroundABody(t *testing.T) {
	text := `upstream tool failure: {"content":[{"text":"{\"result\":{\"_svg\":\"<svg/>\"}}"}]}`
	out := scrubMarkup(text)
	if strings.Contains(out, renderField) || strings.Contains(out, "<svg") {
		t.Errorf("markup survived: %s", out)
	}
	if !strings.HasPrefix(out, "upstream tool failure: ") {
		t.Errorf("the diagnostic was lost: %s", out)
	}
	if plain := scrubMarkup("dial tcp: connection refused"); plain != "dial tcp: connection refused" {
		t.Errorf("a message with no markup must be untouched, got %q", plain)
	}
}

func TestFitWithinPanelReturnsMarkupItCannotRead(t *testing.T) {
	for _, in := range []string{"not markup at all", "<svg without a close", ""} {
		if out := fitWithinPanel(in); out != in {
			t.Errorf("fitWithinPanel(%q) = %q, want it unchanged", in, out)
		}
	}
}

func TestWidgetHTMLSaysSoWhenThereIsNoPictureYet(t *testing.T) {
	out := widgetHTML("")
	if strings.Contains(out, "<svg") {
		t.Errorf("no picture should mean no drawing: %s", out)
	}
	if !strings.Contains(out, "No graph has been drawn yet") {
		t.Errorf("the widget must say why it is empty: %s", out)
	}
}

func TestServeHidesTheResourceFromAClientWithoutMCPApps(t *testing.T) {
	// Some clients turn the resources capability alone into a model-facing read
	// tool that ignores the listing, so declaring it would let a model fetch the
	// widget's markup by guessing the URI.
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	serveConfiguredHome(t, doer)
	lines := serveLines(t, doer, initPlainRPC,
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"`+widgetURI+`"}}`,
	)

	var handshake map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &handshake); err != nil {
		t.Fatal(err)
	}
	caps, _ := handshake["result"].(map[string]any)["capabilities"].(map[string]any)
	if _, declared := caps["resources"]; declared {
		t.Errorf("the resources capability must not be offered: %s", lines[0])
	}

	var read map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &read); err != nil {
		t.Fatal(err)
	}
	if _, bad := read["error"]; !bad {
		t.Fatalf("the widget must not be readable: %s", lines[1])
	}
	assertNoMarkup(t, "unnegotiated resources/read", lines[1])
}

func TestServeDeclaresResourcesOnlyAfterNegotiation(t *testing.T) {
	doer := &callRecorder{fakeMCP: &fakeMCP{tools: finderCatalog()}}
	serveConfiguredHome(t, doer)
	lines := serveLines(t, doer, initWithUI)

	var handshake map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &handshake); err != nil {
		t.Fatal(err)
	}
	caps, _ := handshake["result"].(map[string]any)["capabilities"].(map[string]any)
	if _, declared := caps["resources"]; !declared {
		t.Errorf("a client that negotiated MCP Apps needs the resources capability: %s", lines[0])
	}
}

func TestFitWithinPanelConstrainsWithoutResizingTheDrawing(t *testing.T) {
	// Measured in a browser: an svg with only a viewBox stretches to fill a wide
	// panel — 926px of drawing blown up to 1400, taking 11px labels and a raster
	// mark with it. Keeping the intrinsic size is what caps it at natural size.
	svg := `<svg xmlns="http://www.w3.org/2000/svg" width="926" height="762" viewBox="0 0 926 762"><title>x</title></svg>`
	out := fitWithinPanel(svg)

	for _, want := range []string{`width="926"`, `height="762"`, `viewBox="0 0 926 762"`} {
		if !strings.Contains(out, want) {
			t.Errorf("intrinsic size must survive, missing %s: %s", want, out)
		}
	}
	if !strings.Contains(out, "max-width:100%") || !strings.Contains(out, "height:auto") {
		t.Errorf("missing the responsive constraint: %s", out)
	}
	if strings.Contains(out, "max-height") {
		t.Error("a height cap scales the drawing, shrinking its labels with it")
	}
	if !strings.Contains(out, "<title>x</title></svg>") {
		t.Errorf("the drawing must survive: %s", out)
	}
}
