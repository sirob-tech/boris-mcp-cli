package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWantsPictureOnlyForTheFinders(t *testing.T) {
	t.Setenv("BMCP_RENDER", "")
	cases := map[string]bool{
		"tools___search_infrastructure_by_description": true,
		"tools___search_infrastructure_relationships":  true,
		// Raw Cypher has no resolvable entry point to centre a picture on.
		"tools___search_infrastructure_graph": false,
		"tools___list_aws_resources":          false,
		"tools___call_aws_api":                false,
	}
	for name, want := range cases {
		if got := wantsPicture(name); got != want {
			t.Errorf("wantsPicture(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestBMCPRenderAcceptsEverySpellingTheRestOfTheCLIDoes(t *testing.T) {
	// This was the one switch that matched "off" alone, so an operator turning
	// it off the way BMCP_NON_INTERACTIVE is turned off got pictures anyway,
	// silently.
	finder := "tools___search_infrastructure_by_description"

	for _, value := range []string{"off", "OFF", " off ", "false", "0", "no", "NO"} {
		t.Setenv("BMCP_RENDER", value)
		if wantsPicture(finder) {
			t.Errorf("BMCP_RENDER=%q must disable rendering", value)
		}
	}
	for _, value := range []string{"", "on", "true", "1", "yes", "nonsense"} {
		t.Setenv("BMCP_RENDER", value)
		if !wantsPicture(finder) {
			t.Errorf("BMCP_RENDER=%q must leave rendering on", value)
		}
	}
}

func TestWithPictureRequestDoesNotMutateTheCallersInput(t *testing.T) {
	original := map[string]any{"query": "the shared vpc"}
	out := withPictureRequest(original)

	if _, leaked := original["_render"]; leaked {
		t.Fatal("the caller's map must be left alone so a retry sends what it passed")
	}
	if out[renderMarker] != true {
		t.Fatalf("marker missing from the outgoing input: %v", out)
	}
	if out["query"] != "the shared vpc" {
		t.Fatalf("declared arguments must survive: %v", out)
	}
}

func TestTakePictureMovesTheMarkupToDisk(t *testing.T) {
	home := t.TempDir()
	payload := `{"result":{"status":"success","data":[{"id":"vpc-1"}],"_svg":"<svg>x</svg>"}}`

	out := takePicture(home, []byte(payload))

	if strings.Contains(string(out), "<svg") {
		t.Fatalf("markup must not survive into the tool result: %s", out)
	}
	var envelope struct {
		Result struct {
			Status  string `json:"status"`
			Picture string `json:"picture"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		t.Fatalf("rewritten payload is not valid JSON: %v", err)
	}
	if envelope.Result.Status != "success" {
		t.Errorf("the finder's own answer must be preserved, got %q", envelope.Result.Status)
	}
	want := filepath.Join(home, pictureName)
	if envelope.Result.Picture != want {
		t.Errorf("picture path = %q, want %q", envelope.Result.Picture, want)
	}
	written, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("picture was not written: %v", err)
	}
	if string(written) != "<svg>x</svg>" {
		t.Errorf("picture contents = %q", written)
	}
}

func TestTakePictureLeavesEverythingElseAlone(t *testing.T) {
	home := t.TempDir()
	// Each of these must come back byte-for-byte: a decoration may never cost
	// the caller the answer it asked for.
	cases := map[string]string{
		"no picture":        `{"result":{"status":"success","data":[]}}`,
		"no result key":     `{"error":"TypeError: tool invocation failed"}`,
		"not an object":     `[1,2,3]`,
		"not json":          `# AWS Organization`,
		"empty markup":      `{"result":{"_svg":""}}`,
		"markup not string": `{"result":{"_svg":{"nested":true}}}`,
	}
	for name, payload := range cases {
		if got := string(takePicture(home, []byte(payload))); got != payload {
			t.Errorf("%s: payload changed\n got %s\nwant %s", name, got, payload)
		}
	}
}

func TestTakePictureDropsTheMarkupEvenWhenItCannotBeWritten(t *testing.T) {
	// The markup must go whether or not the file lands. Keeping the answer
	// intact here would hand ~13 KB of it to a model, which is the one outcome
	// the render field exists to prevent.
	payload := `{"result":{"status":"ok","_svg":"<svg/>"}}`
	got := string(takePicture("", []byte(payload)))

	if strings.Contains(got, "<svg") || strings.Contains(got, renderField) {
		t.Fatalf("markup survived an unwritable home: %s", got)
	}
	if !strings.Contains(got, `"status":"ok"`) {
		t.Errorf("the answer itself must survive: %s", got)
	}
	var envelope struct {
		Result struct {
			Picture string `json:"picture"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(got), &envelope); err != nil {
		t.Fatalf("rewritten payload is not valid JSON: %v", err)
	}
	if !strings.Contains(envelope.Result.Picture, "could not be written") {
		t.Errorf("the caller must be told why there is no picture, got %q", envelope.Result.Picture)
	}
}

func TestWritePictureReplacesAtomically(t *testing.T) {
	home := t.TempDir()
	if _, err := writePicture(home, "<svg>first</svg>"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	path, err := writePicture(home, "<svg>second</svg>")
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != "<svg>second</svg>" {
		t.Errorf("stable path must carry the newest picture, got %q", written)
	}
	// No temp files left behind for a watcher to trip over.
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != pictureName {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("expected only %s to remain, found %v", pictureName, names)
	}
}
