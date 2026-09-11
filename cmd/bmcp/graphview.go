package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// The resource finders can return a rendered picture of their top hit for a
// person to look at. It is not a tool and it is not advertised: BMCP asks for
// it, BMCP takes it back out, and the agent's view of the response is unchanged
// apart from a file path. Raw Cypher is deliberately absent — there is no way to
// infer what such a query should be centred on.
var renderableTools = map[string]bool{
	"search_infrastructure_by_description": true,
	"search_infrastructure_relationships":  true,
}

const (
	// Asked for as an undeclared argument, which the gateway forwards to the
	// Lambda. A deployment with rendering off ignores it and returns its normal
	// answer, so asking costs nothing and needs no capability negotiation.
	renderMarker = "_render"
	// Carried back inside the tool's own result, and never allowed to reach a
	// model: the markup is ~13 KB of no use to it.
	renderField = "_svg"
	// Substituted for the markup, so the answer still says a picture exists.
	pictureField = "picture"
	// Stable rather than unique, so a person can leave a viewer open on the
	// path and watch it change.
	pictureName = "last-graph.svg"
)

// wantsPicture reports whether this call should ask for one. Any of the
// spellings BMCP_NON_INTERACTIVE accepts turns it off, and the request is then
// byte-identical to a build without this feature.
//
// It reads through parseStrictBool rather than matching "off" alone: this used
// to be the only switch in the CLI that did not, so BMCP_RENDER=false and
// BMCP_RENDER=0 left rendering on and said nothing about it.
func wantsPicture(name string) bool {
	if enabled, set := parseStrictBool(os.Getenv("BMCP_RENDER")); set && !enabled {
		return false
	}
	return renderableTools[displayToolName(name)]
}

// withPictureRequest returns input plus the marker, leaving the caller's map
// alone so a retry sends what the caller actually passed.
func withPictureRequest(input map[string]any) map[string]any {
	out := make(map[string]any, len(input)+1)
	for key, value := range input {
		out[key] = value
	}
	out[renderMarker] = true
	return out
}

// takePicture moves the markup out of an unwrapped tool result and onto disk,
// substituting the path. The payload is the Lambda's `{"result": …}` envelope,
// so the markup sits one level in.
//
// Anything unexpected — a shape it cannot parse, no picture, an unwritable
// directory — returns the payload byte-for-byte unchanged. A decoration must
// never cost a caller the answer it asked for.
func takePicture(home string, raw []byte) []byte {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return raw
	}
	inner, ok := envelope["result"]
	if !ok {
		return raw
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(inner, &result); err != nil {
		return raw
	}
	blob, ok := result[renderField]
	if !ok {
		return raw
	}
	var svg string
	if err := json.Unmarshal(blob, &svg); err != nil || svg == "" {
		return raw
	}

	// Removed before anything can fail. Returning the original once the field is
	// known to be there is what would put ~13 KB of markup in front of a model,
	// which is the one thing this field must never do.
	delete(result, renderField)
	note, err := json.Marshal(pictureNote(home, svg))
	if err != nil {
		return raw
	}
	result[pictureField] = note

	rewrittenInner, err := json.Marshal(result)
	if err != nil {
		return raw
	}
	envelope["result"] = rewrittenInner
	rewritten, err := json.Marshal(envelope)
	if err != nil {
		return raw
	}
	return rewritten
}

// pictureNote writes the picture and reports where it went, or why it did not.
func pictureNote(home, svg string) string {
	path, err := writePicture(home, svg)
	if err != nil {
		return "the picture could not be written: " + err.Error()
	}
	return path
}

// writePicture writes the markup whole and renames it into place, so a viewer
// watching the path never reads a half-written document.
func writePicture(home, svg string) (string, error) {
	if home == "" {
		return "", errors.New("no home directory to write the picture to")
	}
	if err := os.MkdirAll(home, 0o755); err != nil {
		return "", err
	}
	temp, err := os.CreateTemp(home, pictureName+".*")
	if err != nil {
		return "", err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.WriteString(svg); err != nil {
		temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}
	path := filepath.Join(home, pictureName)
	if err := os.Rename(temp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}
