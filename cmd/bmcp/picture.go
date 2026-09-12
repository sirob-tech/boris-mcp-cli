package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// How long a widget's request for its own picture waits before answering empty.
// Every renderable call publishes something the moment it finishes, drawing or
// not, so this only bounds a request no call will ever answer.
const pictureWait = 90 * time.Second

// pictureDesk holds each drawing under the call that produced it.
//
// The widget mounts while the tool input is still streaming, so it asks for its
// picture before the call that draws one has been dispatched. Its request waits
// here until that call publishes.
type pictureDesk struct {
	mu    sync.Mutex
	drawn map[string]string
	wait  map[string][]chan string
}

func newPictureDesk() *pictureDesk {
	return &pictureDesk{drawn: map[string]string{}, wait: map[string][]chan string{}}
}

// publish records what a call drew, and releases whoever was waiting for it. An
// empty svg is published too: a call that drew nothing is an answer, not a
// reason to leave a widget waiting.
func (d *pictureDesk) publish(call, svg string) {
	if call == "" {
		return
	}
	d.mu.Lock()
	d.drawn[call] = svg
	waiting := d.wait[call]
	delete(d.wait, call)
	d.mu.Unlock()
	for _, ch := range waiting {
		ch <- svg
	}
}

// collect answers with one call's drawing, waiting for it if the call is still
// running.
func (d *pictureDesk) collect(call string, wait time.Duration) string {
	d.mu.Lock()
	if svg, ok := d.drawn[call]; ok {
		d.mu.Unlock()
		return svg
	}
	ch := make(chan string, 1)
	d.wait[call] = append(d.wait[call], ch)
	d.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case svg := <-ch:
		return svg
	case <-timer.C:
		d.mu.Lock()
		d.wait[call] = without(d.wait[call], ch)
		d.mu.Unlock()
		return ""
	}
}

func without(waiting []chan string, ch chan string) []chan string {
	kept := waiting[:0]
	for _, c := range waiting {
		if c != ch {
			kept = append(kept, c)
		}
	}
	return kept
}

// callDigest names a call by the arguments the host sent it. Those arguments are
// the only thing the widget and this server can both see: the host hands the
// widget the same ones it put on the wire, and neither end is told the other's
// identifier for the call.
func callDigest(args map[string]any) string {
	if args == nil {
		args = map[string]any{}
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	// Off, so a query containing < or & hashes as the widget's JSON.stringify
	// writes it rather than as <.
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(args); err != nil {
		return ""
	}
	return fnv1a(bytes.TrimRight(buf.Bytes(), "\n"))
}

func fnv1a(data []byte) string {
	hash := uint32(2166136261)
	for _, b := range data {
		hash ^= uint32(b)
		hash *= 16777619
	}
	return strconv.FormatUint(uint64(hash), 16)
}
