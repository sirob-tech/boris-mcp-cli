package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	defaultTTL     = 168 * time.Hour
	defaultConnect = 30 * time.Second
	defaultSync    = 60 * time.Second
	defaultCall    = 10 * time.Minute

	exitGeneric    = 1
	exitConfig     = 2
	exitAuth       = 3
	exitSync       = 4
	exitValidation = 5
	exitUpstream   = 6
)

// Injected by GoReleaser at build time. `version` arrives unprefixed
// (`0.3.0`) while git tags and the release redirect carry a `v`, so anything
// comparing the two must normalize first — see normalizeVersion.
//
// buildCommit is the sole source-build sentinel: `version` defaults to a string
// that is also a real released tag, so it cannot distinguish the two. Note that
// release-please-config.json lists this file under extra-files but no line here
// carries an x-release-please-version annotation, so nothing rewrites `version`
// today. Adding one would turn the default into a real version and break that
// detection; key install classification on buildCommit instead.
var (
	version     = "0.1.0"
	buildCommit = "unknown"
	buildDate   = "unknown"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type credentialsFunc func(context.Context, effectiveConfig) (aws.Credentials, string, error)

type app struct {
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	now         func() time.Time
	httpClient  httpDoer
	credentials credentialsFunc
	lookPath    func(string) (string, error)
	interactive func() bool
	// executable and verifySignature are injectable so the swap can be tested.
	// Without them a test exercising the update path resolves to, and would
	// overwrite, the `go test` binary itself.
	executable      func() (string, error)
	verifySignature func(string) error
	// update carries the result of the auto-update check from run() to whatever
	// command wants to report it. Only doctor reads it.
	update           *updateState
	warnedAutoUpdate bool
	// refusedEmptyCatalog records that syncTools already declined to overwrite the
	// cache this run. Without it a single `bmcp <tool>` call syncs twice —
	// cmdDynamic resolves the tool, then runCall resolves it again — because the
	// refusal deliberately leaves LastSync stale, so the second lookup is still
	// due. Two handshakes per call against an already-degraded server, and the
	// warning printed twice.
	refusedEmptyCatalog bool
}

func main() {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, now: time.Now}
	os.Exit(a.run(os.Args[1:]))
}

func (a *app) isInteractive() bool {
	if a.interactive != nil {
		return a.interactive()
	}
	return isInteractive()
}

func isInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
