package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"golang.org/x/term"

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
	// stderrTTY is injectable because a test cannot make a pipe a character
	// device, and the branch it selects — keeping a credential_process helper's
	// stderr visible — exists only for a terminal. See retrieveCredentials.
	stderrTTY func() bool
	// realStderr is os.Stderr's value from startup: the descriptor a child
	// process would have inherited as fd 2 before anything reassigned the
	// variable. retrieveCredentials points os.Stderr at /dev/null and, on a
	// cancelled retrieval, deliberately leaves it there — so the variable is not
	// a reliable answer to "what is fd 2" for the rest of the run. Everything
	// that needs the real answer reads this instead: the terminal test, and every
	// subprocess bmcp spawns itself.
	realStderr *os.File
	// stderrSunk latches when a retrieval was abandoned with the /dev/null sink
	// still installed. An SDK goroutine outliving that call can still read
	// os.Stderr to build its command, so from then on nothing may write the
	// variable — not to install a second sink, and not to put the original back.
	// See retrieveCredentials.
	stderrSunk bool
	// helperStderrDiscarded records that retrieveCredentials sent a
	// credential_process helper's stderr to /dev/null, so a failure message can
	// say so. Without it an operator reads an empty CI log as "the helper printed
	// nothing" when bmcp is what threw it away.
	helperStderrDiscarded bool
	// executable and verifySignature are injectable so the swap can be tested.
	// Without them a test exercising the update path resolves to, and would
	// overwrite, the `go test` binary itself.
	executable      func() (string, error)
	verifySignature func(string) error
	// update carries the result of the auto-update check from run() to whatever
	// command wants to report it. Only doctor reads it.
	update           *updateState
	warnedAutoUpdate bool
	// machine records that this invocation answers in a machine format, and quiet
	// that its progress prose is therefore suppressed. Both are set by selectOutput
	// once dispatch has resolved the output format.
	//
	// They are separate because --verbose separates them: it puts the prose back
	// without making the invocation interactive. Anything deciding whether it may
	// prompt must read machine, not quiet — a machine caller that asked for
	// diagnostics is still a machine caller.
	machine bool
	quiet   bool
	// warnings collects the degradations warn() reported, so a machine document can
	// carry what the prose channel would have said.
	warnings []string
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

// warn records a degradation and prints it for a human.
//
// Warnings are not progress: "using a stale cache" and "the server listed no
// tools" change what the answer means, and a machine format that merely
// swallowed them would report ok:true on a catalog the human form flags as
// suspect. So they are collected here as well as printed, and the success
// documents carry whatever was collected — see output.go.
func (a *app) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.warnings = append(a.warnings, msg)
	fmt.Fprintln(a.prose(), msg)
}

// warnUpdate is warn for the self-update path, which the legacy --json has always
// silenced — every one of those sites used to sit behind `if !flags.jsonOut`.
// Routing them through prose() alone would have started showing update notices to
// every `bmcp doctor --json` caller on their next automatic update, which is the
// exact class of change this release exists not to make.
//
// The warning is still recorded, so a --format document carries it either way.
func (a *app) warnUpdate(flags globalFlags, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.warnings = append(a.warnings, msg)
	if flags.legacyJSON() {
		return
	}
	fmt.Fprintln(a.prose(), msg)
}

// prose is the writer for progress, warnings and anything else a person reads.
// It is stderr in a human format and io.Discard in a machine one, so that
// merging the two streams — which is what agents do to keep hold of errors —
// cannot put a line of English into a document a parser is reading.
//
// Errors are not prose and do not go through here: they keep stderr in every
// format, as a stable JSON document in the machine ones. See output.go.
func (a *app) prose() io.Writer {
	if a.quiet {
		return io.Discard
	}
	return a.stderr
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

// subprocessStderr is the descriptor a child of bmcp should be given for fd 2:
// the value os.Stderr held at startup, never whatever retrieveCredentials may
// have left in the variable since. Handing a subprocess the live global is how a
// sink installed for a *helper* ends up swallowing the output of an unrelated
// command — `aws sso login`'s verification URL, for one.
//
// The fallback exists for tests, which build an app directly. Production always
// pins it in main().
func (a *app) subprocessStderr() *os.File {
	if a.realStderr != nil {
		return a.realStderr
	}
	return os.Stderr
}

func (a *app) stderrIsTerminal() bool {
	if a.stderrTTY != nil {
		return a.stderrTTY()
	}
	return stderrIsTerminal(a.subprocessStderr())
}

// stderrIsTerminal asks "could a person read what a subprocess writes to fd 2,
// right now" — a pipe, a file, a CI log and an agent transcript all answer no.
//
// It is a real terminal test, not a character-device test. Those are not the
// same question and the difference is a disclosure: /dev/console and /dev/kmsg
// are character devices that persist what is written to them — kmsg into the
// kernel log, console into a serial console a cloud provider will hand back
// through its API — so `bmcp <tool> 2>/dev/kmsg` from an init script would have
// passed a ModeCharDevice test and put a credential_process helper's trace into
// a durable log. term.IsTerminal issues the terminal ioctl, which those devices
// fail and a tty passes.
//
// A pty still answers yes, and nothing here can separate an operator's own
// terminal from one a recorder is driving (`script`, `docker run -t`, a logging
// tmux pane). That residual is why the policy in retrieveCredentials has two
// more conjuncts.
//
// It takes the descriptor rather than reading os.Stderr so that a caller cannot
// be handed the answer for a sink retrieveCredentials installed — see
// subprocessStderr.
func stderrIsTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
