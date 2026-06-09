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
