// ©AngelaMos | 2026
// main.go

package main

import (
	"errors"
	"fmt"
	"os"
)

const (
	exitOK        = 0
	exitFound     = 1
	exitToolError = 2
	exitRateLimit = 3
)

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

func main() {
	err := newRootCommand().Execute()
	if err == nil {
		os.Exit(exitOK)
	}

	var ex *exitError
	if errors.As(err, &ex) {
		if ex.code != exitFound {
			_, _ = fmt.Fprintf(os.Stderr, "erinyes: %v\n", ex.err)
		}
		os.Exit(ex.code)
	}

	_, _ = fmt.Fprintf(os.Stderr, "erinyes: %v\n", err)
	os.Exit(exitToolError)
}
