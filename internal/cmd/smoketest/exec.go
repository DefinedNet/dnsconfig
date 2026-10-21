package main

import (
	"fmt"
	"strings"
)

// ExecResult bundles the captured outputs of a single command invocation.
type ExecResult struct {
	// Stdout is the subprocess's standard output.
	Stdout []byte

	// Stderr is the subprocess's standard error.
	Stderr []byte

	// ExitCode is the subprocess's exit code. It is 0 on success and the
	// usual non-zero values on failure. It is -1 if the runner failed to
	// spawn the subprocess at all (in which case Err is non-nil).
	ExitCode int

	// Err is non-nil when the runner failed to spawn the subprocess or the
	// subprocess exited non-zero. Callers that explicitly tolerate non-zero
	// exits should check ExitCode and ignore Err.
	Err error
}

// Successful reports whether the exec produced a zero exit code with no
// runner error.
func (r ExecResult) Successful() bool {
	return r.ExitCode == 0 && r.Err == nil
}

// String returns a multi-line summary suitable for logging on failure.
func (r ExecResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "exit=%d", r.ExitCode)
	if r.Err != nil {
		fmt.Fprintf(&b, " err=%v", r.Err)
	}
	if len(r.Stdout) > 0 {
		fmt.Fprintf(&b, "\n--- stdout ---\n%s", string(r.Stdout))
	}
	if len(r.Stderr) > 0 {
		fmt.Fprintf(&b, "\n--- stderr ---\n%s", string(r.Stderr))
	}
	return b.String()
}
