// Package runnertest provides a recording fake runner.Runner for backend
// tests. It lives outside package runner so production builds do not link it.
package runnertest

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Call captures a FakeRunner.Run invocation with copied Args and drained Stdin.
type Call struct {
	Name  string
	Args  []string
	Stdin []byte
}

// Response is one canned reply a FakeRunner will return for an invocation.
// Tests register Responses on FakeRunner.ResponseByCmd; FakeRunner consumes
// them in FIFO order.
type Response struct {
	Stdout []byte
	Stderr []byte
	Err    error
}

// FakeRunner is a test runner.Runner that records every invocation and returns
// canned responses keyed by command name (the binary name).
//
// OnCall and OnCallErr queue responses by baseName(name), so bare names
// and absolute paths share a queue. An empty queue returns nil output and error.
//
// Methods are safe for concurrent use. Access Calls and ResponseByCmd directly
// only when no method is running. Run ignores context cancellation.
type FakeRunner struct {
	mu    sync.Mutex
	Calls []Call

	// ResponseByCmd is keyed by command basename (e.g. "scutil"). The
	// fake pops responses from the front of the slice on each matching
	// call. Tests may pre-populate this map directly or use OnCall.
	ResponseByCmd map[string][]Response
}

// baseName trims either separator rather than using filepath.Base, whose
// notion of a separator follows the test host. A Windows backend test running
// on another OS must still key `C:\Windows\System32\ipconfig.exe` as
// "ipconfig.exe".
func baseName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// Run implements runner.Runner. It drains stdin (if non-nil) into the Call
// record, then returns the next queued Response for baseName(name).
func (f *FakeRunner) Run(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	_ = ctx
	var stdinBytes []byte
	if stdin != nil {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, nil, fmt.Errorf("fake runner: read stdin: %w", err)
		}
		stdinBytes = b
	}

	argsCopy := append([]string(nil), args...)

	f.mu.Lock()
	defer f.mu.Unlock()

	f.Calls = append(f.Calls, Call{
		Name:  name,
		Args:  argsCopy,
		Stdin: stdinBytes,
	})

	key := baseName(name)
	queue := f.ResponseByCmd[key]
	if len(queue) == 0 {
		return nil, nil, nil
	}
	resp := queue[0]
	f.ResponseByCmd[key] = queue[1:]
	return resp.Stdout, resp.Stderr, resp.Err
}

// OnCall registers a canned Response that will be returned by the next
// Run call whose basename matches name. Multiple OnCall registrations for
// the same name are queued FIFO.
func (f *FakeRunner) OnCall(name string, resp Response) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ResponseByCmd == nil {
		f.ResponseByCmd = map[string][]Response{}
	}
	key := baseName(name)
	f.ResponseByCmd[key] = append(f.ResponseByCmd[key], resp)
}

// OnCallErr queues a response whose only non-zero field is Err.
func (f *FakeRunner) OnCallErr(name string, err error) {
	f.OnCall(name, Response{Err: err})
}

// CallsFor returns a shallow copy of calls whose command basename matches name.
// The Args and Stdin slices remain shared with the recorded calls.
func (f *FakeRunner) CallsFor(name string) []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := baseName(name)
	out := make([]Call, 0)
	for _, c := range f.Calls {
		if baseName(c.Name) == key {
			out = append(out, c)
		}
	}
	return out
}

// CallCount returns the number of recorded calls whose basename matches
// name. Equivalent to len(CallsFor(name)) but avoids the allocation.
func (f *FakeRunner) CallCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := baseName(name)
	n := 0
	for _, c := range f.Calls {
		if baseName(c.Name) == key {
			n++
		}
	}
	return n
}
