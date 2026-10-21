// Package runner abstracts backend subprocess execution for testability.
// Runner captures command output; Starter supports streaming event sources.
package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// Runner runs external commands and returns their stdout, stderr, and
// exit error. Implementations must respect ctx cancellation: when ctx is
// done, the underlying process must be killed and Run must return.
//
// The returned err is the same shape that os/exec.Cmd.Run returns: nil
// on success, *exec.ExitError when the process ran and exited non-zero,
// or another error type when the process could not be started or was
// canceled.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin io.Reader) (stdout, stderr []byte, err error)
}

// Process is a long-running child with attached stdin and stdout, used for
// event streams such as scutil's n.watch mode.
type Process interface {
	// Stdin is the child's standard input, for driving an interactive tool.
	Stdin() io.Writer

	// Stdout streams the child's standard output.
	Stdout() io.Reader

	// Kill terminates and reaps the child, closing both pipes. Safe to call
	// more than once and after the child has already exited.
	Kill() error
}

// Starter is the optional capability to launch a long-running child with
// attached pipes. Backends that need a streaming event source type-assert
// their Runner for it. The darwin backend reports monitoring unhealthy
// without one, leaving the worker's periodic check as the only drift
// coverage. Implementations must bind the child lifetime to ctx so
// cancellation terminates the child and unblocks reads from Process.Stdout.
type Starter interface {
	Start(ctx context.Context, name string, args []string) (Process, error)
}

// ExecRunner implements Runner and Starter using os/exec.CommandContext.
type ExecRunner struct{}

// Run captures stdout and stderr and returns the command's error. Cancellation
// kills the child, and the error then wraps ctx.Err() around the exit error:
// the kill alone reads as an ordinary failure, exit status 1 on Windows. The
// C locale keeps tool output stable for backend parsers.
func (ExecRunner) Run(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var killed atomic.Bool
	cmd.Cancel = func() error {
		err := cmd.Process.Kill()
		if err == nil {
			killed.Store(true)
		}
		return err
	}
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	// Descendants can keep stdout/stderr open after the child exits.
	// Bound the wait for those pipes so they cannot hold Run open indefinitely.
	cmd.WaitDelay = 2 * time.Second
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil && killed.Load() {
		err = fmt.Errorf("%w: %w", ctx.Err(), err)
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

// Start implements Starter using the same C locale as Run. Cancellation
// kills the child; callers must call Kill to reap it and close its pipes.
func (ExecRunner) Start(ctx context.Context, name string, args []string) (Process, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.WaitDelay = 2 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &execProcess{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

type execProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser

	killOnce sync.Once
}

func (p *execProcess) Stdin() io.Writer  { return p.stdin }
func (p *execProcess) Stdout() io.Reader { return p.stdout }

// Kill terminates and reaps the child, ignoring its exit status.
func (p *execProcess) Kill() error {
	p.killOnce.Do(func() {
		_ = p.stdin.Close()
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		_ = p.cmd.Wait()
	})
	return nil
}
