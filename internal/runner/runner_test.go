package runner_test

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/runner"
)

// TestExecRunnerEcho checks output capture from a real command.
func TestExecRunnerEcho(t *testing.T) {
	stdout, stderr, err := runner.ExecRunner{}.Run(context.Background(), "echo", []string{"hello", "world"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", string(stdout))
	assert.Empty(t, stderr)
}

// TestExecRunnerStdin checks that stdin reaches the command.
func TestExecRunnerStdin(t *testing.T) {
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skip("cat not on PATH; skipping stdin round-trip")
	}
	stdout, _, err := runner.ExecRunner{}.Run(
		context.Background(),
		"cat", nil,
		strings.NewReader("piped-input\n"),
	)
	require.NoError(t, err)
	assert.Equal(t, "piped-input\n", string(stdout))
}

// TestExecRunnerNonZeroExit checks that the command's exit code is preserved
// and that an exit the context did not cause is not wrapped as a kill.
func TestExecRunnerNonZeroExit(t *testing.T) {
	_, _, err := runner.ExecRunner{}.Run(context.Background(), "false", nil, nil)
	require.Error(t, err)
	var exitErr *exec.ExitError
	require.True(t, errors.As(err, &exitErr), "expected *exec.ExitError; got %T", err)
	assert.Equal(t, 1, exitErr.ExitCode())
	assert.Same(t, exitErr, err, "an ordinary exit returns the exit error unwrapped")
	assert.NotErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
}

// TestExecRunnerDeadlineKill checks that a child killed at the deadline
// reports the deadline, not only its exit status.
func TestExecRunnerDeadlineKill(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep not on PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, _, err := runner.ExecRunner{}.Run(ctx, "sleep", []string{"30"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	var exitErr *exec.ExitError
	assert.ErrorAs(t, err, &exitErr)
}

// TestExecRunnerForcesCLocale checks the locale used by backend parsers.
func TestExecRunnerForcesCLocale(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh-based test")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not on PATH")
	}
	stdout, _, err := runner.ExecRunner{}.Run(context.Background(), "sh",
		[]string{"-c", "printf '%s:%s' \"$LC_ALL\" \"$LANG\""}, nil)
	require.NoError(t, err)
	assert.Equal(t, "C:C", string(stdout))
}

// TestExecRunnerBoundedDespitePipeHolders checks that inherited pipes cannot
// hold Run open for a grandchild's lifetime after the direct child exits.
func TestExecRunnerBoundedDespitePipeHolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh-based test")
	}
	start := time.Now()
	_, _, _ = runner.ExecRunner{}.Run(context.Background(), "sh",
		[]string{"-c", "sleep 10 & exit 0"}, nil)
	assert.Less(t, time.Since(start), 6*time.Second,
		"Run must return within WaitDelay of the parent exiting, not wait out the pipe-holding orphan")
}
