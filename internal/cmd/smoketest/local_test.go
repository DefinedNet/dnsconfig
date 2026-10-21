package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
)

// TestLocalExec preserves the command and argument boundaries.
func TestLocalExec(t *testing.T) {
	fr := &runnertest.FakeRunner{}
	l := &Local{Runner: fr}
	res := l.Exec(context.Background(), "dscacheutil", "-q", "host", "-a", "name", "example.com")
	require.True(t, res.Successful())
	require.Len(t, fr.Calls, 1)
	assert.Equal(t, "dscacheutil", fr.Calls[0].Name)
	assert.Equal(t, []string{"-q", "host", "-a", "name", "example.com"}, fr.Calls[0].Args)
}

// TestLocalCopyFile confirms the copy happens in-process, without an external
// cp, which Windows lacks. It must not touch the Runner.
func TestLocalCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	dst := filepath.Join(dir, "dst.bin")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0o600))

	fr := &runnertest.FakeRunner{}
	res := (&Local{Runner: fr}).CopyFile(src, dst)
	require.True(t, res.Successful())
	assert.Empty(t, fr.Calls, "CopyFile must copy in-process, not shell out")
	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, []byte("payload"), got)
}

// TestLocalCopyFileError confirms a copy failure (missing source) surfaces
// as an unsuccessful ExecResult rather than a panic.
func TestLocalCopyFileError(t *testing.T) {
	dir := t.TempDir()
	res := (&Local{}).CopyFile(filepath.Join(dir, "absent"), filepath.Join(dir, "dst"))
	assert.False(t, res.Successful())
	assert.Error(t, res.Err)
}

// TestLocalExecExitCode confirms a non-zero exit from the subprocess surfaces
// as the ExecResult's ExitCode (preserving the subprocess result).
func TestLocalExecExitCode(t *testing.T) {
	fr := &runnertest.FakeRunner{}
	fr.OnCallErr("false", exitErr(t, 3))
	res := (&Local{Runner: fr}).Exec(context.Background(), "false")
	assert.False(t, res.Successful())
	assert.Equal(t, 3, res.ExitCode)
}

// TestLocalExecEmptyArgv confirms an empty argv is rejected without invoking
// the Runner.
func TestLocalExecEmptyArgv(t *testing.T) {
	fr := &runnertest.FakeRunner{}
	res := (&Local{Runner: fr}).Exec(context.Background())
	assert.False(t, res.Successful())
	assert.Equal(t, -1, res.ExitCode)
	assert.Error(t, res.Err)
	assert.Empty(t, fr.Calls)
}
