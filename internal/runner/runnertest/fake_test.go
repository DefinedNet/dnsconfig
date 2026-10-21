package runnertest_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
)

// TestFakeRunnerRecordsCalls verifies the FakeRunner records each Run
// invocation in order with args/stdin captured.
func TestFakeRunnerRecordsCalls(t *testing.T) {
	f := &runnertest.FakeRunner{}
	_, _, err := f.Run(context.Background(), "scutil", []string{"-a", "eth0.dnsconfig"}, strings.NewReader("nameserver 1.1.1.1\n"))
	require.NoError(t, err)
	_, _, err = f.Run(context.Background(), "scutil", []string{"-d", "eth0.dnsconfig", "-f"}, nil)
	require.NoError(t, err)

	require.Len(t, f.Calls, 2)
	assert.Equal(t, "scutil", f.Calls[0].Name)
	assert.Equal(t, []string{"-a", "eth0.dnsconfig"}, f.Calls[0].Args)
	assert.Equal(t, "nameserver 1.1.1.1\n", string(f.Calls[0].Stdin))

	assert.Equal(t, []string{"-d", "eth0.dnsconfig", "-f"}, f.Calls[1].Args)
	assert.Nil(t, f.Calls[1].Stdin)
}

// TestFakeRunnerCannedResponses checks the FIFO behavior of queued
// responses for the same command.
func TestFakeRunnerCannedResponses(t *testing.T) {
	f := &runnertest.FakeRunner{}
	sentinel := errors.New("boom")
	f.OnCall("scutil", runnertest.Response{Stdout: []byte("first\n")})
	f.OnCallErr("scutil", sentinel)

	stdout, _, err := f.Run(context.Background(), "scutil", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(stdout))

	_, _, err = f.Run(context.Background(), "scutil", nil, nil)
	require.ErrorIs(t, err, sentinel)

	// Queue is drained; subsequent calls return zero-value responses.
	stdout, stderr, err := f.Run(context.Background(), "scutil", nil, nil)
	require.NoError(t, err)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
}

// TestFakeRunnerBasenameMatching verifies that absolute paths and bare
// command names share the same response queue.
func TestFakeRunnerBasenameMatching(t *testing.T) {
	f := &runnertest.FakeRunner{}
	f.OnCall("scutil", runnertest.Response{Stdout: []byte("registered\n")})

	stdout, _, err := f.Run(context.Background(), "/usr/sbin/scutil", nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "registered\n", string(stdout))
}

// TestFakeRunnerCallCount checks counts by command name.
func TestFakeRunnerCallCount(t *testing.T) {
	f := &runnertest.FakeRunner{}
	_, _, _ = f.Run(context.Background(), "scutil", []string{"-a", "x"}, nil)
	_, _, _ = f.Run(context.Background(), "scutil", []string{"-d", "x"}, nil)
	_, _, _ = f.Run(context.Background(), "other", nil, nil)
	assert.Equal(t, 2, f.CallCount("scutil"))
	assert.Equal(t, 1, f.CallCount("other"))
}

// TestFakeRunnerKeysAbsolutePathsAcrossHosts checks that the response queue and
// the call lookups key on the trailing element for both separators. Backends
// pass absolute paths, and the windows backend's tests run on any host, so a
// filepath.Base that follows the test host would stop matching.
func TestFakeRunnerKeysAbsolutePathsAcrossHosts(t *testing.T) {
	cases := []struct {
		name     string
		called   string
		registry string
	}{
		{"unix absolute", "/usr/sbin/scutil", "scutil"},
		{"windows absolute", `C:\Windows\System32\ipconfig.exe`, "ipconfig.exe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &runnertest.FakeRunner{}
			f.OnCall(tc.registry, runnertest.Response{Stdout: []byte("queued\n")})

			stdout, _, err := f.Run(context.Background(), tc.called, nil, nil)
			require.NoError(t, err)
			assert.Equal(t, "queued\n", string(stdout), "the absolute path must drain the bare-name queue")

			assert.Equal(t, 1, f.CallCount(tc.registry))
			assert.Len(t, f.CallsFor(tc.registry), 1)
		})
	}
}
