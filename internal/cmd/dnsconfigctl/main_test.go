package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binPath lets CLI tests reuse one compiled binary.
var binPath string

// TestMain builds the binary used by CLI subprocess tests.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "dnsconfigctl-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: mktemp: %v\n", err)
		os.Exit(2)
	}
	bin := filepath.Join(tmp, "dnsconfigctl")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TestMain: build: %v\n", err)
		_ = os.RemoveAll(tmp)
		os.Exit(2)
	}
	binPath = bin
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// runResult bundles the outcome of a single CLI invocation.
type runResult struct {
	stdout string
	stderr string
	code   int
}

// runCLI executes the test binary with args and captures stdout/stderr and
// exit code. It deliberately does not fail the test on non-zero exit so
// callers can assert on specific failure codes.
func runCLI(t *testing.T, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("runCLI: unexpected error type %T: %v", err, err)
		}
		code = ee.ExitCode()
	}
	return runResult{
		stdout: stdout.String(),
		stderr: stderr.String(),
		code:   code,
	}
}

// knownBackendKinds lists every BackendKind string the public package
// declares. Used by TestDetect to assert the output parses as something
// reasonable.
var knownBackendKinds = map[string]bool{
	"darwin":  true,
	"windows": true,
	"noop":    true,
}

// TestDetect exercises `dnsconfigctl detect`. The output must be a single
// line that parses as a known BackendKind. The exact value depends on the
// host the test runs on, so we accept any of the known strings.
func TestDetect(t *testing.T) {
	res := runCLI(t, "detect")
	require.Equal(t, 0, res.code, "stderr=%q stdout=%q", res.stderr, res.stdout)
	line := strings.TrimSpace(res.stdout)
	require.NotEmpty(t, line, "detect produced empty stdout")
	assert.True(t, knownBackendKinds[line], "detect printed %q, want one of the known BackendKinds", line)
}

// TestDetectForcedBackend confirms that -backend short-circuits detection:
// the CLI echoes the forced value back without running any OS probes.
func TestDetectForcedBackend(t *testing.T) {
	res := runCLI(t, "-backend", "noop", "detect")
	require.Equal(t, 0, res.code, "stderr=%q", res.stderr)
	assert.Equal(t, "noop\n", res.stdout)
}

// TestNoSubcommand confirms that invoking with no arguments exits with the
// usage-error code (2).
func TestNoSubcommand(t *testing.T) {
	res := runCLI(t)
	assert.Equal(t, 2, res.code)
}

// TestUnknownSubcommand confirms an unknown verb is a usage error.
func TestUnknownSubcommand(t *testing.T) {
	res := runCLI(t, "blarg")
	assert.Equal(t, 2, res.code)
	assert.Contains(t, res.stderr, "unknown subcommand")
}

// TestUnknownGlobalFlag confirms a stray global flag is a usage error.
func TestUnknownGlobalFlag(t *testing.T) {
	res := runCLI(t, "-not-a-flag", "detect")
	assert.Equal(t, 2, res.code)
	assert.Contains(t, res.stderr, "flag provided but not defined")
}

// TestUnknownBackend confirms -backend with an unknown kind is a usage
// error reported by the subcommand (not the global parser).
func TestUnknownBackend(t *testing.T) {
	res := runCLI(t, "-backend", "made-up", "detect")
	assert.Equal(t, 2, res.code)
	assert.Contains(t, res.stderr, "unknown backend")
}

// TestSetMissingNS checks that missing --ns is a usage error.
func TestSetMissingNS(t *testing.T) {
	res := runCLI(t, "set")
	assert.Equal(t, 2, res.code)
	assert.Contains(t, res.stderr, "--ns is required")
}

// TestSetInvalidNS confirms `set --ns garbage` is a usage error before any
// Manager construction happens.
func TestSetInvalidNS(t *testing.T) {
	res := runCLI(t, "set", "--ns", "not-an-ip")
	assert.Equal(t, 2, res.code)
	assert.Contains(t, res.stderr, "--ns")
}

// TestSetNoopDetach exercises CLI parsing, Manager construction, and detach
// without changing system DNS.
func TestSetNoopDetach(t *testing.T) {
	res := runCLI(t, "-backend", "noop", "set", "--ns", "1.2.3.4", "--detach")
	require.Equal(t, 0, res.code, "stderr=%q stdout=%q", res.stderr, res.stdout)
	assert.Contains(t, res.stdout, "set OK")
}

// TestResetNoop exercises the reset path through the public Manager API
// with the noop backend. The Clear converges without finding anything, which
// the harness distinguishes from a performed cleanup by the exact line.
func TestResetNoop(t *testing.T) {
	res := runCLI(t, "-backend", "noop", "reset")
	require.Equal(t, 0, res.code, "stderr=%q stdout=%q", res.stderr, res.stdout)
	assert.Equal(t, "reset OK (nothing to reset)\n", res.stdout)
}

// TestSetUnknownArgs confirms a trailing positional argument to `set` is a
// usage error. This guards against the smoke harness accidentally passing
// a positional where a flag was meant.
func TestSetUnknownArgs(t *testing.T) {
	res := runCLI(t, "set", "--ns", "1.2.3.4", "extra-positional")
	assert.Equal(t, 2, res.code)
	assert.Contains(t, res.stderr, "unexpected argument")
}

// TestWatchMissingNS confirms `watch` requires --ns, like `set`.
func TestWatchMissingNS(t *testing.T) {
	res := runCLI(t, "watch")
	assert.Equal(t, 2, res.code)
	assert.Contains(t, res.stderr, "--ns is required")
}

// TestWatchNegativeNoop checks the unapplied observation path without
// changing system DNS.
func TestWatchNegativeNoop(t *testing.T) {
	res := runCLI(t, "-backend", "noop", "watch", "--ns", "1.2.3.4", "--expect-apply=false", "--timeout", "500ms")
	require.Equal(t, 0, res.code, "stderr=%q stdout=%q", res.stderr, res.stdout)
	assert.Contains(t, res.stdout, "WATCH: ready applied=false")
	assert.Contains(t, res.stdout, "WATCH: negative-ok")
}

// TestWatchTimeoutNoop exercises the hold bound: a harness that never signals
// the process must see it exit non-zero rather than hang. Status lines
// appear while holding.
func TestWatchTimeoutNoop(t *testing.T) {
	res := runCLI(t, "-backend", "noop", "watch", "--ns", "1.2.3.4", "--timeout", "500ms", "--status-interval", "100ms")
	require.Equal(t, 1, res.code, "stderr=%q stdout=%q", res.stderr, res.stdout)
	assert.Contains(t, res.stdout, "WATCH: ready applied=true")
	assert.Contains(t, res.stdout, "WATCH: status converged=true changed=none err=<nil>")
	assert.Contains(t, res.stderr, "WATCH: timeout hold expired")
}

func TestFinishWatchSignal(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		g := &globalFlags{stdout: &stdout, stderr: &stderr}

		rc := finishWatchSignal(g, func() error { return nil })

		assert.Equal(t, exitOK, rc)
		assert.Equal(t, "WATCH: closed teardown-ok\n", stdout.String())
		assert.Empty(t, stderr.String())
	})

	t.Run("close error", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		g := &globalFlags{stdout: &stdout, stderr: &stderr}

		rc := finishWatchSignal(g, func() error { return fmt.Errorf("close failed") })

		assert.Equal(t, exitFail, rc)
		assert.Empty(t, stdout.String())
		assert.Equal(t, "dnsconfigctl watch: close: close failed\n", stderr.String())
	})
}

// TestBuildSetConfigCommaSeparatedMatch pins the contract the smoke harness
// depends on when a row routes both a forward domain and a reverse zone:
// --match takes one comma-separated value and keeps every domain in order.
func TestBuildSetConfigCommaSeparatedMatch(t *testing.T) {
	cfg, err := buildSetConfig("192.0.2.1", "",
		"sentinel.dnsconfig-smoke.example.,2.0.192.in-addr.arpa.")
	require.NoError(t, err)
	require.Len(t, cfg.MatchDomains, 2)
	assert.Equal(t, "sentinel.dnsconfig-smoke.example.", cfg.MatchDomains[0])
	assert.Equal(t, "2.0.192.in-addr.arpa.", cfg.MatchDomains[1])
}
