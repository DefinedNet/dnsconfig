package dnsconfig

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// closeAsync starts Close and returns its result channel.
func closeAsync(m *Manager) <-chan error {
	done := make(chan error, 1)
	go func() { done <- m.Close() }()
	return done
}

func waitClose(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(testWait):
		t.Fatal("Close did not return")
		return nil
	}
}

// TestClose_CancelsInFlightAttempt: Close cancels the attempt's context,
// joins the worker, and only then runs its own cleanup, so the final Clear
// never overlaps a worker attempt.
func TestClose_CancelsInFlightAttempt(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	inFlight := h.next()

	done := closeAsync(h.m)
	select {
	case <-inFlight.ctx.Done():
	case <-time.After(testWait):
		t.Fatal("Close did not cancel the in-flight attempt")
	}
	final := h.next()
	assert.Equal(t, "clear", final.op)
	assert.Equal(t, backend.Attempt{Final: true}, final.attempt)
	assert.True(t, final.hostHeld, "the final Clear runs inside the critical section")
	assert.True(t, final.identityHeld)
	final.ok(backend.Result{Changed: true})
	require.NoError(t, waitClose(t, done))

	s := h.m.Status()
	assert.False(t, s.Converged, "the final Clear undid the Set goal")
	assert.True(t, s.LastConvergedCleared, "the final Clear is the last successful converge")
	assert.False(t, s.LastChangedAt.IsZero(), "the final Clear changed the host")
	assert.NoError(t, s.LastError)
	assert.False(t, h.identityHeld(), "Close releases the identity")
	assert.Equal(t, 1, h.b.closeCalls)
}

// TestClose_ShutdownTimeoutBoundsFinalClear: a hanging cleanup becomes a
// reported failure within ShutdownTimeout, and the identity is still freed.
func TestClose_ShutdownTimeoutBoundsFinalClear(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{ShutdownTimeout: 50 * time.Millisecond})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")

	done := closeAsync(h.m)
	final := h.next()
	require.Equal(t, "clear", final.op)
	err := waitClose(t, done)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, "Close", e.Op)
	assert.Same(t, err, h.m.Status().LastError)
	assert.False(t, h.identityHeld(), "a failed cleanup still frees the identity for recovery")
	assert.Equal(t, 1, h.b.closeCalls)
}

// TestClose_ShutdownTimeoutBoundsHostLockWait: the ShutdownTimeout budget
// covers the wait for the host-wide lock, so a holder that never releases
// cancels the final Clear before it starts instead of stalling Close.
func TestClose_ShutdownTimeoutBoundsHostLockWait(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{ShutdownTimeout: 50 * time.Millisecond})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	h.lk.HoldExternally(hostLockName)
	t.Cleanup(func() { h.lk.Release(hostLockName) })

	err := waitClose(t, closeAsync(h.m))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	select {
	case c := <-h.b.calls:
		t.Fatalf("cleanup ran without the host lock: %q", c.op)
	default:
	}
	assert.False(t, h.identityHeld())
}

// TestSet_ValidatesBeforeClosedCheck: Config.Validate runs before the closed
// check, so an invalid config reports its own error even after Close, and only
// a valid one sees ErrClosed.
func TestSet_ValidatesBeforeClosedCheck(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Close())
	err := h.m.Set(Config{})
	require.ErrorIs(t, err, ErrEmptyConfig)
	assert.NotErrorIs(t, err, ErrClosed)
	assert.ErrorIs(t, h.m.Set(sampleConfig(t)), ErrClosed)
}
