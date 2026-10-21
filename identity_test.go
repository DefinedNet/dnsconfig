package dnsconfig

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// TestIdentityLockFollowsGoal: New takes nothing, the first attempt
// takes the identity, repeats reuse it, and a converged Clear frees it.
func TestIdentityLockFollowsGoal(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	assert.False(t, h.identityHeld(), "New takes nothing")

	require.NoError(t, h.m.Set(sampleConfig(t)))
	c := h.next()
	require.True(t, c.identityHeld)
	c.fail(errors.New("write failed"))
	h.clk.AdvanceTo(t, h.settle())
	assert.True(t, h.identityHeld(), "a failed attempt may have written, so the identity stays")
	h.converged("set")

	require.NoError(t, h.m.Clear())
	c = h.next()
	require.True(t, c.identityHeld, "the Clear reuses the held identity")
	c.fail(errors.New("sweep failed"))
	h.clk.AdvanceTo(t, h.settle())
	assert.True(t, h.identityHeld(), "a failed Clear keeps the identity for its retry")
	h.converged("clear")
	assert.False(t, h.identityHeld(), "a converged Clear frees the identity")

	require.NoError(t, h.m.Set(sampleConfig(t)))
	c = h.next()
	assert.True(t, c.identityHeld, "a later Set acquires it again")
	c.ok(backend.Result{Changed: true})
	h.settle()
}

// TestIdentityHeldElsewhereRetries: a live holder of the same identity blocks
// every attempt before the backend runs, and the worker retries until the
// holder leaves.
func TestIdentityHeldElsewhereRetries(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	name := identityLockName(testIdentity)
	h.lk.HoldExternally(name)

	require.NoError(t, h.m.Set(sampleConfig(t)))
	next := h.settle()
	s := h.m.Status()
	require.ErrorIs(t, s.LastError, ErrManagerAlreadyRunning)
	assert.Equal(t, h.clk.Now().Add(backoffMin), next)

	h.clk.AdvanceTo(t, next)
	next = h.settle()
	assert.Equal(t, h.clk.Now().Add(2*backoffMin), next, "consecutive failures back off further")

	h.lk.Release(name)
	h.clk.AdvanceTo(t, next)
	c := h.next()
	assert.Equal(t, backend.Attempt{}, c.attempt, "the goal's first attempt already ran")
	c.ok(backend.Result{Changed: true})
	h.settle()
	assert.True(t, h.m.Status().Converged)
}

// TestRecoveryClearWaitsForLiveHolder: recovery never sweeps a live holder's
// artifacts.
func TestRecoveryClearWaitsForLiveHolder(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	h.lk.HoldExternally(identityLockName(testIdentity))
	require.NoError(t, h.m.Clear())
	h.settle()
	s := h.m.Status()
	require.ErrorIs(t, s.LastError, ErrManagerAlreadyRunning)
	assert.False(t, s.Converged)
}

// TestHostLockWaitIsBounded: a holder that never releases the host lock
// turns into a reported, retried refusal rather than a stalled worker.
func TestHostLockWaitIsBounded(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{}, func(m *Manager) { m.hostLockTimeout = 20 * time.Millisecond })
	h.lk.HoldExternally(hostLockName)

	require.NoError(t, h.m.Set(sampleConfig(t)))
	next := h.settle()
	s := h.m.Status()
	require.ErrorIs(t, s.LastError, context.DeadlineExceeded)
	assert.Equal(t, h.clk.Now().Add(backoffMin), next)
	assert.True(t, h.identityHeld(), "the identity was taken before the host lock")

	h.lk.Release(hostLockName)
	h.clk.AdvanceTo(t, next)
	h.next().ok(backend.Result{Changed: true})
	h.settle()
	assert.True(t, h.m.Status().Converged)
}

// TestHungAttemptReleasesHostLock: a backend call that never returns fails
// the attempt at attemptTimeout and frees the host-wide lock, so a hung
// command cannot stall every identity until Close.
func TestHungAttemptReleasesHostLock(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{}, func(m *Manager) { m.attemptTimeout = 20 * time.Millisecond })

	require.NoError(t, h.m.Set(sampleConfig(t)))
	hung := h.next()
	require.True(t, hung.hostHeld)
	next := h.settle()
	s := h.m.Status()
	require.ErrorIs(t, s.LastError, context.DeadlineExceeded)
	assert.False(t, h.lk.Held(hostLockName))
	assert.True(t, h.identityHeld(), "a failed attempt keeps the identity")

	h.clk.AdvanceTo(t, next)
	h.next().ok(backend.Result{Changed: true})
	h.settle()
	assert.True(t, h.m.Status().Converged)
}

// TestHostUnlockFailureIsLogged: a failed host-lock release is a warning, not
// an attempt failure, because the attempt's own result describes the host.
func TestHostUnlockFailureIsLogged(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, BackendDarwin, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	h.lk.UnlockErr = errors.New("unlock failed")
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	s := h.m.Status()
	assert.True(t, s.Converged)
	assert.NoError(t, s.LastError)
	assert.False(t, h.lk.Held(hostLockName), "the attempt called Unlock; the fake drops the hold even when Unlock fails")
	assert.Contains(t, logs.String(), `level=WARN msg="dnsconfig: releasing host lock failed" err="unlock failed"`)
}

// TestSecondManagerTakesOverAfterClose: Close releases the identity so a
// successor can converge, and never earlier.
func TestSecondManagerTakesOverAfterClose(t *testing.T) {
	first := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, first.m.Set(sampleConfig(t)))
	first.converged("set")

	second := newHarness(t, BackendDarwin, Options{}, func(m *Manager) { m.locker = first.lk })
	require.NoError(t, second.m.Set(sampleConfig(t)))
	next := second.settle()
	require.ErrorIs(t, second.m.Status().LastError, ErrManagerAlreadyRunning)

	first.closeAnswering()
	assert.False(t, first.identityHeld())
	second.clk.AdvanceTo(t, next)
	c := second.next()
	assert.True(t, c.identityHeld)
	c.ok(backend.Result{Changed: true})
	second.settle()
	assert.True(t, second.m.Status().Converged)
}
