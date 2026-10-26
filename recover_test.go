package dnsconfig

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/hostlock"
)

type recoverResult struct {
	changed bool
	err     error
}

// startRecover runs Recover's body over a scripted backend and a counting
// fake locker, as Recover would over the native backend.
func startRecover(t *testing.T, configure func(*scriptedBackend, *countingLocker)) (<-chan recoverResult, *scriptedBackend, *countingLocker) {
	t.Helper()
	b := newScriptedBackend()
	lk := &countingLocker{Fake: hostlock.NewFake()}
	b.locker, b.identity = lk.Fake, testIdentity
	if configure != nil {
		configure(b, lk)
	}
	m := newWithBackend(Options{Identity: testIdentity, Logger: slog.New(slog.DiscardHandler)}, BackendDarwin, b, lk)
	done := make(chan recoverResult, 1)
	go func() {
		changed, err := m.recoverHost(context.Background())
		done <- recoverResult{changed, err}
	}()
	return done, b, lk
}

func waitRecover(t *testing.T, done <-chan recoverResult) recoverResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(testWait):
		t.Fatal("Recover did not return")
		return recoverResult{}
	}
}

// assertNoClear fails if Recover made a backend Set or Clear.
func assertNoClear(t *testing.T, b *scriptedBackend) {
	t.Helper()
	select {
	case c := <-b.calls:
		t.Fatalf("unexpected backend call %q", c.op)
	default:
	}
}

func TestRecover_NothingFoundWritesNothing(t *testing.T) {
	done, b, lk := startRecover(t, nil)
	r := waitRecover(t, done)
	require.NoError(t, r.err)
	assert.False(t, r.changed)
	assertNoClear(t, b)
	assert.Equal(t, 1, b.probes)
	assert.False(t, b.probeHeld, "the probe runs without locks")
	assert.Zero(t, lk.count(), "nothing found takes no identity lock")
	assert.Equal(t, 1, b.closeCalls, "the backend is still closed")
}

func TestRecover_RemovesFoundArtifacts(t *testing.T) {
	done, b, lk := startRecover(t, func(b *scriptedBackend, _ *countingLocker) { b.found = true })
	c := <-b.calls
	assert.Equal(t, "clear", c.op)
	assert.Equal(t, backend.Attempt{Final: true}, c.attempt, "the removal is Close's final cleanup")
	assert.True(t, c.hostHeld)
	assert.True(t, c.identityHeld)
	deadline, ok := c.ctx.Deadline()
	require.True(t, ok, "the removal is bounded")
	assert.WithinDuration(t, time.Now().Add(DefaultShutdownTimeout), deadline, time.Second)
	c.ok(backend.Result{Changed: true})

	r := waitRecover(t, done)
	require.NoError(t, r.err)
	assert.True(t, r.changed)
	assert.False(t, b.probeHeld, "the probe runs without locks")
	assert.False(t, lk.Held(identityLockName(testIdentity)), "Recover releases the identity")
	assert.False(t, lk.Held(hostLockName))
	assert.Equal(t, 1, b.closeCalls)
}

func TestRecover_CleanupFailureIsReturned(t *testing.T) {
	done, b, lk := startRecover(t, func(b *scriptedBackend, _ *countingLocker) { b.found = true })
	errOwed := errors.New("cache flush owed")
	(<-b.calls).fail(errOwed)

	r := waitRecover(t, done)
	require.ErrorIs(t, r.err, errOwed)
	var e *Error
	require.ErrorAs(t, r.err, &e)
	assert.Equal(t, "Recover", e.Op)
	assert.True(t, r.changed, "a partial removal still reports the change")
	assert.False(t, lk.Held(identityLockName(testIdentity)), "a failed Recover frees the identity for a retry")
}

func TestRecover_LiveHolderIsReturned(t *testing.T) {
	done, b, lk := startRecover(t, func(b *scriptedBackend, lk *countingLocker) {
		b.found = true
		lk.HoldExternally(identityLockName(testIdentity))
	})
	r := waitRecover(t, done)
	require.ErrorIs(t, r.err, ErrManagerAlreadyRunning, "the caller asked for removal and did not get it")
	var e *Error
	require.ErrorAs(t, r.err, &e)
	assert.Equal(t, "Recover", e.Op)
	assert.False(t, r.changed)
	assertNoClear(t, b)
	assert.True(t, lk.Held(identityLockName(testIdentity)), "the holder keeps the identity")
	assert.Equal(t, 1, b.closeCalls)
}

func TestRecover_ProbeErrorWritesNothing(t *testing.T) {
	errProbe := errors.New("list failed")
	done, b, lk := startRecover(t, func(b *scriptedBackend, _ *countingLocker) {
		b.found, b.probeErr = true, errProbe
	})
	r := waitRecover(t, done)
	require.ErrorIs(t, r.err, errProbe)
	assert.False(t, r.changed)
	assertNoClear(t, b)
	assert.Zero(t, lk.count())
	assert.Equal(t, 1, b.closeCalls)
}

func TestRecover_Noop(t *testing.T) {
	changed, err := Recover(context.Background(), Options{Identity: testIdentity, ForceBackend: BackendNoop})
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestRecover_InvalidOptions(t *testing.T) {
	_, err := Recover(context.Background(), Options{})
	require.ErrorIs(t, err, ErrInvalidOptions)
	var e *Error
	assert.False(t, errors.As(err, &e), "invalid Options are returned as-is, as from New")
}
