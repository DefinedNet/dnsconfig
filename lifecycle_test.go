package dnsconfig

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/hostlock"
)

// TestClose_WithoutGoalChangesNothing: a Manager never asked for anything
// has no claim on its identity and must not sweep a live holder's artifacts.
func TestClose_WithoutGoalChangesNothing(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, waitClose(t, closeAsync(h.m)))
	select {
	case c := <-h.b.calls:
		t.Fatalf("Close touched the host: %q", c.op)
	default:
	}
	assert.False(t, h.identityHeld())
	assert.Equal(t, 1, h.b.closeCalls, "resources are released either way")
}

// stopWorker ends the worker before it can attempt anything, so a goal
// recorded afterwards reaches Close unattempted. Close joins the finished
// worker as usual.
func stopWorker(h *harness) {
	h.m.cancel()
	<-h.m.done
}

// TestClose_HonorsRecordedGoal: a goal the worker never finished is still a
// request for this identity's cleanup. Close takes the identity itself and
// runs the final Clear, on native and no-op backends alike.
func TestClose_HonorsRecordedGoal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kind  BackendKind
		setup func(h *harness)
	}{
		{name: "clear never attempted", kind: BackendDarwin, setup: func(h *harness) {
			stopWorker(h)
			require.NoError(t, h.m.Clear())
		}},
		{name: "set never attempted", kind: BackendDarwin, setup: func(h *harness) {
			stopWorker(h)
			require.NoError(t, h.m.Set(sampleConfig(t)))
		}},
		{name: "identity freed after refusal", kind: BackendDarwin, setup: func(h *harness) {
			name := identityLockName(testIdentity)
			h.lk.HoldExternally(name)
			require.NoError(t, h.m.Clear())
			h.settle()
			require.ErrorIs(t, h.m.Status().LastError, ErrManagerAlreadyRunning)
			h.lk.Release(name)
		}},
		{name: "noop clear never attempted", kind: BackendNoop, setup: func(h *harness) {
			stopWorker(h)
			require.NoError(t, h.m.Clear())
		}},
		// Without a locker the lifetime is never held, so a converged Set
		// reaches Close through the recorded-goal path like an unattempted
		// one, and must still be cleaned up.
		{name: "noop converged set", kind: BackendNoop, setup: func(h *harness) {
			require.NoError(t, h.m.Set(sampleConfig(t)))
			h.converged("set")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.kind, Options{ForceBackend: tc.kind})
			tc.setup(h)
			done := closeAsync(h.m)
			c := h.next()
			require.Equal(t, "clear", c.op)
			assert.True(t, c.attempt.Final)
			if h.lk != nil {
				assert.True(t, c.identityHeld, "Close took the identity for the cleanup")
			}
			c.ok(backend.Result{Changed: true})
			require.NoError(t, waitClose(t, done))
			s := h.m.Status()
			assert.True(t, s.LastConvergedCleared)
			assert.NoError(t, s.LastError)
			if h.lk != nil {
				assert.False(t, h.identityHeld(), "Close released what it took")
			}
		})
	}
}

// TestClose_IdentityHeldElsewhereIsNil: a recorded goal Close cannot honor
// because a live Manager holds the identity is not a Close failure, since
// that holder's artifacts are meant to stay; Status still reports it.
func TestClose_IdentityHeldElsewhereIsNil(t *testing.T) {
	for _, tc := range []struct {
		name string
		goal func(h *harness) error
	}{
		{name: "clear", goal: func(h *harness) error { return h.m.Clear() }},
		{name: "set", goal: func(h *harness) error { return h.m.Set(sampleConfig(t)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, BackendDarwin, Options{})
			h.lk.HoldExternally(identityLockName(testIdentity))
			require.NoError(t, tc.goal(h))
			h.settle()

			require.NoError(t, waitClose(t, closeAsync(h.m)))
			select {
			case c := <-h.b.calls:
				t.Fatalf("Close touched the host: %q", c.op)
			default:
			}
			s := h.m.Status()
			require.ErrorIs(t, s.LastError, ErrManagerAlreadyRunning)
			var e *Error
			require.ErrorAs(t, s.LastError, &e)
			assert.Equal(t, "Close", e.Op)
			assert.False(t, s.Converged)
			assert.False(t, s.LastConvergedCleared)
			assert.Equal(t, 1, h.b.closeCalls, "resources are released either way")
		})
	}
}

// TestClose_IdentityHeldElsewhereKeepsTeardownError: a teardown failure beside
// a held identity is still returned, and Status reports both causes.
func TestClose_IdentityHeldElsewhereKeepsTeardownError(t *testing.T) {
	closeErr := errors.New("watcher stop failed")
	h := newHarness(t, BackendDarwin, Options{})
	h.lk.HoldExternally(identityLockName(testIdentity))
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.settle()
	h.b.mu.Lock()
	h.b.closeErr = closeErr
	h.b.mu.Unlock()

	err := waitClose(t, closeAsync(h.m))
	require.ErrorIs(t, err, closeErr)
	assert.NotErrorIs(t, err, ErrManagerAlreadyRunning)
	s := h.m.Status()
	assert.ErrorIs(t, s.LastError, closeErr)
	assert.ErrorIs(t, s.LastError, ErrManagerAlreadyRunning)
}

// TestClose_AfterConvergedClearChangesNothing: the identity was released, so
// there is nothing left for Close to own.
func TestClose_AfterConvergedClearChangesNothing(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	require.NoError(t, h.m.Clear())
	h.converged("clear")
	require.NoError(t, waitClose(t, closeAsync(h.m)))
	select {
	case c := <-h.b.calls:
		t.Fatalf("Close repeated a converged Clear: %q", c.op)
	default:
	}
}

func TestClose_JoinsCleanupAndTeardownErrors(t *testing.T) {
	cleanupErr := errors.New("sweep failed")
	closeErr := errors.New("watcher stop failed")
	h := newHarness(t, BackendDarwin, Options{})
	h.b.closeErr = closeErr
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")

	done := closeAsync(h.m)
	h.next().fail(cleanupErr)
	err := waitClose(t, done)
	require.ErrorIs(t, err, cleanupErr)
	assert.ErrorIs(t, err, closeErr)
	assert.Same(t, err, h.m.Status().LastError)
	assert.False(t, h.m.Status().LastConvergedCleared, "a failed cleanup is not a converge")

	assert.NoError(t, h.m.Close(), "Close is one-shot")
	require.ErrorIs(t, h.m.Set(sampleConfig(t)), ErrClosed)
	require.ErrorIs(t, h.m.Clear(), ErrClosed)
}

// TestClose_ReportsIdentityReleaseFailure: a cleanup that could not start
// and a failed identity release are both in Close's error.
func TestClose_ReportsIdentityReleaseFailure(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{ShutdownTimeout: 20 * time.Millisecond})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	h.lk.HoldExternally(hostLockName)
	t.Cleanup(func() { h.lk.Release(hostLockName) })
	releaseErr := errors.New("identity unlock failed")
	h.lk.UnlockErr = releaseErr

	err := waitClose(t, closeAsync(h.m))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.ErrorIs(t, err, releaseErr)
	assert.False(t, h.identityHeld(), "Close called Unlock; the fake drops the hold even when Unlock fails")
}

// TestClose_StatusDescribesCleanup: Close's final Clear is the last attempt
// to touch the host, so afterwards a Set goal never reads Converged and a
// Clear goal reads Converged exactly when its cleanup is confirmed. No retry
// deadline outlives the worker.
func TestClose_StatusDescribesCleanup(t *testing.T) {
	cleanupErr := errors.New("remove failed")
	closeErr := errors.New("watcher stop failed")
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, h *harness)
		// final answers Close's final Clear; nil means Close must not make one.
		final         func(c *call)
		wantErr       error
		wantGoal      Goal
		wantConverged bool
		wantCleared   bool
	}{
		{
			name: "converged set, cleanup succeeds",
			setup: func(t *testing.T, h *harness) {
				require.NoError(t, h.m.Set(sampleConfig(t)))
				h.converged("set")
			},
			final:       func(c *call) { c.ok(backend.Result{Changed: true}) },
			wantGoal:    GoalSet,
			wantCleared: true,
		},
		{
			// The host may be half removed; Converged must not still claim
			// the Set goal is installed.
			name: "converged set, cleanup fails",
			setup: func(t *testing.T, h *harness) {
				require.NoError(t, h.m.Set(sampleConfig(t)))
				h.converged("set")
			},
			final: func(c *call) {
				c.reply <- callResult{res: backend.Result{Changed: true}, err: cleanupErr}
			},
			wantErr:  cleanupErr,
			wantGoal: GoalSet,
		},
		{
			name: "failing clear goal, cleanup succeeds",
			setup: func(t *testing.T, h *harness) {
				require.NoError(t, h.m.Set(sampleConfig(t)))
				h.converged("set")
				require.NoError(t, h.m.Clear())
				h.next().fail(cleanupErr)
				next := h.settle()
				require.ErrorIs(t, h.m.Status().LastError, cleanupErr)
				require.Equal(t, h.clk.Now().Add(backoffMin), next, "the worker is backing off")
			},
			final:         func(c *call) { c.ok(backend.Result{Changed: true}) },
			wantGoal:      GoalClear,
			wantConverged: true,
			wantCleared:   true,
		},
		{
			// Backend teardown is resource-only; the worker's confirmed
			// cleanup stands.
			name: "converged clear, backend close fails",
			setup: func(t *testing.T, h *harness) {
				require.NoError(t, h.m.Set(sampleConfig(t)))
				h.converged("set")
				require.NoError(t, h.m.Clear())
				h.converged("clear")
				h.b.mu.Lock()
				h.b.closeErr = closeErr
				h.b.mu.Unlock()
			},
			wantErr:       closeErr,
			wantGoal:      GoalClear,
			wantConverged: true,
			wantCleared:   true,
		},
		{
			name: "set goal held by a live manager",
			setup: func(t *testing.T, h *harness) {
				h.lk.HoldExternally(identityLockName(testIdentity))
				require.NoError(t, h.m.Set(sampleConfig(t)))
				next := h.settle()
				require.ErrorIs(t, h.m.Status().LastError, ErrManagerAlreadyRunning)
				require.Equal(t, h.clk.Now().Add(backoffMin), next, "the worker is backing off")
			},
			wantGoal: GoalSet,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, BackendDarwin, Options{})
			tc.setup(t, h)
			done := closeAsync(h.m)
			if tc.final != nil {
				c := h.next()
				require.Equal(t, "clear", c.op)
				require.True(t, c.attempt.Final)
				tc.final(c)
			}
			err := waitClose(t, done)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			select {
			case c := <-h.b.calls:
				t.Fatalf("unexpected backend call %q", c.op)
			default:
			}

			s := h.m.Status()
			assert.Equal(t, tc.wantGoal, s.Goal, "Close leaves the recorded goal")
			if tc.wantGoal == GoalSet {
				assert.True(t, s.Desired.Equal(sampleConfig(t)), "Close leaves Desired as recorded")
			}
			assert.Equal(t, tc.wantConverged, s.Converged)
			assert.Equal(t, tc.wantCleared, s.LastConvergedCleared)
		})
	}
}

// TestLifecycle_RandomSequencesLeaveHostClean drives the worker over a host
// model through random goals, failures, and clock movement. Whenever Status
// says the goal converged, the host must match it, and Close must always
// leave the host clean and the identity free.
func TestLifecycle_RandomSequencesLeaveHostClean(t *testing.T) {
	for seed := range uint64(40) {
		t.Run("", func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
			host := newFakeHost()
			clk := newFakeClock()
			idle := make(chan time.Time, 1024)
			m := newWithBackend(Options{Identity: testIdentity, Logger: slog.New(slog.DiscardHandler)}, BackendDarwin, host, hostlock.NewFake())
			m.clock = clk
			m.onIdle = func(next time.Time) { idle <- next }
			lk := m.locker.(*hostlock.Fake)
			m.start()
			waitNext := func() time.Time {
				select {
				case n := <-idle:
					return n
				case <-time.After(testWait):
					t.Fatal("worker did not go idle")
					return time.Time{}
				}
			}
			next := waitNext()

			cfgs := []Config{
				{Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
				{Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.2")}},
				splitConfig(t),
			}
			for range 30 {
				s := m.Status()
				woke := false
				switch rng.IntN(5) {
				case 0, 1:
					cfg := cfgs[rng.IntN(len(cfgs))]
					woke = s.Goal != GoalSet || !s.Desired.Equal(cfg)
					require.NoError(t, m.Set(cfg))
				case 2:
					woke = s.Goal != GoalClear
					require.NoError(t, m.Clear())
				case 3:
					host.mu.Lock()
					host.failWrite = rng.IntN(2) == 0
					host.failFlush = rng.IntN(3) == 0
					host.mu.Unlock()
				case 4:
					d := time.Duration(rng.IntN(40)) * time.Second
					woke = !next.IsZero() && !next.After(clk.Now().Add(d))
					clk.Advance(d)
				}
				if woke {
					next = waitNext()
				}

				s = m.Status()
				if s.Converged {
					host.mu.Lock()
					installed := host.installed
					host.mu.Unlock()
					switch s.Goal {
					case GoalSet:
						require.NotNil(t, installed, "a converged Set goal is installed")
						assert.Equal(t, toBackendConfig(s.Desired), *installed)
					case GoalClear:
						assert.Nil(t, installed, "a converged Clear left nothing behind")
					case GoalNone:
						t.Fatal("Converged without a goal")
					}
				}
			}

			host.mu.Lock()
			host.failWrite, host.failFlush = false, false
			host.mu.Unlock()
			require.NoError(t, m.Close())
			s := m.Status()
			assert.Equal(t, s.Goal == GoalClear, s.Converged,
				"after a clean Close only a Clear goal reads Converged")
			clean, err := host.clean()
			require.NoError(t, err)
			assert.True(t, clean, "Close removes whatever the Manager may have installed")
			assert.False(t, lk.Held(identityLockName(testIdentity)))
			assert.False(t, lk.Held(hostLockName))
		})
	}
}
