package dnsconfig

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/hostlock"
)

// TestWorker_GoalReplacedMidAttempt: an attempt that finishes after its goal
// was replaced records what it did to the host but leaves Converged and the
// retry policy to the replacement goal.
func TestWorker_GoalReplacedMidAttempt(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	first, second := sampleConfig(t), splitConfig(t)
	require.NoError(t, h.m.Set(first))
	c := h.next()
	require.NoError(t, h.m.Set(second))
	c.ok(backend.Result{Changed: true})

	c = h.next()
	assert.True(t, c.attempt.NewGoal, "the replacement goal gets its own first attempt")
	assert.Equal(t, toBackendConfig(second), c.cfg)
	s := h.m.Status()
	assert.False(t, s.Converged, "the finished attempt was for a replaced goal")
	assert.Equal(t, second, s.Desired)
	assert.False(t, s.LastChangedAt.IsZero(), "the finished attempt's write is still recorded")

	c.fail(errors.New("write failed"))
	next := h.settle()
	s = h.m.Status()
	assert.Error(t, s.LastError)
	assert.Equal(t, h.clk.Now().Add(backoffMin), next, "the replacement's first failure")
}

// TestWorker_StaleFailureDoesNotBackOffNewGoal: a failure of a replaced
// goal's attempt must not count against the new goal, so the new goal's own
// first failure retries after backoffMin rather than a doubled delay.
func TestWorker_StaleFailureDoesNotBackOffNewGoal(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	c := h.next()
	require.NoError(t, h.m.Set(splitConfig(t)))
	c.fail(errors.New("old goal failed"))
	c = h.next()
	require.True(t, c.attempt.NewGoal)
	c.fail(errors.New("new goal failed"))
	next := h.settle()
	s := h.m.Status()
	assert.Equal(t, h.clk.Now().Add(backoffMin), next, "only the current goal's failure counts")
	assert.ErrorContains(t, s.LastError, "new goal failed")
}

// TestWorker_StaleClearKeepsIdentity: a Clear replaced by a Set while it ran
// converged a goal nobody wants anymore, so it must neither release the
// identity under the live Set nor mark that Set converged, though the host
// observation still records the clean host.
func TestWorker_StaleClearKeepsIdentity(t *testing.T) {
	var locker *countingLocker
	h := newHarness(t, BackendDarwin, Options{}, func(m *Manager) {
		locker = &countingLocker{Fake: m.locker.(*hostlock.Fake)}
		m.locker = locker
	})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	require.NoError(t, h.m.Clear())
	c := h.next()
	require.Equal(t, "clear", c.op)
	require.NoError(t, h.m.Set(splitConfig(t)))
	c.ok(backend.Result{Changed: true})

	c = h.next()
	assert.Equal(t, "set", c.op)
	assert.Equal(t, backend.Attempt{NewGoal: true}, c.attempt, "the new goal has not converged")
	assert.Equal(t, toBackendConfig(splitConfig(t)), c.cfg)
	assert.Equal(t, 1, locker.count(), "the identity was never released and retaken")
	s := h.m.Status()
	assert.False(t, s.Converged)
	assert.True(t, s.LastConvergedCleared, "the host observation still records the Clear")
}

// TestWorker_StaleRepeatChangeDoesNotPace: pacing restrains repair of the
// goal whose repeat rewrote the host; a replaced goal's repeat must not
// delay the new goal's signal-driven converges. The writer fight is still
// logged, since it happened.
func TestWorker_StaleRepeatChangeDoesNotPace(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, BackendDarwin, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	h.b.signal()
	h.clk.AdvanceTo(t, h.waitIdle())
	c := h.next()
	require.Equal(t, backend.Attempt{Converged: true}, c.attempt)
	require.NoError(t, h.m.Set(splitConfig(t)))
	c.ok(backend.Result{Changed: true})

	h.converged("set")
	assert.Contains(t, logs.String(), "repeat converge changed the host")
	h.b.signal()
	// The replacing Set queued a wake-up while the repeat ran, so idle
	// reports before the signal's may still arrive, armed for the periodic
	// check.
	next := h.waitIdle()
	for next.Equal(h.clk.Now().Add(periodicCheckInterval)) {
		next = h.waitIdle()
	}
	assert.Equal(t, h.clk.Now().Add(signalDebounce), next, "the stale repeat did not pace the new goal")
}

// TestWorker_StaleSuccessDoesNotSkipCleanup: a Set replaced by a Clear while
// it ran did not converge the Clear, so Close still owes the final Clear.
// The no-op backend has no identity lock, so the recorded goal alone decides.
func TestWorker_StaleSuccessDoesNotSkipCleanup(t *testing.T) {
	h := newHarness(t, BackendNoop, Options{ForceBackend: BackendNoop})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	c := h.next()
	require.NoError(t, h.m.Clear())
	c.ok(backend.Result{Changed: true})
	require.Equal(t, "clear", h.next().op)

	done := closeAsync(h.m)
	select {
	case final := <-h.b.calls:
		assert.Equal(t, "clear", final.op)
		assert.True(t, final.attempt.Final)
		final.ok(backend.Result{Changed: true})
	case err := <-done:
		t.Fatalf("Close skipped the final Clear (err %v)", err)
	case <-time.After(testWait):
		t.Fatal("Close did not return")
	}
	require.NoError(t, waitClose(t, done))
}

func TestWorker_BackoffDoublesToCap(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	c := h.next()
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i, secs := range want {
		c.fail(errors.New("write failed"))
		next := h.settle()
		assert.Equal(t, h.clk.Now().Add(secs*time.Second), next, "failure %d", i+1)
		assert.False(t, h.m.Status().Converged)

		h.clk.Advance(secs*time.Second - time.Millisecond)
		h.clk.Advance(time.Millisecond)
		c = h.next()
		assert.Equal(t, backend.Attempt{}, c.attempt, "a retry is not a new goal")
	}
	c.ok(backend.Result{})
	assert.Equal(t, h.clk.Now().Add(periodicCheckInterval), h.settle(), "success ends backoff")
	assert.True(t, h.m.Status().Converged)
}

// TestWorker_NewGoalResetsBackoff: a new goal runs at once and starts the
// backoff sequence over.
func TestWorker_NewGoalResetsBackoff(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	for range 3 {
		h.next().fail(errors.New("write failed"))
		h.clk.AdvanceTo(t, h.settle())
	}
	h.next().fail(errors.New("write failed"))
	require.Equal(t, h.clk.Now().Add(8*time.Second), h.settle())

	require.NoError(t, h.m.Set(splitConfig(t)))
	c := h.next()
	assert.True(t, c.attempt.NewGoal)
	c.fail(errors.New("write failed"))
	next := h.settle()
	assert.Equal(t, h.clk.Now().Add(backoffMin), next)
}

// TestWorker_SignalDuringBackoffDoesNotConverge: neither signals nor the
// periodic check shorten backoff.
func TestWorker_SignalDuringBackoffDoesNotConverge(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	for range 3 {
		h.next().fail(errors.New("write failed"))
		h.clk.AdvanceTo(t, h.settle())
	}
	h.next().fail(errors.New("write failed"))
	retryAt := h.settle()
	require.Equal(t, h.clk.Now().Add(8*time.Second), retryAt)

	h.b.signal()
	assert.Equal(t, retryAt, h.waitIdle(), "a signal must not arm an earlier wake-up")
	h.clk.Advance(signalDebounce)
	select {
	case c := <-h.b.calls:
		t.Fatalf("signal converged during backoff: %+v", c.attempt)
	default:
	}
	h.clk.AdvanceTo(t, retryAt)
	c := h.next()
	c.ok(backend.Result{})
	h.settle()
	assert.True(t, h.m.Status().Converged)
}

// TestWorker_SignalEndsBackoffAfterRefusal: a refusal wrote nothing, so a
// change signal during its backoff, such as the holder of a conflicting
// namespace leaving, converges after the debounce instead of waiting out the
// retry deadline.
func TestWorker_SignalEndsBackoffAfterRefusal(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(splitConfig(t)))
	refuse := func() {
		h.next().refuse(backend.NewConflictError("corp.example.com", "net-b"))
	}
	for range 3 {
		refuse()
		h.clk.AdvanceTo(t, h.settle())
	}
	refuse()
	retryAt := h.settle()
	require.Equal(t, h.clk.Now().Add(8*time.Second), retryAt)

	h.b.signal()
	signalAt := h.clk.Now().Add(signalDebounce)
	assert.Equal(t, signalAt, h.waitIdle(), "the debounced signal arms an earlier wake-up")
	h.clk.AdvanceTo(t, signalAt)
	c := h.next()
	c.ok(backend.Result{Changed: true})
	h.settle()
	s := h.m.Status()
	assert.True(t, s.Converged)
	assert.NoError(t, s.LastError)
}

// TestWorker_SignalsAreDebounced: a burst of change signals produces one
// repeat converge after the debounce window opened by the first signal.
func TestWorker_SignalsAreDebounced(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")

	start := h.clk.Now()
	h.b.signal()
	assert.Equal(t, start.Add(signalDebounce), h.waitIdle())
	h.clk.Advance(time.Second)
	h.b.signal()
	assert.Equal(t, start.Add(signalDebounce), h.waitIdle(), "later signals do not extend the window")
	h.clk.Advance(time.Second)

	c := h.next()
	assert.Equal(t, backend.Attempt{Converged: true}, c.attempt, "repair is a repeat of the converged goal")
	c.ok(backend.Result{})
	next := h.settle()
	assert.Equal(t, h.clk.Now().Add(periodicCheckInterval), next)
}

// TestWorker_SignalIgnoredWithoutSetGoal: only a live Set goal has anything
// for a change signal to repair.
func TestWorker_SignalIgnoredWithoutSetGoal(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	h.b.signal()
	assert.True(t, h.waitIdle().IsZero(), "no goal: nothing to schedule")

	require.NoError(t, h.m.Clear())
	h.converged("clear")
	h.b.signal()
	assert.True(t, h.waitIdle().IsZero(), "a converged Clear ignores signals")
}

func TestWorker_PeriodicCheckWhileSetGoalLive(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	c := h.next()
	c.ok(backend.Result{Changed: true})
	next := h.settle()
	require.Equal(t, h.clk.Now().Add(periodicCheckInterval), next)

	for range 2 {
		h.clk.AdvanceTo(t, next)
		c = h.next()
		assert.Equal(t, backend.Attempt{Converged: true}, c.attempt)
		c.ok(backend.Result{})
		next = h.settle()
		assert.Equal(t, h.clk.Now().Add(periodicCheckInterval), next)
	}
	assert.True(t, h.m.Status().Converged)
}

// TestWorker_PacesChangedRepeatConverges: a repeat converge that had to
// rewrite the host delays the next signal-driven converge, so a writer that
// keeps undoing ours cannot drive a rewrite every debounce window.
func TestWorker_PacesChangedRepeatConverges(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, BackendDarwin, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")

	h.b.signal()
	h.clk.AdvanceTo(t, h.waitIdle())
	c := h.next()
	c.ok(backend.Result{Changed: true})
	h.settle()
	repairedAt := h.clk.Now()
	assert.Equal(t, repairedAt, h.m.Status().LastChangedAt)
	assert.Contains(t, logs.String(), "repeat converge changed the host")

	h.b.signal()
	assert.Equal(t, repairedAt.Add(repeatChangeInterval), h.waitIdle(),
		"the signal waits out the pacing interval, not just the debounce")
	h.clk.Advance(signalDebounce)
	select {
	case c := <-h.b.calls:
		t.Fatalf("paced signal converged early: %+v", c.attempt)
	default:
	}
	h.clk.AdvanceTo(t, repairedAt.Add(repeatChangeInterval))
	h.next().ok(backend.Result{})
	h.settle()

	// Without a further change, signals return to the plain debounce.
	h.b.signal()
	assert.Equal(t, h.clk.Now().Add(signalDebounce), h.waitIdle())
}

// TestWorker_RetryFinishingFirstInstallDoesNotPace: a retry that completes a
// partial first attempt is still the initial install, not a writer fight;
// only a change after the goal converged paces and logs.
func TestWorker_RetryFinishingFirstInstallDoesNotPace(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, BackendDarwin, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.next().reply <- callResult{res: backend.Result{Changed: true}, err: errors.New("verification failed")}
	h.clk.AdvanceTo(t, h.settle())

	c := h.next()
	require.Equal(t, backend.Attempt{}, c.attempt, "the retry follows no successful attempt")
	c.ok(backend.Result{Changed: true})
	h.settle()
	assert.NotContains(t, logs.String(), "repeat converge changed the host")
	h.b.signal()
	assert.Equal(t, h.clk.Now().Add(signalDebounce), h.waitIdle(), "finishing the first install does not pace")

	h.clk.Advance(signalDebounce)
	c = h.next()
	require.Equal(t, backend.Attempt{Converged: true}, c.attempt)
	c.ok(backend.Result{Changed: true})
	h.settle()
	repairedAt := h.clk.Now()
	assert.Contains(t, logs.String(), "repeat converge changed the host")
	h.b.signal()
	assert.Equal(t, repairedAt.Add(repeatChangeInterval), h.waitIdle(), "a change after convergence paces")
}

// TestWorker_NewGoalClearsPacing: pacing restrains repair, never a caller's
// new goal or the signals that follow it.
func TestWorker_NewGoalClearsPacing(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	h.b.signal()
	h.clk.AdvanceTo(t, h.waitIdle())
	h.next().ok(backend.Result{Changed: true})
	h.settle()

	require.NoError(t, h.m.Set(splitConfig(t)))
	c := h.next()
	assert.True(t, c.attempt.NewGoal, "a new goal runs at once despite pacing")
	c.ok(backend.Result{Changed: true})
	h.settle()
	h.b.signal()
	assert.Equal(t, h.clk.Now().Add(signalDebounce), h.waitIdle(),
		"a first attempt's change is not a fight and does not pace")
}

// TestWorker_PacingEndsBeforePeriodicCheck: plan's retry branch ignores
// pacing because the periodic check after a paced attempt lands after pacing ends.
func TestWorker_PacingEndsBeforePeriodicCheck(t *testing.T) {
	assert.Less(t, repeatChangeInterval, periodicCheckInterval)
}

// TestWorker_EmptyGPContainer: the first attempt writes the local copies and
// fails; repeats write nothing and end their backoff on a change signal such
// as the container's removal.
func TestWorker_EmptyGPContainer(t *testing.T) {
	h := newHarness(t, BackendWindows, Options{InterfaceName: "Ethernet"})
	require.NoError(t, h.m.Set(splitConfig(t)))
	emptyErr := fmt.Errorf("windows: container: %w", backend.ErrGroupPolicyContainerEmpty)
	// Each of these attempts rewrote something, as if the local copies kept
	// being removed, so backoff grows past the signal debounce.
	for range 2 {
		h.next().reply <- callResult{res: backend.Result{Changed: true, Pending: true}, err: emptyErr}
		h.clk.AdvanceTo(t, h.settle())
	}
	h.next().reply <- callResult{res: backend.Result{Changed: true, Pending: true}, err: emptyErr}
	retryAt := h.settle()
	require.Equal(t, h.clk.Now().Add(4*time.Second), retryAt)

	h.b.signal()
	assert.Equal(t, retryAt, h.waitIdle(), "a signal after our own writes may be their echo")
	h.clk.AdvanceTo(t, retryAt)
	// A write-free repeat still owes the flush, as the backend reports it.
	h.next().reply <- callResult{res: backend.Result{Pending: true}, err: emptyErr}
	retryAt = h.settle()
	s := h.m.Status()
	require.ErrorIs(t, s.LastError, ErrGroupPolicyContainerEmpty)

	h.b.signal()
	signalAt := h.clk.Now().Add(signalDebounce)
	require.True(t, signalAt.Before(retryAt))
	assert.Equal(t, signalAt, h.waitIdle(), "the debounced signal arms an earlier wake-up")
	h.clk.AdvanceTo(t, signalAt)
	h.next().ok(backend.Result{})
	h.settle()
	s = h.m.Status()
	assert.True(t, s.Converged)
	assert.NoError(t, s.LastError)
}

// TestWorker_ConflictRetries: a conflict is refused before mutation, visible
// with its holder, and retried rather than latched.
func TestWorker_ConflictRetries(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(splitConfig(t)))
	h.next().refuse(backend.NewConflictError("corp.example.com", "net-b"))
	next := h.settle()

	s := h.m.Status()
	require.ErrorIs(t, s.LastError, ErrConflict)
	var conflict *ConflictError
	require.ErrorAs(t, s.LastError, &conflict)
	assert.Equal(t, "corp.example.com.", conflict.Domain, "the domain is canonical")
	assert.Equal(t, "net-b", conflict.Holder)
	var e *Error
	require.ErrorAs(t, s.LastError, &e)
	assert.Equal(t, "Converge", e.Op)
	text := s.LastError.Error()
	assert.True(t, strings.HasPrefix(text, "dnsconfig Converge (darwin): "), text)
	assert.Equal(t, 1, strings.Count(text, "dnsconfig"), "only *Error names the package: %s", text)
	assert.Equal(t, 1, strings.Count(text, "corp.example.com."), "the domain appears once: %s", text)

	h.clk.AdvanceTo(t, next)
	h.next().refuse(backend.NewConflictError(".", "net-b"))
	h.clk.AdvanceTo(t, h.settle())
	require.ErrorAs(t, h.m.Status().LastError, &conflict)
	assert.Equal(t, ".", conflict.Domain)

	h.next().ok(backend.Result{Changed: true})
	h.settle()
	s = h.m.Status()
	assert.True(t, s.Converged, "the goal converges once the holder leaves")
	assert.NoError(t, s.LastError)
}

// failLogLevels returns "<level> <event>" for each converge failed and
// converge recovered line in order.
func failLogLevels(out string) []string {
	var got []string
	for line := range strings.Lines(out) {
		var event string
		switch {
		case strings.Contains(line, `msg="dnsconfig: converge failed"`):
			event = "failed"
		case strings.Contains(line, `msg="dnsconfig: converge recovered"`):
			event = "recovered"
		default:
			continue
		}
		for field := range strings.FieldsSeq(line) {
			if lvl, ok := strings.CutPrefix(field, "level="); ok {
				got = append(got, lvl+" "+event)
			}
		}
	}
	return got
}

// TestWorker_RepeatedFailureWarnsOnce: a goal failing the same way on every
// retry warns once, repeats at Debug, warns again when the failure changes,
// and logs its recovery.
func TestWorker_RepeatedFailureWarnsOnce(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, BackendDarwin, Options{Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	for range 3 {
		h.next().fail(errors.New("scutil failed"))
		h.clk.AdvanceTo(t, h.settle())
	}
	h.next().fail(errors.New("resolver dir unreadable"))
	h.clk.AdvanceTo(t, h.settle())
	h.next().ok(backend.Result{Changed: true})
	h.settle()

	assert.Equal(t, []string{
		"WARN failed", "DEBUG failed", "DEBUG failed",
		"WARN failed",
		"INFO recovered",
	}, failLogLevels(logs.String()))
	assert.Contains(t, logs.String(), `msg="dnsconfig: converge recovered" goal=set`)
}

// TestWorker_NewGoalRearmsFailureWarning: a new goal's first failure warns
// even when it repeats the previous goal's failure.
func TestWorker_NewGoalRearmsFailureWarning(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, BackendDarwin, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.next().fail(errors.New("scutil failed"))
	h.settle()
	require.NoError(t, h.m.Set(splitConfig(t)))
	h.next().fail(errors.New("scutil failed"))
	h.settle()

	assert.Equal(t, []string{"WARN failed", "WARN failed"}, failLogLevels(logs.String()))
}

// TestWorker_ClearAfterFailedSetIsNotRecovery: a Clear that converges after
// a failed Set is a different goal, not the Set recovering.
func TestWorker_ClearAfterFailedSetIsNotRecovery(t *testing.T) {
	var logs bytes.Buffer
	h := newHarness(t, BackendDarwin, Options{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.next().fail(errors.New("scutil failed"))
	h.settle()
	require.NoError(t, h.m.Clear())
	c := h.next()
	require.Equal(t, "clear", c.op)
	c.ok(backend.Result{Changed: true})
	h.settle()

	assert.Equal(t, []string{"WARN failed"}, failLogLevels(logs.String()))
}
