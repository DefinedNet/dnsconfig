package dnsconfig

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// waitStatus polls a Manager on the real clock until cond holds.
func waitStatus(t *testing.T, m *Manager, cond func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(testWait)
	for {
		s := m.Status()
		if cond(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never satisfied the condition: %+v", s)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestNew_ForceBackendNoop(t *testing.T) {
	m, err := New(context.Background(), Options{Identity: "app", ForceBackend: BackendNoop})
	require.NoError(t, err)
	defer m.Close()
	assert.Equal(t, BackendNoop, m.kind)
	assert.Nil(t, m.locker, "the no-op backend takes no host locks")
}

// TestNew_ShutdownTimeoutDefault: a zero ShutdownTimeout selects
// DefaultShutdownTimeout, so Close's final cleanup always has a deadline.
func TestNew_ShutdownTimeoutDefault(t *testing.T) {
	t.Run("zero selects the default", func(t *testing.T) {
		m, err := New(context.Background(), Options{Identity: "app", ForceBackend: BackendNoop})
		require.NoError(t, err)
		defer m.Close()
		assert.Equal(t, DefaultShutdownTimeout, m.opts.ShutdownTimeout)
		assert.Greater(t, DefaultShutdownTimeout, attemptTimeout, "a Close queued behind a peer's longest attempt keeps time for its own cleanup")
	})
	t.Run("explicit value is kept", func(t *testing.T) {
		m, err := New(context.Background(), Options{Identity: "app", ForceBackend: BackendNoop, ShutdownTimeout: 5 * time.Second})
		require.NoError(t, err)
		defer m.Close()
		assert.Equal(t, 5*time.Second, m.opts.ShutdownTimeout)
	})
}

// TestSet_ForcedNoopConverges pins that a caller who named BackendNoop asked
// for goals that change nothing, so they converge.
func TestSet_ForcedNoopConverges(t *testing.T) {
	m, err := New(context.Background(), Options{Identity: "app", ForceBackend: BackendNoop})
	require.NoError(t, err)
	defer m.Close()

	require.NoError(t, m.Set(sampleConfig(t)))
	s := waitStatus(t, m, func(s Status) bool { return s.Converged })
	assert.Equal(t, GoalSet, s.Goal)
	assert.True(t, s.LastChangedAt.IsZero(), "noop never changes the host")
	assert.NoError(t, s.LastError)
	require.NoError(t, m.Close())
}

func TestSet_ValidationReturnsDirectly(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want error
	}{
		{name: "zero config", cfg: Config{}, want: ErrEmptyConfig},
		{name: "no nameservers", cfg: Config{SearchDomains: []string{"corp.example."}}},
		{name: "root search domain", cfg: Config{
			Nameservers:   []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			SearchDomains: []string{"."},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, BackendDarwin, Options{})
			before := h.m.Status()
			err := h.m.Set(tc.cfg)
			require.Error(t, err)
			if tc.want != nil {
				assert.ErrorIs(t, err, tc.want)
			}
			var e *Error
			assert.False(t, errors.As(err, &e), "validation errors are returned unwrapped")
			h.unchanged(before, "an invalid config records no goal")
			s := h.m.Status()
			assert.Equal(t, GoalNone, s.Goal)
			assert.NoError(t, s.LastError)
		})
	}
}

func TestSet_BackendLimitReturnsDirectly(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	limit := errors.New("exceeds an OS limit")
	h.b.limitErr = limit
	before := h.m.Status()
	err := h.m.Set(sampleConfig(t))
	require.ErrorIs(t, err, limit)
	var e *Error
	assert.False(t, errors.As(err, &e), "a backend limit is a validation error")
	h.unchanged(before, "an unappliable config records no goal")
	s := h.m.Status()
	assert.Equal(t, GoalNone, s.Goal)
	assert.NoError(t, s.LastError)

	h.closeAnswering()
	assert.ErrorIs(t, h.m.Set(sampleConfig(t)), ErrClosed, "a closed Manager refuses before checking limits")
}

func TestSet_TerminalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     BackendKind
		opts     Options
		close    bool
		want     error
		recorded bool
	}{
		{name: "closed", kind: BackendDarwin, close: true, want: ErrClosed},
		{name: "declined noop", kind: BackendNoop, want: ErrConfigurationDeclined, recorded: true},
		{name: "windows without interface", kind: BackendWindows, want: ErrInterfaceRequired, recorded: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.kind, tc.opts)
			if tc.close {
				require.NoError(t, h.m.Close())
			}
			before := h.m.Status()
			err := h.m.Set(sampleConfig(t))
			require.ErrorIs(t, err, tc.want)
			var e *Error
			require.ErrorAs(t, err, &e)
			assert.Equal(t, "Set", e.Op)
			s := h.m.Status()
			assert.Equal(t, GoalNone, s.Goal)
			if tc.recorded {
				assert.Same(t, err, s.LastError)
			} else {
				assert.NoError(t, s.LastError)
			}
			want := before
			want.LastError = s.LastError
			assert.Equal(t, want, s, "a refused Set changes nothing but LastError")
			if !tc.close {
				h.quiet()
			}
		})
	}
}

func TestSet_WindowsWithInterfaceRecordsGoal(t *testing.T) {
	h := newHarness(t, BackendWindows, Options{InterfaceName: "myvpn0"})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	assert.True(t, h.m.Status().Converged)
}

// TestSet_RecordsGoalThenConverges covers the whole first attempt: the goal
// is visible at once, the backend sees a new goal inside both locks, and a
// successful result populates the converge record.
func TestSet_RecordsGoalThenConverges(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	cfg := sampleConfig(t)
	require.NoError(t, h.m.Set(cfg))

	s := h.m.Status()
	assert.Equal(t, GoalSet, s.Goal)
	assert.Equal(t, cfg, s.Desired)
	assert.False(t, s.Converged, "Set is not a completion barrier")

	c := h.next()
	assert.Equal(t, "set", c.op)
	assert.Equal(t, backend.Attempt{NewGoal: true}, c.attempt)
	assert.Equal(t, toBackendConfig(cfg), c.cfg)
	assert.True(t, c.identityHeld, "the identity lock precedes the first attempt")
	assert.True(t, c.hostHeld, "every attempt runs inside the host-wide critical section")

	h.clk.Advance(time.Second)
	doneAt := h.clk.Now()
	c.ok(backend.Result{Changed: true})
	h.settle()

	s = h.m.Status()
	assert.True(t, s.Converged)
	assert.NoError(t, s.LastError)
	assert.Equal(t, doneAt, s.LastChangedAt)
	assert.False(t, s.LastConvergedCleared)
	assert.False(t, h.lk.Held(hostLockName), "the critical section ends with the attempt")
	assert.True(t, h.identityHeld(), "a live Set goal keeps the identity")
}

// TestSet_RepeatIsNoop: repeating the current goal neither wakes the worker
// nor restarts backoff, so a caller that re-Sets on every network event
// cannot defeat the retry policy.
func TestSet_RepeatIsNoop(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")

	converged := h.m.Status()
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.unchanged(converged, "repeating a converged goal is a no-op")

	require.NoError(t, h.m.Set(splitConfig(t)))
	c := h.next()
	c.fail(errors.New("write failed"))
	retryAt := h.settle()
	require.Equal(t, h.clk.Now().Add(backoffMin), retryAt)
	backingOff := h.m.Status()

	require.NoError(t, h.m.Set(splitConfig(t)))
	assert.Equal(t, retryAt, h.unchanged(backingOff, "a repeat during backoff must not trigger an attempt"),
		"a repeat during backoff must not restart backoff")
}

// TestSet_CanonicalizesDomains: the goal and the backend see one spelling, so
// a repeat that differs only in case or trailing dot is still a no-op.
func TestSet_CanonicalizesDomains(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	ns := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	require.NoError(t, h.m.Set(Config{
		Nameservers:   ns,
		SearchDomains: []string{"Eng.Corp.Example"},
		MatchDomains:  []string{"CORP.example"},
	}))
	assert.Equal(t, []string{"eng.corp.example."}, h.m.Status().Desired.SearchDomains)
	assert.Equal(t, []string{"corp.example."}, h.m.Status().Desired.MatchDomains)

	c := h.next()
	assert.Equal(t, []string{"eng.corp.example"}, c.cfg.SearchDomains, "backends get the dotless form")
	assert.Equal(t, []string{"corp.example"}, c.cfg.MatchDomains)
	c.ok(backend.Result{Changed: true})
	h.settle()

	converged := h.m.Status()
	require.NoError(t, h.m.Set(Config{
		Nameservers:   ns,
		SearchDomains: []string{"eng.corp.example."},
		MatchDomains:  []string{"corp.example."},
	}))
	h.unchanged(converged, "a repeat in canonical spelling is a no-op")
}

func TestSet_DoesNotAliasCallerSlices(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	search := []string{"a.corp.example.com."}
	match := []string{"corp.example.com."}
	ns := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	require.NoError(t, h.m.Set(Config{Nameservers: ns, SearchDomains: search, MatchDomains: match}))

	search[0] = "evil.example.com."
	match[0] = "evil.example.com."
	ns[0] = netip.MustParseAddr("203.0.113.1")

	c := h.next()
	assert.Equal(t, "a.corp.example.com", c.cfg.SearchDomains[0])
	assert.Equal(t, "corp.example.com", c.cfg.MatchDomains[0])
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), c.cfg.Nameservers[0])
	c.ok(backend.Result{Changed: true})
	h.settle()

	s := h.m.Status()
	s.Desired.SearchDomains[0] = "mutated.example.com."
	s.Desired.MatchDomains[0] = "mutated.example.com."
	again := h.m.Status()
	assert.Equal(t, "a.corp.example.com.", again.Desired.SearchDomains[0], "Status returns copies")
	assert.Equal(t, "corp.example.com.", again.Desired.MatchDomains[0])
}

func TestClear_FreshManagerRecovers(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Clear())
	assert.Equal(t, GoalClear, h.m.Status().Goal)

	c := h.next()
	assert.Equal(t, "clear", c.op)
	assert.Equal(t, backend.Attempt{NewGoal: true}, c.attempt)
	assert.True(t, c.identityHeld, "recovery must hold the identity before discovery")
	assert.True(t, c.hostHeld)
	c.ok(backend.Result{Changed: true})
	next := h.settle()

	s := h.m.Status()
	assert.True(t, s.Converged)
	assert.True(t, s.LastConvergedCleared)
	assert.Equal(t, Config{}, s.Desired)
	assert.False(t, s.LastChangedAt.IsZero(), "the Clear removed a predecessor's artifacts")
	assert.False(t, h.identityHeld(), "a converged Clear frees the identity")
	assert.True(t, next.IsZero(), "a converged Clear has nothing left to check")

	cleared := h.m.Status()
	require.NoError(t, h.m.Clear())
	h.unchanged(cleared, "repeating a converged Clear is a no-op")
}

// TestClear_RepeatDuringBackoffIsNoop: like a repeated Set, a repeated Clear
// must not restart the retry policy of a Clear that is failing.
func TestClear_RepeatDuringBackoffIsNoop(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Clear())
	c := h.next()
	require.Equal(t, "clear", c.op)
	c.fail(errors.New("remove failed"))
	retryAt := h.settle()
	require.Equal(t, h.clk.Now().Add(backoffMin), retryAt)
	backingOff := h.m.Status()

	require.NoError(t, h.m.Clear())
	assert.Equal(t, retryAt, h.unchanged(backingOff, "a repeat during backoff must not trigger an attempt"),
		"a repeat during backoff must not restart backoff")
}

func TestClear_ReplacesSetGoal(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	h.converged("set")
	require.NoError(t, h.m.Clear())
	s := h.m.Status()
	assert.Equal(t, GoalClear, s.Goal)
	assert.False(t, s.Converged)
	assert.Equal(t, Config{}, s.Desired, "Desired is meaningful only for a Set goal")
	c := h.converged("clear")
	assert.True(t, c.attempt.NewGoal)
	assert.False(t, h.identityHeld())
}

func TestClear_AfterClose(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Close())
	err := h.m.Clear()
	require.ErrorIs(t, err, ErrClosed)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, "Clear", e.Op)
}

// TestStatus_DoesNotWaitForConverge: Status reads bookkeeping only, so a
// backend call that hangs cannot stall a caller polling for progress.
func TestStatus_DoesNotWaitForConverge(t *testing.T) {
	h := newHarness(t, BackendDarwin, Options{})
	require.NoError(t, h.m.Set(sampleConfig(t)))
	c := h.next()

	got := make(chan Status, 1)
	go func() { got <- h.m.Status() }()
	select {
	case s := <-got:
		assert.Equal(t, GoalSet, s.Goal)
		assert.False(t, s.Converged)
	case <-time.After(testWait):
		t.Fatal("Status waited for an in-flight converge")
	}
	require.NoError(t, h.m.Set(splitConfig(t)), "Set must not wait for an in-flight converge either")
	c.ok(backend.Result{})
	h.converged("set")
}

func TestToBackendConfigUnmapsNameservers(t *testing.T) {
	v4 := netip.MustParseAddr("1.2.3.4")
	v6 := netip.MustParseAddr("2001:db8::1")
	mapped := netip.MustParseAddr("::ffff:1.2.3.4")
	require.False(t, mapped.Is4(), "precondition: mapped form is not Is4")

	in := Config{Nameservers: []netip.Addr{mapped, v6, v4}}
	got := toBackendConfig(in)

	require.Len(t, got.Nameservers, 3)
	assert.Equal(t, v4, got.Nameservers[0], "mapped v4-in-v6 is unmapped to native v4")
	assert.Equal(t, v6, got.Nameservers[1])
	assert.Equal(t, v4, got.Nameservers[2])
	assert.Equal(t, mapped, in.Nameservers[0], "the caller's Config must not be mutated")
}
