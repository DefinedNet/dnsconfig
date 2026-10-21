package windows

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// fakeWatcher is a Watcher the test drives with signal and fail.
type fakeWatcher struct {
	events chan struct{}
	done   chan struct{}
	mu     sync.Mutex
	err    error
	once   sync.Once
	closed bool
	// closeErr is what Close returns, as a failed unregister would.
	closeErr error
}

func newFakeWatcher() *fakeWatcher {
	return &fakeWatcher{events: make(chan struct{}, 1), done: make(chan struct{})}
}

func (w *fakeWatcher) Events() <-chan struct{} { return w.events }
func (w *fakeWatcher) Done() <-chan struct{}   { return w.done }

func (w *fakeWatcher) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *fakeWatcher) Close() error {
	w.mu.Lock()
	w.closed = true
	err := w.closeErr
	w.mu.Unlock()
	w.stop()
	return err
}

func (w *fakeWatcher) isClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

func (w *fakeWatcher) stop() {
	w.once.Do(func() {
		close(w.events)
		close(w.done)
	})
}

func (w *fakeWatcher) fail(err error) {
	w.mu.Lock()
	w.err = err
	w.mu.Unlock()
	w.stop()
}

func (w *fakeWatcher) signal() {
	select {
	case w.events <- struct{}{}:
	default:
	}
}

// watchers records every watcher a harness's factories created.
type watchers struct {
	mu       sync.Mutex
	policy   []*fakeWatcher
	registry []*fakeWatcher
	keys     [][]RegistryWatchKey
}

func (ws *watchers) lastPolicy() *fakeWatcher {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.policy[len(ws.policy)-1]
}

func (ws *watchers) lastRegistry() *fakeWatcher {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	return ws.registry[len(ws.registry)-1]
}

// installWatchers replaces h's factories with recording fakes.
func installWatchers(h *harness) *watchers {
	ws := &watchers{}
	h.watchFactory = func() (Watcher, error) {
		w := newFakeWatcher()
		ws.mu.Lock()
		ws.policy = append(ws.policy, w)
		ws.mu.Unlock()
		return w, nil
	}
	h.regWatchFactory = func(keys []RegistryWatchKey) (Watcher, error) {
		w := newFakeWatcher()
		ws.mu.Lock()
		ws.registry = append(ws.registry, w)
		ws.keys = append(ws.keys, keys)
		ws.mu.Unlock()
		return w, nil
	}
	return ws
}

// waitSignal fails the test unless Changes delivers a value.
func waitSignal(t *testing.T, b *Backend) {
	t.Helper()
	_, ok := <-b.Changes()
	require.True(t, ok, "Changes closed while a signal was expected")
}

// drainSignal empties a pending coalesced signal, if any.
func drainSignal(b *Backend) {
	select {
	case <-b.Changes():
	default:
	}
}

func TestPolicyWatcherStartupFailureGatesGP(t *testing.T) {
	for _, state := range []string{"absent", "empty", "foreign", "values", "owned", "peer"} {
		t.Run(state, func(t *testing.T) {
			h := newHarness(t)
			switch state {
			case "empty":
				require.NoError(t, h.reg.CreateKey(gpoNrptBase))
			case "foreign":
				seedForeignGPRule(t, h.reg, "foreign")
			case "values":
				require.NoError(t, h.reg.SetDWord(gpoNrptBase, "foreign", 1))
			case "owned", "peer":
				key, target := gpRuleKey(0), adapterTarget{guid: testGUID}
				if state == "peer" {
					key, target = gpoNrptBase+`\`+ruleName(otherIdentity, 0), adapterTarget{guid: otherGUID}
				}
				require.NoError(t, h.populateRule(key, nrptRule{[]string{".old.example"}, "192.0.2.1"}, target))
			}
			var logs bytes.Buffer
			h.logger = slog.New(slog.NewTextHandler(&logs, nil))
			startErr := errors.New("register failed")
			starts := 0
			h.watchFactory = func() (Watcher, error) { starts++; return nil, startErr }
			reg := &failInjectRegistry{fakeRegistry: h.reg, failAt: -1}
			h.Backend.reg = reg
			before := reg.snapshot()
			res, err := h.Set(context.Background(), catchAll(t), backend.Attempt{NewGoal: true})
			if state == "absent" {
				require.NoError(t, err)
				assert.True(t, reg.hasKey(ruleKey(0)))
				assert.False(t, reg.hasKey(gpoNrptBase))
			} else {
				require.ErrorIs(t, err, startErr)
				assert.False(t, res.Changed)
				assert.Zero(t, reg.seen, "refusal must precede every registry write")
				assert.Equal(t, before, reg.snapshot())
			}
			assert.Zero(t, h.notify.calls)
			assert.Contains(t, logs.String(), "machine-policy watcher unavailable")
			assert.Contains(t, logs.String(), startErr.Error())
			if state == "absent" {
				replacement := catchAll(t)
				replacement.Nameservers = mustAddrs(t, "192.0.2.99")
				require.NoError(t, h.setGoal(context.Background(), replacement))
				assert.Equal(t, "192.0.2.99", reg.keys[ruleKey(0)]["GenericDNSServers"])
				assert.Equal(t, 2, starts, "every attempt retries registration")
			}
			beforeCleanup := starts
			require.NoError(t, h.clearGoal(context.Background()))
			assert.Empty(t, reg.ourRuleNames())
			assert.Empty(t, reg.gpRuleNames())
			if state == "owned" {
				assert.Equal(t, 1, h.notify.calls, "recovery still notifies Windows")
			}
			assert.Equal(t, beforeCleanup, starts, "cleanup does not require registration")
		})
	}
}

func TestPolicyWatcherStoppedBeforeStartupReturns(t *testing.T) {
	h := newHarness(t)
	seedForeignGPRule(t, h.reg, "foreign")
	w := newFakeWatcher()
	w.signal()
	waitErr := errors.New("wait failed")
	w.fail(waitErr)
	h.watchFactory = func() (Watcher, error) { return w, nil }
	before := h.reg.snapshot()
	res, err := h.Set(context.Background(), catchAll(t), backend.Attempt{NewGoal: true})
	require.ErrorIs(t, err, waitErr)
	assert.False(t, res.Changed)
	assert.Equal(t, before, h.reg.snapshot())
}

// TestPolicyWatcherFailureAndRestart checks that a dying watcher is reported,
// wakes the caller, and is replaced by the next converge without disturbing
// installed rules.
func TestPolicyWatcherFailureAndRestart(t *testing.T) {
	for _, initiallyGP := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "GP"}[initiallyGP], func(t *testing.T) {
			h := newHarness(t)
			logs := h.captureLogs()
			ws := installWatchers(h)
			if initiallyGP {
				seedForeignGPRule(t, h.reg, "foreign")
			}
			ctx := context.Background()
			_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			drainSignal(h.Backend)
			before := h.reg.snapshot()
			old := ws.lastPolicy()
			waitErr := errors.New("wait failed")
			old.fail(waitErr)
			waitSignal(t, h.Backend)
			assert.Equal(t, before, h.reg.snapshot(), "monitoring failure retains installed rules")
			// The forwarder logs before it signals, so the read is ordered.
			assert.Contains(t, logs.String(), "machine-policy watcher unavailable")
			assert.Contains(t, logs.String(), waitErr.Error())

			res, err := h.Set(ctx, catchAll(t), backend.Attempt{})
			require.NoError(t, err)
			assert.False(t, res.Changed)
			assert.True(t, old.isClosed())
			assert.Len(t, ws.policy, 2)
		})
	}
}

// TestPolicyWatcherRestartFailureRefusesGPWrite keeps a GP configuration
// unchanged when monitoring cannot be restored.
func TestPolicyWatcherRestartFailureRefusesGPWrite(t *testing.T) {
	h := newHarness(t)
	ws := installWatchers(h)
	seedForeignGPRule(t, h.reg, "foreign")
	ctx := context.Background()
	_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	ws.lastPolicy().fail(errors.New("wait failed"))
	before := h.reg.snapshot()
	startErr := errors.New("restart failed")
	h.watchFactory = func() (Watcher, error) { return nil, startErr }
	replacement := catchAll(t)
	replacement.Nameservers = mustAddrs(t, "192.0.2.99")
	res, err := h.Set(ctx, replacement, backend.Attempt{NewGoal: true})
	require.ErrorIs(t, err, startErr)
	assert.False(t, res.Changed)
	assert.Equal(t, before, h.reg.snapshot())
}

func TestChangesFedByEverySource(t *testing.T) {
	h := newHarness(t)
	ws := installWatchers(h)
	_, err := h.Set(context.Background(), catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	drainSignal(h.Backend)

	ws.lastPolicy().signal()
	waitSignal(t, h.Backend)
	ws.lastRegistry().signal()
	waitSignal(t, h.Backend)

	require.Len(t, ws.keys, 1)
	want := []RegistryWatchKey{
		{Path: nrptBase, Floor: dnscacheParameters},
		{Path: gpoNrptBase, Floor: policiesRoot},
	}
	for _, path := range adapterPaths(testGUID) {
		want = append(want, RegistryWatchKey{Path: path, Floor: path})
	}
	assert.Equal(t, want, ws.keys[0])
}

// TestRegistryWatcherFollowsAdapterAndFailure restarts the registry watch
// when the adapter changes and reports, without refusing, a failed start.
func TestRegistryWatcherFollowsAdapterAndFailure(t *testing.T) {
	h := newHarness(t)
	logs := h.captureLogs()
	ws := installWatchers(h)
	ctx := context.Background()
	_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	_, err = h.Set(ctx, catchAll(t), backend.Attempt{})
	require.NoError(t, err)
	assert.Len(t, ws.registry, 1, "an unchanged live watch is kept")

	for _, path := range adapterPaths(otherGUID) {
		require.NoError(t, h.reg.CreateKey(path))
	}
	h.resolveInterface = func(string) (string, error) { return otherGUID, nil }
	_, err = h.Set(ctx, catchAll(t), backend.Attempt{})
	require.NoError(t, err)
	require.Len(t, ws.registry, 2)
	assert.True(t, ws.registry[0].isClosed())
	assert.Equal(t, adapterPaths(otherGUID)[0], ws.keys[1][2].Path)

	drainSignal(h.Backend)
	ws.lastRegistry().fail(errors.New("key vanished"))
	waitSignal(t, h.Backend)
	assert.Contains(t, logs.String(), "registry change watcher unavailable")
	assert.Contains(t, logs.String(), "key vanished")
	assert.NotContains(t, logs.String(), "machine-policy watcher unavailable",
		"registry monitoring is not policy monitoring")

	startErr := errors.New("no notify")
	h.regWatchFactory = func([]RegistryWatchKey) (Watcher, error) { return nil, startErr }
	_, err = h.Set(ctx, catchAll(t), backend.Attempt{})
	require.NoError(t, err, "missing registry monitoring leaves periodic checks, not a refusal")
	assert.Contains(t, logs.String(), startErr.Error())
}

// TestDeadRegistryWatcherIsReported logs the failure of a watcher that
// stopped before its forwarder ran.
func TestDeadRegistryWatcherIsReported(t *testing.T) {
	h := newHarness(t)
	logs := h.captureLogs()
	installWatchers(h)
	dead := errors.New("dead on arrival")
	h.regWatchFactory = func([]RegistryWatchKey) (Watcher, error) {
		w := newFakeWatcher()
		w.fail(dead)
		return w, nil
	}
	_, err := h.Set(context.Background(), catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	// The forwarder logs before it signals, so the read is ordered.
	waitSignal(t, h.Backend)
	assert.Contains(t, logs.String(), "registry change watcher unavailable")
	assert.Contains(t, logs.String(), dead.Error())
}

func TestConvergedClearStopsSources(t *testing.T) {
	h := newHarness(t)
	ws := installWatchers(h)
	ctx := context.Background()
	_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	drainSignal(h.Backend)
	ws.lastRegistry().fail(errors.New("registry watch lost"))
	waitSignal(t, h.Backend)

	_, err = h.Clear(ctx, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.True(t, ws.lastPolicy().isClosed())
	assert.True(t, ws.lastRegistry().isClosed())

	_, err = h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	ws.mu.Lock()
	policies, registries := len(ws.policy), len(ws.registry)
	ws.mu.Unlock()
	assert.Equal(t, 2, policies, "Set restarts the policy watcher")
	assert.Equal(t, 2, registries, "Set restarts the registry watcher")
	assert.False(t, ws.lastPolicy().isClosed())
}

// TestFinalClearLeavesSourcesToClose: the final attempt keeps the sources,
// so a teardown failure surfaces from Close rather than only a log line.
func TestFinalClearLeavesSourcesToClose(t *testing.T) {
	h := newHarness(t)
	ws := installWatchers(h)
	ctx := context.Background()
	_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	unregisterErr := errors.New("unregister failed")
	ws.lastPolicy().mu.Lock()
	ws.lastPolicy().closeErr = unregisterErr
	ws.lastPolicy().mu.Unlock()

	_, err = h.Clear(ctx, backend.Attempt{Final: true})
	require.NoError(t, err)
	assert.False(t, ws.lastPolicy().isClosed())
	assert.ErrorIs(t, h.Close(), unregisterErr)
}

func TestCloseStopsSourcesAndClosesChanges(t *testing.T) {
	h := newHarness(t)
	logs := h.captureLogs()
	ws := installWatchers(h)
	_, err := h.Set(context.Background(), catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	ws.lastPolicy().signal()
	ws.lastRegistry().signal()
	require.NoError(t, h.Close())
	assert.True(t, ws.lastPolicy().isClosed())
	assert.True(t, ws.lastRegistry().isClosed())
	for range h.Changes() {
	}
	assert.NotContains(t, logs.String(), "watcher unavailable", "a requested stop is not a monitoring failure")
	require.NoError(t, h.Close(), "Close is idempotent")
	assert.NotEmpty(t, h.reg.ourRuleNames(), "backend Close must not clear NRPT rules")
}
