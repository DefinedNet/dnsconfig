package dnsconfig

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/hostlock"
)

// testWait bounds every wait for the worker so a broken test fails instead
// of hanging. Worker timing itself runs on fakeClock, never on this.
const testWait = 5 * time.Second

// fakeClock is a manual clock. Timers fire only when Advance passes their
// deadline, so tests drive debounce, backoff, and periodic checks exactly.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c    chan time.Time
	at   time.Time
	done bool
	clk  *fakeClock
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) clockTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: make(chan time.Time, 1), at: c.now.Add(d), clk: c}
	if d <= 0 {
		t.c <- c.now
		t.done = true
		return t
	}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the clock forward and fires every timer now due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	live := c.timers[:0]
	for _, t := range c.timers {
		if t.done {
			continue
		}
		if !t.at.After(c.now) {
			t.c <- c.now
			t.done = true
			continue
		}
		live = append(live, t)
	}
	c.timers = live
}

// AdvanceTo moves the clock to at, which must not be in the past.
func (c *fakeClock) AdvanceTo(t *testing.T, at time.Time) {
	t.Helper()
	d := at.Sub(c.Now())
	require.GreaterOrEqual(t, d, time.Duration(0), "cannot move the clock backwards")
	c.Advance(d)
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Stop() bool {
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	wasLive := !t.done
	t.done = true
	return wasLive
}

// call is one backend Set or Clear the worker made. The scripted backend
// blocks it until the test replies or the attempt's context ends.
type call struct {
	op      string
	cfg     backend.Config
	attempt backend.Attempt
	ctx     context.Context
	// hostHeld and identityHeld are the lock states observed during the call.
	hostHeld     bool
	identityHeld bool
	reply        chan callResult
}

type callResult struct {
	res backend.Result
	err error
}

func (c *call) ok(res backend.Result) { c.reply <- callResult{res: res} }

// fail reports a failure that may have written part of the goal.
func (c *call) fail(err error) { c.reply <- callResult{res: backend.Result{Changed: true}, err: err} }

// refuse reports a failure that wrote nothing, which the Manager treats as a
// refusal.
func (c *call) refuse(err error) { c.reply <- callResult{err: err} }

// scriptedBackend hands every Set and Clear to the test through calls.
type scriptedBackend struct {
	calls    chan *call
	changes  chan struct{}
	locker   *hostlock.Fake
	identity string

	mu         sync.Mutex
	closeCalls int
	closeErr   error
	limitErr   error
	// found and probeErr answer HasArtifacts; probeHeld records whether
	// either lock was held during the last probe.
	found     bool
	probeErr  error
	probes    int
	probeHeld bool
}

func (b *scriptedBackend) HasArtifacts(context.Context) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probes++
	if b.locker != nil {
		b.probeHeld = b.locker.Held(hostLockName) || b.locker.Held(identityLockName(b.identity))
	}
	return b.found, b.probeErr
}

func newScriptedBackend() *scriptedBackend {
	return &scriptedBackend{
		calls:   make(chan *call),
		changes: make(chan struct{}, 1),
	}
}

func (b *scriptedBackend) do(ctx context.Context, op string, cfg backend.Config, a backend.Attempt) (backend.Result, error) {
	c := &call{op: op, cfg: cfg, attempt: a, ctx: ctx, reply: make(chan callResult, 1)}
	if b.locker != nil {
		c.hostHeld = b.locker.Held(hostLockName)
		c.identityHeld = b.locker.Held(identityLockName(b.identity))
	}
	select {
	case b.calls <- c:
	case <-ctx.Done():
		return backend.Result{}, ctx.Err()
	}
	select {
	case r := <-c.reply:
		return r.res, r.err
	case <-ctx.Done():
		// A backend cancelled after it started may have written.
		return backend.Result{Changed: true}, ctx.Err()
	}
}

func (b *scriptedBackend) Set(ctx context.Context, cfg backend.Config, a backend.Attempt) (backend.Result, error) {
	return b.do(ctx, "set", cfg, a)
}

func (b *scriptedBackend) Clear(ctx context.Context, a backend.Attempt) (backend.Result, error) {
	return b.do(ctx, "clear", backend.Config{}, a)
}

func (b *scriptedBackend) ValidateConfig(backend.Config) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.limitErr
}

func (b *scriptedBackend) Changes() <-chan struct{} { return b.changes }

func (b *scriptedBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeCalls++
	return b.closeErr
}

func (b *scriptedBackend) signal() {
	select {
	case b.changes <- struct{}{}:
	default:
	}
}

// harness drives one Manager over a scripted backend and a fake clock.
type harness struct {
	t    *testing.T
	m    *Manager
	b    *scriptedBackend
	clk  *fakeClock
	lk   *hostlock.Fake
	idle chan time.Time
}

const testIdentity = "net-a"

// newHarness starts a Manager over a scripted backend. configure runs before
// the worker starts, for fields the worker reads without locks.
func newHarness(t *testing.T, kind BackendKind, opts Options, configure ...func(*Manager)) *harness {
	t.Helper()
	if opts.Identity == "" {
		opts.Identity = testIdentity
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	var locker hostlock.Locker
	if kind != BackendNoop {
		locker = hostlock.NewFake()
	}
	b := newScriptedBackend()
	h := &harness{t: t, b: b, clk: newFakeClock(), idle: make(chan time.Time, 1024)}
	m := newWithBackend(opts, kind, b, locker)
	m.clock = h.clk
	m.onIdle = func(next time.Time) { h.idle <- next }
	b.identity = opts.Identity
	for _, fn := range configure {
		fn(m)
	}
	switch l := m.locker.(type) {
	case *hostlock.Fake:
		h.lk = l
	case *countingLocker:
		h.lk = l.Fake
	}
	b.locker = h.lk
	h.m = m
	m.start()
	t.Cleanup(func() { h.closeAnswering() })
	// The first idle report means the worker is blocked and ready.
	h.waitIdle()
	return h
}

// closeAnswering closes the Manager, answering its final Clear if it makes one.
func (h *harness) closeAnswering() {
	done := make(chan error, 1)
	go func() { done <- h.m.Close() }()
	for {
		select {
		case <-done:
			return
		case c := <-h.b.calls:
			c.ok(backend.Result{})
		case <-time.After(testWait):
			h.t.Error("Close did not return")
			return
		}
	}
}

// next returns the next backend call.
func (h *harness) next() *call {
	h.t.Helper()
	select {
	case c := <-h.b.calls:
		return c
	case <-time.After(testWait):
		h.t.Fatal("worker made no backend call")
		return nil
	}
}

// waitIdle returns the wake-up time the worker armed when it next blocked.
func (h *harness) waitIdle() time.Time {
	h.t.Helper()
	select {
	case next := <-h.idle:
		return next
	case <-time.After(testWait):
		h.t.Fatal("worker did not go idle")
		return time.Time{}
	}
}

// settle waits for the worker to block after the call just answered and
// asserts that it made no further call.
func (h *harness) settle() time.Time {
	h.t.Helper()
	next := h.waitIdle()
	select {
	case c := <-h.b.calls:
		h.t.Fatalf("unexpected backend call %q", c.op)
	default:
	}
	return next
}

// quiet wakes the worker and asserts it goes idle without a backend call.
// Any wake makes an idle worker re-plan and report idle again, so this proves
// nothing the test did beforehand left an attempt due.
func (h *harness) quiet() time.Time {
	h.t.Helper()
	h.m.wakeWorker()
	select {
	case next := <-h.idle:
		select {
		case c := <-h.b.calls:
			h.t.Fatalf("unexpected backend call %q", c.op)
		default:
		}
		return next
	case c := <-h.b.calls:
		h.t.Fatalf("unexpected backend call %q", c.op)
	case <-time.After(testWait):
		h.t.Fatal("worker did not go idle")
	}
	return time.Time{}
}

// unchanged asserts that Status still equals before and that the worker has
// no attempt due, the two effects a recorded goal would have. It returns the
// worker's next wake-up so a caller can check that backoff was not restarted.
func (h *harness) unchanged(before Status, msg string) time.Time {
	h.t.Helper()
	assert.Equal(h.t, before, h.m.Status(), msg)
	return h.quiet()
}

// converged answers the next call successfully and waits for the worker.
func (h *harness) converged(op string) *call {
	h.t.Helper()
	c := h.next()
	require.Equal(h.t, op, c.op)
	c.ok(backend.Result{Changed: c.attempt.NewGoal})
	h.settle()
	return c
}

// countingLocker counts TryLock calls, which the Manager makes only to take
// the identity lock, so a test can see a release and reacquire that leaves
// the lock held at every point it could look.
type countingLocker struct {
	*hostlock.Fake
	mu       sync.Mutex
	tryLocks int
}

func (l *countingLocker) TryLock(name string) (hostlock.Handle, error) {
	l.mu.Lock()
	l.tryLocks++
	l.mu.Unlock()
	return l.Fake.TryLock(name)
}

func (l *countingLocker) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tryLocks
}

func (h *harness) identityHeld() bool { return h.lk.Held(identityLockName(h.m.opts.Identity)) }

func sampleConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Nameservers:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		SearchDomains: []string{"corp.example.com."},
	}
}

func splitConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Nameservers:  []netip.Addr{netip.MustParseAddr("100.64.0.2")},
		MatchDomains: []string{"corp.example.com."},
	}
}
