package dnsconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/hostlock"
)

const (
	// signalDebounce coalesces a burst of change notifications into one
	// converge. The window opens at the first signal and is not extended by
	// later ones, so a steady stream cannot postpone the converge forever.
	// Our own writes produce such bursts.
	signalDebounce = 2 * time.Second

	// periodicCheckInterval bounds how long a loss the change signals miss
	// can go unrepaired while a Set goal is live.
	periodicCheckInterval = 30 * time.Second

	// backoffMin and backoffMax bound the delay before retrying a failed
	// attempt. The delay doubles per consecutive failure, so a host that
	// keeps refusing costs one attempt per backoffMax.
	backoffMin = 1 * time.Second
	backoffMax = 30 * time.Second

	// repeatChangeInterval paces repairs during a fight with another DNS
	// writer. Once a Set goal has converged, a repair that has to rewrite
	// the host means something undid our settings; signal-driven repairs
	// then wait this long before rewriting again. Failure backoff cannot
	// do this job because the rewrite succeeds, and without a floor every
	// debounce window would cost a rewrite plus its cache flush or policy
	// notification. The periodic check is unaffected and a new goal clears
	// the pacing.
	repeatChangeInterval = 10 * time.Second

	// hostLockAcquireTimeout bounds each worker attempt's wait for the host
	// lock, which serializes every dnsconfig process's conflict check and the
	// writes it admits. A holder that never releases then becomes a reported
	// failure instead of a silent stall. It sits above the longest legitimate
	// hold so ordinary contention still waits it out.
	hostLockAcquireTimeout = 30 * time.Second

	// attemptTimeout sets the cancellation deadline for the work done while
	// holding the host lock. Cancellation kills scutil and ipconfig, but
	// synchronous Windows API calls must return before the attempt can stop.
	// It stays below hostLockAcquireTimeout to allow for ordinary contention.
	attemptTimeout = 10 * time.Second
)

// hostLockName serializes conflict checks and the mutations they admit.
const hostLockName = "host"

func identityLockName(identity string) string { return "identity-" + identity }

// Manager owns one application instance's DNS configuration and resources.
// Construct one with [New], record a goal with [Manager.Set] or
// [Manager.Clear], observe progress through [Manager.Status], and call
// [Manager.Close] when done.
//
// A Manager runs one worker goroutine for goals and retries. Close joins it
// before final cleanup. All methods are safe for concurrent use. Set, Clear,
// and Status do not wait for a converge to finish.
type Manager struct {
	opts    Options
	logger  *slog.Logger
	kind    BackendKind
	backend backend.Backend
	// declined distinguishes unsupported hosts from an explicitly forced noop.
	declined bool

	// locker issues the per-identity lifetime lock and the host lock. It is
	// nil for noop, which never touches the host.
	locker hostlock.Locker
	// lifetime is held from the first attempt at a goal until a Clear
	// converges or Close finishes. Only the worker touches it while running;
	// Close takes it over after joining the worker.
	lifetime hostlock.Handle

	clock           clock
	hostLockTimeout time.Duration
	attemptTimeout  time.Duration
	// onIdle, when set by tests, observes the worker's next wake-up just
	// before it blocks. A zero time means no timer is armed.
	onIdle func(next time.Time)

	wake      chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once

	// mu guards st. The worker holds it only for bookkeeping, never across a
	// backend call, so Status and the goal setters never wait for a converge.
	mu sync.Mutex
	st workerState
}

// workerState is the worker's bookkeeping. Fields are guarded by Manager.mu.
type workerState struct {
	goal    Goal
	desired Config
	// seq identifies the current goal so a finished attempt can tell
	// whether a newer goal replaced it while it ran.
	seq     uint64
	newGoal bool
	// goalConverged reports that an attempt at the current goal has
	// succeeded, so a later change to the host undid ours rather than
	// completing a first install.
	goalConverged bool

	attempts int
	backoff  time.Duration
	// failing and failText record the last failure logged at Warn. A retry
	// whose backend error has the same text logs at Debug, so error text
	// must carry no per-attempt detail.
	failing  bool
	failText string
	// retryAt is the backoff deadline; zero when not backing off.
	retryAt time.Time
	// refused reports that the attempt behind retryAt wrote no artifact, so
	// a change signal during that backoff cannot echo an artifact write of
	// ours and may mean the condition that refused us is gone. A completed
	// side effect can echo once; it is not repeated, so that ends there.
	refused bool
	// signalAt is when a debounced change signal comes due; zero when none.
	signalAt   time.Time
	pacedUntil time.Time
	periodicAt time.Time

	converged bool
	lastErr   error

	lastChangedAt        time.Time
	lastConvergedCleared bool

	closed bool
}

// attemptJob is one converge the worker has committed to, captured under mu.
type attemptJob struct {
	goal    Goal
	cfg     Config
	seq     uint64
	attempt backend.Attempt
	trigger string
}

// New constructs a Manager and starts its worker without applying or
// reverting DNS configuration. It validates opts, selects the native backend
// unless ForceBackend is set, and initializes that backend. ctx bounds
// construction only; Close uses ShutdownTimeout, or [DefaultShutdownTimeout]
// when it is zero.
//
// Invalid Options are returned as-is. Construction failures are wrapped in
// *Error, with ErrInvalidOptions for a backend absent on this OS. No backend
// touches the host at construction or needs Options.InterfaceName; Windows
// checks it at Set.
func New(ctx context.Context, opts Options) (*Manager, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}

	kind := opts.ForceBackend
	if kind == BackendAuto {
		kind = Detect()
	}

	b, err := newBackend(ctx, kind, opts)
	if err != nil {
		return nil, &Error{Op: "New", Backend: kind, Err: err}
	}

	// noop never touches the host, so it takes no locks.
	var locker hostlock.Locker
	if kind != BackendNoop {
		locker = hostlock.System()
	}
	m := newWithBackend(opts, kind, b, locker)
	m.start()
	return m, nil
}

// newWithBackend builds an unstarted Manager around an injected backend and
// locker. opts.Logger must be non-nil. Tests replace the clock or hooks before
// calling start.
func newWithBackend(opts Options, kind BackendKind, b backend.Backend, locker hostlock.Locker) *Manager {
	if opts.ShutdownTimeout == 0 {
		opts.ShutdownTimeout = DefaultShutdownTimeout
	}
	return &Manager{
		opts:            opts,
		logger:          opts.Logger,
		kind:            kind,
		backend:         b,
		declined:        kind == BackendNoop && opts.ForceBackend != BackendNoop,
		locker:          locker,
		clock:           realClock{},
		hostLockTimeout: hostLockAcquireTimeout,
		attemptTimeout:  attemptTimeout,
		wake:            make(chan struct{}, 1),
		done:            make(chan struct{}),
	}
}

// start launches the worker. Close joins it.
func (m *Manager) start() {
	m.ctx, m.cancel = context.WithCancel(context.Background())
	go m.run()
}

// wrapSentinel preserves the public classification and underlying cause.
func wrapSentinel(sentinel, err error) error {
	return fmt.Errorf("%w: %w", sentinel, err)
}

// Set records cfg as this Manager's goal and returns without waiting for the
// host to change. The worker converges toward it, retries failures, and
// repairs drift until another goal replaces it or Close. Observe progress
// through [Manager.Status]; Set provides no completion barrier. Nameserver
// ordering, split routing, and search-domain behavior are defined by [Config].
//
// Set returns only failures that retrying cannot fix. [Config.Validate]
// errors, including [ErrEmptyConfig] for a zero Config, and a config that
// exceeds a limit of the platform's DNS mechanism, judged from the Config
// alone, are returned directly
// without an [Error] wrapper. The other refusals record no goal:
// [ErrClosed] after Close, [ErrConfigurationDeclined] when
// detection selected the no-op backend, and [ErrInterfaceRequired] on Windows
// without Options.InterfaceName. The last two are also recorded in
// Status.LastError.
//
// Everything the host decides is reported through Status.LastError and
// retried with backoff, including [ErrConflict] and
// [ErrManagerAlreadyRunning]. A failed attempt does not roll back what it
// wrote, so the host can hold parts of the previous and new configurations
// until an attempt succeeds.
//
// A cfg [Config.Equal] to the current goal is a no-op: it neither restarts
// backoff nor starts an attempt.
func (m *Manager) Set(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg = cfg.canonical()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.closed {
		return &Error{Op: "Set", Backend: m.kind, Err: ErrClosed}
	}
	if m.declined {
		return m.refuseSetLocked(ErrConfigurationDeclined)
	}
	// Recovery records identify the adapter for Clear, but a Set has no
	// adapter to write without the caller naming one.
	if m.kind == BackendWindows && m.opts.InterfaceName == "" {
		return m.refuseSetLocked(ErrInterfaceRequired)
	}
	if err := m.backend.ValidateConfig(toBackendConfig(cfg)); err != nil {
		return err
	}
	if m.st.goal == GoalSet && m.st.desired.Equal(cfg) {
		return nil
	}
	m.newGoalLocked(GoalSet, cfg)
	m.wakeWorker()
	return nil
}

// refuseSetLocked records and returns a terminal Set refusal. Caller holds mu.
func (m *Manager) refuseSetLocked(cause error) error {
	err := &Error{Op: "Set", Backend: m.kind, Err: cause}
	m.st.lastErr = err
	return err
}

// Clear records removal of this identity's DNS configuration as the goal and
// returns without waiting. The worker removes discoverable artifacts,
// including a crashed predecessor's, and completes owed cache flushes,
// Windows adapter reloads, and policy notifications, retrying with backoff
// until an attempt succeeds, which leaves nothing pending. Once the Clear
// converges, the worker releases the identity lock so another Manager can use
// the identity; Status.Goal is [GoalClear] and Status.Converged is true.
//
// macOS discovers prefixed State keys and owned resolver and staging files.
// Windows discovers NRPT records naming the controlled adapter's GUID, so
// recovery does not need InterfaceName or a saved snapshot, and clears that
// adapter's DNS values rather than restoring older ones. Discovering nothing
// attributable is a successful Clear, so a setting whose ownership evidence
// was lost stays in place.
//
// Clear returns [ErrClosed] after Close and otherwise nil. Calling it while
// Clear is already the goal is a no-op.
func (m *Manager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.closed {
		return &Error{Op: "Clear", Backend: m.kind, Err: ErrClosed}
	}
	if m.st.goal == GoalClear {
		return nil
	}
	m.newGoalLocked(GoalClear, Config{})
	m.wakeWorker()
	return nil
}

// newGoalLocked replaces the goal and restarts the retry policy for it.
// Caller holds mu.
func (m *Manager) newGoalLocked(goal Goal, cfg Config) {
	m.st.goal = goal
	m.st.desired = cfg
	m.st.seq++
	m.st.newGoal = true
	m.st.goalConverged = false
	m.st.converged = false
	m.st.attempts = 0
	m.st.backoff = 0
	m.st.retryAt = time.Time{}
	m.st.refused = false
	m.st.pacedUntil = time.Time{}
	m.st.failing, m.st.failText = false, ""
}

// wakeWorker nudges the worker without blocking; one pending wake suffices
// because the worker rereads all state when it runs.
func (m *Manager) wakeWorker() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// run is the worker loop. Each pass either converges once or blocks until
// the next input: a new goal, a change signal, a timer, or Close.
func (m *Manager) run() {
	defer close(m.done)
	for {
		if m.ctx.Err() != nil {
			return
		}
		now := m.clock.Now()
		m.mu.Lock()
		trigger, next := m.st.plan(now)
		var job attemptJob
		if trigger != "" {
			job = m.st.begin(trigger)
		}
		m.mu.Unlock()
		if trigger != "" {
			m.converge(job)
			continue
		}

		changes := m.backend.Changes()
		var timer clockTimer
		var timerC <-chan time.Time
		if !next.IsZero() {
			timer = m.clock.NewTimer(next.Sub(now))
			timerC = timer.C()
		}
		if m.onIdle != nil {
			m.onIdle(next)
		}
		select {
		case <-m.ctx.Done():
		case <-m.wake:
		case <-changes:
			m.noteSignal()
		case <-timerC:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// plan decides whether an attempt is due at now and, if not, when the worker
// must next wake. A new goal runs at once; a pending retry deadline
// suppresses period-driven converges, and
// signal-driven ones unless the attempt was refused; otherwise a
// debounced signal or the periodic check triggers one.
func (s *workerState) plan(now time.Time) (trigger string, next time.Time) {
	if s.goal == GoalNone {
		return "", time.Time{}
	}
	if s.newGoal {
		return "goal", time.Time{}
	}
	if !s.retryAt.IsZero() {
		if !now.Before(s.retryAt) {
			return "retry", time.Time{}
		}
		next = s.retryAt
		if s.refused && !s.signalAt.IsZero() {
			// Pacing never reaches a retry: a signal waits out pacedUntil,
			// the periodic check lands after it, and a new goal clears it,
			// so the failed attempt behind retryAt began after pacing ended.
			if !now.Before(s.signalAt) {
				return "signal", time.Time{}
			}
			if s.signalAt.Before(next) {
				next = s.signalAt
			}
		}
		return "", next
	}
	if !s.signalAt.IsZero() {
		due := s.signalAt
		if s.pacedUntil.After(due) {
			due = s.pacedUntil
		}
		if !now.Before(due) {
			return "signal", time.Time{}
		}
		next = due
	}
	// A converged Clear has nothing to watch, so the worker idles.
	if s.goal == GoalSet {
		if !now.Before(s.periodicAt) {
			return "periodic", time.Time{}
		}
		if next.IsZero() || s.periodicAt.Before(next) {
			next = s.periodicAt
		}
	}
	return "", next
}

// begin captures the attempt the worker is committing to. Any queued signal
// is satisfied by it, because every attempt rereads all owned artifacts.
func (s *workerState) begin(trigger string) attemptJob {
	job := attemptJob{
		goal:    s.goal,
		cfg:     cloneConfig(s.desired),
		seq:     s.seq,
		attempt: backend.Attempt{NewGoal: s.newGoal, Converged: s.goalConverged},
		trigger: trigger,
	}
	s.newGoal = false
	s.retryAt = time.Time{}
	s.signalAt = time.Time{}
	return job
}

// noteSignal opens a debounce window for a change signal. Only a live Set
// goal has anything to repair; a Clear's owed side effects ride its failure
// backoff.
func (m *Manager) noteSignal() {
	now := m.clock.Now()
	m.mu.Lock()
	opened := m.st.goal == GoalSet && m.st.signalAt.IsZero()
	if opened {
		m.st.signalAt = now.Add(signalDebounce)
	}
	m.mu.Unlock()
	m.logger.Debug("dnsconfig: change signal", slog.Bool("opened", opened))
}

// converge runs one attempt and records its outcome. An attempt cut short by
// Close is not recorded: Close's own cleanup describes the host afterwards.
func (m *Manager) converge(job attemptJob) {
	start := m.clock.Now()
	res, err := m.attempt(m.ctx, job)
	if m.ctx.Err() != nil {
		return
	}
	now := m.clock.Now()
	m.logger.Debug("dnsconfig: attempt finished",
		slog.String("trigger", job.trigger),
		slog.Duration("duration", now.Sub(start)),
		slog.Bool("changed", res.Changed),
		slog.Bool("failed", err != nil))
	m.mu.Lock()
	release := m.finishLocked(job, res, err, now)
	m.mu.Unlock()
	if release {
		if rerr := m.releaseLifetime(); rerr != nil {
			m.logger.Warn("dnsconfig: releasing identity lock after Clear failed", slog.Any("error", rerr))
		}
	}
}

// attempt takes the identity lock if needed and runs one backend Set or
// Clear under the host lock. A lock failure returns a zero Result.
func (m *Manager) attempt(ctx context.Context, job attemptJob) (res backend.Result, err error) {
	if lerr := m.acquireLifetime(); lerr != nil {
		return res, lerr
	}
	var berr error
	lerr := m.withHostLock(ctx, m.hostLockTimeout, func() {
		ctx, cancel := context.WithTimeout(ctx, m.attemptTimeout)
		defer cancel()
		switch job.goal {
		case GoalSet:
			res, berr = m.backend.Set(ctx, toBackendConfig(job.cfg), job.attempt)
		case GoalClear:
			res, berr = m.backend.Clear(ctx, job.attempt)
		case GoalNone:
			// The worker schedules no attempt without a goal.
		}
	})
	if lerr != nil {
		return res, lerr
	}
	return res, berr
}

// finishLocked records an attempt's outcome and schedules the next one. It
// reports whether the worker should release the identity lock because the
// current Clear goal converged. Caller holds mu.
//
// A result from an attempt whose goal was replaced while it ran still
// updates the host observations (LastError, LastChangedAt,
// LastConvergedCleared) but leaves the retry policy and Converged to the
// newer goal.
func (m *Manager) finishLocked(job attemptJob, res backend.Result, err error, now time.Time) (release bool) {
	s := &m.st
	current := job.seq == s.seq
	s.periodicAt = now.Add(periodicCheckInterval)
	if res.Changed {
		s.lastChangedAt = now
	}
	if err != nil {
		// A failed attempt that wrote no artifact is a refusal.
		refused := !res.Changed
		s.lastErr = m.convergeErr(err)
		if current {
			s.converged = false
			s.attempts++
			if s.backoff == 0 {
				s.backoff = backoffMin
			} else {
				s.backoff = min(2*s.backoff, backoffMax)
			}
			s.retryAt = now.Add(s.backoff)
			s.refused = refused
			level := slog.LevelWarn
			if text := err.Error(); s.failing && text == s.failText {
				level = slog.LevelDebug
			} else {
				s.failing, s.failText = true, text
			}
			if m.logger.Enabled(context.Background(), level) {
				m.logger.Log(context.Background(), level, "dnsconfig: converge failed",
					slog.String("goal", string(job.goal)),
					slog.String("trigger", job.trigger),
					slog.Int("attempts", s.attempts),
					slog.Duration("retryIn", s.backoff),
					slog.Bool("changed", res.Changed),
					slog.Bool("pending", res.Pending),
					slog.Any("error", err))
			}
		}
		return false
	}

	s.lastErr = nil
	s.lastConvergedCleared = job.goal == GoalClear
	if res.Changed && job.attempt.Converged {
		// Changing the host after the goal had converged means something
		// undid our artifacts; keep a record at Info because it may be a
		// writer fight. A retry that finishes the first install is not one.
		m.logger.Info("dnsconfig: repeat converge changed the host",
			slog.String("goal", string(job.goal)),
			slog.String("trigger", job.trigger))
		if current && job.goal == GoalSet {
			s.pacedUntil = now.Add(repeatChangeInterval)
		}
	}
	if !current {
		return false
	}
	if s.failing {
		m.logger.Info("dnsconfig: converge recovered", slog.String("goal", string(job.goal)))
		s.failing, s.failText = false, ""
	}
	s.attempts = 0
	s.backoff = 0
	s.refused = false
	s.goalConverged = true
	s.converged = true
	return job.goal == GoalClear
}

// convergeErr wraps a worker attempt's failure for Status.
func (m *Manager) convergeErr(err error) error {
	return &Error{Op: "Converge", Backend: m.kind, Err: err}
}

// withHostLock runs fn under the host lock, waiting at most wait for it when
// wait is positive. A release failure is logged, not returned: Unlock closes
// the lock file regardless, which releases the OS lock, and fn's result is
// what describes the host.
func (m *Manager) withHostLock(ctx context.Context, wait time.Duration, fn func()) error {
	if m.locker == nil {
		fn()
		return nil
	}
	lockCtx := ctx
	if wait > 0 {
		var cancel context.CancelFunc
		lockCtx, cancel = context.WithTimeout(ctx, wait)
		defer cancel()
	}
	h, err := m.locker.Lock(lockCtx, hostLockName)
	if err != nil {
		return fmt.Errorf("acquire host lock: %w", err)
	}
	fn()
	if uerr := h.Unlock(); uerr != nil {
		m.logger.Warn("dnsconfig: releasing host lock failed", slog.Any("error", uerr))
	}
	return nil
}

// acquireLifetime takes the identity lock without waiting, unless this
// Manager already holds it. Another live holder is reported as
// [ErrManagerAlreadyRunning]. The no-op backend has no locker and needs none.
// Only the worker and, after joining it, Close call this.
func (m *Manager) acquireLifetime() error {
	if m.locker == nil || m.lifetime != nil {
		return nil
	}
	h, err := m.locker.TryLock(identityLockName(m.opts.Identity))
	if errors.Is(err, hostlock.ErrHeld) {
		return ErrManagerAlreadyRunning
	}
	if err != nil {
		return fmt.Errorf("acquire identity lock: %w", err)
	}
	m.lifetime = h
	return nil
}

// owesCleanupLocked reports that the recorded goal still needs cleanup on
// Close: any Set, converged or not, and a Clear that has not converged. A
// converged Clear already released the identity and leaves nothing to own.
// Caller holds mu.
func (m *Manager) owesCleanupLocked() bool {
	if m.st.goal == GoalClear && m.st.goalConverged {
		return false
	}
	return m.st.goal != GoalNone
}

// releaseLifetime releases the identity lock if held. It is called only by
// the worker, or by Close after the worker has exited.
func (m *Manager) releaseLifetime() error {
	if m.lifetime == nil {
		return nil
	}
	h := m.lifetime
	m.lifetime = nil
	if err := h.Unlock(); err != nil {
		return fmt.Errorf("release identity lock: %w", err)
	}
	return nil
}

// Close stops the worker, removes this identity's DNS configuration, and
// releases backend resources and the identity lock. Cleanup, teardown, and
// lock failures are joined in an [Error] with Op "Close" and recorded in
// Status.LastError. Cleanup that still owes a cache flush, adapter reload, or
// policy notification is a failure too.
//
// Close cancels an in-flight attempt and waits for the worker to exit. If a
// goal was recorded and no Clear converged since, Close then makes one final
// Clear under the host lock. The worker holds the identity lock from its
// first attempt at a goal until a Clear converges; when it does not hold the
// lock, because it never attempted the goal or every attempt failed to take
// it, Close takes the lock itself without waiting. While another live
// Manager holds the identity, Close changes nothing and does not report it:
// that holder's configuration is meant to stay, so no recovery is needed.
// Teardown failures are still returned. Status.LastError then includes
// [ErrManagerAlreadyRunning] and Converged stays false. Like
// [Manager.Clear], the cleanup removes every artifact attributable to the
// identity. A Manager that was never given a goal changes nothing.
//
// Close is one-shot: the first call returns any cleanup error; later calls do
// nothing and return nil. [Manager.Status] remains callable. Recover a failed
// cleanup with a fresh [New] followed by Clear. The identity lock is released
// after backend teardown even when cleanup fails, so that Manager can recover.
//
// Options.ShutdownTimeout, or [DefaultShutdownTimeout] when it is zero, sets
// the cancellation deadline for the host-wide lock wait and final cleanup
// together. Lock waits and subprocesses observe cancellation. Windows cleanup
// checks cancellation between operations, but cannot interrupt a synchronous
// API call. It finishes the empty-container check after deleting policy rules
// and requests any owed policy notification even after cancellation.
// Close keeps the locks until cleanup returns. The deadline does not bound
// waiting for the canceled worker to return or resource teardown. Keep the
// resolver and its network path available until Close returns. The package
// documentation describes what a nil error means on Windows, where consumers
// are expected to run as LocalSystem.
func (m *Manager) Close() error {
	var err error
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.st.closed = true
		m.mu.Unlock()
		m.cancel()
		<-m.done

		// The worker has exited, so lifetime belongs to Close now. A recorded
		// goal the worker never got to is still a request for this identity's
		// cleanup, so Close takes the identity for it; a live holder means
		// the artifacts are someone else's to keep.
		m.mu.Lock()
		owed := m.owesCleanupLocked()
		m.mu.Unlock()
		var cleanupResult backend.Result
		var cleanupErr error
		cleanup := m.lifetime != nil
		if !cleanup && owed {
			cleanupErr = m.acquireLifetime()
			cleanup = cleanupErr == nil
		}
		if cleanup {
			cleanupResult, cleanupErr = m.finalClear()
		}
		// A live holder's configuration is its own, so leaving it is not a
		// failure of this Close. Status still records it: Converged stays
		// false and LastError says why.
		held := errors.Is(cleanupErr, ErrManagerAlreadyRunning)
		switch {
		case held:
			m.logger.Info("dnsconfig: close left the identity to its live holder",
				slog.String("backend", string(m.kind)))
		case cleanupErr != nil:
			m.logger.Warn("dnsconfig: cleanup on close failed",
				slog.String("backend", string(m.kind)),
				slog.Any("error", cleanupErr))
		}
		closeErr := m.backend.Close()
		// Release after the backend stops, even when cleanup failed: a closed
		// Manager cannot retry, so holding on would only block the fresh
		// Manager that recovers.
		lockErr := m.releaseLifetime()

		now := m.clock.Now()
		m.mu.Lock()
		defer m.mu.Unlock()
		if cleanup {
			if cleanupResult.Changed {
				m.st.lastChangedAt = now
			}
			// The final Clear is the last attempt to touch the host: it undoes
			// a Set goal and completes a Clear goal.
			m.st.converged = m.st.goal == GoalClear && cleanupErr == nil
			if cleanupErr == nil {
				m.st.lastConvergedCleared = true
			}
		}
		// Status gets every cause so the held identity stays visible beside a
		// teardown failure; the return value leaves the held identity out.
		cause := errors.Join(cleanupErr, closeErr, lockErr)
		switch {
		case cause != nil:
			e := &Error{Op: "Close", Backend: m.kind, Err: cause}
			m.st.lastErr = e
			switch returned := errors.Join(closeErr, lockErr); {
			case !held:
				err = e
			case returned != nil:
				err = &Error{Op: "Close", Backend: m.kind, Err: returned}
			}
		case cleanup:
			m.st.lastErr = nil
		}
	})
	return err
}

// finalClear shares one cancellation deadline between the host-lock wait and
// Clear. The lock stays held until the backend returns, even past the deadline,
// so unfinished native calls cannot race a successor's cleanup.
func (m *Manager) finalClear() (res backend.Result, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.opts.ShutdownTimeout)
	defer cancel()
	var cerr error
	lerr := m.withHostLock(ctx, 0, func() {
		res, cerr = m.backend.Clear(ctx, backend.Attempt{Final: true})
	})
	if lerr != nil {
		return res, lerr
	}
	return res, cerr
}

// Status returns a snapshot of the Manager's goal and the worker's progress
// toward it. It never waits for an in-flight converge and never probes the
// OS. The returned value is a copy.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{
		Goal:                 m.st.goal,
		Converged:            m.st.converged,
		LastError:            m.st.lastErr,
		LastChangedAt:        m.st.lastChangedAt,
		LastConvergedCleared: m.st.lastConvergedCleared,
	}
	if m.st.goal == GoalSet {
		s.Desired = cloneConfig(m.st.desired)
	}
	return s
}

// toBackendConfig normalizes mapped IPv4 addresses for OS address-family
// handling, drops the trailing dot that no OS mechanism writes, and copies
// slices so caller mutations cannot alter retained state. c must be canonical.
func toBackendConfig(c Config) backend.Config {
	var ns []netip.Addr
	if len(c.Nameservers) > 0 {
		ns = make([]netip.Addr, len(c.Nameservers))
		for i, a := range c.Nameservers {
			ns[i] = a.Unmap()
		}
	}
	return backend.Config{
		Nameservers:   ns,
		SearchDomains: trimTrailingDots(c.SearchDomains),
		MatchDomains:  trimTrailingDots(c.MatchDomains),
	}
}

func trimTrailingDots(domains []string) []string {
	if domains == nil {
		return nil
	}
	out := make([]string, len(domains))
	for i, d := range domains {
		out[i] = strings.TrimSuffix(d, ".")
	}
	return out
}

// cloneConfig copies c's slices so retained goals and Status snapshots never
// alias caller or worker memory.
func cloneConfig(c Config) Config {
	return Config{
		Nameservers:   slices.Clone(c.Nameservers),
		SearchDomains: slices.Clone(c.SearchDomains),
		MatchDomains:  slices.Clone(c.MatchDomains),
	}
}
