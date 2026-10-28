package dnsconfig

import "time"

// Goal names what a Manager's worker is converging the host toward.
type Goal string

const (
	// GoalNone means neither Set nor Clear has been called.
	GoalNone Goal = ""
	// GoalSet means the worker installs and repairs Status.Desired.
	GoalSet Goal = "set"
	// GoalClear means the worker removes this identity's configuration.
	GoalClear Goal = "clear"
)

// Status is a snapshot of a Manager's goal and its worker's progress toward
// it. Reading it neither probes the OS nor waits for an in-flight converge,
// so it can lag the host by one attempt.
//
// Status has no per-request completion barrier: a converge records what it
// achieved, not which Set asked for it.
type Status struct {
	// Goal is the most recent goal the caller recorded with Set or Clear.
	Goal Goal

	// Desired is the configuration the worker converges toward when Goal is
	// GoalSet, and the zero Config otherwise. Close leaves Goal and Desired
	// as recorded.
	Desired Config

	// Converged reports that the most recent attempt at the current goal
	// passed its artifact checks and completed every owed side-effect
	// request, and no newer goal has been recorded since. Later drift is
	// found by a change signal or periodic check. Close's final cleanup,
	// when it runs, counts as an attempt: afterwards Converged is false for
	// a Set goal and reports whether that cleanup succeeded for a Clear goal.
	Converged bool

	// LastError is the failure of the most recent attempt, as an [Error] with
	// Op "Converge", or of Close, or a Set refusal that Set also returned.
	// After a Close that left a live holder's configuration in place it
	// includes [ErrManagerAlreadyRunning] with Op "Close", which Close
	// itself does not return. It is nil after a successful attempt, except
	// on a Manager that declined DNS management: from New on it holds
	// [ErrConfigurationDeclined], as Op "New" or a Set refusal, because
	// nothing on the host was checked. errors.Is and errors.As reach the
	// cause.
	// Before Close the worker retries a failed attempt with backoff; Set
	// refusals and Close's failure are not retried.
	LastError error

	// LastChangedAt is when an attempt last changed or may have changed the
	// host, including a partially failed write, or zero if none has. A change
	// after the goal had converged means something else undid this Manager's
	// configuration.
	LastChangedAt time.Time

	// LastConvergedCleared reports that the most recent successful attempt,
	// including Close's final cleanup, was a Clear. It is false before any
	// attempt succeeds and always false on a Manager that declined DNS
	// management, which removes nothing.
	LastConvergedCleared bool
}
