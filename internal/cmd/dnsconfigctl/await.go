package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/DefinedNet/dnsconfig"
)

// defaultWait bounds how long set, reset, and watch wait for the worker to
// converge. It covers several backoff steps, so a transient failure can
// recover before the command gives up.
const defaultWait = 30 * time.Second

// awaitPoll is how often the CLI rereads Status while waiting.
const awaitPoll = 50 * time.Millisecond

// statusReader is the part of *dnsconfig.Manager the wait loop needs.
type statusReader interface {
	Status() dnsconfig.Status
}

// awaitGoal waits until the Manager reports goal converged, returning the
// final Status. The library has no completion barrier, so the CLI polls.
//
// before is the Status read just before the goal was recorded. Its
// LastError is stale, so only a newer error can end the wait early. A newer
// ErrConflict or ErrManagerAlreadyRunning ends it at once: the worker would
// retry, but in the smoke harness the conflicting identity or holder does not
// leave within the bound, and the harness asserts on the refusal text. Other
// failures, such as a transient read failure or host-lock timeout, may clear
// on the worker's next retry, so they run out the bound.
func awaitGoal(m statusReader, goal dnsconfig.Goal, before dnsconfig.Status, bound time.Duration) (dnsconfig.Status, error) {
	deadline := time.Now().Add(bound)
	for {
		s := m.Status()
		if s.Goal == goal && s.Converged {
			return s, nil
		}
		fresh := s.LastError != nil && s.LastError != before.LastError
		if fresh && (errors.Is(s.LastError, dnsconfig.ErrConflict) || errors.Is(s.LastError, dnsconfig.ErrManagerAlreadyRunning)) {
			return s, s.LastError
		}
		if time.Now().After(deadline) {
			if fresh {
				return s, fmt.Errorf("not converged after %s: %w", bound, s.LastError)
			}
			return s, fmt.Errorf("not converged after %s", bound)
		}
		time.Sleep(awaitPoll)
	}
}
