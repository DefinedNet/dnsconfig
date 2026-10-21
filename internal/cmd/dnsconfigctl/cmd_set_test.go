package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig"
)

// scriptedStatus returns each Status in turn, then repeats the last.
type scriptedStatus struct {
	mu    sync.Mutex
	steps []dnsconfig.Status
}

func (s *scriptedStatus) Status() dnsconfig.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.steps[0]
	if len(s.steps) > 1 {
		s.steps = s.steps[1:]
	}
	return st
}

func TestAwaitGoal(t *testing.T) {
	stale := &dnsconfig.Error{Op: "Converge", Err: dnsconfig.ErrConflict}
	conflict := &dnsconfig.Error{Op: "Converge", Err: dnsconfig.ErrConflict}
	held := &dnsconfig.Error{Op: "Converge", Err: dnsconfig.ErrManagerAlreadyRunning}
	heldSet := &dnsconfig.Error{Op: "Converge", Err: dnsconfig.ErrManagerAlreadyRunning}
	rejected := &dnsconfig.Error{Op: "Converge", Err: errors.New("scutil read failed")}
	transient := &dnsconfig.Error{Op: "Converge", Err: errors.New("verification failed")}
	for _, tc := range []struct {
		name    string
		goal    dnsconfig.Goal
		before  dnsconfig.Status
		steps   []dnsconfig.Status
		wantErr error
		// timedOut reports that the wait must end at the bound, not early.
		timedOut bool
	}{
		{
			name:  "converges after a transient failure",
			goal:  dnsconfig.GoalSet,
			steps: []dnsconfig.Status{{Goal: dnsconfig.GoalSet}, {Goal: dnsconfig.GoalSet, LastError: transient}, {Goal: dnsconfig.GoalSet, Converged: true}},
		},
		{
			name:  "a transient refusal waits for the retry",
			goal:  dnsconfig.GoalSet,
			steps: []dnsconfig.Status{{Goal: dnsconfig.GoalSet, LastError: rejected}, {Goal: dnsconfig.GoalSet, LastError: rejected}, {Goal: dnsconfig.GoalSet, Converged: true}},
		},
		{
			name:     "a transient refusal that persists runs out the bound",
			goal:     dnsconfig.GoalSet,
			steps:    []dnsconfig.Status{{Goal: dnsconfig.GoalSet, LastError: rejected}},
			wantErr:  rejected,
			timedOut: true,
		},
		{
			name:    "a held identity ends a Set wait",
			goal:    dnsconfig.GoalSet,
			steps:   []dnsconfig.Status{{Goal: dnsconfig.GoalSet, LastError: heldSet}},
			wantErr: dnsconfig.ErrManagerAlreadyRunning,
		},
		{
			name:    "a fresh conflict ends the wait",
			goal:    dnsconfig.GoalSet,
			steps:   []dnsconfig.Status{{Goal: dnsconfig.GoalSet, LastError: conflict}},
			wantErr: dnsconfig.ErrConflict,
		},
		{
			name:    "a held identity ends a Clear wait",
			goal:    dnsconfig.GoalClear,
			steps:   []dnsconfig.Status{{Goal: dnsconfig.GoalClear, LastError: held}},
			wantErr: dnsconfig.ErrManagerAlreadyRunning,
		},
		{
			name:   "a stale refusal from the previous goal does not",
			goal:   dnsconfig.GoalClear,
			before: dnsconfig.Status{LastError: stale},
			steps:  []dnsconfig.Status{{Goal: dnsconfig.GoalClear, LastError: stale}, {Goal: dnsconfig.GoalClear, Converged: true}},
		},
		{
			name:     "the bound reports the last error",
			goal:     dnsconfig.GoalSet,
			steps:    []dnsconfig.Status{{Goal: dnsconfig.GoalSet, LastError: transient}},
			wantErr:  transient,
			timedOut: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := awaitGoal(&scriptedStatus{steps: tc.steps}, tc.goal, tc.before, 200*time.Millisecond)
			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.True(t, s.Converged)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			if tc.timedOut {
				assert.Contains(t, err.Error(), "not converged after")
			} else {
				assert.NotContains(t, err.Error(), "not converged after")
			}
		})
	}
}

func TestSetDetachConflictsWithCloseImmediately(t *testing.T) {
	res := runCLI(t, "-backend", "noop", "set", "--ns", "1.2.3.4", "--detach", "--close-immediately")
	assert.Equal(t, exitUsage, res.code)
	assert.Contains(t, res.stderr, "cannot be combined")
}

func TestSetCloseImmediatelyNoop(t *testing.T) {
	res := runCLI(t, "-backend", "noop", "set", "--ns", "1.2.3.4", "--close-immediately")
	require.Equal(t, exitOK, res.code, "%s", res.stderr)
	assert.Equal(t, "set OK\nclose OK\n", res.stdout)
}
