// Package backendtest checks the shared converge contract of
// backend.Backend implementations using backend-specific fakes.
package backendtest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// Fixture is what a backend test hands Suite: a live backend over fakes,
// a config it accepts, and observers of the fake system.
type Fixture struct {
	// Backend is a fresh backend over fakes, with nothing installed.
	Backend backend.Backend

	// ValidConfig is a config the backend accepts.
	ValidConfig backend.Config

	// SecondConfig is another accepted config that differs from ValidConfig,
	// so a Set that replaces one with the other must write.
	SecondConfig backend.Config

	// Clean reports whether managed system DNS artifacts are absent.
	Clean func() (bool, error)

	// Snapshot returns a comparable representation of the fake system's DNS
	// state. Nil marks a backend that installs nothing.
	Snapshot func() (any, error)

	// Writes counts every host mutation the fakes observed, including cache
	// flushes and policy notifications. Nil marks a backend that installs
	// nothing, which skips the no-op check.
	Writes func() int

	// FailSideEffects, while armed, makes each owed side effect (a cache
	// flush or policy notification) fail. Nil skips the side-effect clauses.
	FailSideEffects func(fail bool)

	// FailInspection, while armed, makes each attempt fail while it inspects
	// the host, before it changes anything or reaches its side effects. Nil
	// skips the clauses that need it.
	FailInspection func(fail bool)
}

// Factory builds a fresh Fixture over fresh fakes. Suite calls it
// once per subtest so no clause observes another's mutations.
type Factory func(t *testing.T) Fixture

// Suite runs the one-shot converge contract against injected backends.
func Suite(t *testing.T, newFixture Factory) {
	t.Helper()
	ctx := context.Background()
	first := backend.Attempt{NewGoal: true}
	// retry follows an attempt that may have failed; converged follows one
	// that succeeded, as the worker marks them.
	retry := backend.Attempt{}
	converged := backend.Attempt{Converged: true}

	t.Run("RepeatSetWritesNothing", func(t *testing.T) {
		s := newFixture(t)
		if s.Writes == nil {
			t.Skip("backend installs nothing")
		}
		_, err := s.Backend.Set(ctx, s.ValidConfig, first)
		require.NoError(t, err)
		before := s.Writes()
		res, err := s.Backend.Set(ctx, s.ValidConfig, converged)
		require.NoError(t, err)
		assert.False(t, res.Changed, "a converged host has nothing to change")
		assert.False(t, res.Pending, "a converged host owes nothing")
		assert.Equal(t, before, s.Writes(),
			"our own writes wake the worker; a repeat converge that writes anything can sustain its own loop")
	})

	t.Run("ClearFreshChangesNothing", func(t *testing.T) {
		s := newFixture(t)
		res, err := s.Backend.Clear(ctx, first)
		require.NoError(t, err)
		assert.False(t, res.Changed)
		assert.False(t, res.Pending)
		assertCleanFunc(t, s.Clean, "Clear on a fresh backend must not create artifacts")
		res, err = s.Backend.Clear(ctx, converged)
		require.NoError(t, err)
		assert.False(t, res.Changed, "a second Clear finds nothing either")
	})

	t.Run("SetClearClean", func(t *testing.T) {
		s := newFixture(t)
		res, err := s.Backend.Set(ctx, s.ValidConfig, first)
		require.NoError(t, err)
		assert.False(t, res.Pending)
		if s.Snapshot != nil {
			assert.True(t, res.Changed, "the first Set installs artifacts")
		}
		res, err = s.Backend.Clear(ctx, first)
		require.NoError(t, err)
		assert.False(t, res.Pending)
		if s.Snapshot != nil {
			assert.True(t, res.Changed, "Clear removes what Set installed")
		}
		assertCleanFunc(t, s.Clean, "Clear must remove everything Set installed")
	})

	t.Run("HasArtifactsReadsOnly", func(t *testing.T) {
		s := newFixture(t)
		has, err := s.Backend.HasArtifacts(ctx)
		require.NoError(t, err)
		assert.False(t, has, "a fresh host holds nothing of this identity's")
		_, err = s.Backend.Set(ctx, s.ValidConfig, first)
		require.NoError(t, err)
		var before int
		if s.Writes != nil {
			before = s.Writes()
		}
		has, err = s.Backend.HasArtifacts(ctx)
		require.NoError(t, err)
		assert.Equal(t, s.Snapshot != nil, has, "the probe finds what Set installed")
		if s.Writes != nil {
			assert.Equal(t, before, s.Writes(), "the probe writes nothing")
		}
		_, err = s.Backend.Clear(ctx, first)
		require.NoError(t, err)
		has, err = s.Backend.HasArtifacts(ctx)
		require.NoError(t, err)
		assert.False(t, has, "Clear leaves nothing to find")
	})

	t.Run("ClosePreservesSystemState", func(t *testing.T) {
		s := newFixture(t)
		if s.Snapshot == nil {
			t.Skip("backend installs nothing")
		}
		_, err := s.Backend.Set(ctx, s.ValidConfig, first)
		require.NoError(t, err)
		before, err := s.Snapshot()
		require.NoError(t, err)
		require.NoError(t, s.Backend.Close())
		after, err := s.Snapshot()
		require.NoError(t, err)
		assert.Equal(t, before, after, "backend Close must not change system DNS state")
		require.NoError(t, s.Backend.Close(), "Close is idempotent")
	})

	t.Run("CloseClosesChanges", func(t *testing.T) {
		s := newFixture(t)
		ch := s.Backend.Changes()
		require.NoError(t, s.Backend.Close())
		if ch == nil {
			return
		}
		deadline := time.After(5 * time.Second)
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					return
				}
			case <-deadline:
				t.Fatal("Close must close the Changes channel")
			}
		}
	})

	t.Run("FailedAttemptKeepsSideEffectOwed", func(t *testing.T) {
		s := newFixture(t)
		if s.FailSideEffects == nil {
			t.Skip("fakes cannot fail side effects")
		}
		s.FailSideEffects(true)
		res, err := s.Backend.Set(ctx, s.ValidConfig, first)
		require.Error(t, err, "an attempt that leaves a side effect owed fails")
		require.True(t, res.Pending, "a failed side effect must be reported in Pending")
		s.FailSideEffects(false)
		res, err = s.Backend.Set(ctx, s.ValidConfig, retry)
		require.NoError(t, err)
		assert.False(t, res.Pending, "the next attempt completes the owed side effect")
		before := s.Writes()
		res, err = s.Backend.Set(ctx, s.ValidConfig, converged)
		require.NoError(t, err)
		assert.False(t, res.Changed)
		assert.Equal(t, before, s.Writes(), "a completed side effect is not repeated")
	})

	t.Run("ClearReportsOwedSideEffect", func(t *testing.T) {
		s := newFixture(t)
		if s.FailSideEffects == nil {
			t.Skip("fakes cannot fail side effects")
		}
		_, err := s.Backend.Set(ctx, s.ValidConfig, first)
		require.NoError(t, err)
		s.FailSideEffects(true)
		res, err := s.Backend.Clear(ctx, first)
		require.Error(t, err, "an attempt that leaves a side effect owed fails")
		require.True(t, res.Pending, "a failed side effect must be reported in Pending")
		assertCleanFunc(t, s.Clean, "artifacts are removed even when the side effect fails")
		s.FailSideEffects(false)
		res, err = s.Backend.Clear(ctx, retry)
		require.NoError(t, err)
		assert.False(t, res.Pending, "Clear completes the owed side effect after the artifacts are gone")
		assert.False(t, res.Changed, "nothing was left to remove")
	})

	// Pending describes every attempt, so a side effect owed by an earlier
	// attempt must still be reported by a later one that fails before
	// reaching it.
	t.Run("OwedSideEffectSurvivesUnrelatedFailure", func(t *testing.T) {
		s := newFixture(t)
		if s.FailSideEffects == nil || s.FailInspection == nil {
			t.Skip("fakes cannot fail side effects and inspection")
		}
		s.FailSideEffects(true)
		res, err := s.Backend.Set(ctx, s.ValidConfig, first)
		require.Error(t, err, "an attempt that leaves a side effect owed fails")
		require.True(t, res.Pending, "a failed side effect must be reported in Pending")
		s.FailSideEffects(false)
		s.FailInspection(true)
		res, err = s.Backend.Set(ctx, s.SecondConfig, first)
		require.Error(t, err, "the injected inspection failure must fail the attempt")
		// The fault fires during inspection, before the attempt arms any debt
		// of its own, so Pending here can only be the earlier attempt's.
		// Changed false is a check on that placement, not a proof by itself:
		// both backends can arm debt on a failed attempt that changed nothing.
		require.False(t, res.Changed, "the attempt failed before changing anything")
		require.True(t, res.Pending, "a failed attempt still reports the side effect an earlier one owed")
		s.FailInspection(false)
		res, err = s.Backend.Set(ctx, s.SecondConfig, retry)
		require.NoError(t, err)
		assert.False(t, res.Pending, "the next attempt completes the owed side effect")
	})

	t.Run("OwedSideEffectSurvivesUnrelatedClearFailure", func(t *testing.T) {
		s := newFixture(t)
		if s.FailSideEffects == nil || s.FailInspection == nil {
			t.Skip("fakes cannot fail side effects and inspection")
		}
		s.FailSideEffects(true)
		res, err := s.Backend.Set(ctx, s.ValidConfig, first)
		require.Error(t, err, "an attempt that leaves a side effect owed fails")
		require.True(t, res.Pending, "a failed side effect must be reported in Pending")
		s.FailSideEffects(false)
		s.FailInspection(true)
		res, err = s.Backend.Clear(ctx, first)
		require.Error(t, err, "the injected inspection failure must fail the attempt")
		require.False(t, res.Changed, "the attempt failed before changing anything")
		require.True(t, res.Pending, "a failed Clear still reports the side effect an earlier attempt owed")
		s.FailInspection(false)
		res, err = s.Backend.Clear(ctx, retry)
		require.NoError(t, err)
		assert.False(t, res.Pending, "the next attempt completes the owed side effect")
		assertCleanFunc(t, s.Clean, "the retried Clear removes everything")
	})
}

// assertCleanFunc fails the test when the backend's fake system is not pristine.
func assertCleanFunc(t *testing.T, clean func() (bool, error), msg string) {
	t.Helper()
	ok, err := clean()
	require.NoError(t, err, "Clean probe must not error")
	assert.True(t, ok, msg)
}
