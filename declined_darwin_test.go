package dnsconfig

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend/noop"
)

// withRoot answers the process root check for the duration of t.
func withRoot(t *testing.T, root bool) {
	t.Helper()
	prev := isRoot
	isRoot = func() bool { return root }
	t.Cleanup(func() { isRoot = prev })
}

// TestNew_DarwinWithoutRootDeclines checks that a non-root macOS process,
// which can write none of the store, /etc/resolver, or the lock directory,
// gets a declined Manager instead of one that retries failing attempts.
func TestNew_DarwinWithoutRootDeclines(t *testing.T) {
	withRoot(t, false)
	var logs bytes.Buffer
	m, err := New(context.Background(), Options{
		Identity:     "facade-declined",
		ForceBackend: BackendDarwin,
		Logger:       slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })

	s := m.Status()
	require.ErrorIs(t, s.LastError, ErrConfigurationDeclined, "the refusal is visible from New on")
	assert.ErrorContains(t, s.LastError, "requires root")
	assert.False(t, s.LastConvergedCleared)

	assert.Equal(t, BackendDarwin, m.kind)
	assert.Nil(t, m.locker, "a declined Manager takes no host locks")
	assert.IsType(t, &noop.Backend{}, m.backend, "the darwin backend is never built")

	err = m.Set(sampleConfig(t))
	require.ErrorIs(t, err, ErrConfigurationDeclined)
	assert.ErrorContains(t, err, "requires root")
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, BackendDarwin, e.Backend)
	s = m.Status()
	assert.Equal(t, GoalNone, s.Goal)
	assert.Same(t, err, s.LastError)

	require.NoError(t, m.Clear())
	s = waitStatus(t, m, func(s Status) bool { return s.Converged })
	assert.Equal(t, GoalClear, s.Goal)
	assert.True(t, s.LastChangedAt.IsZero(), "a declined Clear never changes the host")
	assert.ErrorIs(t, s.LastError, ErrConfigurationDeclined, "a declined Clear verified nothing")
	assert.False(t, s.LastConvergedCleared)

	require.NoError(t, m.Close())
	s = m.Status()
	assert.ErrorIs(t, s.LastError, ErrConfigurationDeclined)
	assert.ErrorContains(t, s.LastError, "requires root")
	assert.False(t, s.LastConvergedCleared)
	out := logs.String()
	assert.Equal(t, 1, strings.Count(out, "level=INFO"), out)
	assert.Contains(t, out, "DNS management declined")
	assert.NotContains(t, out, "level=WARN")
}

// TestNew_DarwinWithRootBuildsBackend pins that root keeps the live backend.
func TestNew_DarwinWithRootBuildsBackend(t *testing.T) {
	withRoot(t, true)
	m, err := New(context.Background(), Options{Identity: "facade-root", ForceBackend: BackendDarwin})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	assert.NotNil(t, m.locker)
	assert.Nil(t, m.declined)
}
