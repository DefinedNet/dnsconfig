//go:build windows

package windows

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestNativePolicyWatcherLifecycle(t *testing.T) {
	watcher, err := newDefaultPolicyWatcher()
	require.NoError(t, err)
	defer watcher.Close()
	w := watcher.(*systemPolicyWatcher)
	select {
	case <-w.Done():
		t.Fatal("native watcher stopped before receiving an event")
	default:
	}
	// Signal only this watcher's private event; no machine policy is changed.
	require.NoError(t, windows.SetEvent(w.event))
	select {
	case _, ok := <-w.Events():
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("native watcher did not deliver the signalled event")
	}
	require.NoError(t, w.Close())
	select {
	case <-w.Done():
	default:
		t.Fatal("Close returned before monitoring stopped")
	}
	for range w.Events() {
	}
	assert.NoError(t, w.Err())
	assert.NoError(t, w.Close())
}
