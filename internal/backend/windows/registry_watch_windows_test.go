//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TestNativeRegistryWatcherLifecycle registers without writing to the
// registry: an absent key falls back to its floor, and a signal on the
// watcher's private event is re-armed and delivered.
func TestNativeRegistryWatcherLifecycle(t *testing.T) {
	watcher, err := newDefaultRegistryWatcher([]RegistryWatchKey{
		{Path: `SOFTWARE\dnsconfig-watch-test-absent\child`, Floor: `SOFTWARE`},
		{Path: dnscacheParameters, Floor: dnscacheParameters},
	})
	require.NoError(t, err)
	defer watcher.Close()
	w := watcher.(*systemRegistryWatcher)
	require.NoError(t, windows.SetEvent(w.slots[0].event))
	select {
	case _, ok := <-w.Events():
		require.True(t, ok)
	case <-time.After(5 * time.Second):
		t.Fatal("native registry watcher did not deliver the signalled event")
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

func TestNativeRegistryWatcherRefusesAbsentFloor(t *testing.T) {
	path := `SOFTWARE\dnsconfig-watch-test-absent`
	_, err := newDefaultRegistryWatcher([]RegistryWatchKey{{Path: path, Floor: path}})
	require.Error(t, err)
}

// TestNativeRegistryWatcherDeliversOneEventPerChange writes under a private
// key: each change, and a spurious wake, yields one event and then silence.
// Re-arming must not signal its own event, or one change becomes a stream.
func TestNativeRegistryWatcherDeliversOneEventPerChange(t *testing.T) {
	base := fmt.Sprintf(`SOFTWARE\dnsconfig-watch-test-%d`, os.Getpid())
	child := base + `\child`
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, base, registry.ALL_ACCESS)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("writing HKLM requires an elevated test process")
	}
	require.NoError(t, err)
	require.NoError(t, k.Close())
	t.Cleanup(func() {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, child)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, base)
	})

	watcher, err := newDefaultRegistryWatcher([]RegistryWatchKey{{Path: child, Floor: base}})
	require.NoError(t, err)
	defer watcher.Close()
	w := watcher.(*systemRegistryWatcher)

	expectOne := func(step string) {
		t.Helper()
		select {
		case _, ok := <-w.Events():
			// Err blocks until the watcher stops, so read it only once it has.
			if !ok {
				t.Fatalf("%s: watcher stopped: %v", step, w.Err())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: no event", step)
		}
		select {
		case <-w.Events():
			t.Fatalf("%s: re-arming raised another event", step)
		case <-time.After(2 * time.Second):
		}
	}

	// A wake without a change leaves the registration pending; closing that
	// key to re-arm would signal the event again.
	require.NoError(t, windows.SetEvent(w.slots[0].event))
	expectOne("spurious wake")

	ck, _, err := registry.CreateKey(registry.LOCAL_MACHINE, child, registry.ALL_ACCESS)
	require.NoError(t, err)
	expectOne("create child")

	require.NoError(t, ck.SetStringValue("probe", "1"))
	expectOne("set value")
	require.NoError(t, ck.Close())

	require.NoError(t, registry.DeleteKey(registry.LOCAL_MACHINE, child))
	expectOne("delete child")

	require.NoError(t, w.Close())
	assert.NoError(t, w.Err())
}
