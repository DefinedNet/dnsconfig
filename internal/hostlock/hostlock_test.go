package hostlock

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileLockerExcludesSecondHolder drives the native lock: a second handle
// in the same process must see ErrHeld, Lock must wait for release, and the
// lock file must survive Unlock.
func TestFileLockerExcludesSecondHolder(t *testing.T) {
	l := &FileLocker{Dir: filepath.Join(t.TempDir(), "locks")}
	first, err := l.TryLock("identity-a")
	require.NoError(t, err)

	_, err = l.TryLock("identity-a")
	assert.ErrorIs(t, err, ErrHeld)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = l.Lock(ctx, "identity-a")
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	other, err := l.TryLock("identity-b")
	require.NoError(t, err, "distinct names do not contend")
	require.NoError(t, other.Unlock())

	type result struct {
		h   Handle
		err error
	}
	waited := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h, err := l.Lock(ctx, "identity-a")
		waited <- result{h, err}
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, first.Unlock())
	r := <-waited
	require.NoError(t, r.err, "a waiting Lock acquires once the holder releases")
	require.NoError(t, r.h.Unlock())

	again, err := l.TryLock("identity-a")
	require.NoError(t, err, "release must free the name")
	require.NoError(t, again.Unlock())
	assert.FileExists(t, filepath.Join(l.Dir, "identity-a.lock"), "Unlock must not remove the lock file")
}

func TestFileLockerRejectsUnsafeNames(t *testing.T) {
	l := &FileLocker{Dir: filepath.Join(t.TempDir(), "locks")}
	for _, name := range []string{"", "../x", "a/b", "a b"} {
		_, err := l.TryLock(name)
		assert.Error(t, err, name)
	}
}

func TestFakeReproducesContention(t *testing.T) {
	f := NewFake()
	f.HoldExternally("host")
	_, err := f.TryLock("host")
	assert.ErrorIs(t, err, ErrHeld)
	f.Release("host")
	h, err := f.TryLock("host")
	require.NoError(t, err)
	assert.True(t, f.Held("host"))
	require.NoError(t, h.Unlock())
	assert.False(t, f.Held("host"))
}
