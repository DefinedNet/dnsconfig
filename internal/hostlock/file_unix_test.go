//go:build !windows

package hostlock

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	return info.Mode().Perm()
}

func TestLockerCreatesPrivateObjects(t *testing.T) {
	l := &FileLocker{Dir: filepath.Join(t.TempDir(), "locks")}
	h, err := l.TryLock("host")
	require.NoError(t, err)
	require.NoError(t, h.Unlock())
	assert.Equal(t, os.FileMode(dirMode), mode(t, l.Dir))
	assert.Equal(t, os.FileMode(fileMode), mode(t, filepath.Join(l.Dir, "host.lock")))
}

// TestLockerRestrictsExistingObjects covers a directory and lock file left
// world-readable, which another account could open and hold.
func TestLockerRestrictsExistingObjects(t *testing.T) {
	l := &FileLocker{Dir: filepath.Join(t.TempDir(), "locks")}
	require.NoError(t, os.Mkdir(l.Dir, 0o755))
	require.NoError(t, os.Chmod(l.Dir, 0o755))
	path := filepath.Join(l.Dir, "host.lock")
	require.NoError(t, os.WriteFile(path, nil, 0o644))
	require.NoError(t, os.Chmod(path, 0o644))

	h, err := l.TryLock("host")
	require.NoError(t, err)
	require.NoError(t, h.Unlock())
	assert.Equal(t, os.FileMode(dirMode), mode(t, l.Dir))
	assert.Equal(t, os.FileMode(fileMode), mode(t, path))
}

// TestLockerRefusesRedirectedObjects covers links that would move the lock
// onto an object outside the directory.
func TestLockerRefusesRedirectedObjects(t *testing.T) {
	t.Run("directory symlink", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		require.NoError(t, os.Mkdir(target, 0o755))
		link := filepath.Join(parent, "locks")
		require.NoError(t, os.Symlink(target, link))
		_, err := (&FileLocker{Dir: link}).TryLock("host")
		assert.ErrorContains(t, err, "not a directory")
		assert.NoFileExists(t, filepath.Join(target, "host.lock"), "nothing is created through the symlink")
		assert.Equal(t, os.FileMode(0o755), mode(t, target), "the target keeps its mode")
	})

	t.Run("lock file symlink", func(t *testing.T) {
		parent := t.TempDir()
		l := &FileLocker{Dir: filepath.Join(parent, "locks")}
		h, err := l.TryLock("host")
		require.NoError(t, err)
		require.NoError(t, h.Unlock())
		outside := filepath.Join(parent, "outside")
		require.NoError(t, os.WriteFile(outside, nil, 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(l.Dir, "linked.lock")))
		_, err = l.TryLock("linked")
		assert.ErrorContains(t, err, "symlink")
	})

	t.Run("lock file hard link", func(t *testing.T) {
		parent := t.TempDir()
		l := &FileLocker{Dir: filepath.Join(parent, "locks")}
		h, err := l.TryLock("host")
		require.NoError(t, err)
		require.NoError(t, h.Unlock())
		outside := filepath.Join(parent, "outside")
		require.NoError(t, os.WriteFile(outside, nil, 0o644))
		require.NoError(t, os.Link(outside, filepath.Join(l.Dir, "linked.lock")))
		_, err = l.TryLock("linked")
		assert.ErrorContains(t, err, "hard links")
		assert.Equal(t, os.FileMode(0o644), mode(t, outside), "the aliased file keeps its mode")
	})
}

// TestLockerRefusesForeignOwner presents this process as another uid, so a
// directory it created looks like another account's.
func TestLockerRefusesForeignOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned objects are always trusted")
	}
	dir := filepath.Join(t.TempDir(), "locks")
	require.NoError(t, os.Mkdir(dir, 0o700))
	euid := os.Geteuid()
	geteuid = func() int { return euid + 1 }
	t.Cleanup(func() { geteuid = os.Geteuid })
	_, err := (&FileLocker{Dir: dir}).TryLock("host")
	assert.ErrorContains(t, err, "not root or this process")
}

// TestLockerRefusesWrongObjectTypes covers a file where the directory
// belongs and a non-regular file where a lock file belongs.
func TestLockerRefusesWrongObjectTypes(t *testing.T) {
	t.Run("file at directory path", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "locks")
		require.NoError(t, os.WriteFile(dir, nil, 0o600))
		_, err := (&FileLocker{Dir: dir}).TryLock("host")
		assert.Error(t, err)
	})

	t.Run("fifo lock file", func(t *testing.T) {
		l := &FileLocker{Dir: filepath.Join(t.TempDir(), "locks")}
		h, err := l.TryLock("other")
		require.NoError(t, err)
		require.NoError(t, h.Unlock())
		require.NoError(t, unix.Mkfifo(filepath.Join(l.Dir, "host.lock"), 0o600))
		_, err = l.TryLock("host")
		assert.ErrorContains(t, err, "not a regular file")
	})
}

// TestChildDoesNotInheritLock covers a holder that exits while a child it
// started is still running. flock belongs to the open file description, so
// an inherited descriptor would keep the lock held after the holder is gone.
// Closing without LOCK_UN models the exit, since an explicit unlock would
// release the lock for the child's copy too.
func TestChildDoesNotInheritLock(t *testing.T) {
	l := &FileLocker{Dir: filepath.Join(t.TempDir(), "locks")}
	h, err := l.TryLock("host")
	require.NoError(t, err)

	child := exec.Command("sleep", "60")
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})

	require.NoError(t, h.(*fileHandle).f.Close())
	again, err := l.TryLock("host")
	require.NoError(t, err, "a running child must not keep the lock held")
	require.NoError(t, again.Unlock())
}
