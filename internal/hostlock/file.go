package hostlock

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// FileLocker locks files under Dir with the platform's exclusive,
// non-blocking file lock. The lock is tied to the open file, so it dies with
// the process and does not depend on the holder's thread.
type FileLocker struct {
	// Dir holds the lock files. It is created on first use.
	Dir string
}

// System returns the FileLocker for this host's default directory.
func System() *FileLocker { return &FileLocker{Dir: defaultDir()} }

// TryLock implements Locker.
func (l *FileLocker) TryLock(name string) (Handle, error) {
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("hostlock: invalid lock name %q", name)
	}
	if err := prepareDir(l.Dir); err != nil {
		return nil, err
	}
	path := filepath.Join(l.Dir, name+".lock")
	f, err := openLockFile(path)
	if err != nil {
		return nil, err
	}
	if err := tryLockFile(f); err != nil {
		_ = f.Close()
		if err == ErrHeld {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("hostlock: lock %s: %w", path, err)
	}
	return &fileHandle{f: f}, nil
}

// Lock implements Locker.
func (l *FileLocker) Lock(ctx context.Context, name string) (Handle, error) {
	return lockWithRetry(ctx, func() (Handle, error) { return l.TryLock(name) })
}

type fileHandle struct {
	f *os.File
}

// Unlock releases the lock and closes its handle, leaving the file on disk.
func (h *fileHandle) Unlock() error {
	if err := unlockFile(h.f); err != nil {
		_ = h.f.Close()
		return err
	}
	return h.f.Close()
}
