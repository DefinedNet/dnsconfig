//go:build !windows

package hostlock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// geteuid is a seam so unprivileged tests can present a foreign owner.
var geteuid = os.Geteuid

// defaultDir is cleared at boot, which cannot strand a lock because the
// holder is gone too.
func defaultDir() string { return "/var/run/dnsconfig" }

// flock needs only a read descriptor, so any account that can open a lock
// file could hold it and stall every identity. The directory and its lock
// files are therefore reachable only by their owner.
const (
	dirMode  = 0o700
	fileMode = 0o600
)

// prepareDir creates dir, or validates an existing one: it must not be a
// symlink and must be owned by root or this process's account, since an
// owner can always restore access for itself.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("hostlock: create %s: %w", dir, err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return fmt.Errorf("hostlock: lock directory %s is a symlink or not a directory; remove it so it can be recreated", dir)
		}
		return fmt.Errorf("hostlock: open %s: %w", dir, err)
	}
	defer func() { _ = unix.Close(fd) }()
	return secureFD(fd, dir, "lock directory", dirMode)
}

// openLockFile opens or creates path without following symlinks. A file
// with more than one link could alias a file outside the directory, which
// secureFD would then re-mode.
func openLockFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("hostlock: lock file %s is a symlink; remove it", path)
		}
		return nil, fmt.Errorf("hostlock: open %s: %w", path, err)
	}
	if err := checkLockFile(fd, path); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func checkLockFile(fd int, path string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("hostlock: inspect %s: %w", path, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("hostlock: lock file %s is not a regular file; remove it", path)
	case st.Nlink > 1:
		return fmt.Errorf("hostlock: lock file %s has %d hard links; remove it", path, st.Nlink)
	}
	return secureFD(fd, path, "lock file", fileMode)
}

// secureFD refuses an object owned by another account and narrows any other
// mode to mode, since any account that can open a lock file can hold it.
func secureFD(fd int, path, kind string, mode uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("hostlock: inspect %s: %w", path, err)
	}
	if st.Uid != 0 && int(st.Uid) != geteuid() {
		return fmt.Errorf("hostlock: %s %s is owned by uid %d, not root or this process; remove it", kind, path, st.Uid)
	}
	if uint32(st.Mode)&0o7777 == mode {
		return nil
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return fmt.Errorf("hostlock: restrict %s: %w", path, err)
	}
	return nil
}

func tryLockFile(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return ErrHeld
	}
	return err
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
