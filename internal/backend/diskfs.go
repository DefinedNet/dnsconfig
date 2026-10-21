//go:build darwin

package backend

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// DiskFS implements FS using the os package and is safe for concurrent use.
type DiskFS struct{}

// Open implements FS.
func (DiskFS) Open(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// WriteFile implements FS.
func (DiskFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// Chmod implements FS.
func (DiskFS) Chmod(path string, mode os.FileMode) error {
	return os.Chmod(path, mode)
}

// Sync implements FS. File.Sync issues F_FULLFSYNC on darwin, which also
// flushes the drive's write cache; plain fsync does not.
func (DiskFS) Sync(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// SyncDir implements FS.
func (DiskFS) SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// Remove implements FS.
func (DiskFS) Remove(path string) error {
	return os.Remove(path)
}

// IsRegularFile implements FS.
func (DiskFS) IsRegularFile(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().IsRegular(), nil
}

// MkdirAll implements FS.
func (DiskFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// ReadDir implements FS.
func (DiskFS) ReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

// Rename implements FS.
func (DiskFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }
