package backend

import (
	"io"
	"os"
)

// FS is the filesystem seam used by the macOS backend.
// The backend serializes access to its resolver files.
type FS interface {
	// Open opens a stream so the backend can bound resolver-file reads.
	Open(path string) (io.ReadCloser, error)

	// WriteFile writes data to path with the given mode, creating or
	// truncating the file as needed. perm is honored only on creation; an
	// existing file's mode is left unchanged, mirroring os.WriteFile.
	//
	// The process umask masks perm on creation. Use Chmod afterward when
	// resolver files must remain world-readable under a restrictive umask.
	WriteFile(path string, data []byte, perm os.FileMode) error

	// Chmod sets the mode bits of the file at path, mirroring os.Chmod. A
	// missing path returns an error satisfying errors.Is(err, os.ErrNotExist).
	Chmod(path string, mode os.FileMode) error

	// Sync flushes the file at path, data and metadata, to stable storage.
	// It does not follow a link at path. The macOS backend syncs a staged
	// resolver file before renaming it into place.
	Sync(path string) error

	// Remove removes the file at path. Missing files produce an error that
	// satisfies errors.Is(err, os.ErrNotExist).
	Remove(path string) error

	// SyncDir flushes the directory at path to stable storage, making
	// earlier removals and renames in it durable. The macOS backend syncs
	// /etc/resolver after removing resolver files.
	SyncDir(path string) error

	// IsRegularFile reports whether path itself is a regular file, without
	// following a final link, so a link reports false. A missing path
	// returns an error satisfying errors.Is(err, os.ErrNotExist).
	IsRegularFile(path string) (bool, error)

	// MkdirAll creates path and any missing parents, mirroring os.MkdirAll.
	// It returns nil if path already exists as a directory. perm is honored
	// only on creation. The macOS backend uses this to create
	// /etc/resolver on demand.
	MkdirAll(path string, perm os.FileMode) error

	// ReadDir returns the directory entries of path, mirroring os.ReadDir.
	// A missing path returns an error satisfying errors.Is(err,
	// os.ErrNotExist). The macOS backend uses this to sweep stale
	// /etc/resolver files.
	ReadDir(path string) ([]os.DirEntry, error)

	// Rename moves oldpath to newpath, mirroring rename(2): it replaces
	// newpath atomically and replaces a link there rather than writing
	// through it, so a reader sees either the old file or the complete new
	// one. The macOS backend stages resolver files and renames them into
	// place.
	Rename(oldpath, newpath string) error
}
