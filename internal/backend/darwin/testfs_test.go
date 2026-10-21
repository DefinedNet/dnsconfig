//go:build darwin

package darwin

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// testFS is the real filesystem, with a temporary directory standing in for
// /etc/resolver. It logs every call that can change or sync a file, so tests
// can assert what an attempt wrote and in what order, and it can fail Open,
// Remove, or Sync for one path. Fixtures write through os directly, so the
// log holds only the backend's calls.
type testFS struct {
	backend.DiskFS
	// dir does not exist until the backend creates it, as /etc/resolver
	// may not.
	dir string

	mu       sync.Mutex
	log      []fsMutation
	failures map[fsOp]map[string]error
	// order, when set, also receives each logged call, interleaved with
	// the scutil fake's.
	order *hostOrder
}

// fsMutation is one logged call; for Rename, Path is the destination.
type fsMutation struct {
	Op   string
	Path string
}

type fsOp string

const (
	opOpen    fsOp = "Open"
	opRemove  fsOp = "Remove"
	opSync    fsOp = "Sync"
	opSyncDir fsOp = "SyncDir"
)

func newTestFS(t *testing.T) *testFS {
	return &testFS{dir: filepath.Join(t.TempDir(), "resolver")}
}

// dirFS is a testFS, possibly wrapped to change one call.
type dirFS interface {
	backend.FS
	resolverDirectory() string
}

func (f *testFS) resolverDirectory() string { return f.dir }

// useFS points b at fs's resolver directory.
func useFS(b *Backend, fs dirFS) *Backend {
	b.resolverDir = fs.resolverDirectory()
	return b
}

// path returns the resolver file path for name.
func (f *testFS) path(name string) string { return filepath.Join(f.dir, name) }

// seed writes a file the backend did not write.
func (f *testFS) seed(t *testing.T, name string, body []byte, perm os.FileMode) string {
	t.Helper()
	p := f.path(name)
	require.NoError(t, os.MkdirAll(f.dir, 0o755))
	require.NoError(t, os.WriteFile(p, body, perm))
	require.NoError(t, os.Chmod(p, perm))
	return p
}

// fileMode returns the permission bits of the file at path.
func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	return fi.Mode().Perm()
}

// isSymlink reports whether path itself is a link.
func isSymlink(t *testing.T, path string) bool {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	return fi.Mode()&os.ModeSymlink != 0
}

// mutations returns a copy of the log in call order.
func (f *testFS) mutations() []fsMutation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fsMutation(nil), f.log...)
}

// fail sets the error op returns for path until it is called again with nil.
func (f *testFS) fail(op fsOp, path string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures == nil {
		f.failures = map[fsOp]map[string]error{}
	}
	if f.failures[op] == nil {
		f.failures[op] = map[string]error{}
	}
	if err == nil {
		delete(f.failures[op], path)
		return
	}
	f.failures[op][path] = err
}

var errOutside = errors.New("testFS: path outside the resolver directory")

// contained refuses a path outside dir: it means a test forgot useFS and
// would touch the host's /etc/resolver. Paths are cleaned first so a ".."
// element cannot climb out.
func (f *testFS) contained(op fsOp, paths ...string) error {
	for _, p := range paths {
		c := filepath.Clean(p)
		if c != f.dir && !strings.HasPrefix(c, f.dir+string(filepath.Separator)) {
			return fmt.Errorf("%w: %s %s is outside %s", errOutside, op, p, f.dir)
		}
	}
	return nil
}

// record checks containment, logs a mutating call, and returns the
// injected failure, if any. For Rename, path is the destination.
func (f *testFS) record(op fsOp, path string, also ...string) error {
	if err := f.contained(op, append([]string{path}, also...)...); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if op != opOpen {
		f.log = append(f.log, fsMutation{Op: string(op), Path: path})
		f.order.add("fs " + string(op) + " " + filepath.Base(path))
	}
	return f.failures[op][path]
}

func (f *testFS) Open(path string) (io.ReadCloser, error) {
	if err := f.record(opOpen, path); err != nil {
		return nil, err
	}
	return f.DiskFS.Open(path)
}

func (f *testFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := f.record("WriteFile", path); err != nil {
		return err
	}
	return f.DiskFS.WriteFile(path, data, perm)
}

func (f *testFS) Chmod(path string, mode os.FileMode) error {
	if err := f.record("Chmod", path); err != nil {
		return err
	}
	return f.DiskFS.Chmod(path, mode)
}

func (f *testFS) Sync(path string) error {
	if err := f.record(opSync, path); err != nil {
		return err
	}
	return f.DiskFS.Sync(path)
}

func (f *testFS) SyncDir(path string) error {
	if err := f.record(opSyncDir, path); err != nil {
		return err
	}
	return f.DiskFS.SyncDir(path)
}

func (f *testFS) Remove(path string) error {
	if err := f.record(opRemove, path); err != nil {
		return err
	}
	return f.DiskFS.Remove(path)
}

func (f *testFS) MkdirAll(path string, perm os.FileMode) error {
	if err := f.record("MkdirAll", path); err != nil {
		return err
	}
	return f.DiskFS.MkdirAll(path, perm)
}

func (f *testFS) Rename(oldpath, newpath string) error {
	if err := f.record("Rename", newpath, oldpath); err != nil {
		return err
	}
	return f.DiskFS.Rename(oldpath, newpath)
}

func (f *testFS) IsRegularFile(path string) (bool, error) {
	if err := f.contained("IsRegularFile", path); err != nil {
		return false, err
	}
	return f.DiskFS.IsRegularFile(path)
}

func (f *testFS) ReadDir(path string) ([]os.DirEntry, error) {
	if err := f.contained("ReadDir", path); err != nil {
		return nil, err
	}
	return f.DiskFS.ReadDir(path)
}

// TestTestFSRefusesOutsidePaths: a backend left on /etc/resolver fails
// instead of reading or writing the host's files.
func TestTestFSRefusesOutsidePaths(t *testing.T) {
	fs := newTestFS(t)
	inside := fs.seed(t, "inside", []byte("x"), 0o644)
	// Both outside paths exist, so a read that skipped the check would
	// succeed rather than fail for a missing file.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "outside")
	require.NoError(t, os.WriteFile(outside, []byte("o"), 0o644))
	climb := filepath.Join(filepath.Dir(fs.dir), "climb")
	require.NoError(t, os.WriteFile(climb, []byte("c"), 0o644))
	traversal := fs.dir + "/../climb"

	for _, p := range []string{outside, traversal} {
		t.Run(filepath.Base(p), func(t *testing.T) {
			_, err := fs.Open(p)
			assert.ErrorIs(t, err, errOutside, "Open")
			_, err = fs.IsRegularFile(p)
			assert.ErrorIs(t, err, errOutside, "IsRegularFile")
			assert.ErrorIs(t, fs.WriteFile(p, []byte("x"), 0o644), errOutside, "WriteFile")
			assert.ErrorIs(t, fs.Chmod(p, 0o600), errOutside, "Chmod")
			assert.ErrorIs(t, fs.Sync(p), errOutside, "Sync")
			assert.ErrorIs(t, fs.SyncDir(filepath.Dir(p)), errOutside, "SyncDir")
			assert.ErrorIs(t, fs.Remove(p), errOutside, "Remove")
			assert.ErrorIs(t, fs.MkdirAll(p+"-dir", 0o755), errOutside, "MkdirAll")
			assert.ErrorIs(t, fs.Rename(inside, p), errOutside, "Rename to outside")
			assert.ErrorIs(t, fs.Rename(p, inside), errOutside, "Rename from outside")
		})
	}
	for _, d := range []string{outsideDir, fs.dir + "/.."} {
		_, err := fs.ReadDir(d)
		assert.ErrorIs(t, err, errOutside, "ReadDir %s", d)
	}

	for p, want := range map[string]string{outside: "o", climb: "c", inside: "x"} {
		body, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, want, string(body), "%s is unchanged", p)
		assert.Equal(t, os.FileMode(0o644), fileMode(t, p), "%s mode is unchanged", p)
	}
	_, err := os.Lstat(outside + "-dir")
	assert.ErrorIs(t, err, os.ErrNotExist, "no directory was created")
	assert.Empty(t, fs.mutations(), "refused calls are not logged")
}
