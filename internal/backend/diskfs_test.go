//go:build darwin

package backend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiskFSChmodMissing confirms Chmod on an absent path reports
// os.ErrNotExist, as os.Chmod does.
func TestDiskFSChmodMissing(t *testing.T) {
	fs := DiskFS{}
	err := fs.Chmod(filepath.Join(t.TempDir(), "nope"), 0o644)
	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// TestDiskFSSync covers a regular file and the refusal to follow a link.
func TestDiskFSSync(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("data"), 0o644))

	t.Run("regular file", func(t *testing.T) {
		assert.NoError(t, DiskFS{}.Sync(target))
	})
	t.Run("link", func(t *testing.T) {
		link := filepath.Join(dir, "link")
		require.NoError(t, os.Symlink(target, link))
		assert.Error(t, DiskFS{}.Sync(link))
	})
	t.Run("missing", func(t *testing.T) {
		assert.ErrorIs(t, DiskFS{}.Sync(filepath.Join(dir, "nope")), os.ErrNotExist)
	})
}
