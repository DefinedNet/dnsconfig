//go:build darwin

package backend

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiskFSChmodDefeatsUmask checks that resolver files can remain
// world-readable under a restrictive umask. Do not run in parallel:
// syscall.Umask changes process-global state.
func TestDiskFSChmodDefeatsUmask(t *testing.T) {
	old := syscall.Umask(0o027)
	defer syscall.Umask(old)

	fs := DiskFS{}
	path := filepath.Join(t.TempDir(), "resolv.conf")

	require.NoError(t, fs.WriteFile(path, []byte("nameserver 1.1.1.1\n"), 0o644))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), fi.Mode().Perm(),
		"precondition: umask should have masked the create mode")

	require.NoError(t, fs.Chmod(path, 0o644))
	fi, err = os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}
