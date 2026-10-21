//go:build windows

package hostlock

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

const disableMaxPrivilege = 0x1

// requireElevated skips unless the test process can act as an administrator,
// which the locker requires and the restricted token is derived from. CI
// runners are elevated, and a silent skip there would drop the evidence.
func requireElevated(t *testing.T) {
	t.Helper()
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	if os.Getenv("CI") != "" {
		t.Fatal("CI must run the Windows host-lock tests elevated")
	}
	t.Skip("requires an elevated process")
}

// programDataParent returns a fresh directory under ProgramData. It inherits
// ProgramData's ACL, so standard users may read files beneath it and create
// files and folders in it, as they may in ProgramData itself.
func programDataParent(t *testing.T) string {
	t.Helper()
	var b [8]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	base := os.Getenv("ProgramData")
	require.NotEmpty(t, base)
	dir := filepath.Join(base, "dnsconfig-test-"+hex.EncodeToString(b[:]))
	require.NoError(t, os.Mkdir(dir, 0o755))
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// standardUserToken derives an impersonation token from the process token
// with Administrators deny-only and every privilege removed, which is how a
// standard member of Users is checked against a DACL.
func standardUserToken(t *testing.T) windows.Token {
	t.Helper()
	var proc windows.Token
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &proc))
	defer func() { _ = proc.Close() }()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	require.NoError(t, err)
	deny := windows.SIDAndAttributes{Sid: admins}
	var restricted windows.Token
	r, _, callErr := procCreateRestrictedToken.Call(uintptr(proc), disableMaxPrivilege,
		1, uintptr(unsafe.Pointer(&deny)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	require.NotZero(t, r, "CreateRestrictedToken: %v", callErr)
	defer func() { _ = restricted.Close() }()
	var imp windows.Token
	require.NoError(t, windows.DuplicateTokenEx(restricted, windows.MAXIMUM_ALLOWED, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &imp))
	t.Cleanup(func() { _ = imp.Close() })
	return imp
}

// asStandardUser runs fn on this goroutine's OS thread while it impersonates
// the standard-user token. fn must not start goroutines.
func asStandardUser(t *testing.T, fn func()) {
	t.Helper()
	tok := standardUserToken(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	require.NoError(t, windows.SetThreadToken(nil, tok))
	defer func() { require.NoError(t, windows.RevertToSelf()) }()
	fn()
}

// openForRead opens path for reading, the least access LockFileEx accepts.
func openForRead(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

func createFile(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, 0, 0)
	if err != nil {
		return err
	}
	return windows.CloseHandle(h)
}

func createDir(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.CreateDirectory(p, nil)
}

func lockByte(h windows.Handle) error {
	return windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped))
}

// TestStandardUserHoldsInheritedACLLock is the control: under ProgramData's
// inherited ACL a standard user can open a lock file an administrator
// created, take its lock, and so block the administrator. It also shows the
// user can plant files in the directory and folders beside it.
func TestStandardUserHoldsInheritedACLLock(t *testing.T) {
	requireElevated(t)
	parent := programDataParent(t)
	dir := filepath.Join(parent, "dnsconfig")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "host.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	var held windows.Handle
	asStandardUser(t, func() {
		h, err := openForRead(path)
		require.NoError(t, err, "a standard user must be able to open the inherited-ACL lock file; if not, the finding is theoretical")
		held = h
		require.NoError(t, lockByte(h), "a read handle suffices for LockFileEx")
		assert.NoError(t, createFile(filepath.Join(dir, "planted.lock")), "users may create files in ProgramData subfolders")
		assert.NoError(t, createDir(filepath.Join(parent, "sibling")), "users may create folders beside the lock directory")
	})
	defer func() { _ = windows.CloseHandle(held) }()

	admin, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	defer func() { _ = admin.Close() }()
	assert.ErrorIs(t, tryLockFile(admin), ErrHeld, "the user's lock blocks the administrator")
}

// TestStandardUserCannotReachProtectedLock checks the fix: the locker's
// directory and lock file admit neither a read handle nor a new file from a
// standard user, and a held lock stays the administrator's.
func TestStandardUserCannotReachProtectedLock(t *testing.T) {
	requireElevated(t)
	parent := programDataParent(t)
	l := &FileLocker{Dir: filepath.Join(parent, "dnsconfig")}
	h, err := l.TryLock("host")
	require.NoError(t, err)
	require.NoError(t, h.Unlock())
	path := filepath.Join(l.Dir, "host.lock")

	asStandardUser(t, func() {
		_, err := openForRead(path)
		assert.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
		assert.ErrorIs(t, createFile(filepath.Join(l.Dir, "planted.lock")), windows.ERROR_ACCESS_DENIED)
	})

	h, err = l.TryLock("host")
	require.NoError(t, err)
	require.NoError(t, h.Unlock())
}

// TestLockerProtectsInheritedACLDirectory: a directory and lock file
// created under the inherited ACL by an administrator are trusted, so the
// locker keeps them and replaces their DACLs.
func TestLockerProtectsInheritedACLDirectory(t *testing.T) {
	requireElevated(t)
	parent := programDataParent(t)
	dir := filepath.Join(parent, "dnsconfig")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "host.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	l := &FileLocker{Dir: dir}
	h, err := l.TryLock("host")
	require.NoError(t, err)
	require.NoError(t, h.Unlock())

	asStandardUser(t, func() {
		_, err := openForRead(path)
		assert.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
		assert.ErrorIs(t, createFile(filepath.Join(dir, "planted.lock")), windows.ERROR_ACCESS_DENIED)
	})
}

// TestLockerRefusesUntrustedObjects covers what a standard user could leave
// behind: a pre-created directory, a lock file planted under the inherited
// ACL, and reparse points or extra links that redirect the lock elsewhere.
func TestLockerRefusesUntrustedObjects(t *testing.T) {
	requireElevated(t)

	t.Run("directory created by a user", func(t *testing.T) {
		parent := programDataParent(t)
		dir := filepath.Join(parent, "dnsconfig")
		asStandardUser(t, func() {
			require.NoError(t, createDir(dir))
		})
		_, err := (&FileLocker{Dir: dir}).TryLock("host")
		assert.ErrorContains(t, err, "not SYSTEM or Administrators")
	})

	t.Run("lock file planted by a user", func(t *testing.T) {
		parent := programDataParent(t)
		dir := filepath.Join(parent, "dnsconfig")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		asStandardUser(t, func() {
			require.NoError(t, createFile(filepath.Join(dir, "host.lock")))
		})
		l := &FileLocker{Dir: dir}
		_, err := l.TryLock("host")
		assert.ErrorContains(t, err, "not SYSTEM or Administrators")
		other, err := l.TryLock("other")
		require.NoError(t, err, "a planted file refuses only its own name")
		require.NoError(t, other.Unlock())
	})

	t.Run("directory junction", func(t *testing.T) {
		parent := programDataParent(t)
		target := filepath.Join(parent, "target")
		require.NoError(t, os.Mkdir(target, 0o755))
		link := filepath.Join(parent, "dnsconfig")
		out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
		require.NoError(t, err, "%s", out)
		_, err = (&FileLocker{Dir: link}).TryLock("host")
		assert.ErrorContains(t, err, "reparse point")
		_, err = os.Stat(filepath.Join(target, "host.lock"))
		assert.True(t, errors.Is(err, os.ErrNotExist), "nothing is created through the junction")
	})

	t.Run("lock file symlink", func(t *testing.T) {
		parent := programDataParent(t)
		l := &FileLocker{Dir: filepath.Join(parent, "dnsconfig")}
		h, err := l.TryLock("host")
		require.NoError(t, err)
		require.NoError(t, h.Unlock())
		outside := filepath.Join(parent, "outside")
		require.NoError(t, os.WriteFile(outside, nil, 0o644))
		require.NoError(t, os.Symlink(outside, filepath.Join(l.Dir, "linked.lock")))
		_, err = l.TryLock("linked")
		assert.ErrorContains(t, err, "reparse point")
	})

	t.Run("lock file hard link", func(t *testing.T) {
		parent := programDataParent(t)
		l := &FileLocker{Dir: filepath.Join(parent, "dnsconfig")}
		h, err := l.TryLock("host")
		require.NoError(t, err)
		require.NoError(t, h.Unlock())
		outside := filepath.Join(parent, "outside")
		require.NoError(t, os.WriteFile(outside, nil, 0o644))
		require.NoError(t, os.Link(outside, filepath.Join(l.Dir, "linked.lock")))
		_, err = l.TryLock("linked")
		assert.ErrorContains(t, err, "hard links")
	})
}

func TestProtectedDACL(t *testing.T) {
	for _, tc := range []struct {
		sddl string
		want bool
	}{
		{"D:P" + dirDACL, true},
		{"D:PAI" + dirDACL, true},
		{"D:AI" + dirDACL, false},
		{"D:P" + dirDACL + "(A;OICI;0x1200a9;;;BU)", false},
		{"D:P" + fileDACL, false},
		{"D:P", false},
	} {
		t.Run(tc.sddl, func(t *testing.T) {
			assert.Equal(t, tc.want, protectedDACL(tc.sddl, dirDACL))
		})
	}
}
