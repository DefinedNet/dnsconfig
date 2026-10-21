//go:build windows

package hostlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// defaultDir lives under ProgramData because the Manager already needs
// administrator rights to apply DNS, and the directory survives reboots
// without stranding anything: a dead holder's handle releases its lock.
// The known-folder lookup ignores the environment, because a process that
// resolved a different directory would fall outside the host-wide lock.
func defaultDir() string {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "dnsconfig")
}

// ProgramData lets standard users read files in subdirectories and create
// files and folders there. A read handle is enough for LockFileEx, so under
// the inherited ACL any user could hold a lock and stall every identity. The
// directory and its lock files therefore carry protected DACLs granting only
// SYSTEM and Administrators.
const (
	dirDACL  = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	fileDACL = "(A;;FA;;;SY)(A;;FA;;;BA)"
)

// prepareDir creates dir with its protected DACL, or validates an existing
// one. Users may create folders in ProgramData, so an existing directory is
// trusted only when it is not a reparse point and SYSTEM or Administrators
// own it; an owner keeps WRITE_DAC whatever the DACL says.
func prepareDir(dir string) error {
	sa, err := securityAttributes("O:BAD:P" + dirDACL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("hostlock: %s: %w", dir, err)
	}
	if err := windows.CreateDirectory(p, sa); err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return fmt.Errorf("hostlock: create %s: %w", dir, err)
	}
	h, err := windows.CreateFile(p,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("hostlock: open %s: %w", dir, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("hostlock: inspect %s: %w", dir, err)
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return fmt.Errorf("hostlock: lock directory %s is a reparse point; remove it so it can be recreated", dir)
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0:
		return fmt.Errorf("hostlock: lock directory %s is not a directory", dir)
	}
	return secureHandle(h, dir, "lock directory", dirDACL)
}

// openLockFile opens or creates path without following reparse points and
// refuses a file another account could have planted before the directory
// was protected. A file with more than one link could alias a file outside
// the directory, so the lock would land on that file too.
func openLockFile(path string) (*os.File, error) {
	sa, err := securityAttributes("O:BAD:P" + fileDACL)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("hostlock: %s: %w", path, err)
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		sa, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("hostlock: open %s: %w", path, err)
	}
	if err := checkLockFile(h, path); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func checkLockFile(h windows.Handle, path string) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("hostlock: inspect %s: %w", path, err)
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return fmt.Errorf("hostlock: lock file %s is a reparse point; remove it", path)
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return fmt.Errorf("hostlock: lock file %s is a directory; remove it", path)
	case info.NumberOfLinks > 1:
		return fmt.Errorf("hostlock: lock file %s has %d hard links; remove it", path, info.NumberOfLinks)
	}
	return secureHandle(h, path, "lock file", fileDACL)
}

// secureHandle refuses an object SYSTEM or Administrators do not own and
// replaces a DACL that differs from the protected aces, since an
// administrator-created object inherits ProgramData's user-readable ACL.
func secureHandle(h windows.Handle, path, kind, aces string) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("hostlock: read owner of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("hostlock: read owner of %s: %w", path, err)
	}
	if !trustedOwner(owner) {
		return fmt.Errorf("hostlock: %s %s is owned by %s, not SYSTEM or Administrators; remove it so it can be recreated",
			kind, path, accountName(owner))
	}
	sd, err = windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("hostlock: read DACL of %s: %w", path, err)
	}
	if protectedDACL(sd.String(), aces) {
		return nil
	}
	want, err := windows.SecurityDescriptorFromString("D:P" + aces)
	if err != nil {
		return fmt.Errorf("hostlock: build DACL: %w", err)
	}
	dacl, _, err := want.DACL()
	if err != nil {
		return fmt.Errorf("hostlock: build DACL: %w", err)
	}
	err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("hostlock: protect %s: %w", path, err)
	}
	return nil
}

// protectedDACL reports whether sddl, a DACL-only descriptor string, is
// protected from inheritance and holds exactly aces. Flags such as AI vary
// with how the DACL was set, so only P is required.
func protectedDACL(sddl, aces string) bool {
	flags, rest, ok := strings.Cut(strings.TrimPrefix(sddl, "D:"), "(")
	return ok && strings.Contains(flags, "P") && "("+rest == aces
}

func trustedOwner(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func accountName(sid *windows.SID) string {
	if sid == nil {
		return "no owner"
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sid.String()
	}
	return domain + `\` + account + " (" + sid.String() + ")"
}

func securityAttributes(sddl string) (*windows.SecurityAttributes, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("hostlock: build security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	return sa, nil
}

func tryLockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	err := windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return ErrHeld
	}
	return err
}

func unlockFile(f *os.File) error {
	ol := new(windows.Overlapped)
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}
