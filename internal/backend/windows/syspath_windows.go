//go:build windows

package windows

import (
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

// systemPath resolves a System32 executable through GetSystemDirectory rather
// than %PATH% or %SystemRoot%. A LocalSystem caller must not pick up a
// substitute from a writable path entry, and the system directory is not
// guaranteed to be %SystemRoot%\System32 under terminal services.
var systemPath = sync.OnceValues(func() (string, error) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ipconfigExe), nil
})
