//go:build !windows

package windows

// systemPath yields the bare name off Windows so backend tests keep the same
// runner key without a native system directory to resolve.
func systemPath() (string, error) { return ipconfigExe, nil }
