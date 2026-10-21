package dnsconfig

import "runtime"

// Detect reports the native backend without initializing it.
// It returns BackendDarwin on macOS, BackendWindows on Windows, and BackendNoop
// on unsupported platforms. New uses this backend unless Options.ForceBackend is set.
func Detect() BackendKind {
	switch runtime.GOOS {
	case "darwin":
		return BackendDarwin
	case "windows":
		return BackendWindows
	default:
		return BackendNoop
	}
}
