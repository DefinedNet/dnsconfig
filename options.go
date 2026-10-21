package dnsconfig

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// BackendKind names a DNS-configuration backend. The zero value, BackendAuto,
// requests detection.
type BackendKind string

const (
	// BackendAuto is the zero value; it requests backend detection.
	BackendAuto BackendKind = ""
	// BackendDarwin uses /etc/resolver files and SCDynamicStore keys on macOS.
	BackendDarwin BackendKind = "darwin"
	// BackendWindows uses NRPT rules and controlled-adapter DNS settings on Windows.
	BackendWindows BackendKind = "windows"
	// BackendNoop applies nothing. Detection selects it on unsupported platforms,
	// where Set returns ErrConfigurationDeclined. Explicitly forcing it permits
	// Set goals that converge without touching the host.
	BackendNoop BackendKind = "noop"
)

// IsValid reports whether k is one of the declared BackendKind constants.
// It says nothing about whether that backend exists on the current OS or can
// be initialized; New answers those.
func (k BackendKind) IsValid() bool {
	switch k {
	case BackendAuto,
		BackendDarwin,
		BackendWindows,
		BackendNoop:
		return true
	}
	return false
}

// DefaultShutdownTimeout is Close's final-cleanup cancellation budget when
// Options.ShutdownTimeout is zero. It exceeds the worker's attempt budget
// to allow time for cleanup after waiting behind a peer.
const DefaultShutdownTimeout = 15 * time.Second

// Options configures a Manager. Identity is required; other zero values select
// the native backend and discard log output. Windows Set requires InterfaceName.
// Options are fixed for a Manager's life; changing them requires a new Manager.
type Options struct {
	// Identity is required and names the application instance that owns this
	// Manager's DNS artifacts, so Clear and Close remove only its work. Reuse
	// it across restarts and give independent instances different identities.
	// It must pass [ValidateIdentity], which rejects uppercase.
	Identity string

	// Logger is the slog logger used for warnings and debug output.
	// Nil discards output independently of slog.Default(). The library logs
	// while holding internal locks, so the handler must not call back into
	// the Manager.
	Logger *slog.Logger

	// ForceBackend selects a specific backend; the zero value requests
	// detection. New never falls back to a different backend: an undeclared
	// kind fails Validate, and a kind with no implementation on this OS fails
	// New with ErrInvalidOptions. See [BackendNoop] for forcing the no-op one.
	ForceBackend BackendKind

	// InterfaceName is the friendly name of a Windows adapter, such as a
	// tunnel adapter, whose DNS settings the caller controls through cleanup.
	// Windows Set requires it. It is resolved to the adapter's GUID at each
	// converge, so a recreated adapter needs no new Manager but a renamed one
	// does. An adapter belongs to one identity at a time: another identity's
	// Set naming it is refused with [ErrConflict] until that identity clears.
	// Turn off its dynamic DNS registration with RegistrationEnabled=0,
	// DisableDynamicUpdate=1, and MaxNumberOfAddressesToRegister=0 under both
	// its Tcpip and Tcpip6 interface keys. The darwin and noop backends
	// ignore it.
	InterfaceName string

	// ShutdownTimeout sets the cancellation deadline for Close's final cleanup,
	// including the host-wide lock wait. Synchronous Windows API calls can
	// exceed the deadline. Zero selects [DefaultShutdownTimeout]; a negative
	// value fails Validate. [Manager.Close] describes cancellation and teardown.
	ShutdownTimeout time.Duration
}

// Validate reports ErrInvalidOptions for an unknown ForceBackend, an invalid
// or missing Identity, or a negative ShutdownTimeout.
// New calls it before initializing the backend.
func (o Options) Validate() error {
	if !o.ForceBackend.IsValid() {
		return fmt.Errorf("%w: ForceBackend %q is not a known backend", ErrInvalidOptions, string(o.ForceBackend))
	}
	if o.ShutdownTimeout < 0 {
		return fmt.Errorf("%w: ShutdownTimeout %v is negative", ErrInvalidOptions, o.ShutdownTimeout)
	}
	if err := ValidateIdentity(o.Identity); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	return nil
}

// ValidateIdentity reports whether s is an acceptable Options.Identity: 1 to
// 63 characters of lowercase letters, digits, '.', '_', or '-', starting with
// a letter or digit.
func ValidateIdentity(s string) error {
	return backend.ValidateIdentity(s)
}
