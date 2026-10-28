package dnsconfig

import (
	"errors"
	"fmt"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// Sentinel errors. Library callers should compare with errors.Is rather than
// equality so wrapping via *Error works. Sentinels that backends also report
// are defined once in the backend contract and re-exported here.
var (
	// ErrInterfaceRequired is returned by [Manager.Set] when the Windows
	// backend is selected and Options.InterfaceName is empty. Set records no
	// goal and also records the refusal in Status.LastError.
	ErrInterfaceRequired = errors.New("interface required for this backend")

	// ErrManagerAlreadyRunning reports, through Status.LastError, that
	// another live Manager, in this or another process, holds this
	// Options.Identity. From the worker it means the attempt changed nothing
	// and retries with backoff. After Close it means the final cleanup for a
	// recorded goal was not run because the holder's configuration stays;
	// Close itself does not return it.
	ErrManagerAlreadyRunning = errors.New("another Manager holds this identity")

	// ErrConflict reports, through Status.LastError, that another identity
	// already publishes one of the requested domains or a catch-all, or on
	// Windows records the Options.InterfaceName adapter. The attempt changed
	// nothing; for a domain or catch-all, errors.As yields a *ConflictError
	// naming it and the holder. The worker retries with backoff, so the goal
	// converges once the holder leaves.
	ErrConflict = backend.ErrConflict

	// ErrEmptyConfig is returned by Config.Validate (and so by Set) when the
	// Config is the zero value. Use Clear to remove managed configuration.
	ErrEmptyConfig = errors.New("dnsconfig: empty Config; call Clear to remove configuration")

	// ErrInvalidOptions is returned by Options.Validate, which New calls
	// first, and by New inside *Error when the forced backend is absent on
	// this OS.
	ErrInvalidOptions = errors.New("dnsconfig: invalid Options")

	// ErrClosed is returned by Set and Clear after Close.
	ErrClosed = errors.New("manager closed")

	// ErrGroupPolicyContainerEmpty reports, through Status.LastError, a
	// Windows Group Policy NRPT container with no rules or values. Its
	// presence makes the DNS Client ignore the local NRPT table, and nothing
	// attributes it to dnsconfig, so it is left in place. Each Set attempt
	// keeps the local copies written and fails with this error, or fails
	// before writing when Group Policy cannot be monitored. The goal
	// converges once the key is removed; after a manual deletion, reboot so
	// the DNS Client drops its cached policy table.
	ErrGroupPolicyContainerEmpty = backend.ErrGroupPolicyContainerEmpty

	// ErrConfigurationDeclined is returned by Set when the active backend
	// applies nothing and the caller did not ask for that. Detection answers
	// BackendNoop on unsupported platforms, and New declines the macOS backend
	// for a process that is not root, since every write it would attempt
	// needs root. A declined macOS Manager names BackendDarwin in its errors,
	// its refusal says why, and its Clear converges without touching the host or
	// taking locks. Set records no goal. Explicitly selecting BackendNoop
	// through Options.ForceBackend permits a goal that converges without
	// touching the host.
	//
	// Retrying on the same Manager cannot change this condition.
	ErrConfigurationDeclined = errors.New("backend applies no DNS configuration")
)

// Error is the structured error type returned by Manager operations. Use
// errors.Is to compare against sentinels; use errors.As to inspect Op and
// Backend.
type Error struct {
	// Op names the operation: "New", "Set", "Clear", or "Close", or
	// "Converge" for a worker attempt recorded in Status.LastError.
	Op string
	// Backend identifies the selected backend, or is empty before selection.
	Backend BackendKind
	// Err is the underlying cause.
	Err error
}

// Error describes the failed operation and its cause.
func (e *Error) Error() string {
	if e.Backend == "" {
		return fmt.Sprintf("dnsconfig %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("dnsconfig %s (%s): %v", e.Op, e.Backend, e.Err)
}

// Unwrap returns the underlying cause.
func (e *Error) Unwrap() error { return e.Err }

// ConflictError reports, inside Status.LastError, that another identity
// already publishes a requested domain. Domain is that domain in canonical
// form, lowercase with a trailing dot, or "." for a catch-all; Holder is the
// identity. It matches [ErrConflict] through errors.Is.
type ConflictError = backend.ConflictError
