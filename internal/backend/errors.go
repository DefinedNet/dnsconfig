package backend

import (
	"errors"
	"fmt"
	"strings"
)

// The dnsconfig package re-exports these sentinels and ConflictError, so a
// backend's error satisfies errors.Is and errors.As for the public names
// without translation. Text that reaches callers inside the Manager's *Error
// carries no package prefix, since *Error supplies one.
var (
	// ErrConflict reports that another identity already publishes a requested
	// domain or catch-all, or records the requested Windows adapter. A
	// *ConflictError matches it through errors.Is.
	ErrConflict = errors.New("domain held by another identity")

	// ErrGroupPolicyContainerEmpty reports a Group Policy NRPT container with
	// no rules or values, which makes Windows ignore the local NRPT table.
	// Set returns it once the local copies are in place, whether or not that
	// attempt wrote them.
	ErrGroupPolicyContainerEmpty = errors.New("empty Group Policy NRPT container suppresses local NRPT rules")
)

// ConflictError reports that another identity already publishes Domain.
// Backends return it before the first write.
type ConflictError struct {
	// Domain is the conflicting domain in canonical form, lowercase with a
	// trailing dot, or the root "." for a catch-all.
	Domain string
	// Holder is the identity that publishes Domain.
	Holder string
}

// NewConflictError returns a ConflictError for a domain in backend form,
// converting it to the canonical form callers see. A domain that already
// carries its trailing dot is accepted as is.
func NewConflictError(domain, holder string) *ConflictError {
	if domain != "." {
		domain = strings.TrimSuffix(strings.ToLower(domain), ".") + "."
	}
	return &ConflictError{Domain: domain, Holder: holder}
}

// Error identifies the conflicting domain and its holder.
func (e *ConflictError) Error() string {
	if e.Domain == "." {
		return fmt.Sprintf("catch-all held by identity %q", e.Holder)
	}
	return fmt.Sprintf("domain %s held by identity %q", e.Domain, e.Holder)
}

// Is reports whether target is ErrConflict, so every error carrying a
// ConflictError matches ErrConflict without a separate wrap.
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }
