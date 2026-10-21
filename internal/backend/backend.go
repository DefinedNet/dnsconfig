// Package backend defines the contract between the dnsconfig.Manager worker
// and the per-OS backends it drives.
package backend

import (
	"context"
	"net/netip"
)

// Backend is the one-shot toolbox the public Manager's worker drives.
// It runs no background loops: Set and Clear each make one attempt to
// converge the host toward a goal and return, and Changes supplies a signal
// that the host may have drifted. The worker is the only caller of Set and
// Clear and the only place that retries. The Manager serializes Set, Clear,
// and Close, so those need not be safe for concurrent use with each other.
// ValidateConfig and Changes may be called at any time.
type Backend interface {
	// Set converges the host toward cfg. It reads
	// live state, writes only artifacts that differ from cfg, removes
	// obsolete owned artifacts, and verifies installation even when nothing
	// was written. A converge that finds everything in place writes nothing
	// and, with no owed side effect, requests none, except the Windows
	// first-attempt adapter reload described in doc.go. A failed attempt does not roll back; one
	// that wrote nothing returns Result.Changed false, which lets a change
	// signal end the Manager's backoff.
	// Side effects still owed are reported in Result.Pending on every
	// attempt, failed or not.
	Set(ctx context.Context, cfg Config, attempt Attempt) (Result, error)

	// ValidateConfig reports whether cfg exceeds a limit of this backend's
	// OS mechanism, judged from cfg alone. It reads nothing, so the Manager
	// can refuse such a goal synchronously instead of retrying an attempt
	// that may never succeed. It may refuse a cfg that fits only because of
	// current host state, but a cfg it accepts fits on every host. Set and
	// Clear rely on the caller for validated input: the Manager passes Set
	// only a Config that passed Config.Validate and ValidateConfig, and calls
	// neither after Close.
	ValidateConfig(cfg Config) error

	// Clear converges the host toward no configuration owned by this
	// identity, including a crashed predecessor's artifacts, and completes
	// pending side effects. Result.Pending reports unfinished side effects
	// even when the attempt fails or every artifact is already gone. An
	// inspection failure before the first write returns an error and changes
	// nothing.
	Clear(ctx context.Context, attempt Attempt) (Result, error)

	// Changes returns a channel that receives a value whenever the host may
	// have changed in a way that can affect owned artifacts. Sends are
	// coalesced and never block; the channel carries no payload because the
	// worker re-reads every owned artifact. Close closes the channel; the
	// Manager stops reading Changes before it calls Close. A backend with no
	// notification source returns nil.
	Changes() <-chan struct{}

	// Close releases resources and stops signal sources without changing
	// system DNS configuration. The public Manager owns close-time cleanup
	// by running Clear first with the caller's shutdown cancellation deadline.
	// Close must be idempotent.
	Close() error
}

// Attempt describes why the worker is calling Set or Clear, so a backend can
// tell repair from a first install and the final cleanup from an attempt
// that will be retried.
type Attempt struct {
	// NewGoal marks the first attempt after the goal changed, for
	// diagnostics. Repeating the current goal, whether by retry, change
	// signal, or periodic check, leaves it false.
	NewGoal bool

	// Converged reports that an earlier attempt at the current goal
	// succeeded, so artifacts missing now were removed by something else
	// rather than never installed.
	Converged bool

	// Final marks the cleanup attempt Close makes. It has no retry, so a
	// backend requests owed side effects even after a failed phase while
	// the cleanup context is still live. Windows requests an owed policy
	// notification even after cancellation if its recovery records may be gone.
	// macOS removes the resolver files it attributed even when the State-key
	// list fails, since those files outlive the keys.
	Final bool
}

// Result reports what one converge attempt did.
type Result struct {
	// Changed reports that this attempt wrote or may have written an artifact;
	// a failed write can have partially succeeded.
	Changed bool

	// Pending reports side effects still owed after this attempt, such as a
	// cache flush, Windows adapter reload, or policy notification that
	// failed. A nil error means Pending is false: an attempt that cannot
	// complete an owed side effect fails. An error does not by itself mean a
	// side effect is owed. The Manager logs it with the failure and retries
	// the attempt.
	Pending bool
}

// Config mirrors dnsconfig.Config without importing the public package.
// The Manager passes only validated domains, lowercase and without a trailing
// dot, the form scutil, resolver files, and NRPT use, so backends compare
// them without folding case.
type Config struct {
	Nameservers   []netip.Addr
	SearchDomains []string
	MatchDomains  []string
}

// IsSplit reports whether c requests split DNS.
func (c Config) IsSplit() bool { return len(c.MatchDomains) > 0 }
