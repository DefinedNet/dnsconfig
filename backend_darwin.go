package dnsconfig

import (
	"context"
	"errors"
	"os"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/backend/darwin"
)

func newNativeBackend(ctx context.Context, kind BackendKind, opts Options) (backend.Backend, error) {
	if kind != BackendDarwin {
		return nil, errBackendUnsupported(kind)
	}
	b, err := darwin.New(ctx, darwin.Options{
		Identity: opts.Identity,
		Logger:   opts.Logger,
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

// isRoot is replaced by tests so the declined path does not depend on the
// test runner's user.
var isRoot = func() bool { return os.Geteuid() == 0 }

// nativeDeclined reports why this process cannot manage kind's DNS, or nil.
// The dynamic store, /etc/resolver, and the lock directory all require root,
// so a non-root darwin Manager could only fail and retry every attempt.
func nativeDeclined(kind BackendKind) error {
	if kind == BackendDarwin && !isRoot() {
		return errors.New("darwin: requires root")
	}
	return nil
}
