package dnsconfig

import (
	"context"
	"fmt"
	"runtime"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/backend/noop"
)

// newBackend constructs the backend for kind, which detection has already
// made concrete.
func newBackend(ctx context.Context, kind BackendKind, opts Options) (backend.Backend, error) {
	if kind == BackendNoop {
		return noop.New(), nil
	}
	return newNativeBackend(ctx, kind, opts)
}

// errBackendUnsupported reports a backend with no implementation on this OS.
// That is a property of the Options that retrying cannot fix.
func errBackendUnsupported(kind BackendKind) error {
	return wrapSentinel(ErrInvalidOptions, fmt.Errorf("backend %q is not supported on %s", kind, runtime.GOOS))
}
