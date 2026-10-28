//go:build !darwin && !windows

package dnsconfig

import (
	"context"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

func newNativeBackend(_ context.Context, kind BackendKind, _ Options) (backend.Backend, error) {
	return nil, errBackendUnsupported(kind)
}

// nativeDeclined reports why this process cannot manage kind's DNS, or nil.
func nativeDeclined(BackendKind) error { return nil }
