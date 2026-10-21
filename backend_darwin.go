package dnsconfig

import (
	"context"

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
