package dnsconfig

import (
	"context"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/backend/windows"
)

func newNativeBackend(ctx context.Context, kind BackendKind, opts Options) (backend.Backend, error) {
	if kind != BackendWindows {
		return nil, errBackendUnsupported(kind)
	}
	b, err := windows.New(ctx, windows.Options{
		Identity:      opts.Identity,
		Logger:        opts.Logger,
		Registry:      windows.NewSystemRegistry(),
		InterfaceName: opts.InterfaceName,
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}
