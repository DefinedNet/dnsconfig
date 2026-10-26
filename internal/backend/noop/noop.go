// Package noop is the fallback backend used on unsupported platforms
// or when explicitly requested by a caller.
package noop

import (
	"context"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// Backend implements backend.Backend as a no-op. Set and Clear
// succeed without touching the host and never report a change or pending
// work.
//
// The public Manager rejects Set with ErrConfigurationDeclined when detection
// selects noop. Explicitly selecting noop permits Set to converge without
// configuring DNS.
type Backend struct{}

// New returns a no-op Backend.
func New() *Backend { return &Backend{} }

// Set applies nothing.
func (b *Backend) Set(context.Context, backend.Config, backend.Attempt) (backend.Result, error) {
	return backend.Result{}, nil
}

// Clear has nothing to remove.
func (b *Backend) Clear(context.Context, backend.Attempt) (backend.Result, error) {
	return backend.Result{}, nil
}

// HasArtifacts finds nothing: noop never installs anything.
func (b *Backend) HasArtifacts(context.Context) (bool, error) { return false, nil }

// ValidateConfig accepts every config: nothing is installed, so no OS limit
// applies.
func (b *Backend) ValidateConfig(backend.Config) error { return nil }

// Changes reports no signal source: nothing installed can drift.
func (b *Backend) Changes() <-chan struct{} { return nil }

// Close holds no resources.
func (b *Backend) Close() error { return nil }
