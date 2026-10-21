package noop

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/backend/backendtest"
)

// TestSuite runs the shared converge contract against the no-op backend.
// noop installs nothing, so it is always clean and has no side effects.
func TestSuite(t *testing.T) {
	backendtest.Suite(t, func(t *testing.T) backendtest.Fixture {
		return backendtest.Fixture{
			Backend: New(),
			ValidConfig: backend.Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"example.com"},
			},
			Clean: func() (bool, error) { return true, nil },
		}
	})
}

// TestSetReportsNothing checks that a forced no-op converges without
// claiming a change or owing work, so the worker settles immediately.
func TestSetReportsNothing(t *testing.T) {
	cfg := backend.Config{Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	res, err := New().Set(context.Background(), cfg, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
}
