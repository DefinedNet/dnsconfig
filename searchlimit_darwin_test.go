package dnsconfig

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetRejectsSearchListOverScutilLine checks that the native macOS
// backend refuses a search list that does not fit one scutil line before a
// goal is recorded, so nothing is applied and Close has nothing to revert.
func TestSetRejectsSearchListOverScutilLine(t *testing.T) {
	m, err := New(context.Background(), Options{Identity: "facade-search-limit", ForceBackend: BackendDarwin})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close()) })

	label := strings.Repeat("x", 63)
	cfg := Config{Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	for i := range 10 {
		cfg.SearchDomains = append(cfg.SearchDomains, fmt.Sprintf("%s.%s.%s.k%d.example", label, label, label, i))
	}
	err = m.Set(cfg)
	require.ErrorContains(t, err, "macOS accepts at most 2047 bytes")
	var e *Error
	assert.False(t, errors.As(err, &e), "a platform limit is returned unwrapped")
	s := m.Status()
	assert.Equal(t, GoalNone, s.Goal)
	assert.NoError(t, s.LastError)
}
