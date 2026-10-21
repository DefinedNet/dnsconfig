package backend_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

func TestNewConflictError(t *testing.T) {
	for _, tc := range []struct {
		name, domain, want, text string
	}{
		{name: "domain", domain: "Corp.Example", want: "corp.example.", text: `domain corp.example. held by identity "net-b"`},
		{name: "catch-all", domain: ".", want: ".", text: `catch-all held by identity "net-b"`},
		{name: "already canonical", domain: "corp.example.", want: "corp.example.", text: `domain corp.example. held by identity "net-b"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := backend.NewConflictError(tc.domain, "net-b")
			assert.Equal(t, tc.want, err.Domain)
			assert.Equal(t, "net-b", err.Holder)
			assert.Equal(t, tc.text, err.Error())

			wrapped := fmt.Errorf("refused: %w", err)
			require.ErrorIs(t, wrapped, backend.ErrConflict, "a ConflictError carries ErrConflict")
			var conflict *backend.ConflictError
			require.ErrorAs(t, wrapped, &conflict)
			assert.Same(t, err, conflict)
			assert.NotErrorIs(t, wrapped, backend.ErrGroupPolicyContainerEmpty, "Is matches ErrConflict only")
		})
	}
}
