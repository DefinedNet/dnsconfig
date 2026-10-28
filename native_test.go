package dnsconfig

import (
	"context"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewConstructsNativeBackend checks native constructor wiring that fake
// backends cannot validate, without applying DNS configuration. The nil
// Logger relies on New substituting a discard logger, since the native
// constructors reject nil.
func TestNewConstructsNativeBackend(t *testing.T) {
	var kind BackendKind
	switch runtime.GOOS {
	case "darwin":
		// A non-root test user would get a declined Manager here.
		t.Skip("covered by TestNew_DarwinWithRootBuildsBackend, which forces the root check")
	case "windows":
		kind = BackendWindows
	default:
		t.Skip("no native backend on this OS")
	}
	m, err := New(context.Background(), Options{Identity: "facade-test", ForceBackend: kind})
	require.NoError(t, err)
	require.NoError(t, m.Close())
}
