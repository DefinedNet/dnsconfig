package dnsconfig

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBackendKindIsValidAcceptsAndRejects samples valid and invalid kinds.
// The exhaustive linter checks coverage of declared constants in IsValid.
func TestBackendKindIsValidAcceptsAndRejects(t *testing.T) {
	assert.True(t, BackendAuto.IsValid(), "the zero value requests detection and is valid")
	assert.True(t, BackendDarwin.IsValid())
	assert.True(t, BackendNoop.IsValid())

	assert.False(t, BackendKind("unknown").IsValid())
	assert.False(t, BackendKind("Darwin").IsValid(), "the comparison is exact, not case-folded")
}

// TestOptionsValidate pins the closed-set checks and that every failure is
// classifiable without matching on its text.
func TestOptionsValidate(t *testing.T) {
	cases := []struct {
		name   string
		opts   Options
		wantIn string
	}{
		{"identity only", Options{Identity: "app"}, ""},
		{"explicit backend", Options{Identity: "app", ForceBackend: BackendDarwin}, ""},
		{"unknown backend", Options{Identity: "app", ForceBackend: BackendKind("unknown")}, "ForceBackend"},
		{"zero", Options{}, "identity"},
		{"shutdown timeout set", Options{Identity: "app", ShutdownTimeout: time.Second}, ""},
		{"negative shutdown timeout", Options{Identity: "app", ShutdownTimeout: -time.Second}, "ShutdownTimeout"},
		{"identity with slash", Options{Identity: "a/b"}, "identity"},
		{"identity uppercase", Options{Identity: "App"}, "identity"},
		{"identity leading dash", Options{Identity: "-a"}, "identity"},
		{"identity too long", Options{Identity: strings.Repeat("a", 64)}, "identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.opts.Validate()
			if tc.wantIn == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidOptions)
			assert.Contains(t, err.Error(), tc.wantIn)
		})
	}
}

// TestNewRejectsInvalidOptions ensures caller errors are returned before
// backend construction and without an operation error wrapper.
func TestNewRejectsInvalidOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"unknown backend", Options{Identity: "app", ForceBackend: BackendKind("unknown")}},
		{"missing identity", Options{ForceBackend: BackendNoop}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := New(context.Background(), tc.opts)
			require.Error(t, err)
			assert.Nil(t, m)
			assert.ErrorIs(t, err, ErrInvalidOptions)
			var e *Error
			assert.NotErrorAs(t, err, &e, "a malformed Options is not an operation failure")
		})
	}
}

// TestNewRejectsBackendAbsentOnThisOS distinguishes invalid options from
// host conditions that a caller might retry.
func TestNewRejectsBackendAbsentOnThisOS(t *testing.T) {
	kind := BackendWindows
	if runtime.GOOS == "windows" {
		kind = BackendDarwin
	}
	m, err := New(context.Background(), Options{Identity: "app", ForceBackend: kind})
	require.Error(t, err)
	assert.Nil(t, m)
	assert.ErrorIs(t, err, ErrInvalidOptions)
	assert.ErrorContains(t, err, fmt.Sprintf("backend %q is not supported on %s", kind, runtime.GOOS))
	var e *Error
	require.ErrorAs(t, err, &e, "the constructor answered, so this is a construction failure")
	assert.Equal(t, "New", e.Op)
	assert.Equal(t, kind, e.Backend)
}
