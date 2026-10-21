package backend_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

func TestValidateIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"simple", "app", true},
		{"punctuation", "my-net.example_1", true},
		{"max length", strings.Repeat("a", 63), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 64), false},
		{"uppercase", "App", false},
		{"leading dash", "-a", false},
		{"slash", "a/b", false},
		{"dot dot slash", "../etc", false},
		{"backslash", `a\b`, false},
		{"newline", "a\nremove State:/Network/Global/DNS", false},
		{"space", "a b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := backend.ValidateIdentity(tc.in)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
