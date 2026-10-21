package dnsconfig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDomainAccepts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "example.com", "example.com."},
		{"trailing-dot", "example.com.", "example.com."},
		{"deep", "a.b.c.example.com.", "a.b.c.example.com."},
		{"root-dot", ".", "."},
		{"lowercased", "Example.COM", "example.com."},
		{"single-label", "localhost", "localhost."},
		{"digits", "1.2.3.example.", "1.2.3.example."},
		{"hyphen-middle", "foo-bar.example.", "foo-bar.example."},
		{"underscore-label", "_acme-challenge.example.", "_acme-challenge.example."},
		{"max-label", strings.Repeat("a", 63) + ".example.", strings.Repeat("a", 63) + ".example."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDomain(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseDomainRejects(t *testing.T) {
	// 254 bytes total is the limit; build a name that exceeds it after the
	// trailing dot is added.
	overlongLabel := strings.Repeat("a", 64)
	tooLongName := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." +
		strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." +
		strings.Repeat("e", 60)

	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"too-long-name", tooLongName},
		{"label-too-long", overlongLabel + ".example."},
		{"leading-hyphen", "-foo.example."},
		{"trailing-hyphen", "foo-.example."},
		{"dollar-sign", "fo$o.example."},
		{"space", "foo bar.example."},
		{"empty-label", "foo..example."},
		{"leading-dot", ".example."},
		{"double-trailing-dot", "example.."},
		{"kelvin-sign", "\u212aorp.example"},
		{"dotted-capital-i", "\u0130nternal.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDomain(tc.in)
			assert.Error(t, err, "expected parseDomain(%q) to fail", tc.in)
		})
	}
}

func TestIsUnder(t *testing.T) {
	cases := []struct {
		name   string
		d      string
		suffix string
		want   bool
	}{
		{"label-boundary-match", "foo.example.", "example.", true},
		{"deep-match", "a.b.example.com.", "example.com.", true},
		{"non-boundary-no-match", "fooexample.", "example.", false},
		{"equal", "example.com.", "example.com.", true},
		{"longer-suffix-no-match", "com.", "example.com.", false},
		{"different-no-match", "example.org.", "example.com.", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isUnder(tc.d, tc.suffix))
		})
	}
}
