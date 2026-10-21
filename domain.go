package dnsconfig

import (
	"errors"
	"fmt"
	"strings"
)

// maxDomainLength is the maximum length of a textual domain name in bytes,
// including its trailing dot.
const maxDomainLength = 254

// maxLabelLength is the maximum length of a single DNS label in bytes,
// per RFC 1035 section 2.3.4.
const maxLabelLength = 63

// parseDomain returns s in canonical form, lowercase with a single trailing
// dot. "." is the root domain and must be spelled explicitly, so a blank
// field is an error rather than silently naming every domain.
func parseDomain(s string) (string, error) {
	if s == "" {
		return "", errors.New(`empty domain name; use "." for the root domain`)
	}
	if s == "." {
		return s, nil
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	if len(s) > maxDomainLength {
		return "", fmt.Errorf("%q exceeds %d bytes", s, maxDomainLength)
	}
	for _, lab := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if lab == "" {
			return "", fmt.Errorf("%q has empty label", s)
		}
		if len(lab) > maxLabelLength {
			return "", fmt.Errorf("label %q exceeds %d bytes", lab, maxLabelLength)
		}
		if err := validateLabel(lab); err != nil {
			return "", fmt.Errorf("%q: %w", s, err)
		}
	}
	return strings.ToLower(s), nil
}

// validateLabel allows underscores as well as letters, digits, and hyphens
// because names such as SRV records and ACME challenges require them.
func validateLabel(lab string) error {
	// Ranging over runes keeps a multibyte character whole in the error.
	for _, c := range lab {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return fmt.Errorf("invalid character %q in label %q", c, lab)
		}
	}
	if lab[0] == '-' || lab[len(lab)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with hyphen", lab)
	}
	return nil
}

// isUnder reports whether canonical name equals canonical non-root suffix or
// sits under it at a label boundary, so "fooexample." is not under "example.".
func isUnder(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}
