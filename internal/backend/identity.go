package backend

import (
	"errors"
	"fmt"
	"regexp"
)

// identityPattern bounds an identity to characters that are safe in scutil key
// names, registry key names, and resolver-file headers. Lowercase only, so one
// identity has exactly one spelling in every namespace it names.
var identityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidateIdentity reports whether s is an acceptable identity. Each backend
// checks it again at construction because it interpolates the identity
// unescaped into scutil scripts, file names, and registry paths.
func ValidateIdentity(s string) error {
	if s == "" {
		return errors.New("identity is required")
	}
	if !identityPattern.MatchString(s) {
		return fmt.Errorf("identity %q must match %s", s, identityPattern)
	}
	return nil
}
