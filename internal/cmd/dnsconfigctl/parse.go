package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// parseAddrList parses a comma-separated list of IP addresses. Empty input
// is an error.
func parseAddrList(raw string) ([]netip.Addr, error) {
	parts := splitCommas(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no addresses provided")
	}
	out := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		a, err := netip.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", p, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// parseDomainList splits a comma-separated domain list; Config.Validate
// checks the names.
func parseDomainList(raw string) ([]string, error) {
	parts := splitCommas(raw)
	if len(parts) == 0 {
		return nil, fmt.Errorf("no domains provided")
	}
	return parts, nil
}

// splitCommas trims comma-separated values and discards empty entries.
func splitCommas(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
