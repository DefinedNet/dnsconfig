//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// scutilDNSHeader opens every section of a completed scutil --dns read.
const scutilDNSHeader = "DNS configuration"

type dnsResolver struct {
	Domain     string
	Servers    []string
	Order      int
	Supplement bool
	Scoped     bool
}

// parseDNSResolvers accepts only a table under the "DNS configuration"
// header as a completed scutil --dns read. scutil prints "No DNS
// configuration available" both when configd has no configuration and when
// it cannot reach configd, so that line is unanswered like any other output.
func parseDNSResolvers(body []byte) ([]dnsResolver, error) {
	text := strings.TrimSpace(string(body))
	if first, _, _ := strings.Cut(text, "\n"); !strings.HasPrefix(strings.TrimSpace(first), scutilDNSHeader) {
		return nil, unansweredError("--dns", strings.TrimSpace(first))
	}
	var out []dnsResolver
	var current *dnsResolver
	var scoped bool
	for raw := range strings.SplitSeq(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, scutilDNSHeader) {
			scoped = strings.Contains(line, "(")
			current = nil
			continue
		}
		if strings.HasPrefix(line, "resolver #") {
			out = append(out, dnsResolver{Scoped: scoped})
			current = &out[len(out)-1]
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, " : ")
		if !ok {
			if strings.HasPrefix(line, "domain") && strings.HasSuffix(line, ":") {
				current.Domain = ""
			}
			continue
		}
		key = strings.TrimSpace(key)
		switch {
		case key == "domain":
			current.Domain = strings.TrimSuffix(value, ".")
		case strings.HasPrefix(key, "nameserver["):
			current.Servers = append(current.Servers, value)
		case key == "flags":
			current.Supplement = strings.Contains(value, "Supplemental")
			current.Scoped = current.Scoped || strings.Contains(value, "Scoped")
		case key == "order":
			current.Order, _ = strconv.Atoi(value)
		}
	}
	return out, nil
}

func (b *Backend) readCompiledDNS(ctx context.Context) ([]dnsResolver, error) {
	stdout, stderr, err := b.runner.Run(ctx, scutilBinary, []string{"--dns"}, nil)
	if err != nil {
		return nil, fmt.Errorf("darwin: scutil --dns: %w: %s", err, bytes.TrimSpace(stderr))
	}
	if len(stdout) > maxScutilOutput {
		return nil, fmt.Errorf("darwin: scutil --dns exceeded %d bytes", maxScutilOutput)
	}
	return parseDNSResolvers(stdout)
}

// verifyCompiledDNS requires a non-scoped supplemental resolver for every
// key domain carrying the key's first server. It checks presence only.
func verifyCompiledDNS(keys []stateKeyConfig, resolvers []dnsResolver) error {
	for _, key := range keys {
		for _, domain := range key.Domains {
			found := false
			for _, resolver := range resolvers {
				if resolver.Scoped || resolver.Domain != domain || !resolver.Supplement ||
					!slices.Contains(resolver.Servers, key.Servers[0]) {
					continue
				}
				found = true
				break
			}
			if !found {
				return fmt.Errorf("darwin: compiled resolver table does not contain supplemental domain %q on %s", domain, key.Servers[0])
			}
		}
	}
	return nil
}

func addrsToStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, addr := range addrs {
		out[i] = addr.String()
	}
	return out
}
