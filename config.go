package dnsconfig

import (
	"fmt"
	"net/netip"
	"slices"
)

// Config is the DNS configuration a caller asks the OS to apply.
//
// [Manager.Set] makes it the goal the Manager converges the host toward.
// Static per-name host overrides are outside this API.
//
// Domains are case-insensitive and may omit the trailing dot:
// "Corp.Example" and "corp.example." name the same domain. Labels may contain
// ASCII letters, digits, hyphens, and underscores. Configs that [Manager.Set]
// accepts and [Status] reports back use the canonical form, lowercase with a
// trailing dot.
type Config struct {
	// Nameservers is the list of DNS server addresses queries should be
	// sent to. Must be non-empty for a non-zero Config.
	//
	// The list is applied in order and is not deduplicated. [Manager.Set]
	// rejects a list that exceeds the OS mechanism's hard limit; it never
	// silently truncates. macOS split DNS accepts at most three nameservers. Entries are IP addresses
	// without ports; a non-53 upstream port requires a caller-provided forwarder
	// on port 53.
	//
	// Unspecified (0.0.0.0, ::), multicast, and limited broadcast
	// (255.255.255.255) addresses are rejected, including their IPv4-mapped
	// IPv6 forms.
	//
	// IPv6 link-local addresses may carry a zone (e.g. fe80::1%en0).
	// macOS preserves it; Windows rejects it because NRPT scoped-address
	// support is undocumented.
	Nameservers []netip.Addr

	// SearchDomains is the list of domain suffixes appended to single-label
	// names during resolution. May be empty; entries must not be the root
	// domain. Entries keep their configured order. In a split configuration
	// each entry must sit under a MatchDomains entry.
	//
	// macOS publishes every entry, in configured order, in one dynamic-store
	// key ahead of the primary service's search domains, so requested
	// suffixes take precedence for short names; the relative order of
	// different identities' suffixes is unspecified. [Manager.Set] rejects a
	// list that does not fit one scutil command line (2047 bytes, at most 99
	// entries). An
	// entry the primary service lists in the same spelling moves to the
	// front; one it lists in a different case appears twice; its other
	// domains keep their order. Each entry also routes that exact domain to
	// Nameservers unless an identity's MatchDomains entry for that exact
	// domain exists, since the resolver file wins over every search entry.
	// Another identity's search entry for it causes [ErrConflict] unless
	// this identity or that one has it in MatchDomains; then the two share
	// the suffix, which appears once in the search list. As an exact domain it can outrank another
	// resolver more specific than MatchDomains or a catch-all. [Manager.Clear] removes what this identity published. Windows
	// sets suffixes on the controlled adapter and allows the same suffix on
	// other identities' adapters; routing comes from MatchDomains alone. Global
	// and policy search lists remain unchanged and can suppress adapter suffixes.
	SearchDomains []string

	// MatchDomains, when non-empty, requests split DNS: queries whose names
	// end in one of these suffixes route to Nameservers. Empty MatchDomains
	// means Nameservers handles everything (catch-all). Entries must not be
	// the root domain; express catch-all with an empty list.
	//
	// Reverse-lookup zones belong here too. A split configuration listing
	// only forward suffixes sends PTR queries to the host's other resolvers,
	// potentially disclosing private addresses. List the covering zones
	// alongside the forward suffixes: "2.0.192.in-addr.arpa." for
	// 192.0.2.0/24, "8.b.d.0.1.0.0.2.ip6.arpa." for 2001:db8::/32. Name the
	// zone that covers the prefix, not the whole "in-addr.arpa." or
	// "ip6.arpa." tree, which would capture every reverse lookup on the host.
	MatchDomains []string
}

// Validate reports whether c is internally consistent. It does not check
// whether c can be applied by any particular backend; [Manager.Set] also
// checks the platform's limits before recording c as its goal.
//
// Each domain must be a valid name, neither list may contain the root domain
// or the same domain twice in any spelling, and in a split configuration each
// search domain must equal or sit under a MatchDomains entry. Validate does not
// modify c.
func (c Config) Validate() error {
	if c.IsZero() {
		return ErrEmptyConfig
	}
	if len(c.Nameservers) == 0 {
		return fmt.Errorf("dnsconfig: Config has no Nameservers")
	}
	for i, ns := range c.Nameservers {
		if !ns.IsValid() {
			return fmt.Errorf("dnsconfig: Nameservers[%d] is the zero netip.Addr", i)
		}
		// Unmap so ::ffff:0.0.0.0 and ::ffff:255.255.255.255 are caught too;
		// IsUnspecified does not look through the mapping.
		if a := ns.Unmap(); a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return fmt.Errorf("dnsconfig: Nameservers[%d] (%s) is an unspecified, multicast, or broadcast address, which cannot serve DNS", i, ns)
		}
		if zone := ns.Zone(); zone != "" {
			if !ns.Is6() || !ns.IsLinkLocalUnicast() {
				return fmt.Errorf("dnsconfig: Nameservers[%d] (%s) has a zone, but zones are valid only on IPv6 link-local nameservers", i, ns)
			}
			for _, c := range zone {
				if !isZoneChar(c) {
					return fmt.Errorf("dnsconfig: Nameservers[%d] (%s) has invalid zone %q", i, ns, zone)
				}
			}
		}
	}
	search, err := parseDomains("SearchDomains", c.SearchDomains, "")
	if err != nil {
		return err
	}
	match, err := parseDomains("MatchDomains", c.MatchDomains, "; use empty MatchDomains for catch-all")
	if err != nil {
		return err
	}
	// macOS cannot publish a search suffix without routing it, so a search
	// domain means "search and route" on every platform; catch-all already routes.
	if c.IsSplit() {
		for i, d := range search {
			if !slices.ContainsFunc(match, func(m string) bool { return isUnder(d, m) }) {
				return fmt.Errorf("dnsconfig: SearchDomains[%d] (%q) is not under any MatchDomains entry", i, c.SearchDomains[i])
			}
		}
	}
	return nil
}

// parseDomains checks an empty entry before parseDomain, whose own empty-name
// error suggests the root domain that Config forbids. It rejects entries that
// differ only in case or trailing dot, which would otherwise be published
// twice.
func parseDomains(field string, domains []string, rootHint string) ([]string, error) {
	out := make([]string, len(domains))
	seen := make(map[string]int, len(domains))
	for i, d := range domains {
		if d == "" {
			return nil, fmt.Errorf("dnsconfig: %s[%d] is empty", field, i)
		}
		f, err := parseDomain(d)
		if err != nil {
			return nil, fmt.Errorf("dnsconfig: %s[%d] (%q) is not a valid domain: %w", field, i, d, err)
		}
		if f == "." {
			return nil, fmt.Errorf("dnsconfig: %s[%d] must not be the root domain%s", field, i, rootHint)
		}
		if j, ok := seen[f]; ok {
			return nil, fmt.Errorf("dnsconfig: %s[%d] (%q) duplicates %s[%d]", field, i, d, field, j)
		}
		seen[f] = i
		out[i] = f
	}
	return out, nil
}

func isZoneChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

// IsZero reports whether c is the zero value (no nameservers, no domains).
// A zero Config is rejected by Validate with ErrEmptyConfig: it is not a
// request to revert. Callers remove configuration with [Manager.Clear].
func (c Config) IsZero() bool {
	return len(c.Nameservers) == 0 &&
		len(c.SearchDomains) == 0 &&
		len(c.MatchDomains) == 0
}

// IsSplit reports whether c requests split DNS (non-empty MatchDomains).
func (c Config) IsSplit() bool { return len(c.MatchDomains) > 0 }

// Equal reports whether c and other hold the same nameservers, search
// domains, and match domains in the same order. Domains compare in canonical
// form, so case and a trailing dot do not matter. Order matters because Set
// neither deduplicates nor reorders. Addresses compare as given, so an
// IPv4-mapped IPv6 address differs from its IPv4 form although Set installs
// both the same way.
func (c Config) Equal(other Config) bool {
	return slices.Equal(c.Nameservers, other.Nameservers) &&
		slices.EqualFunc(c.SearchDomains, other.SearchDomains, sameDomain) &&
		slices.EqualFunc(c.MatchDomains, other.MatchDomains, sameDomain)
}

// sameDomain compares invalid names exactly, since they have no canonical form.
func sameDomain(a, b string) bool {
	if a == b {
		return true
	}
	fa, errA := parseDomain(a)
	fb, errB := parseDomain(b)
	return errA == nil && errB == nil && fa == fb
}

// canonical returns a copy of c with every domain in canonical form. It
// expects a Config that passed Validate; invalid names are copied unchanged.
func (c Config) canonical() Config {
	return Config{
		Nameservers:   slices.Clone(c.Nameservers),
		SearchDomains: canonicalDomains(c.SearchDomains),
		MatchDomains:  canonicalDomains(c.MatchDomains),
	}
}

func canonicalDomains(domains []string) []string {
	if domains == nil {
		return nil
	}
	out := make([]string, len(domains))
	for i, d := range domains {
		out[i] = canonicalDomain(d)
	}
	return out
}

func canonicalDomain(d string) string {
	if f, err := parseDomain(d); err == nil {
		return f
	}
	return d
}
