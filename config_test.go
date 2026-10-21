package dnsconfig

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string // substring the error must contain; "" means no error
	}{
		{
			name:    "zero config rejected as empty",
			cfg:     Config{},
			wantErr: "empty Config",
		},
		{
			name:    "non-zero config without nameservers",
			cfg:     Config{SearchDomains: []string{"example.com"}},
			wantErr: "has no Nameservers",
		},
		{
			name:    "zero netip.Addr nameserver",
			cfg:     Config{Nameservers: []netip.Addr{{}}},
			wantErr: "is the zero netip.Addr",
		},
		{
			name: "IPv4 unspecified rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("0.0.0.0"),
			}},
			wantErr: "Nameservers[1] (0.0.0.0) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "IPv6 unspecified rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("::"),
			}},
			wantErr: "Nameservers[1] (::) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "IPv4-mapped unspecified rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("::ffff:0.0.0.0"),
			}},
			wantErr: "Nameservers[1] (::ffff:0.0.0.0) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "IPv4 multicast rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("224.0.0.251"),
			}},
			wantErr: "Nameservers[1] (224.0.0.251) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "IPv6 multicast rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("ff02::fb"),
			}},
			wantErr: "Nameservers[1] (ff02::fb) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "IPv4-mapped multicast rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("::ffff:239.1.1.1"),
			}},
			wantErr: "Nameservers[1] (::ffff:239.1.1.1) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "IPv4 limited broadcast rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("255.255.255.255"),
			}},
			wantErr: "Nameservers[1] (255.255.255.255) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "IPv4-mapped limited broadcast rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("::ffff:255.255.255.255"),
			}},
			wantErr: "Nameservers[1] (::ffff:255.255.255.255) is an unspecified, multicast, or broadcast address",
		},
		{
			name: "unzoned IPv4 accepted",
			cfg:  Config{Nameservers: []netip.Addr{netip.MustParseAddr("1.1.1.1")}},
		},
		{
			name: "unzoned IPv6 accepted",
			cfg:  Config{Nameservers: []netip.Addr{netip.MustParseAddr("2001:db8::1")}},
		},
		{
			name: "zoned link-local IPv6 accepted",
			cfg:  Config{Nameservers: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}},
		},
		{
			name: "numeric zone accepted",
			cfg:  Config{Nameservers: []netip.Addr{netip.MustParseAddr("fe80::1%5")}},
		},
		{
			name:    "zoned global IPv6 rejected",
			cfg:     Config{Nameservers: []netip.Addr{netip.MustParseAddr("2001:db8::1%eth0")}},
			wantErr: "zones are valid only",
		},
		{
			name: "unsafe zone rejected",
			cfg: Config{Nameservers: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("fe80::1").WithZone("eth0\nremove State:/Network/Global/DNS"),
			}},
			wantErr: "Nameservers[2]",
		},
		{
			name: "search domain equal to a match domain accepted",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"corp.example."},
				MatchDomains:  []string{"corp.example."},
			},
		},
		{
			name: "search domain under a match domain accepted",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"eng.corp.example."},
				MatchDomains:  []string{"other.example.", "corp.example."},
			},
		},
		{
			name: "catch-all search domain needs no match domain",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"corp.example."},
			},
		},
		{
			name: "split search domain outside every match domain rejected",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"corp.example."},
				MatchDomains:  []string{"internal.example."},
			},
			wantErr: "SearchDomains[0] (\"corp.example.\") is not under any MatchDomains entry",
		},
		{
			name: "split search domain that is a parent of a match domain rejected",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"example."},
				MatchDomains:  []string{"corp.example."},
			},
			wantErr: "SearchDomains[0]",
		},
		{
			name: "split search domain sharing only a label suffix rejected",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"notcorp.example."},
				MatchDomains:  []string{"corp.example."},
			},
			wantErr: "SearchDomains[0]",
		},
		{
			name: "coverage reported per search domain index",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"corp.example.", "lab.example."},
				MatchDomains:  []string{"corp.example."},
			},
			wantErr: "SearchDomains[1]",
		},
		{
			name: "root search domain rejected",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"corp.example.", "."},
			},
			wantErr: "SearchDomains[1] must not be the root domain",
		},
		{
			name: "root-only match domain rejected",
			cfg: Config{
				Nameservers:  []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				MatchDomains: []string{"."},
			},
			wantErr: "MatchDomains[0] must not be the root domain",
		},
		{
			name: "root match domain rejected",
			cfg: Config{
				Nameservers:  []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				MatchDomains: []string{"corp.example.", "."},
			},
			wantErr: "MatchDomains[1] must not be the root domain",
		},
		{
			name: "garbage search domain rejected",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"not a domain"},
			},
			wantErr: "SearchDomains[0]",
		},
		{
			name: "mixed-case domains accepted",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"Eng.Corp.Example."},
				MatchDomains:  []string{"CORP.example."},
			},
		},
		{
			name: "domains without trailing dot accepted",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"eng.corp.example"},
				MatchDomains:  []string{"corp.example"},
			},
		},
		{
			name: "coverage compares canonical forms",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"Corp.Example"},
				MatchDomains:  []string{"corp.example."},
			},
		},
		{
			name: "garbage match domain rejected",
			cfg: Config{
				Nameservers:  []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				MatchDomains: []string{"ok.example.", "bad domain"},
			},
			wantErr: "MatchDomains[1] (\"bad domain\") is not a valid domain",
		},
		{
			name: "empty-string domain rejected",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{""},
			},
			wantErr: "SearchDomains[0] is empty",
		},
		{
			name: "domain repeated in another spelling rejected",
			cfg: Config{
				Nameservers:  []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				MatchDomains: []string{"a.example", "b.example.", "A.Example."},
			},
			wantErr: "MatchDomains[2] (\"A.Example.\") duplicates MatchDomains[0]",
		},
		{
			name: "same domain in search and match accepted",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"corp.example"},
				MatchDomains:  []string{"Corp.Example."},
			},
		},
		{
			name: "non-ASCII character named whole",
			cfg: Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
				SearchDomains: []string{"bücher.example"},
			},
			wantErr: "invalid character 'ü'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestConfigEqual(t *testing.T) {
	ns := func(addrs ...string) []netip.Addr {
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	domains := func(names ...string) []string { return names }
	base := Config{
		Nameservers:   ns("192.0.2.1", "192.0.2.2"),
		SearchDomains: domains("corp.example."),
		MatchDomains:  domains("internal.example."),
	}
	cases := []struct {
		name  string
		other Config
		want  bool
	}{
		{"identical", base, true},
		{"equal copies", Config{
			Nameservers:   ns("192.0.2.1", "192.0.2.2"),
			SearchDomains: append([]string{}, base.SearchDomains...),
			MatchDomains:  append([]string{}, base.MatchDomains...),
		}, true},
		{"nameserver order", Config{
			Nameservers:   ns("192.0.2.2", "192.0.2.1"),
			SearchDomains: base.SearchDomains,
			MatchDomains:  base.MatchDomains,
		}, false},
		{"search domain differs", Config{
			Nameservers:   base.Nameservers,
			SearchDomains: domains("other.example."),
			MatchDomains:  base.MatchDomains,
		}, false},
		{"match domain missing", Config{
			Nameservers:   base.Nameservers,
			SearchDomains: base.SearchDomains,
		}, false},
		{"case and trailing dot ignored", Config{
			Nameservers:   base.Nameservers,
			SearchDomains: domains("Corp.Example"),
			MatchDomains:  domains("INTERNAL.example."),
		}, true},
		{"invalid names compare exactly", Config{
			Nameservers:   base.Nameservers,
			SearchDomains: domains("corp example"),
			MatchDomains:  base.MatchDomains,
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, base.Equal(tc.other))
			assert.Equal(t, tc.want, tc.other.Equal(base), "Equal is symmetric")
		})
	}

	empty := Config{
		Nameservers:   []netip.Addr{},
		SearchDomains: []string{},
		MatchDomains:  []string{},
	}
	for _, tc := range []struct {
		name string
		a, b Config
	}{
		{"zero values", Config{}, Config{}},
		{"nil and empty slices agree", Config{}, empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, tc.a.Equal(tc.b))
			assert.True(t, tc.b.Equal(tc.a))
		})
	}
}

func TestConfigValidateDoesNotModify(t *testing.T) {
	c := Config{
		Nameservers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		SearchDomains: []string{"Eng.Corp.Example"},
		MatchDomains:  []string{"Corp.Example"},
	}
	require.NoError(t, c.Validate())
	assert.Equal(t, []string{"Eng.Corp.Example"}, c.SearchDomains)
	assert.Equal(t, []string{"Corp.Example"}, c.MatchDomains)
}
