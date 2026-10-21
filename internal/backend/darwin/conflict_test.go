//go:build darwin

package darwin

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

const thirdIdentity = "third-app"

// sharedHost is one fake host that several identities' backends converge on.
type sharedHost struct {
	t        *testing.T
	fs       *testFS
	fake     *scutilFake
	backends map[string]*Backend
}

func newSharedHost(t *testing.T) *sharedHost {
	return &sharedHost{t: t, fs: newTestFS(t), fake: newScutilFake(), backends: map[string]*Backend{}}
}

func (h *sharedHost) backend(identity string) *Backend {
	if b, ok := h.backends[identity]; ok {
		return b
	}
	b, err := New(context.Background(), Options{Identity: identity, FS: h.fs, Runner: h.fake, Logger: discardLogger(), IsRoot: asRoot})
	require.NoError(h.t, err)
	useFS(b, h.fs)
	h.t.Cleanup(func() { _ = b.Close() })
	h.backends[identity] = b
	return b
}

func ns(addr string) []netip.Addr { return []netip.Addr{netip.MustParseAddr(addr)} }

// The Acme shapes: an office catch-all searching corp.example, and an
// infrastructure network routing it.
var (
	officeCatchAll = backend.Config{Nameservers: ns("127.0.0.99"), SearchDomains: []string{"corp.example"}}
	infraRoutes    = backend.Config{Nameservers: ns("127.0.0.98"), MatchDomains: []string{"corp.example", "cloud.example"}}
	infraSearches  = backend.Config{Nameservers: ns("127.0.0.98"), MatchDomains: []string{"corp.example", "cloud.example"}, SearchDomains: []string{"corp.example"}}
	parentSearcher = backend.Config{Nameservers: ns("127.0.0.97"), MatchDomains: []string{"example"}, SearchDomains: []string{"corp.example"}}
	fileOnly       = backend.Config{Nameservers: ns("127.0.0.96"), MatchDomains: []string{"corp.example"}}
	officeSub      = backend.Config{Nameservers: ns("127.0.0.99"), SearchDomains: []string{"eng.corp.example"}}
	infraSub       = backend.Config{Nameservers: ns("127.0.0.98"), MatchDomains: []string{"corp.example"}, SearchDomains: []string{"eng.corp.example"}}
	otherCatchAll  = backend.Config{Nameservers: ns("127.0.0.95"), SearchDomains: []string{"lab.example"}}
)

type claimStep struct {
	identity string
	cfg      backend.Config
	// conflict is the refused domain and holder, or empty when Set succeeds.
	conflict, holder string
}

// TestFileCoversKeyClaims runs the macOS claim rule in both arrival orders:
// a State key beside the resolver file of the key holder or of its peer,
// including one this attempt writes, does not conflict; two files, two
// catch-alls, and two keys neither holder covers do, even when a third
// identity owns the file, as does a search domain more specific than any
// file.
// Every admitted identity then repairs without refusal and reports no
// shadowing, and the folded search-list entry passes verification.
func TestFileCoversKeyClaims(t *testing.T) {
	a, b, c := testIdentity, otherIdentity, thirdIdentity
	for _, tc := range []struct {
		name  string
		steps []claimStep
	}{
		{"search key then file", []claimStep{{identity: a, cfg: officeCatchAll}, {identity: b, cfg: infraRoutes}}},
		{"file then search key", []claimStep{{identity: b, cfg: infraRoutes}, {identity: a, cfg: officeCatchAll}}},
		{"search key then file and key", []claimStep{{identity: a, cfg: officeCatchAll}, {identity: b, cfg: infraSearches}}},
		{"file and key then search key", []claimStep{{identity: b, cfg: infraSearches}, {identity: a, cfg: officeCatchAll}}},
		{"file owner adds the shared search domain later", []claimStep{
			{identity: a, cfg: officeCatchAll}, {identity: b, cfg: infraRoutes}, {identity: b, cfg: infraSearches},
		}},
		{"a third identity's file covers neither key", []claimStep{
			{identity: c, cfg: fileOnly}, {identity: a, cfg: officeCatchAll},
			{identity: b, cfg: parentSearcher, conflict: "corp.example.", holder: a},
		}},
		{"a third identity's file covers neither key, other order", []claimStep{
			{identity: c, cfg: fileOnly}, {identity: b, cfg: parentSearcher},
			{identity: a, cfg: officeCatchAll, conflict: "corp.example.", holder: b},
		}},
		{"file owner's key admits one peer, not a second", []claimStep{
			{identity: a, cfg: officeCatchAll}, {identity: c, cfg: infraSearches},
			{identity: b, cfg: parentSearcher, conflict: "corp.example.", holder: a},
		}},
		{"two uncovered keys", []claimStep{
			{identity: a, cfg: officeCatchAll}, {identity: b, cfg: parentSearcher, conflict: "corp.example.", holder: a},
		}},
		{"two uncovered keys, other order", []claimStep{
			{identity: b, cfg: parentSearcher}, {identity: a, cfg: officeCatchAll, conflict: "corp.example.", holder: b},
		}},
		{"two files", []claimStep{
			{identity: b, cfg: infraRoutes}, {identity: c, cfg: fileOnly, conflict: "corp.example.", holder: b},
		}},
		{"two catch-alls", []claimStep{
			{identity: a, cfg: officeCatchAll}, {identity: b, cfg: otherCatchAll, conflict: ".", holder: a},
		}},
		{"subdomain search more specific than the file", []claimStep{
			{identity: a, cfg: officeSub}, {identity: b, cfg: infraSub, conflict: "eng.corp.example.", holder: a},
		}},
		{"subdomain search more specific than the file, other order", []claimStep{
			{identity: b, cfg: infraSub}, {identity: a, cfg: officeSub, conflict: "eng.corp.example.", holder: b},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSharedHost(t)
			admitted := map[string]backend.Config{}
			for i, step := range tc.steps {
				be := h.backend(step.identity)
				before := observeHost(h.fs, h.fake)
				err := trySet(be, step.cfg)
				if step.conflict == "" {
					require.NoError(t, err, "step %d", i)
					admitted[step.identity] = step.cfg
					continue
				}
				var conflict *backend.ConflictError
				require.ErrorAs(t, err, &conflict, "step %d", i)
				assert.Equal(t, step.conflict, conflict.Domain)
				assert.Equal(t, step.holder, conflict.Holder)
				assertQuiet(t, observeHost(h.fs, h.fake).since(before), "a refused Set writes nothing")
			}
			for identity, cfg := range admitted {
				be := h.backends[identity]
				_, err := be.Set(context.Background(), cfg, repeat)
				require.NoError(t, err, "%s repairs without refusal", identity)
			}
		})
	}
}

// TestKeysRemovedBeforeFiles: Clear and a Set's obsolete cleanup remove
// State keys before resolver files, so no other identity's key for a covered
// domain is left beside ours without the file.
func TestKeysRemovedBeforeFiles(t *testing.T) {
	key := "scutil remove " + stateKeyName(testIdentity, 0)
	file := "fs Remove corp.example"

	t.Run("clear", func(t *testing.T) {
		fs := newTestFS(t)
		fake := newScutilFake()
		b := newTestBackend(t, fs, fake)
		require.NoError(t, trySet(b, splitConfig()))
		order := recordOrder(fs, fake)
		require.NoError(t, tryClear(b))
		assertInOrder(t, order.snapshot(), key, file)
	})
	t.Run("obsolete", func(t *testing.T) {
		fs := newTestFS(t)
		fake := newScutilFake()
		b := newTestBackend(t, fs, fake)
		require.NoError(t, trySet(b, splitConfig()))
		order := recordOrder(fs, fake)
		next := backend.Config{Nameservers: ns("127.0.0.99"), MatchDomains: []string{"lab.example"}}
		require.NoError(t, trySet(b, next))
		assertInOrder(t, order.snapshot(), key, file)
	})
}

// measuredTable is scutil --dns on macOS 15 with an office catch-all and
// acme.internal search key on 127.0.0.99 written first, then an
// infrastructure identity's acme.internal key and resolver file on
// 127.0.0.98. Both keys compile as separate resolvers sharing one folded
// search entry; the file is listed last with no order and still answers.
const measuredTable = `DNS configuration

resolver #1
  search domain[0] : acme.internal
  search domain[1] : n.example
  nameserver[0] : 127.0.0.99
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
  order    : 101800

resolver #2
  nameserver[0] : 192.0.2.1
  if_index : 15 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
  order    : 200000

resolver #3
  domain   : acme.internal
  nameserver[0] : 127.0.0.99
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
  order    : 102200

resolver #4
  domain   : acme.internal
  nameserver[0] : 127.0.0.98
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
  order    : 102400

resolver #5
  domain   : acme.internal
  nameserver[0] : 127.0.0.98
  flags    : Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : n.example
  nameserver[0] : 192.0.2.1
  if_index : 15 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
`

// TestCoveredKeysVerify: both identities' keys verify against the measured
// table, where they compile as separate resolvers beside the file.
func TestCoveredKeysVerify(t *testing.T) {
	resolvers, err := parseDNSResolvers([]byte(measuredTable))
	require.NoError(t, err)
	infra := []stateKeyConfig{{Servers: []string{"127.0.0.98"}, Domains: []string{"acme.internal"}}}
	office := []stateKeyConfig{
		{Servers: []string{"127.0.0.99"}, Domains: []string{""}, NoSearch: true},
		{Servers: []string{"127.0.0.99"}, Domains: []string{"acme.internal"}},
	}
	require.NoError(t, verifyCompiledDNS(infra, resolvers))
	require.NoError(t, verifyCompiledDNS(office, resolvers))
}
