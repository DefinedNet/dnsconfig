//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner"
	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
)

// testIdentity is the identity every test backend runs under; otherIdentity
// marks artifacts a second application instance would leave.
const (
	testIdentity  = "test-app"
	otherIdentity = "other-app"
)

type scutilFake struct {
	mu sync.Mutex

	keys map[int]stateKeyConfig
	// otherKeys holds keys written under other identities, by full name.
	otherKeys map[string]stateKeyConfig
	base      dnsResolver
	// baseSearch is the primary service's search list. As configd does, the
	// compiled unscoped resolver lists the keys' search domains first, then
	// baseSearch without exact-spelling duplicates of them.
	baseSearch []string

	// scutilRuns counts scutil process starts, whatever the script.
	scutilRuns int
	sets       int
	removes    int
	// otherRemoves counts removals of other identities' keys, which an
	// identity-scoped instance must never issue.
	otherRemoves int
	// flushes counts dscacheutil runs; flushErr fails them.
	flushes  int
	flushErr error
	// mutating logs every command that can change host state, in order: a
	// State-key set or remove as "scutil set <key>" or "scutil remove <key>",
	// and each cache-flush binary by name.
	mutating []string
	// order, when set, also receives each mutating script and each
	// compiled-table read, interleaved with the testFS's calls.
	order *hostOrder

	corruptNextSet bool
	// refuseRemoves makes remove scripts exit 0 without removing, as scutil
	// does when configd denies the request.
	refuseRemoves bool
	omitCompiled  bool
	compiledErr   error
	// listErr fails every State-key list, which Set and Clear both run
	// before they write.
	listErr error
	// compiledOutput, when non-nil, replaces the rendered scutil --dns table
	// from the compiledOutputFrom-th read (0-based) on; compiledReads counts
	// reads.
	compiledOutput     []byte
	compiledOutputFrom int
	compiledReads      int

	// failMutation, when non-negative, fails the failMutation-th set or
	// remove script (0-based) without applying it. mutations counts them.
	failMutation int
	mutations    int

	// outage makes every dynamic-store script exit 0 with outageOutput and
	// no effect, as scutil does when configd does not answer. outageAfter,
	// when positive, starts the outage after that many remove scripts.
	outage       bool
	outageOutput string
	outageAfter  int
}

// recordMutation logs a mutating script before the outage check, so a test
// asserting that nothing was written during an outage sees any attempt.
func (f *scutilFake) recordMutation(script string) {
	if name, ok := strings.CutPrefix(script, "remove "); ok {
		name, _, _ = strings.Cut(name, "\n")
		f.mutating = append(f.mutating, "scutil remove "+strings.TrimSpace(name))
		f.order.add("scutil remove " + strings.TrimSpace(name))
		return
	}
	if strings.HasPrefix(script, "d.init\n") {
		for line := range strings.SplitSeq(script, "\n") {
			if key, ok := strings.CutPrefix(line, "set "); ok {
				f.mutating = append(f.mutating, "scutil set "+key)
				f.order.add("scutil set " + key)
			}
		}
	}
}

// hostOrder is one sequence of both fakes' operations, for tests that
// assert the order of file and dynamic-store changes relative to each other.
// The fakes add to it while holding their own lock, so mu is taken last.
type hostOrder struct {
	mu  sync.Mutex
	ops []string
}

// recordOrder attaches a new hostOrder to both fakes.
func recordOrder(fs *testFS, fake *scutilFake) *hostOrder {
	o := &hostOrder{}
	fs.mu.Lock()
	fs.order = o
	fs.mu.Unlock()
	fake.mu.Lock()
	fake.order = o
	fake.mu.Unlock()
	return o
}

// add appends op; a nil hostOrder records nothing.
func (o *hostOrder) add(op string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ops = append(o.ops, op)
}

func (o *hostOrder) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.ops)
}

func newScutilFake() *scutilFake {
	return &scutilFake{
		keys:         map[int]stateKeyConfig{},
		otherKeys:    map[string]stateKeyConfig{},
		failMutation: -1,
		base:         dnsResolver{Servers: []string{"192.0.2.53"}},
		baseSearch:   []string{"lan.example"},
	}
}

func (f *scutilFake) Run(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	switch name {
	case dscacheutilBinary:
		f.mu.Lock()
		defer f.mu.Unlock()
		f.mutating = append(f.mutating, "dscacheutil")
		f.flushes++
		return nil, nil, f.flushErr
	case killallBinary:
		f.mu.Lock()
		defer f.mu.Unlock()
		f.mutating = append(f.mutating, "killall")
		return nil, nil, nil
	}
	if name != scutilBinary {
		return nil, nil, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scutilRuns++
	if slices.Equal(args, []string{"--dns"}) {
		f.order.add(opCompiledRead)
		if f.compiledErr != nil {
			return nil, []byte("scutil: cannot open"), f.compiledErr
		}
		read := f.compiledReads
		f.compiledReads++
		if f.compiledOutput != nil && read >= f.compiledOutputFrom {
			return f.compiledOutput, nil, nil
		}
		return f.compiledLocked(), nil, nil
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return nil, nil, err
	}
	script := string(body)
	f.recordMutation(script)
	if f.outage {
		return []byte(f.outageOutput), nil, nil
	}
	switch {
	case strings.HasPrefix(script, "show "):
		var out []byte
		for line := range strings.SplitSeq(script, "\n") {
			if name, ok := strings.CutPrefix(line, "show "); ok {
				out = append(out, f.showLocked(strings.TrimSpace(name))...)
			}
		}
		return out, nil, nil
	case strings.HasPrefix(script, "list "):
		if f.listErr != nil {
			return nil, []byte("injected"), f.listErr
		}
		indices := make([]int, 0, len(f.keys))
		for idx := range f.keys {
			indices = append(indices, idx)
		}
		sort.Ints(indices)
		names := make([]string, 0, len(indices)+len(f.otherKeys))
		for _, idx := range indices {
			names = append(names, stateKeyName(testIdentity, idx))
		}
		for name := range f.otherKeys {
			names = append(names, name)
		}
		if len(names) == 0 {
			return []byte("  no keys.\n"), nil, nil
		}
		var out strings.Builder
		for i, name := range names {
			fmt.Fprintf(&out, "  subKey [%d] = %s\n", i, name)
		}
		return []byte(out.String()), nil, nil
	case strings.HasPrefix(script, "remove "):
		name, _, _ := strings.Cut(strings.TrimPrefix(script, "remove "), "\n")
		if f.outageAfter > 0 {
			f.outageAfter--
			f.outage = f.outageAfter == 0
		}
		if f.injectMutationFailure() {
			return nil, []byte("injected"), errInjectedScutil
		}
		if f.refuseRemoves {
			return []byte("  remove: Permission denied\n"), nil, nil
		}
		if _, found := f.otherKeys[strings.TrimSpace(name)]; found {
			f.otherRemoves++
			delete(f.otherKeys, strings.TrimSpace(name))
		}
		idx, ok := indexFromScript(script, "remove ")
		if ok {
			delete(f.keys, idx)
			f.removes++
		}
		return nil, nil, nil
	case strings.HasPrefix(script, "d.init\n"):
		if f.injectMutationFailure() {
			return nil, []byte("injected"), errInjectedScutil
		}
		cfg, err := parseSetScript(script)
		if err != nil {
			return nil, []byte(err.Error()), err
		}
		if name, ok := otherSetKey(script); ok {
			f.otherKeys[name] = cfg
			return nil, nil, nil
		}
		idx, ok := indexFromSetScript(script)
		if !ok {
			return nil, []byte("missing set"), errors.New("invalid scutil script")
		}
		if f.corruptNextSet {
			f.corruptNextSet = false
			cfg.Domains[0] += "truncated"
		}
		f.keys[idx] = cfg
		f.sets++
		return nil, nil, nil
	default:
		return nil, nil, nil
	}
}

// showLocked renders one show command's output. Caller holds f.mu.
func (f *scutilFake) showLocked(name string) []byte {
	if cfg, found := f.otherKeys[name]; found {
		return renderStateKey(cfg)
	}
	idx, ok := indexFromKey(name)
	if !ok {
		return []byte("  No such key\n")
	}
	cfg, found := f.keys[idx]
	if !found {
		return []byte("  No such key\n")
	}
	return renderStateKey(cfg)
}

func indexFromScript(script, command string) (int, bool) {
	line, _, _ := strings.Cut(strings.TrimPrefix(script, command), "\n")
	return indexFromKey(strings.TrimSpace(line))
}

func indexFromSetScript(script string) (int, bool) {
	for raw := range strings.SplitSeq(script, "\n") {
		if strings.HasPrefix(raw, "set ") {
			return indexFromKey(strings.TrimPrefix(raw, "set "))
		}
	}
	return 0, false
}

// otherSetKey returns the key a set script names when it belongs to another
// identity, so a second backend can share the fake.
func otherSetKey(script string) (string, bool) {
	for raw := range strings.SplitSeq(script, "\n") {
		if name, ok := strings.CutPrefix(raw, "set "); ok {
			identity, _, parsed := parseStateKeyName(name)
			return name, parsed && identity != testIdentity
		}
	}
	return "", false
}

func indexFromKey(key string) (int, bool) {
	identity, idx, ok := parseStateKeyName(key)
	return idx, ok && identity == testIdentity
}

func parseSetScript(script string) (stateKeyConfig, error) {
	var cfg stateKeyConfig
	for raw := range strings.SplitSeq(script, "\n") {
		fields := strings.Fields(raw)
		switch {
		case len(fields) >= 4 && fields[0] == "d.add" && fields[1] == "ServerAddresses":
			cfg.Servers = slices.Clone(fields[3:])
		case len(fields) >= 4 && fields[0] == "d.add" && fields[1] == "SupplementalMatchDomains":
			for _, value := range fields[3:] {
				if value == `""` {
					value = ""
				}
				cfg.Domains = append(cfg.Domains, value)
			}
		case len(fields) == 4 && fields[0] == "d.add" && fields[1] == "SupplementalMatchDomainsNoSearch":
			cfg.NoSearch = fields[3] == "1"
		}
	}
	if len(cfg.Servers) == 0 || len(cfg.Domains) == 0 {
		return stateKeyConfig{}, errors.New("incomplete set script")
	}
	return cfg, nil
}

func renderStateKey(cfg stateKeyConfig) []byte {
	var out strings.Builder
	out.WriteString("<dictionary> {\n")
	out.WriteString("  ServerAddresses : <array> {\n")
	for i, value := range cfg.Servers {
		fmt.Fprintf(&out, "    %d : %s\n", i, value)
	}
	out.WriteString("  }\n")
	out.WriteString("  SupplementalMatchDomains : <array> {\n")
	for i, value := range cfg.Domains {
		fmt.Fprintf(&out, "    %d : %s\n", i, value)
	}
	out.WriteString("  }\n")
	if cfg.NoSearch {
		out.WriteString("  SupplementalMatchDomainsNoSearch : 1\n")
	} else {
		out.WriteString("  SupplementalMatchDomainsNoSearch : 0\n")
	}
	out.WriteString("}\n")
	return []byte(out.String())
}

func (f *scutilFake) compiledLocked() []byte {
	var resolvers []dnsResolver
	var effectiveSearch []string
	if !f.omitCompiled {
		indices := make([]int, 0, len(f.keys))
		for idx := range f.keys {
			indices = append(indices, idx)
		}
		sort.Ints(indices)
		for _, idx := range indices {
			cfg := f.keys[idx]
			if !cfg.NoSearch {
				effectiveSearch = append(effectiveSearch, cfg.Domains...)
			}
			for _, domain := range cfg.Domains {
				resolvers = append(resolvers, dnsResolver{
					Domain:     domain,
					Servers:    slices.Clone(cfg.Servers),
					Order:      100000 + 200*idx,
					Supplement: true,
				})
			}
		}
		// Other identities' keys compile as their own resolvers, ahead of
		// ours as if written first; a search domain both publish is folded
		// into one search-list entry.
		names := slices.Sorted(maps.Keys(f.otherKeys))
		for i, name := range names {
			cfg := f.otherKeys[name]
			for _, domain := range cfg.Domains {
				if !cfg.NoSearch && !slices.Contains(effectiveSearch, domain) {
					effectiveSearch = append(effectiveSearch, domain)
				}
				resolvers = append(resolvers, dnsResolver{
					Domain:     domain,
					Servers:    slices.Clone(cfg.Servers),
					Order:      90000 + 200*i,
					Supplement: true,
				})
			}
		}
	}
	for _, domain := range f.baseSearch {
		if !slices.Contains(effectiveSearch, domain) {
			effectiveSearch = append(effectiveSearch, domain)
		}
	}
	base := f.base
	for _, cfg := range f.keys {
		if slices.Contains(cfg.Domains, "") {
			base.Order = 200000
		}
	}
	resolvers = append(resolvers, base)
	sort.SliceStable(resolvers, func(i, j int) bool { return resolvers[i].Order < resolvers[j].Order })

	var out strings.Builder
	out.WriteString("DNS configuration\n\n")
	searched := false
	for i, resolver := range resolvers {
		fmt.Fprintf(&out, "resolver #%d\n", i+1)
		if resolver.Domain != "" {
			fmt.Fprintf(&out, "  domain   : %s\n", resolver.Domain)
		} else if resolver.Supplement {
			out.WriteString("  domain   : \n")
		}
		if !searched && !resolver.Scoped && resolver.Domain == "" {
			searched = true
			for j, domain := range effectiveSearch {
				fmt.Fprintf(&out, "  search domain[%d] : %s\n", j, domain)
			}
		}
		for j, server := range resolver.Servers {
			fmt.Fprintf(&out, "  nameserver[%d] : %s\n", j, server)
		}
		flags := []string{"Request A records"}
		if resolver.Supplement {
			flags = append(flags, "Supplemental")
		}
		if resolver.Scoped {
			flags = append(flags, "Scoped")
		}
		fmt.Fprintf(&out, "  flags    : %s\n", strings.Join(flags, ", "))
		fmt.Fprintf(&out, "  order    : %d\n\n", resolver.Order)
	}
	return []byte(out.String())
}

func (f *scutilFake) key(index int) (stateKeyConfig, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cfg, ok := f.keys[index]
	return cfg, ok
}

func (f *scutilFake) deleteKey(index int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, index)
}

// opCompiledRead is how hostOrder records a scutil --dns read.
const opCompiledRead = "scutil --dns"

var errInjectedScutil = errors.New("darwin test: injected scutil failure")

// injectMutationFailure counts a set or remove script and reports whether it
// is the armed one. Caller holds f.mu.
func (f *scutilFake) injectMutationFailure() bool {
	idx := f.mutations
	f.mutations++
	return idx == f.failMutation
}

// armMutationFailure arms the n-th mutation to fail; a negative n disarms.
func (f *scutilFake) armMutationFailure(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failMutation = n
	f.mutations = 0
}

func (f *scutilFake) setCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets
}

func (f *scutilFake) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scutilRuns
}

func (f *scutilFake) keyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keys)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// asRoot keeps the startup diagnostic independent of the test runner's user.
func asRoot() bool { return true }

func newTestBackend(t *testing.T, fs dirFS, fake runner.Runner) *Backend {
	t.Helper()
	b, err := New(context.Background(), Options{
		Identity: testIdentity,
		FS:       fs,
		Runner:   fake,
		Logger:   discardLogger(),
		IsRoot:   asRoot,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return useFS(b, fs)
}

func TestNewWarnsWithoutRoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		root bool
		want string
	}{
		{name: "root", root: true},
		{name: "not root", want: "requires root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			fs := newTestFS(t)
			fake := newScutilFake()
			calls := 0
			b, err := New(context.Background(), Options{
				Identity: testIdentity,
				FS:       fs,
				Runner:   fake,
				Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
				IsRoot: func() bool {
					calls++
					return tc.root
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = b.Close() })
			assert.Equal(t, 1, calls)
			assertQuiet(t, observeHost(fs, fake), "construction must not change DNS")
			if tc.want == "" {
				assert.Empty(t, logs.String())
				return
			}
			assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"))
			assert.Contains(t, logs.String(), tc.want)
		})
	}
}

var (
	newGoal   = backend.Attempt{NewGoal: true}
	repeat    = backend.Attempt{}
	converged = backend.Attempt{Converged: true}
)

// trySet makes the first converge toward cfg, as a new goal would.
func trySet(b *Backend, cfg backend.Config) error {
	_, err := b.Set(context.Background(), cfg, newGoal)
	return err
}

// tryClear makes one Clear attempt.
func tryClear(b *Backend) error {
	_, err := b.Clear(context.Background(), newGoal)
	return err
}

func catchAllConfig() backend.Config {
	return backend.Config{
		Nameservers:   []netip.Addr{netip.MustParseAddr("127.0.0.99")},
		SearchDomains: []string{"corp.example"},
	}
}

func splitConfig() backend.Config {
	return backend.Config{
		Nameservers:   []netip.Addr{netip.MustParseAddr("127.0.0.99")},
		SearchDomains: []string{"corp.example"},
		MatchDomains:  []string{"corp.example"},
	}
}

func TestBuildStateKeys(t *testing.T) {
	t.Run("catch-all", func(t *testing.T) {
		cfg := catchAllConfig()
		keys, err := buildStateKeys(cfg)
		require.NoError(t, err)
		require.Len(t, keys, 2)
		assert.Equal(t, []string{""}, keys[0].Domains)
		assert.True(t, keys[0].NoSearch)
		assert.Equal(t, []string{"corp.example"}, keys[1].Domains)
		assert.False(t, keys[1].NoSearch)
	})

	t.Run("hybrid split only publishes search domains", func(t *testing.T) {
		cfg := splitConfig()
		keys, err := buildStateKeys(cfg)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.Equal(t, []string{"corp.example"}, keys[0].Domains)
		assert.False(t, keys[0].NoSearch)

		cfg.SearchDomains = nil
		keys, err = buildStateKeys(cfg)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("refuses a domain that would break the scutil script", func(t *testing.T) {
		cfg := catchAllConfig()
		// A domain that skips Config.Validate, which is the only thing
		// standing between a caller and the script builder.
		cfg.SearchDomains = []string{"evil.example\nd.add ServerAddresses * 10.0.0.1"}
		_, err := buildStateKeys(cfg)
		assert.ErrorContains(t, err, "unsupported byte")
	})

	t.Run("nameserver value cap", func(t *testing.T) {
		cfg := catchAllConfig()
		cfg.Nameservers = make([]netip.Addr, 100)
		for i := range cfg.Nameservers {
			cfg.Nameservers[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		}
		_, err := buildStateKeys(cfg)
		assert.ErrorContains(t, err, "at most 99")
	})
}

func TestValidateConfigRejectsMechanismLimits(t *testing.T) {
	b := newTestBackend(t, newTestFS(t), newScutilFake())
	require.NoError(t, b.ValidateConfig(splitConfig()))
	require.NoError(t, b.ValidateConfig(catchAllConfig()))

	excess := splitConfig()
	excess.Nameservers = []netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4"),
	}
	assert.ErrorContains(t, b.ValidateConfig(excess), "at most 3 nameservers")

	search := func(n int) backend.Config {
		cfg := catchAllConfig()
		cfg.SearchDomains = nil
		for i := range n {
			cfg.SearchDomains = append(cfg.SearchDomains, fmt.Sprintf("d%03d.example", i))
		}
		return cfg
	}
	require.NoError(t, b.ValidateConfig(search(maxScutilValues)))
	assert.ErrorContains(t, b.ValidateConfig(search(maxScutilValues+1)), "macOS accepts at most 99")
}

// TestSearchDomainsFillOneKey: every search domain goes in one State key in
// configured order, up to a list that fills scutil's line exactly; one more
// byte is refused with the size and the limit, before any write.
func TestSearchDomainsFillOneKey(t *testing.T) {
	const prefix = "d.add SupplementalMatchDomains *"
	label := strings.Repeat("x", 63)
	var search []string
	used := len(prefix)
	for i := 0; ; i++ {
		d := fmt.Sprintf("%s.%s.%s.k%d.corp.example", label, label, label, (i*5)%9)
		if used+1+len(d) > maxScutilLineBytes {
			break
		}
		search = append(search, d)
		used += 1 + len(d)
	}
	// A filler domain of the remaining length fills the line exactly.
	rem := maxScutilLineBytes - used - 1 - len("corp.example")
	var filler []string
	for i := 0; rem > 0; i++ {
		n := min(63, rem-1)
		if rem-(n+1) == 1 {
			n--
		}
		filler = append(filler, strings.Repeat(string(rune('a'+i)), n))
		rem -= n + 1
	}
	search = append(search, strings.Join(append(filler, "corp.example"), "."))
	require.Equal(t, maxScutilLineBytes, len(scutilAddLine("SupplementalMatchDomains", search)))

	cfg := splitConfig()
	cfg.MatchDomains = []string{"corp.example"}
	cfg.SearchDomains = search
	keys, err := buildStateKeys(cfg)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, search, keys[0].Domains)
	assert.False(t, keys[0].NoSearch)

	fake := newScutilFake()
	b := newTestBackend(t, newTestFS(t), fake)
	require.NoError(t, trySet(b, cfg))
	assert.Equal(t, 1, fake.keyCount())
	key, found := fake.key(0)
	require.True(t, found)
	assert.Equal(t, search, key.Domains)

	over := cfg
	over.SearchDomains = append(slices.Clone(search[:len(search)-1]), "z"+search[len(search)-1])
	err = b.ValidateConfig(over)
	require.ErrorContains(t, err, fmt.Sprintf("search domains need a %d-byte scutil line; macOS accepts at most %d bytes", maxScutilLineBytes+1, maxScutilLineBytes))

	fresh := newScutilFake()
	fb := newTestBackend(t, newTestFS(t), fresh)
	res, err := fb.Set(context.Background(), over, newGoal)
	require.Error(t, err)
	assert.False(t, res.Changed)
	assert.Empty(t, fresh.mutating)
}

// TestSetKeepsNameserverOrderAndDuplicates: the State key and the resolver
// file list nameservers exactly as configured, since Set replaces rather than
// normalizes them.
func TestSetKeepsNameserverOrderAndDuplicates(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(fmt.Sprintf("split=%t", split), func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			b := newTestBackend(t, fs, fake)
			cfg := catchAllConfig()
			cfg.Nameservers = []netip.Addr{
				netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::53"),
				netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.4"),
			}
			if split {
				cfg.MatchDomains = []string{"corp.example"}
				cfg.Nameservers = cfg.Nameservers[:3]
			}
			require.NoError(t, trySet(b, cfg))
			key, found := fake.key(0)
			require.True(t, found)
			wantServers := []string{"192.0.2.1", "2001:db8::53", "192.0.2.1", "192.0.2.4"}
			assert.Equal(t, wantServers[:len(cfg.Nameservers)], key.Servers)
			if split {
				body, err := os.ReadFile(fs.path("corp.example"))
				require.NoError(t, err)
				assert.Equal(t, resolverFileHeaderPrefix+testIdentity+"\nnameserver 192.0.2.1\nnameserver 2001:db8::53\nnameserver 192.0.2.1\n", string(body))
			}
		})
	}
}

func TestSetPreservesZonedNameserverInStateAndResolverFile(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)
	cfg := splitConfig()
	cfg.Nameservers = []netip.Addr{netip.MustParseAddr("fe80::1%en0")}

	require.NoError(t, trySet(b, cfg))
	key, found := fake.key(0)
	require.True(t, found)
	assert.Equal(t, []string{"fe80::1%en0"}, key.Servers)
	body, err := os.ReadFile(fs.path("corp.example"))
	require.NoError(t, err)
	assert.Contains(t, string(body), "nameserver fe80::1%en0\n")
}

func TestHybridSplitAndKeyFirstCutover(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)

	require.NoError(t, trySet(b, splitConfig()))
	body, err := os.ReadFile(fs.path("corp.example"))
	require.NoError(t, err)
	assert.Contains(t, string(body), "nameserver 127.0.0.99")
	key, ok := fake.key(0)
	require.True(t, ok)
	assert.Equal(t, []string{"corp.example"}, key.Domains)
	assert.False(t, key.NoSearch)

	order := recordOrder(fs, fake)
	updated := catchAllConfig()
	updated.Nameservers = []netip.Addr{netip.MustParseAddr("127.0.0.98")}
	require.NoError(t, trySet(b, updated))
	// The catch-all key goes in before the split file comes out.
	assertInOrder(t, order.snapshot(), "scutil set "+stateKeyName(testIdentity, 0), "fs Remove corp.example")
	_, err = os.ReadFile(fs.path("corp.example"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestSetRefusesForeignResolverFile(t *testing.T) {
	fs := newTestFS(t)
	want := []byte("nameserver 192.0.2.1\n")
	path := fs.seed(t, "corp.example", want, 0o600)
	b := newTestBackend(t, fs, newScutilFake())

	err := trySet(b, splitConfig())
	require.ErrorContains(t, err, "refusing to overwrite foreign resolver file")
	assert.ErrorContains(t, err, path)
	require.NoError(t, tryClear(b))
	require.NoError(t, b.Close())

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, os.FileMode(0o600), fileMode(t, path))
}

func TestSetRefusesResolverFileSymlink(t *testing.T) {
	fs := newTestFS(t)
	require.NoError(t, os.MkdirAll(fs.dir, 0o755))
	path := fs.path("corp.example")
	target := filepath.Join(t.TempDir(), "corp-resolver")
	want := renderResolverFile(testIdentity, []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	require.NoError(t, os.WriteFile(target, want, 0o600))
	require.NoError(t, os.Symlink(target, path))
	b := newTestBackend(t, fs, newScutilFake())

	err := trySet(b, splitConfig())
	require.Error(t, err)
	assert.ErrorContains(t, err, path)
	require.NoError(t, tryClear(b))
	require.NoError(t, b.Close())

	assert.True(t, isSymlink(t, path))
	gotTarget, err := os.Readlink(path)
	require.NoError(t, err)
	assert.Equal(t, target, gotTarget)
	got, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, os.FileMode(0o600), fileMode(t, target))
}

func TestSetRefusesSpecialResolverPath(t *testing.T) {
	fs := newTestFS(t)
	path := fs.path("corp.example")
	require.NoError(t, os.MkdirAll(path, 0o755))
	b := newTestBackend(t, fs, newScutilFake())

	err := trySet(b, splitConfig())
	require.ErrorContains(t, err, "refusing to overwrite foreign resolver file")
	assert.ErrorContains(t, err, path)
	require.NoError(t, tryClear(b))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
}

func TestSetPreflightsAllResolverFiles(t *testing.T) {
	fs := newTestFS(t)
	wantOwned := renderResolverFile(testIdentity, []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	wantForeign := []byte("nameserver 192.0.2.2\n")
	ownedPath := fs.seed(t, "alpha.example", wantOwned, 0o600)
	foreignPath := fs.seed(t, "zeta.example", wantForeign, 0o640)
	b := newTestBackend(t, fs, newScutilFake())
	cfg := splitConfig()
	cfg.MatchDomains = []string{
		"alpha.example",
		"zeta.example",
	}

	err := trySet(b, cfg)
	require.Error(t, err)
	assert.ErrorContains(t, err, foreignPath)
	gotOwned, err := os.ReadFile(ownedPath)
	require.NoError(t, err)
	assert.Equal(t, wantOwned, gotOwned)
	assert.Equal(t, os.FileMode(0o600), fileMode(t, ownedPath))
	gotForeign, err := os.ReadFile(foreignPath)
	require.NoError(t, err)
	assert.Equal(t, wantForeign, gotForeign)
	assert.Equal(t, os.FileMode(0o640), fileMode(t, foreignPath))
}

func TestSetOverSetReplacesOwnedResolverFile(t *testing.T) {
	fs := newTestFS(t)
	b := newTestBackend(t, fs, newScutilFake())
	require.NoError(t, trySet(b, splitConfig()))

	updated := splitConfig()
	updated.Nameservers = []netip.Addr{netip.MustParseAddr("127.0.0.98")}
	require.NoError(t, trySet(b, updated))

	got, err := os.ReadFile(fs.path("corp.example"))
	require.NoError(t, err)
	assert.Equal(t, renderResolverFile(testIdentity, updated.Nameservers), got)
}

// TestSnapshotReturnsCompiledReadErrors keeps a failed compiled-table read
// from looking like a table to verify against.
func TestSnapshotReturnsCompiledReadErrors(t *testing.T) {
	fake := newScutilFake()
	fake.compiledErr = errors.New("exit status 1")
	b := newTestBackend(t, newTestFS(t), fake)

	_, err := b.takeSnapshot(context.Background(), true)
	require.ErrorIs(t, err, fake.compiledErr)
	res, err := b.Set(context.Background(), catchAllConfig(), newGoal)
	require.ErrorIs(t, err, fake.compiledErr)
	assert.False(t, res.Changed)
	assert.Empty(t, fake.mutating)
}

// TestClearReportsWhetherItFoundArtifacts checks that discovery finds owned
// keys and files, and that a host with none reports no change and runs no
// flush.
func TestClearReportsWhetherItFoundArtifacts(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)

	res, err := b.Clear(context.Background(), newGoal)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.Zero(t, fake.flushCount(), "nothing removed and nothing owed means no flush")

	require.NoError(t, trySet(b, catchAllConfig()))
	res, err = b.Clear(context.Background(), newGoal)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{Changed: true}, res)

	fs.seed(t, "corp.example", renderResolverFile(testIdentity, []netip.Addr{netip.MustParseAddr("127.0.0.99")}), 0o644)
	has := hasOwned(t, b)
	assert.True(t, has, "a predecessor's file is recovery evidence")
	res, err = b.Clear(context.Background(), newGoal)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{Changed: true}, res)
	has = hasOwned(t, b)
	assert.False(t, has)
}

func TestClearSweepsCrossProcessArtifacts(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	fake.keys[3] = stateKeyConfig{Servers: []string{"127.0.0.99"}, Domains: []string{""}, NoSearch: true}
	fs.seed(t, "ours.example", renderResolverFile(testIdentity, []netip.Addr{netip.MustParseAddr("127.0.0.99")}), 0o644)
	fs.seed(t, "foreign.example", []byte("nameserver 192.0.2.1\n"), 0o644)
	b := newTestBackend(t, fs, fake)

	require.NoError(t, tryClear(b))
	assert.Zero(t, fake.keyCount())
	_, err := os.ReadFile(fs.path("ours.example"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.ReadFile(fs.path("foreign.example"))
	assert.NoError(t, err)
}

// TestClearLeavesKeysItCannotAttribute protects other identities and unexpected
// key shapes. A prefix check alone cannot distinguish identities "a" and "a-b".
func TestClearLeavesKeysItCannotAttribute(t *testing.T) {
	fr := &runnertest.FakeRunner{}
	otherKey := stateKeyName(otherIdentity, 0)
	prefixedOther := stateKeyName(testIdentity+"-b", 0)
	oddShape := stateKeyPrefix + testIdentity + "-future/IPv4"
	ownKey := stateKeyName(testIdentity, 0)
	others := "  subKey [0] = " + otherKey + "\n" +
		"  subKey [1] = " + prefixedOther + "\n" +
		"  subKey [2] = " + oddShape + "\n"
	fr.OnCall(scutilBinary, runnertest.Response{Stdout: []byte(others + "  subKey [3] = " + ownKey + "\n")})
	fr.OnCall(scutilBinary, runnertest.Response{})
	fr.OnCall(scutilBinary, runnertest.Response{Stdout: []byte(others)})
	fs := newTestFS(t)
	b, err := New(context.Background(), Options{
		Identity: testIdentity,
		FS:       fs,
		Runner:   fr,
		Logger:   discardLogger(),
		IsRoot:   asRoot,
	})
	require.NoError(t, err)
	useFS(b, fs)
	require.NoError(t, tryClear(b))

	var removed []string
	for _, call := range fr.CallsFor(scutilBinary) {
		for line := range strings.SplitSeq(string(call.Stdin), "\n") {
			if name, ok := strings.CutPrefix(line, "remove "); ok {
				removed = append(removed, strings.TrimSpace(name))
			}
		}
	}
	assert.Equal(t, []string{ownKey}, removed, "Clear must remove only this identity's parsed keys")
}

func TestParseStateKeyIPv6AndEmptyDomain(t *testing.T) {
	want := stateKeyConfig{
		Servers:  []string{"2001:db8::53"},
		Domains:  []string{""},
		NoSearch: true,
	}
	got, err := parseStateKey(renderStateKey(want))
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestParseDNSResolvers(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want []dnsResolver
		ok   bool
	}{
		{
			name: "scoped sections",
			out: "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.0.2.53\n\n" +
				"DNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 192.0.2.54\n",
			want: []dnsResolver{{Servers: []string{"192.0.2.53"}}, {Servers: []string{"192.0.2.54"}, Scoped: true}},
			ok:   true,
		},
		{
			name: "supplemental",
			out: "DNS configuration\n\nresolver #1\n  domain   : corp.example.\n  nameserver[0] : 127.0.0.99\n" +
				"  flags    : Supplemental, Request A records\n  order    : 100200\n",
			want: []dnsResolver{{Domain: "corp.example", Servers: []string{"127.0.0.99"}, Order: 100200, Supplement: true}},
			ok:   true,
		},
		{"header only", "DNS configuration\n", nil, true},
		{"no configuration", "No DNS configuration available\n", nil, false},
		{"no configuration then more", "No DNS configuration available\nresolver #1\n", nil, false},
		{"silent", "", nil, false},
		{"server gone", "  Configuration daemon not (no longer) available\n", nil, false},
		{"garbage", "resolver #1\n  nameserver[0] : 192.0.2.53\n", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDNSResolvers([]byte(tc.out))
			if !tc.ok {
				assert.ErrorIs(t, err, errScutilUnanswered)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRenderResolverFile(t *testing.T) {
	got := renderResolverFile(testIdentity, []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2001:db8::53"),
	})
	want := resolverFileHeaderPrefix + testIdentity + "\n" + "nameserver 1.1.1.1\nnameserver 2001:db8::53\n"
	assert.True(t, bytes.Equal([]byte(want), got))
}

// TestSetRefusesDomainsHeldByAnotherIdentity checks conflict rejection before
// mutation and coexistence for disjoint configurations.
func TestSetRefusesDomainsHeldByAnotherIdentity(t *testing.T) {
	servers := []string{"127.0.0.77"}
	cases := []struct {
		name    string
		seed    func(t *testing.T, fs *testFS, fake *scutilFake)
		cfg     backend.Config
		domain  string
		accepts backend.Config
	}{
		{
			name: "catch-all key",
			seed: func(t *testing.T, _ *testFS, fake *scutilFake) {
				fake.otherKeys[stateKeyName(otherIdentity, 0)] = stateKeyConfig{Servers: servers, Domains: []string{""}, NoSearch: true}
			},
			cfg:     catchAllConfig(),
			domain:  ".",
			accepts: splitConfig(),
		},
		{
			name: "search key no file covers",
			seed: func(t *testing.T, _ *testFS, fake *scutilFake) {
				fake.otherKeys[stateKeyName(otherIdentity, 1)] = stateKeyConfig{Servers: servers, Domains: []string{"corp.example"}}
			},
			cfg: backend.Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("127.0.0.99")},
				MatchDomains:  []string{"example"},
				SearchDomains: []string{"corp.example"},
			},
			domain: "corp.example.",
			accepts: backend.Config{
				Nameservers:  []netip.Addr{netip.MustParseAddr("127.0.0.99")},
				MatchDomains: []string{"lab.example"},
			},
		},
		{
			name: "resolver file",
			seed: func(t *testing.T, fs *testFS, _ *scutilFake) {
				fs.seed(t, "corp.example", renderResolverFile(otherIdentity, []netip.Addr{netip.MustParseAddr("127.0.0.77")}), 0o644)
			},
			cfg:    splitConfig(),
			domain: "corp.example.",
			accepts: backend.Config{
				Nameservers:  []netip.Addr{netip.MustParseAddr("127.0.0.99")},
				MatchDomains: []string{"lab.example"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			tc.seed(t, fs, fake)
			b := newTestBackend(t, fs, fake)
			sets := fake.setCount()

			res, err := b.Set(context.Background(), tc.cfg, newGoal)
			require.Error(t, err)
			assert.False(t, res.Changed, "conflict must precede mutation: %v", err)
			var conflict *backend.ConflictError
			require.True(t, errors.As(err, &conflict))
			assert.Equal(t, tc.domain, conflict.Domain)
			assert.Equal(t, otherIdentity, conflict.Holder)
			assert.Equal(t, sets, fake.setCount(), "a refused Set writes nothing")
			assert.Zero(t, fake.keyCount(), "a refused Set writes nothing")

			require.NoError(t, trySet(b, tc.accepts), "a disjoint configuration coexists")
			require.NoError(t, tryClear(b))
			assert.Zero(t, fake.otherRemoves, "cleanup must not touch the other identity")
		})
	}
}

// TestCleanupIsScopedToIdentity protects other identities during discovery and Clear.
func TestCleanupIsScopedToIdentity(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	fake.otherKeys[stateKeyName(otherIdentity, 0)] = stateKeyConfig{Servers: []string{"127.0.0.77"}, Domains: []string{"lab.example"}}
	otherFile := renderResolverFile(otherIdentity, []netip.Addr{netip.MustParseAddr("127.0.0.77")})
	fs.seed(t, "lab.example", otherFile, 0o644)
	b := newTestBackend(t, fs, fake)

	has := hasOwned(t, b)
	assert.False(t, has, "another identity's artifacts are not this identity's pre-state")

	require.NoError(t, trySet(b, splitConfig()))
	require.NoError(t, tryClear(b))
	assert.Zero(t, fake.otherRemoves)
	assert.Len(t, fake.otherKeys, 1)
	body, err := os.ReadFile(fs.path("lab.example"))
	require.NoError(t, err)
	assert.Equal(t, otherFile, body, "Clear must leave the other identity's resolver file")
	_, err = os.ReadFile(fs.path("corp.example"))
	assert.Error(t, err, "Clear removes this identity's own file")
}

func TestParseStateKeyName(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity string
		index    int
		ok       bool
	}{
		{stateKeyName("app", 3), "app", 3, true},
		{stateKeyName("my-net.example_1", 0), "my-net.example_1", 0, true},
		{stateKeyPrefix + "app-x/DNS", "", 0, false},
		{stateKeyPrefix + "app/DNS", "", 0, false},
		{stateKeyPrefix + "-0/DNS", "", 0, false},
		{stateKeyPrefix + "app-0/IPv4", "", 0, false},
		{stateKeyPrefix + "app-01/DNS", "", 0, false},
		{stateKeyPrefix + "app-+1/DNS", "", 0, false},
		// The index follows the last '-', so "-0" is identity "app-" with
		// index 0, which is that identity's canonical key name.
		{stateKeyPrefix + "app--0/DNS", "app-", 0, true},
	} {
		identity, index, ok := parseStateKeyName(tc.name)
		assert.Equal(t, tc.ok, ok, tc.name)
		if tc.ok {
			assert.Equal(t, tc.identity, identity)
			assert.Equal(t, tc.index, index)
			assert.Equal(t, tc.name, stateKeyName(identity, index), "only the rendered form is accepted")
		}
	}
}

// TestClearContinuesPastFailedKeyRemoval checks independent cleanup and retry.
func TestClearContinuesPastFailedKeyRemoval(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)
	cfg := splitConfig()
	cfg.SearchDomains = []string{"corp.example", "lab.example"}
	require.NoError(t, trySet(b, cfg))
	require.Equal(t, 1, fake.keyCount())
	// A second key of this identity, as a larger search set would produce.
	fake.mu.Lock()
	fake.keys[1] = stateKeyConfig{Servers: []string{"127.0.0.99"}, Domains: []string{"extra.example"}}
	fake.mu.Unlock()

	fake.armMutationFailure(0)
	err := tryClear(b)
	require.ErrorIs(t, err, errInjectedScutil)
	assert.Equal(t, 1, fake.keyCount(), "the key after the failed one is still removed")
	_, err = os.ReadFile(fs.path("corp.example"))
	assert.Error(t, err, "resolver files are independent of key removal")

	fake.armMutationFailure(-1)
	has := hasOwned(t, b)
	assert.True(t, has, "the surviving key keeps the instance recoverable")
	require.NoError(t, tryClear(b))
	assert.Zero(t, fake.keyCount())
}

// TestRefusedKeyRemovalIsAnError: scutil exits 0 when configd refuses a
// remove, so neither Clear nor a Set dropping an obsolete key may report
// success while the key is still installed.
func TestRefusedKeyRemovalIsAnError(t *testing.T) {
	t.Run("clear", func(t *testing.T) {
		fake := newScutilFake()
		b := newTestBackend(t, newTestFS(t), fake)
		require.NoError(t, trySet(b, catchAllConfig()))
		keys := fake.keyCount()
		require.NotZero(t, keys)

		fake.refuseRemoves = true
		res, err := b.Clear(context.Background(), newGoal)
		require.ErrorContains(t, err, "still present")
		assert.False(t, res.Changed, "an unconfirmed removal changed nothing")
		assert.True(t, hasOwned(t, b), "the surviving key keeps the instance recoverable")

		fake.refuseRemoves = false
		require.NoError(t, tryClear(b))
		assert.Zero(t, fake.keyCount())
	})

	t.Run("obsolete key", func(t *testing.T) {
		fake := newScutilFake()
		b := newTestBackend(t, newTestFS(t), fake)
		require.NoError(t, trySet(b, catchAllConfig()))
		keys := fake.keyCount()
		require.NotZero(t, keys)

		fake.refuseRemoves = true
		require.ErrorContains(t, trySet(b, splitNoSearchConfig()), "still present")
		assert.Equal(t, keys, fake.keyCount())

		fake.refuseRemoves = false
		_, err := b.Set(context.Background(), splitNoSearchConfig(), repeat)
		require.NoError(t, err)
		assert.Zero(t, fake.keyCount())
	})
}

func TestClearContinuesPastResolverFileErrors(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)
	cfg := splitConfig()
	cfg.MatchDomains = []string{
		"a.example", "m.example", "z.example",
	}
	require.NoError(t, trySet(b, cfg))
	foreign := []byte("nameserver 192.0.2.1\n")
	peer := renderResolverFile(otherIdentity, []netip.Addr{netip.MustParseAddr("192.0.2.2")})
	fs.seed(t, "foreign.example", foreign, 0o644)
	fs.seed(t, "peer.example", peer, 0o644)
	firstErr := errors.New("first resolver file failed")
	secondErr := errors.New("second resolver file failed")
	fs.fail(opRemove, fs.path("a.example"), firstErr)
	fs.fail(opRemove, fs.path("m.example"), secondErr)

	err := tryClear(b)
	assert.ErrorIs(t, err, firstErr)
	assert.ErrorIs(t, err, secondErr)
	assert.Zero(t, fake.keyCount(), "State-key cleanup is independent of resolver files")
	_, err = os.ReadFile(fs.path("z.example"))
	assert.ErrorIs(t, err, os.ErrNotExist, "later removable files must still be cleaned up")
	for _, name := range []string{"a.example", "m.example"} {
		body, err := os.ReadFile(fs.path(name))
		require.NoError(t, err)
		assert.Equal(t, renderResolverFile(testIdentity, cfg.Nameservers), body)
	}

	fs.fail(opRemove, fs.path("a.example"), nil)
	fs.fail(opRemove, fs.path("m.example"), nil)
	has := hasOwned(t, b)
	assert.True(t, has, "failed files retain recovery evidence")
	require.NoError(t, tryClear(b))
	has = hasOwned(t, b)
	assert.False(t, has)
	for name, want := range map[string][]byte{"foreign.example": foreign, "peer.example": peer} {
		body, err := os.ReadFile(fs.path(name))
		require.NoError(t, err)
		assert.Equal(t, want, body)
	}
}

// TestFinalClearFlushesAfterFailedRemoval: Close's cleanup has no retry to
// inherit the owed flush, so it flushes what it did remove.
func TestFinalClearFlushesAfterFailedRemoval(t *testing.T) {
	for _, tc := range []struct {
		name      string
		attempt   backend.Attempt
		wantFlush bool
	}{
		{"retry defers the flush", repeat, false},
		{"final cleanup flushes", backend.Attempt{Final: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			b := newTestBackend(t, fs, fake)
			require.NoError(t, trySet(b, splitConfig()))
			flushes := fake.flushCount()
			removeErr := errors.New("remove failed")
			fs.fail(opRemove, fs.path("corp.example"), removeErr)

			res, err := b.Clear(context.Background(), tc.attempt)
			require.ErrorIs(t, err, removeErr)
			assert.Zero(t, fake.keyCount(), "State keys are removed despite the file failure")
			if tc.wantFlush {
				assert.Equal(t, flushes+1, fake.flushCount())
				assert.Equal(t, backend.Result{Changed: true}, res)
			} else {
				assert.Equal(t, flushes, fake.flushCount())
				assert.Equal(t, backend.Result{Changed: true, Pending: true}, res)
			}
		})
	}
}

// TestFinalClearRemovesFilesWhenKeyListFails: a retrying Clear changes nothing
// while configd does not answer, but the final Clear has no retry, so it
// removes the resolver files it attributed and still reports the failure.
func TestFinalClearRemovesFilesWhenKeyListFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     backend.Config
		attempt backend.Attempt
	}{
		{"split without search keys/retry", splitNoSearchConfig(), repeat},
		{"split with a search key/retry", splitConfig(), repeat},
		{"split without search keys/final", splitNoSearchConfig(), backend.Attempt{Final: true}},
		{"split with a search key/final", splitConfig(), backend.Attempt{Final: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			b := newTestBackend(t, fs, fake)
			require.NoError(t, trySet(b, tc.cfg))
			foreign := []byte("nameserver 192.0.2.1\n")
			peer := renderResolverFile(otherIdentity, []netip.Addr{netip.MustParseAddr("192.0.2.2")})
			fs.seed(t, "foreign.example", foreign, 0o644)
			fs.seed(t, "peer.example", peer, 0o644)
			flushes := fake.flushCount()
			mutations := len(fake.mutating)

			fake.mu.Lock()
			fake.outage, fake.outageOutput = true, unansweredOutputs["server gone"]
			fake.mu.Unlock()
			res, err := b.Clear(context.Background(), tc.attempt)
			require.ErrorIs(t, err, errScutilUnanswered, "a failed key list is never an empty store")
			for _, m := range fake.mutating[mutations:] {
				assert.NotContains(t, m, "scutil remove", "keys are not removed blind")
			}

			_, statErr := os.Stat(fs.path("corp.example"))
			if tc.attempt.Final {
				assert.ErrorIs(t, statErr, os.ErrNotExist, "the owned resolver file is removed")
				assert.Equal(t, backend.Result{Changed: true}, res)
				assert.Equal(t, flushes+1, fake.flushCount())
			} else {
				assert.NoError(t, statErr, "the owned resolver file is kept for the retry")
				assert.Equal(t, backend.Result{}, res)
				assert.Equal(t, flushes, fake.flushCount())
			}
			for name, want := range map[string][]byte{"foreign.example": foreign, "peer.example": peer} {
				body, err := os.ReadFile(fs.path(name))
				require.NoError(t, err)
				assert.Equal(t, want, body, name)
			}
		})
	}
}

// TestClearInspectionFailureChangesNothing: an entry Clear cannot attribute
// might be this identity's, so it removes nothing until inspection succeeds.
func TestClearInspectionFailureChangesNothing(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)
	cfg := splitConfig()
	cfg.MatchDomains = []string{"a.example", "z.example"}
	require.NoError(t, trySet(b, cfg))
	flushes := fake.flushCount()
	inspectErr := errors.New("cannot open")
	fs.fail(opOpen, fs.path("a.example"), inspectErr)
	fsLog := len(fs.mutations())

	res, err := b.Clear(context.Background(), repeat)
	require.ErrorIs(t, err, inspectErr)
	assert.Equal(t, backend.Result{}, res)
	assert.Len(t, fs.mutations(), fsLog, "no file was touched")
	assert.Equal(t, 1, fake.keyCount(), "no key was removed")
	assert.Equal(t, flushes, fake.flushCount())

	fs.fail(opOpen, fs.path("a.example"), nil)
	res, err = b.Clear(context.Background(), repeat)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{Changed: true}, res)
	assert.False(t, hasOwned(t, b))
}

// TestRepeatedClearReadsCurrentKeys tolerates external cleanup between attempts.
func TestRepeatedClearReadsCurrentKeys(t *testing.T) {
	fake := newScutilFake()
	b := newTestBackend(t, newTestFS(t), fake)
	require.NoError(t, trySet(b, catchAllConfig()))
	fake.armMutationFailure(0)
	require.Error(t, tryClear(b))
	fake.armMutationFailure(-1)

	fake.deleteKey(0)
	removes := fake.removes
	require.NoError(t, tryClear(b))
	assert.Equal(t, removes, fake.removes, "nothing left to remove means no remove script")
}

// unansweredOutputs are outputs scutil can exit 0 with that are not a
// completed request's result: an SCErrorString line or a present key whose
// value is not a dictionary. Empty output is included as a defensive case.
var unansweredOutputs = map[string]string{
	"silent":      "",
	"server gone": "  Configuration daemon not (no longer) available\n",
	"no session":  "  Configuration daemon session not active\n",
	"scalar":      "1\n",
}

func TestParseKeyList(t *testing.T) {
	key := stateKeyName(testIdentity, 0)
	for _, tc := range []struct {
		name string
		out  string
		want []string
		ok   bool
	}{
		{"empty store", "  no keys.\n", nil, true},
		{"keys", "  subKey [0] = " + key + "\n  subKey [1] = State:/x\n", []string{key, "State:/x"}, true},
		{"silent", "", nil, false},
		{"error string", "  Configuration daemon not (no longer) available\n", nil, false},
		{"key after error", "  Failed!\n  subKey [0] = " + key + "\n", nil, false},
		{"truncated line", "  subKey [0]\n", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseKeyList("list", []byte(tc.out))
			if !tc.ok {
				assert.ErrorIs(t, err, errScutilUnanswered)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestShowSessionSplitsStrictly: one scutil session shows every key, so
// each result is matched to its key by position, and any output that is not
// exactly one absence or dictionary per key fails the read.
func TestShowSessionSplitsStrictly(t *testing.T) {
	own := stateKeyName(testIdentity, 0)
	peer := stateKeyName(otherIdentity, 0)
	dict := string(renderStateKey(stateKeyConfig{Servers: []string{"192.0.2.9"}, Domains: []string{""}, NoSearch: true}))
	for _, tc := range []struct {
		name string
		out  string
		want map[string]stateKeyConfig
	}{
		{"absent then present", "  No such key\n" + dict, map[string]stateKeyConfig{
			peer: {Servers: []string{"192.0.2.9"}, Domains: []string{""}, NoSearch: true},
		}},
		{"both absent", "  No such key\n  No such key\n", map[string]stateKeyConfig{}},
		{"one result short", "  No such key\n", nil},
		{"one result extra", "  No such key\n  No such key\n  No such key\n", nil},
		{"error after first result", "  No such key\n  Configuration daemon not (no longer) available\n", nil},
		{"unterminated dictionary", "  No such key\n<dictionary> {\n  ServerAddresses : <array> {\n", nil},
		{"scalar", "  No such key\n1\n", nil},
		{"empty", "", nil},
		{"whitespace only", "  \n\n", nil},
		{"line between results", "  No such key\nFailed!\n" + dict, nil},
		{"dictionary never closes", dict[:len(dict)-2] + "\n  No such key\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fr := &runnertest.FakeRunner{}
			fr.OnCall(scutilBinary, runnertest.Response{Stdout: []byte(tc.out)})
			b := newTestBackend(t, newTestFS(t), fr)

			got, _, err := b.showStateKeys(context.Background(), []string{own, peer})
			calls := fr.CallsFor(scutilBinary)
			require.Len(t, calls, 1, "one session shows every key")
			assert.Equal(t, "show "+own+"\nshow "+peer+"\nquit\n", string(calls[0].Stdin))
			if tc.want == nil {
				assert.ErrorIs(t, err, errScutilUnanswered)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// liveShowSession is scutil's output for three shows in one session (an
// existing key, a missing key, another existing key), captured from a live
// host with its addresses and domains replaced. A missing key prints "No
// such key" indented by two spaces; a dictionary opens and closes at column
// 0 and nests with indented braces.
const liveShowSession = `<dictionary> {
  SearchDomains : <array> {
    0 : home.example
    1 : localdomain
  }
  ServerAddresses : <array> {
    0 : 2001:db8::1
    1 : 192.0.2.1
  }
  __CONFIGURATION_ID__ : Default: C49541BE-6B37-4978-AB81-D9069B5E5F88 0
  __FLAGS__ : 6
  __IF_INDEX__ : 14
  __ORDER__ : 1
}
  No such key
<dictionary> {
  PrimaryInterface : en0
  PrimaryService : C49541BE-6B37-4978-AB81-D9069B5E5F88
  Router : 192.0.2.1
}
`

// TestSplitShowOutputMatchesLiveFraming guards the splitter against scutil's
// real framing, including a nested dictionary, whose indented opening and
// closing braces belong to the enclosing result.
func TestSplitShowOutputMatchesLiveFraming(t *testing.T) {
	t.Run("live sample", func(t *testing.T) {
		results, err := splitShowOutput("show (3 keys)", []byte(liveShowSession))
		require.NoError(t, err)
		require.Len(t, results, 3)
		require.NotNil(t, results[0])
		assert.Nil(t, results[1])
		require.NotNil(t, results[2])
		assert.True(t, strings.HasSuffix(string(results[0]), "__ORDER__ : 1\n}"))
		assert.Contains(t, string(results[2]), "Router : 192.0.2.1")
		assert.NotContains(t, string(results[2]), "__ORDER__")
	})

	t.Run("nested dictionary", func(t *testing.T) {
		nested := "<dictionary> {\n  Outer : <dictionary> {\n    Inner : <array> {\n      0 : x\n    }\n  }\n  Value : 1\n}\n  No such key\n"
		results, err := splitShowOutput("show (2 keys)", []byte(nested))
		require.NoError(t, err)
		require.Len(t, results, 2)
		assert.Contains(t, string(results[0]), "Value : 1")
		assert.Nil(t, results[1])
	})
}

// TestSnapshotShowsOnlyAttributableKeys: a key under the library prefix
// whose name does not parse belongs to no identity and may hold a value that
// is not a DNS dictionary, so it is listed but never shown.
func TestSnapshotShowsOnlyAttributableKeys(t *testing.T) {
	own := stateKeyName(testIdentity, 0)
	oddShape := stateKeyPrefix + testIdentity + "-future/IPv4"
	fr := &runnertest.FakeRunner{}
	fr.OnCall(scutilBinary, runnertest.Response{Stdout: []byte("  subKey [0] = " + oddShape + "\n  subKey [1] = " + own + "\n")})
	fr.OnCall(scutilBinary, runnertest.Response{Stdout: []byte("  No such key\n")})
	b := newTestBackend(t, newTestFS(t), fr)

	snap, err := b.takeSnapshot(context.Background(), false)
	require.NoError(t, err)
	assert.Equal(t, []string{oddShape, own}, snap.names)
	assert.Empty(t, snap.keys)
	calls := fr.CallsFor(scutilBinary)
	require.Len(t, calls, 2, "a list and one show session, without the compiled table")
	assert.Equal(t, "show "+own+"\nquit\n", string(calls[1].Stdin))
}

// TestUnparseableKeyFailsOnlyItsReaders: a shown value that is not a DNS
// dictionary fails the attempt wherever the plan reads it (a desired key or a
// peer's claims), never passing as absent, but an obsolete owned key that
// nothing reads is still removed.
func TestUnparseableKeyFailsOnlyItsReaders(t *testing.T) {
	cfg := catchAllConfig()
	cfg.SearchDomains = nil
	notDNS := stateKeyConfig{Servers: []string{"192.0.2.1"}}

	t.Run("obsolete owned key", func(t *testing.T) {
		fake := newScutilFake()
		fake.keys[1] = notDNS
		b := newTestBackend(t, newTestFS(t), fake)

		res, err := b.Set(context.Background(), cfg, newGoal)
		require.NoError(t, err)
		assert.True(t, res.Changed)
		_, found := fake.key(1)
		assert.False(t, found)
		assert.Equal(t, 1, fake.keyCount())
	})

	t.Run("desired owned key", func(t *testing.T) {
		fake := newScutilFake()
		fake.keys[0] = notDNS
		b := newTestBackend(t, newTestFS(t), fake)

		res, err := b.Set(context.Background(), cfg, newGoal)
		require.ErrorContains(t, err, "incomplete DNS dictionary")
		assert.False(t, res.Changed)
		assert.Empty(t, fake.mutating)
	})

	t.Run("peer key", func(t *testing.T) {
		fake := newScutilFake()
		fake.otherKeys[stateKeyName(otherIdentity, 0)] = notDNS
		b := newTestBackend(t, newTestFS(t), fake)

		res, err := b.Set(context.Background(), cfg, newGoal)
		require.ErrorContains(t, err, "incomplete DNS dictionary")
		assert.False(t, res.Changed)
		assert.Empty(t, fake.mutating)
	})
}

func TestReadStateKeyDistinguishesAbsenceFromNoAnswer(t *testing.T) {
	for name, out := range unansweredOutputs {
		t.Run(name, func(t *testing.T) {
			fake := newScutilFake()
			fake.outage, fake.outageOutput = true, out
			b := newTestBackend(t, newTestFS(t), fake)
			_, found, err := b.readStateKey(context.Background(), 0)
			assert.ErrorIs(t, err, errScutilUnanswered)
			assert.False(t, found)
		})
	}
	t.Run("absent", func(t *testing.T) {
		b := newTestBackend(t, newTestFS(t), newScutilFake())
		_, found, err := b.readStateKey(context.Background(), 0)
		require.NoError(t, err)
		assert.False(t, found)
	})
}

// TestUnansweredScutilFailsClosed: while configd does not answer, Clear must
// not read an empty key list as a clean host, which would converge it and
// let the worker release the identity lock with keys installed, and Set must
// not read it as no competing claims.
func TestUnansweredScutilFailsClosed(t *testing.T) {
	for name, out := range unansweredOutputs {
		t.Run(name+"/clear", func(t *testing.T) {
			fake := newScutilFake()
			b := newTestBackend(t, newTestFS(t), fake)
			require.NoError(t, trySet(b, catchAllConfig()))
			keys := fake.keyCount()
			mutations := len(fake.mutating)

			fake.mu.Lock()
			fake.outage, fake.outageOutput = true, out
			fake.mu.Unlock()
			res, err := b.Clear(context.Background(), repeat)
			require.ErrorIs(t, err, errScutilUnanswered)
			assert.Equal(t, backend.Result{}, res)
			assert.Len(t, fake.mutating, mutations, "nothing is removed or flushed")
			assert.Equal(t, keys, fake.keyCount())

			fake.mu.Lock()
			fake.outage = false
			fake.mu.Unlock()
			require.NoError(t, tryClear(b))
			assert.Zero(t, fake.keyCount())
		})

		t.Run(name+"/conflict check", func(t *testing.T) {
			fake := newScutilFake()
			fake.otherKeys[stateKeyName(otherIdentity, 0)] = stateKeyConfig{Servers: []string{"192.0.2.9"}, Domains: []string{""}, NoSearch: true}
			fake.outage, fake.outageOutput = true, out
			b := newTestBackend(t, newTestFS(t), fake)

			res, err := b.Set(context.Background(), splitNoSearchConfig(), newGoal)
			require.ErrorIs(t, err, errScutilUnanswered)
			assert.False(t, res.Changed)
			assert.Empty(t, fake.mutating)

			fake.outage = false
			err = trySet(b, catchAllConfig())
			assert.ErrorAs(t, err, new(*backend.ConflictError), "the answered read sees the peer's catch-all")
		})
	}
}

// TestUnansweredRemovalCheckConfirmsNothing: a remove whose follow-up list
// configd does not answer is not a confirmed removal, but it may have taken
// effect, so the attempt reports a change and an owed flush.
func TestUnansweredRemovalCheckConfirmsNothing(t *testing.T) {
	fake := newScutilFake()
	b := newTestBackend(t, newTestFS(t), fake)
	require.NoError(t, trySet(b, catchAllConfig()))
	keys := fake.keyCount()
	require.Equal(t, 2, keys)

	fake.mu.Lock()
	fake.outageAfter = keys
	fake.mu.Unlock()
	res, err := b.Clear(context.Background(), repeat)
	require.ErrorIs(t, err, errScutilUnanswered)
	assert.True(t, res.Changed, "the removes may have taken effect")
	assert.True(t, res.Pending, "so a flush is owed")

	fake.mu.Lock()
	fake.outage = false
	fake.mu.Unlock()
	res, err = b.Clear(context.Background(), repeat)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
}

// failingRemoves wraps a scutil fake so every remove call returns an error
// after the fake has applied it, as a kill or cancel landing after configd
// processed the remove does.
type failingRemoves struct {
	fake *scutilFake
}

func (r failingRemoves) Run(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	if stdin == nil {
		return r.fake.Run(ctx, name, args, nil)
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return nil, nil, err
	}
	stdout, stderr, err := r.fake.Run(ctx, name, args, bytes.NewReader(body))
	if strings.HasPrefix(string(body), "remove ") {
		return nil, nil, errInjectedScutil
	}
	return stdout, stderr, err
}

// TestFailedRemoveCallsCountAsChange: when every remove call fails, no key
// is confirmed gone but each may be, so Clear reports an unverified change
// rather than an untouched host.
func TestFailedRemoveCallsCountAsChange(t *testing.T) {
	fake := newScutilFake()
	b := newTestBackend(t, newTestFS(t), failingRemoves{fake})
	require.NoError(t, trySet(b, catchAllConfig()))
	require.NotZero(t, fake.keyCount())

	res, err := b.Clear(context.Background(), repeat)
	require.ErrorIs(t, err, errInjectedScutil)
	assert.True(t, res.Changed, "the removes may have taken effect")
	assert.True(t, res.Pending, "so a flush is owed")
	assert.Zero(t, fake.keyCount(), "the fake applied the removes before failing")

	res, err = b.Clear(context.Background(), repeat)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
}

// hasOwned reports whether discovery finds any State key or resolver-directory
// entry attributed to the test identity.
func hasOwned(t *testing.T, b *Backend) bool {
	t.Helper()
	keys, err := b.listStateKeyNames(context.Background())
	require.NoError(t, err)
	entries, err := b.scanResolverDir()
	require.NoError(t, err)
	return len(keys)+len(b.ownedNames(entries)) > 0
}

func (f *scutilFake) flushCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.flushes
}

// TestNewRejectsUnsafeIdentity checks that the backend does not rely on the
// facade's validation before interpolating the identity into scutil scripts
// and resolver paths.
func TestNewRejectsUnsafeIdentity(t *testing.T) {
	for _, identity := range []string{"", "../etc", "a\nremove State:/Network/Global/DNS"} {
		b, err := New(context.Background(), Options{
			Identity: identity,
			FS:       newTestFS(t),
			Runner:   &runnertest.FakeRunner{},
			Logger:   discardLogger(),
		})
		assert.Error(t, err, "%q", identity)
		assert.Nil(t, b, "%q", identity)
	}
}
