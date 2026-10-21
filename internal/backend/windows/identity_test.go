package windows

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
)

// otherInstance builds a second identity's Backend over the same fake
// registry, on its own adapter, as a second network's process would.
func otherInstance(t *testing.T, h *harness) *Backend {
	t.Helper()
	return otherInstanceOn(t, h, adapterTarget{guid: otherGUID})
}

// otherInstanceOn is otherInstance on the given adapter.
func otherInstanceOn(t *testing.T, h *harness, target adapterTarget) *Backend {
	t.Helper()
	for _, path := range adapterPaths(target.guid) {
		require.NoError(t, h.reg.CreateKey(path))
	}
	b, err := New(context.Background(), Options{
		Logger:           discardLogger(),
		WatchPolicy:      func() (Watcher, error) { return newFakeWatcher(), nil },
		WatchRegistry:    func([]RegistryWatchKey) (Watcher, error) { return newFakeWatcher(), nil },
		Identity:         otherIdentity,
		Registry:         h.reg,
		Runner:           &runnertest.FakeRunner{},
		Notifier:         &fakeNotifier{delivery: DeliveryNotified},
		InterfaceName:    "other-adapter",
		ResolveInterface: func(string) (string, error) { return target.guid, nil },
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// TestIdentitiesCoexistOnSeparateAdapters checks independent discovery and cleanup.
func TestIdentitiesCoexistOnSeparateAdapters(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	other := otherInstance(t, h)

	ours := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}, SearchDomains: []string{"a.example"}}
	theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}, SearchDomains: []string{"b.example"}}
	require.NoError(t, h.setGoal(ctx, ours))
	require.NoError(t, other.setGoal(ctx, theirs))
	assert.Equal(t, []string{ruleName(testIdentity, 0)}, h.reg.ourRuleNames())
	assert.True(t, h.reg.hasKey(nrptBase+`\`+ruleName(otherIdentity, 0)))

	has, err := other.ownedState()
	require.NoError(t, err)
	assert.True(t, has)

	require.NoError(t, h.clearGoal(ctx))
	assert.Empty(t, h.reg.ourRuleNames())
	assert.True(t, h.reg.hasKey(nrptBase+`\`+ruleName(otherIdentity, 0)), "Clear must leave the other identity's rule")
	for _, path := range adapterPaths(otherGUID) {
		assert.Equal(t, "b.example", h.reg.keys[path][searchListValue], "Clear must leave the other identity's adapter values")
	}
	has, err = h.ownedState()
	require.NoError(t, err)
	assert.False(t, has, "the other identity's rules are not this identity's pre-state")

	require.NoError(t, other.clearGoal(ctx))
	assert.False(t, h.reg.hasKey(nrptBase+`\`+ruleName(otherIdentity, 0)))
}

// TestAdapterHeldByAnotherIdentityRefused checks that an adapter recorded by
// another identity's rule refuses Set before any write, whatever the match
// domains, and is released once that rule goes.
func TestAdapterHeldByAnotherIdentityRefused(t *testing.T) {
	ours := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}, SearchDomains: []string{"a.example"}}
	theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}, SearchDomains: []string{"b.example"}}
	for _, tc := range []struct {
		name string
		// hold makes otherIdentity hold our adapter and returns its release.
		hold func(t *testing.T, h *harness) func()
	}{
		{name: "applied peer", hold: func(t *testing.T, h *harness) func() {
			peer := otherInstanceOn(t, h, adapterTarget{guid: testGUID})
			require.NoError(t, peer.setGoal(context.Background(), theirs))
			return func() { require.NoError(t, peer.clearGoal(context.Background())) }
		}},
		{name: "staged rule before its Name", hold: func(t *testing.T, h *harness) func() {
			key := nrptBase + `\` + ruleName(otherIdentity, 0) + pendingRuleSuffix
			require.NoError(t, h.reg.CreateKey(key))
			// Lowercase, since registry data is not canonicalized.
			require.NoError(t, h.reg.SetString(key, interfaceGUIDValue, strings.ToLower(testGUID)))
			return func() { require.NoError(t, h.reg.DeleteKey(key)) }
		}},
		{name: "Group Policy store rule", hold: func(t *testing.T, h *harness) func() {
			key := gpoNrptBase + `\` + ruleName(otherIdentity, 0)
			require.NoError(t, h.populateRule(key, nrptRule{[]string{".b.example"}, "192.0.2.2"}, adapterTarget{guid: testGUID}))
			return func() {
				require.NoError(t, h.reg.DeleteKey(key))
				require.NoError(t, h.reg.DeleteKey(gpoNrptBase))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			release := tc.hold(t, h)

			before := h.reg.snapshot()
			h.reg.writes = nil
			res, err := h.Set(ctx, ours, backend.Attempt{NewGoal: true})
			require.ErrorIs(t, err, backend.ErrConflict)
			var domainConflict *backend.ConflictError
			assert.False(t, errors.As(err, &domainConflict), "an adapter is not a domain")
			assert.EqualError(t, err, `adapter "test-adapter" ({00000000-0000-0000-0000-000000000001}) held by identity "other-app"`)
			assert.False(t, res.Changed)
			assert.Empty(t, h.reg.writes)
			assert.Equal(t, before, h.reg.snapshot())

			release()
			require.NoError(t, h.setGoal(ctx, ours))
			for _, path := range adapterPaths(testGUID) {
				assert.Equal(t, "a.example", h.reg.keys[path][searchListValue])
			}
		})
	}
}

// TestIdentitiesShareSearchSuffix checks that a search suffix on two adapters
// is not a claim: only exact match domains conflict, so a parent and child
// match domain coexist. Every Set and Clear order runs: a suffix treated as a
// claim only refuses the later Set, and a cleanup that strayed into a
// contained namespace only shows when the parent clears first.
func TestIdentitiesShareSearchSuffix(t *testing.T) {
	type side struct {
		b    *Backend
		rule string
		guid string
	}
	for _, tc := range []struct {
		name              string
		parentSetsFirst   bool
		parentClearsFirst bool
	}{
		{name: "child sets first, child clears first"},
		{name: "child sets first, parent clears first", parentClearsFirst: true},
		{name: "parent sets first, child clears first", parentSetsFirst: true},
		{name: "parent sets first, parent clears first", parentSetsFirst: true, parentClearsFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			other := otherInstance(t, h)

			child := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"shared.example"}, SearchDomains: []string{"shared.example"}}
			parent := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"example"}, SearchDomains: []string{"shared.example"}}
			ours := side{b: h.Backend, rule: nrptBase + `\` + ruleName(testIdentity, 0), guid: testGUID}
			theirs := side{b: other, rule: nrptBase + `\` + ruleName(otherIdentity, 0), guid: otherGUID}
			if tc.parentSetsFirst {
				require.NoError(t, theirs.b.setGoal(ctx, parent))
				require.NoError(t, ours.b.setGoal(ctx, child))
			} else {
				require.NoError(t, ours.b.setGoal(ctx, child))
				require.NoError(t, theirs.b.setGoal(ctx, parent))
			}
			assert.Equal(t, []string{".shared.example"}, h.reg.keys[ours.rule]["Name"])
			assert.Equal(t, "192.0.2.1", h.reg.keys[ours.rule]["GenericDNSServers"])
			assert.Equal(t, []string{".example"}, h.reg.keys[theirs.rule]["Name"])
			assert.Equal(t, "192.0.2.2", h.reg.keys[theirs.rule]["GenericDNSServers"])
			for _, s := range []side{ours, theirs} {
				for _, path := range adapterPaths(s.guid) {
					assert.Equal(t, "shared.example", h.reg.keys[path][searchListValue], s.guid)
					// Split configs route through NRPT only.
					assert.NotContains(t, h.reg.keys[path], nameServerValue, s.guid)
				}
			}

			first, survivor := ours, theirs
			if tc.parentClearsFirst {
				first, survivor = theirs, ours
			}
			// The survivor's rule carries its adapter recovery fields, so this
			// covers every value the surviving identity owns.
			survivorKeys := func() map[string]map[string]any {
				snap := h.reg.snapshot()
				out := map[string]map[string]any{survivor.rule: snap[survivor.rule]}
				for _, path := range adapterPaths(survivor.guid) {
					out[path] = snap[path]
				}
				return out
			}
			before := survivorKeys()
			require.NoError(t, first.b.clearGoal(ctx))
			assert.Equal(t, before, survivorKeys(), "Clear must leave the other identity's rule and adapter values")
			// Checked before the survivor clears, so a cleanup that defers a
			// shared value to the last holder fails here.
			assertCleared := func(s side) {
				t.Helper()
				has, err := s.b.ownedState()
				require.NoError(t, err)
				assert.False(t, has)
				assert.False(t, h.reg.hasKey(s.rule))
				for _, path := range adapterPaths(s.guid) {
					assert.NotContains(t, h.reg.keys[path], searchListValue)
				}
			}
			assertCleared(first)

			require.NoError(t, survivor.b.clearGoal(ctx))
			assertCleared(survivor)
		})
	}
}

// TestSetRefusesNamespaceHeldByAnotherIdentity checks rejection before mutation.
// Staged rules hold namespaces too; a catch-all conflicts only with a catch-all.
func TestSetRefusesNamespaceHeldByAnotherIdentity(t *testing.T) {
	cases := []struct {
		name   string
		theirs backend.Config
		staged bool
		ours   backend.Config
		domain string
	}{
		{
			name:   "split domain",
			theirs: backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"corp.example", "lab.example"}},
			ours:   backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"ours.example", "lab.example"}},
			domain: "lab.example.",
		},
		{
			name:   "catch-all",
			theirs: backend.Config{Nameservers: mustAddrs(t, "192.0.2.2")},
			ours:   backend.Config{Nameservers: mustAddrs(t, "192.0.2.1")},
			domain: ".",
		},
		{
			name:   "staged rule counts",
			theirs: backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"lab.example"}},
			staged: true,
			ours:   backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"lab.example"}},
			domain: "lab.example.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			other := otherInstance(t, h)
			require.NoError(t, other.setGoal(ctx, tc.theirs))
			if tc.staged {
				active := nrptBase + `\` + ruleName(otherIdentity, 0)
				require.NoError(t, h.reg.RenameKey(active, ruleName(otherIdentity, 0)+pendingRuleSuffix))
			}
			before := h.reg.snapshot()

			res, err := h.Set(ctx, tc.ours, backend.Attempt{NewGoal: true})
			require.Error(t, err)
			assert.False(t, res.Changed, "conflict must precede mutation: %v", err)
			var conflict *backend.ConflictError
			require.True(t, errors.As(err, &conflict))
			assert.Equal(t, tc.domain, conflict.Domain)
			assert.Equal(t, otherIdentity, conflict.Holder)
			assert.Equal(t, before, h.reg.snapshot(), "a refused Set writes nothing")
		})
	}

	t.Run("catch-all coexists with split", func(t *testing.T) {
		h := newHarness(t)
		ctx := context.Background()
		other := otherInstance(t, h)
		require.NoError(t, other.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"lab.example"}}))
		require.NoError(t, h.setGoal(ctx, catchAll(t)))
	})

	t.Run("rule without Name is ignored", func(t *testing.T) {
		h := newHarness(t)
		ctx := context.Background()
		require.NoError(t, h.reg.CreateKey(nrptBase+`\`+ruleName(otherIdentity, 0)+pendingRuleSuffix))
		require.NoError(t, h.setGoal(ctx, catchAll(t)))
	})
}

func TestParseRuleName(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity string
		idx      int
		pending  bool
		ok       bool
	}{
		{"dnsconfig-app-0", "app", 0, false, true},
		{"dnsconfig-app-12-pending", "app", 12, true, true},
		{"dnsconfig-my-net.example_1-3", "my-net.example_1", 3, false, true},
		{"dnsconfig-a-pending-0", "a-pending", 0, false, true},
		{"dnsconfig-a-pending-0-pending", "a-pending", 0, true, true},
		{"dnsconfig-0", "", 0, false, false},
		{"dnsconfig--0", "", 0, false, false},
		{"dnsconfig-app-x", "", 0, false, false},
		{"dnsconfig-app-+5", "", 0, false, false},
		{"dnsconfig-app-007", "", 0, false, false},
		{"dnsconfig-app-007-pending", "", 0, false, false},
		{"other-app-0", "", 0, false, false},
	} {
		identity, idx, pending, ok := parseRuleName(tc.name)
		assert.Equal(t, tc.ok, ok, tc.name)
		if tc.ok {
			assert.Equal(t, tc.identity, identity, tc.name)
			assert.Equal(t, tc.idx, idx, tc.name)
			assert.Equal(t, tc.pending, pending, tc.name)
		}
	}
}

func TestSortRuleNames(t *testing.T) {
	names := []string{
		ruleName(testIdentity, 10), ruleName(testIdentity, 1) + pendingRuleSuffix,
		ruleName(testIdentity, 2), ruleName(testIdentity, 1), ruleName(testIdentity, 0),
	}
	sortRuleNames(names)
	assert.Equal(t, []string{
		ruleName(testIdentity, 0), ruleName(testIdentity, 1), ruleName(testIdentity, 1) + pendingRuleSuffix,
		ruleName(testIdentity, 2), ruleName(testIdentity, 10),
	}, names)
}
