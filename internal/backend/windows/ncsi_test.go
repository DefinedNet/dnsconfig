package windows

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// wantExemptHosts pins the exemption's namespaces.
var wantExemptHosts = []string{
	"dns.msftncsi.com",
	"ipv6.msftconnecttest.com",
	"ipv6.msftncsi.com",
	"www.msftconnecttest.com",
	"www.msftncsi.com",
}

// TestCatchAllPublishesExemption checks the exemption encoding: the probe
// hosts with no servers, carrying the same recovery record as every rule.
func TestCatchAllPublishesExemption(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))

	require.Equal(t, catchAllRules, h.reg.ourRuleNames())
	rule := h.reg.keys[ruleKey(1)]
	assert.Equal(t, wantExemptHosts, rule["Name"])
	assert.Equal(t, "", rule["GenericDNSServers"], "no servers is what makes the rule an exemption")
	assert.Equal(t, uint32(nrptUseGenericServers), rule["ConfigOptions"])
	assert.Equal(t, uint32(nrptVersion), rule["Version"])
	assertRecoveryValues(t, h.reg, ruleKey(1), adapterTarget{testGUID})
}

func TestSplitPublishesNoExemption(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	split := splitConfig(t, 1)
	require.NoError(t, h.setGoal(ctx, split))
	assert.Equal(t, []string{rulePrefix + "0"}, h.reg.ourRuleNames())
	assert.Equal(t, []string{".d0.example"}, h.reg.keys[ruleKey(0)]["Name"])

	// Moving between modes adds and removes the exemption with the catch-all.
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
	require.NoError(t, h.setGoal(ctx, split))
	assert.Equal(t, []string{rulePrefix + "0"}, h.reg.ourRuleNames())
	assert.Equal(t, []string{".d0.example"}, h.reg.keys[ruleKey(0)]["Name"])
}

// TestExemptionMirrorsStores keeps the exemption beside the catch-all in
// every store that routes, so the GP store never holds a catch-all alone.
func TestExemptionMirrorsStores(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
	require.NoError(t, h.setGoal(ctx, catchAll(t)))

	assert.Equal(t, catchAllRules, h.reg.gpRuleNames())
	assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
	assert.Equal(t, wantExemptHosts, h.reg.keys[gpRuleKey(1)]["Name"])
	assert.Equal(t, h.reg.keys[gpRuleKey(1)], h.reg.keys[ruleKey(1)])

	// Once foreign policy leaves, the container is retired and both rules
	// stay local.
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\{FOREIGN-RULE}`))
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	assert.False(t, h.reg.hasKey(gpoNrptBase))
	assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
}

// TestDeletedExemptionIsRepaired rewrites only the exemption.
func TestDeletedExemptionIsRepaired(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))

	require.NoError(t, h.reg.DeleteKey(ruleKey(1)))
	h.reg.writes = nil
	res, err := h.Set(ctx, catchAll(t), backend.Attempt{Converged: true})
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
	for _, w := range h.reg.writes {
		assert.NotContains(t, w, ruleKey(0), "the catch-all already matched")
	}
	assertNoOp(t, h, catchAll(t), backend.Attempt{Converged: true})
}

// TestClearRemovesExemption covers both a live instance and a fresh one
// recovering from records alone, in both stores.
func TestClearRemovesExemption(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "same instance", true: "fresh instance"}[fresh], func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
			require.NoError(t, h.setGoal(ctx, catchAll(t)))
			b := h.Backend
			if fresh {
				b = newFreshBackend(t, h.reg, testGUID)
			}
			require.NoError(t, b.clearGoal(ctx))
			assert.Empty(t, h.reg.ourRuleNames())
			assert.Empty(t, h.reg.gpRuleNames())
			assert.True(t, h.reg.hasKey(gpoNrptBase+`\{FOREIGN-RULE}`))
		})
	}
}

// ruleDeleteFault fails every deletion of one key and enumerates subkeys in
// reverse, so ordering under test cannot come from the fake's sorted
// listing.
type ruleDeleteFault struct {
	*fakeRegistry
	path string
}

func (r *ruleDeleteFault) SubKeyNames(keyPath string) ([]string, error) {
	names, err := r.fakeRegistry.SubKeyNames(keyPath)
	slices.Reverse(names)
	return names, err
}

func (r *ruleDeleteFault) DeleteKey(path string) error {
	if path == r.path {
		return errInjectedRegistry
	}
	return r.fakeRegistry.DeleteKey(path)
}

// TestClearKeepsExemptionWithFailedCatchAll never leaves a store with the
// catch-all and no exemption; the reverse leftover is acceptable, and the
// next Clear finishes.
func TestClearKeepsExemptionWithFailedCatchAll(t *testing.T) {
	for _, tc := range []struct {
		name      string
		foreignGP bool
		fail      string
		wantLocal []string
		wantGP    []string
	}{
		{"local catch-all", false, ruleKey(0), catchAllRules, nil},
		{"local exemption", false, ruleKey(1), []string{rulePrefix + "1"}, nil},
		// GP rules go first and local copies wait for them.
		{"GP catch-all", true, gpRuleKey(0), catchAllRules, catchAllRules},
		{"GP exemption", true, gpRuleKey(1), catchAllRules, []string{rulePrefix + "1"}},
		{"local catch-all under GP", true, ruleKey(0), catchAllRules, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			if tc.foreignGP {
				seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
			}
			require.NoError(t, h.setGoal(ctx, catchAll(t)))
			h.Backend.reg = &ruleDeleteFault{fakeRegistry: h.reg, path: tc.fail}

			require.ErrorIs(t, h.clearGoal(ctx), errInjectedRegistry)
			assert.Equal(t, tc.wantLocal, h.reg.ourRuleNames())
			assert.Equal(t, tc.wantGP, h.reg.gpRuleNames())

			h.Backend.reg = h.reg
			require.NoError(t, h.clearGoal(ctx))
			assert.Empty(t, h.reg.ourRuleNames())
			assert.Empty(t, h.reg.gpRuleNames())
		})
	}
}

// TestSplitBesideCatchAllPeer checks that a peer's catch-all and exemption
// do not refuse a split Set for the probe hosts' parent domain.
func TestSplitBesideCatchAllPeer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	peer := otherInstance(t, h)
	require.NoError(t, peer.setGoal(ctx, catchAll(t)))

	split := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"msftconnecttest.com"}}
	require.NoError(t, h.setGoal(ctx, split))
	assert.Equal(t, []string{rulePrefix + "0"}, h.reg.ourRuleNames())
}

// TestExemptionPrecedesCatchAll stages and publishes the exemption before
// the catch-all in each store, so no store routes the catch-all alone.
func TestExemptionPrecedesCatchAll(t *testing.T) {
	h := newHarness(t)
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
	h.reg.writes = nil
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))

	for _, base := range []string{nrptBase, gpoNrptBase} {
		first := map[string]int{}
		for i, w := range h.reg.writes {
			for _, op := range []string{"CreateKey", "RenameKey"} {
				for idx := range catchAllRules {
					key := base + `\` + ruleName(testIdentity, idx)
					if !strings.HasPrefix(w, op+" "+key+pendingRuleSuffix+" ") {
						continue
					}
					if _, ok := first[op+key]; !ok {
						first[op+key] = i
					}
				}
			}
		}
		for _, op := range []string{"CreateKey", "RenameKey"} {
			exemption, okE := first[op+base+`\`+ruleName(testIdentity, 1)]
			catchAllRule, okC := first[op+base+`\`+ruleName(testIdentity, 0)]
			require.True(t, okE && okC, "%s %s", op, base)
			assert.Less(t, exemption, catchAllRule, "%s in %s", op, base)
		}
	}
}

// TestSplitSwitchKeepsExemptionWithFailedCatchAll moves a catch-all goal to
// split with the old catch-all's deletion failing: its store keeps the
// exemption, and the next attempt finishes the switch.
func TestSplitSwitchKeepsExemptionWithFailedCatchAll(t *testing.T) {
	for _, tc := range []struct {
		name      string
		foreignGP bool
		fail      string
	}{
		{"local", false, ruleKey(0)},
		{"GP", true, gpRuleKey(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			if tc.foreignGP {
				seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
			}
			require.NoError(t, h.setGoal(ctx, catchAll(t)))
			h.Backend.reg = &ruleDeleteFault{fakeRegistry: h.reg, path: tc.fail}

			split := splitConfig(t, 1)
			require.ErrorIs(t, h.setGoal(ctx, split), errInjectedRegistry)
			base := strings.TrimSuffix(tc.fail, `\`+ruleName(testIdentity, 0))
			require.Equal(t, []string{"."}, h.reg.keys[tc.fail]["Name"], "the catch-all deletion failed")
			assert.True(t, h.reg.hasKey(base+`\`+ruleName(testIdentity, 1)), "the exemption stays with its catch-all")

			h.Backend.reg = h.reg
			require.NoError(t, h.setGoal(ctx, split))
			assert.Equal(t, []string{rulePrefix + "0"}, h.reg.ourRuleNames())
			assert.Equal(t, []string{".d0.example"}, h.reg.keys[ruleKey(0)]["Name"])
		})
	}
}
