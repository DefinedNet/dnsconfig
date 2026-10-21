package windows

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// populatedKeys drops keys that hold no values from a registry snapshot. The
// fake materializes ancestor keys on CreateKey; an empty local
// DnsPolicyConfig container is inert, so comparisons use values.
func populatedKeys(snapshot map[string]map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for key, values := range snapshot {
		if len(values) > 0 {
			out[key] = values
		}
	}
	return out
}

// sideEffects counts cache flushes and policy notification requests so far.
func (h *harness) sideEffects() (flushes, notifications int) {
	return h.ipconfigCalls("/flushdns"), h.notify.calls
}

// reloads counts adapter reload triggers.
func (h *harness) reloads() int {
	return h.reg.reloads
}

func (h *harness) ipconfigCalls(arg string) int {
	n := 0
	for _, c := range h.fr.CallsFor(ipconfigExe) {
		if slices.Equal(c.Args, []string{arg}) {
			n++
		}
	}
	return n
}

// assertNoOp runs a converge of cfg and requires that it wrote nothing and
// requested no side effect.
func assertNoOp(t *testing.T, h *harness, cfg backend.Config, attempt backend.Attempt) {
	t.Helper()
	flushes, notifications := h.sideEffects()
	h.reg.writes = nil
	res, err := h.Set(context.Background(), cfg, attempt)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.Empty(t, h.reg.writes, "a converged host needs no registry write")
	gotFlushes, gotNotifications := h.sideEffects()
	assert.Equal(t, flushes, gotFlushes, "a converged host needs no cache flush")
	assert.Equal(t, notifications, gotNotifications, "a converged host needs no policy notification")
}

// seedPeerGPRule installs another identity's complete GP rule with no local
// copy, as a peer that has not yet migrated leaves it.
func seedPeerGPRule(t *testing.T, h *harness, namespace string) {
	t.Helper()
	for _, path := range adapterPaths(otherGUID) {
		require.NoError(t, h.reg.CreateKey(path))
	}
	key := gpoNrptBase + `\` + ruleName(otherIdentity, 0)
	require.NoError(t, h.populateRule(key, nrptRule{[]string{namespace}, "192.0.2.2"}, adapterTarget{otherGUID}))
}

func splitConfig(t *testing.T, domains int) backend.Config {
	t.Helper()
	cfg := backend.Config{
		Nameservers:   mustAddrs(t, "192.0.2.53", "2001:db8::53"),
		SearchDomains: []string{"d0.example"},
	}
	for i := range domains {
		cfg.MatchDomains = append(cfg.MatchDomains, fmt.Sprintf("d%d.example", i))
	}
	return cfg
}

// TestSetNoOpInvariant pins the property that keeps self-generated
// notifications from sustaining a loop: repeating a converged goal writes
// nothing, flushes nothing, and requests no policy reload.
func TestSetNoOpInvariant(t *testing.T) {
	cases := []struct {
		name  string
		cfg   func(*testing.T) backend.Config
		setup func(*testing.T, *harness)
	}{
		{name: "catch-all", cfg: func(t *testing.T) backend.Config {
			return backend.Config{Nameservers: mustAddrs(t, "192.0.2.53", "2001:db8::53"), SearchDomains: []string{"corp.example"}}
		}},
		{name: "split", cfg: func(t *testing.T) backend.Config { return splitConfig(t, 2) }},
		{name: "batched", cfg: func(t *testing.T) backend.Config { return splitConfig(t, 2*maxDomainsPerRule+1) }},
		{name: "group policy", cfg: catchAll, setup: func(t *testing.T, h *harness) {
			seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
		}},
		{name: "local with retained GP copy", cfg: func(t *testing.T) backend.Config { return splitConfig(t, 1) },
			setup: func(t *testing.T, h *harness) { seedPeerGPRule(t, h, ".peer.example") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			if tc.setup != nil {
				tc.setup(t, h)
			}
			cfg := tc.cfg(t)
			res, err := h.Set(context.Background(), cfg, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			require.True(t, res.Changed)
			require.False(t, res.Pending)
			assertNoOp(t, h, cfg, backend.Attempt{})
			assertNoOp(t, h, cfg, backend.Attempt{NewGoal: true})
		})
	}
}

// TestOwnNotificationsDoNotLoop drives the change signal the way the worker
// will: our GP write raises policy and registry events, and converging on
// them settles after one pass.
func TestOwnNotificationsDoNotLoop(t *testing.T) {
	h := newHarness(t)
	ws := installWatchers(h)
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
	ctx := context.Background()
	_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	drainSignal(h.Backend)
	// What Windows would raise for our writes and notification. Each wakes
	// the worker, and each converge must settle without new work.
	for _, w := range []*fakeWatcher{ws.lastPolicy(), ws.lastRegistry()} {
		w.signal()
		waitSignal(t, h.Backend)
		assertNoOp(t, h, catchAll(t), backend.Attempt{})
	}
	select {
	case <-h.Changes():
		t.Fatal("a no-op converge must not raise another signal")
	default:
	}
}

func TestFailedAttemptThenSuccessCompletesSideEffectsOnce(t *testing.T) {
	t.Run("registry write fails", func(t *testing.T) {
		h := newHarness(t)
		seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
		reg := &failInjectRegistry{fakeRegistry: h.reg, failAt: 2}
		h.Backend.reg = reg
		ctx := context.Background()
		res, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
		require.ErrorIs(t, err, errInjectedRegistry)
		assert.True(t, res.Changed, "partially populated staging rules changed the host")
		assert.True(t, res.Pending)
		flushes, notifications := h.sideEffects()
		assert.Zero(t, flushes, "side effects wait for the attempt that finishes")
		assert.Zero(t, notifications)

		reg.arm(-1)
		res, err = h.Set(ctx, catchAll(t), backend.Attempt{})
		require.NoError(t, err)
		assert.True(t, res.Changed)
		assert.False(t, res.Pending)
		flushes, notifications = h.sideEffects()
		assert.Equal(t, 1, flushes)
		assert.Equal(t, 1, notifications)
		h.Backend.reg = h.reg
		assertNoOp(t, h, catchAll(t), backend.Attempt{})
	})
	t.Run("flush fails", func(t *testing.T) {
		h := newHarness(t)
		h.fr.OnCallErr(ipconfigExe, errors.New("ipconfig failed"))
		ctx := context.Background()
		res, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
		require.Error(t, err)
		assert.True(t, res.Changed)
		assert.True(t, res.Pending)

		h.reg.writes = nil
		res, err = h.Set(ctx, catchAll(t), backend.Attempt{})
		require.NoError(t, err)
		assert.Equal(t, backend.Result{}, res)
		assert.Empty(t, h.reg.writes)
		flushes, _ := h.sideEffects()
		assert.Equal(t, 2, flushes, "the owed flush is retried once and completes")
		assertNoOp(t, h, catchAll(t), backend.Attempt{})
	})
}

// TestRepeatConvergeRepairs checks that one repeat converge restores every
// owned artifact a writer changed, and that the next one is a no-op.
func TestRepeatConvergeRepairs(t *testing.T) {
	target := adapterTarget{testGUID}
	cases := []struct {
		name    string
		perturb func(*testing.T, *harness)
		gp      bool
	}{
		{name: "deleted local rule", perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.reg.DeleteKey(ruleKey(1)))
		}},
		{name: "changed rule servers", perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.reg.SetString(ruleKey(0), "GenericDNSServers", "192.0.2.66"))
		}},
		{name: "changed adapter value", perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.reg.SetString(adapterPaths(testGUID)[0], searchListValue, "other.example"))
		}},
		{name: "removed adapter value", perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.reg.DeleteValue(adapterPaths(testGUID)[1], searchListValue))
		}},
		{name: "added adapter servers", perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.reg.SetString(adapterPaths(testGUID)[0], nameServerValue, "192.0.2.66"))
		}},
		{name: "leftover pending rules", perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.writeStagedRule(nrptBase, 0, nrptRule{[]string{".old.example"}, "192.0.2.66"}, target))
			require.NoError(t, h.writeStagedRule(nrptBase, 5, nrptRule{[]string{".old5.example"}, "192.0.2.66"}, target))
		}},
		{name: "stale predecessor rule", perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.populateRule(ruleKey(7), nrptRule{[]string{".old.example"}, "192.0.2.66"}, target))
		}},
		{name: "stale rule in the other store", gp: true, perturb: func(t *testing.T, h *harness) {
			require.NoError(t, h.populateRule(gpRuleKey(0), nrptRule{[]string{".old.example"}, "192.0.2.66"}, target))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			cfg := splitConfig(t, maxDomainsPerRule+1)
			_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			want := populatedKeys(h.reg.snapshot())
			flushes, notifications := h.sideEffects()

			tc.perturb(t, h)
			res, err := h.Set(ctx, cfg, backend.Attempt{})
			require.NoError(t, err)
			assert.True(t, res.Changed)
			assert.False(t, res.Pending)
			assert.Equal(t, want, populatedKeys(h.reg.snapshot()))
			assert.False(t, h.reg.hasKey(gpoNrptBase), "an owned rule that emptied the GP container takes it along")
			gotFlushes, gotNotifications := h.sideEffects()
			assert.Equal(t, flushes+1, gotFlushes)
			if tc.gp {
				assert.Equal(t, notifications+1, gotNotifications)
			} else {
				assert.Equal(t, notifications, gotNotifications)
			}
			assertNoOp(t, h, cfg, backend.Attempt{})
		})
	}
}

// TestRuleValueDriftIsRepaired changes one value of an installed rule and
// requires a converged repeat Set to rewrite the rule. Every value ruleMatches
// compares has a case, so dropping a comparison fails one. Both stores run:
// in the GP store the rule also has a local copy, so recovery values that
// disagree between the copies reach recoveryTarget before ruleMatches.
func TestRuleValueDriftIsRepaired(t *testing.T) {
	// The GUID has letters so its recorded case can drift. recoveryTarget
	// canonicalizes it and ruleMatches does not.
	const guid = "{0000000A-0000-0000-0000-00000000000B}"
	type perturbFunc func(t *testing.T, reg *fakeRegistry, key string, domains []string)
	setString := func(name, value string) perturbFunc {
		return func(t *testing.T, reg *fakeRegistry, key string, _ []string) {
			require.NoError(t, reg.SetString(key, name, value))
		}
	}
	setDWord := func(name string, value uint32) perturbFunc {
		return func(t *testing.T, reg *fakeRegistry, key string, _ []string) {
			require.NoError(t, reg.SetDWord(key, name, value))
		}
	}
	deleteValue := func(name string) perturbFunc {
		return func(t *testing.T, reg *fakeRegistry, key string, _ []string) {
			require.NoError(t, reg.DeleteValue(key, name))
		}
	}
	setDomains := func(edit func([]string) []string) perturbFunc {
		return func(t *testing.T, reg *fakeRegistry, key string, domains []string) {
			require.NoError(t, reg.SetMultiString(key, "Name", edit(slices.Clone(domains))))
		}
	}
	cases := []struct {
		name    string
		perturb perturbFunc
	}{
		{name: "unchanged"},
		{name: "domain removed", perturb: setDomains(func(d []string) []string { return d[:1] })},
		{name: "domains reordered", perturb: setDomains(func(d []string) []string { return []string{d[1], d[0]} })},
		{name: "domain appended", perturb: setDomains(func(d []string) []string { return append(d, ".extra.example") })},
		{name: "Name deleted", perturb: deleteValue("Name")},
		{name: "servers changed", perturb: setString("GenericDNSServers", "192.0.2.66")},
		{name: "servers deleted", perturb: deleteValue("GenericDNSServers")},
		{name: "ConfigOptions changed", perturb: setDWord("ConfigOptions", 0x4)},
		{name: "ConfigOptions deleted", perturb: deleteValue("ConfigOptions")},
		{name: "Version changed", perturb: setDWord("Version", nrptVersion+1)},
		{name: "Version deleted", perturb: deleteValue("Version")},
		{name: "adapter GUID case changed", perturb: setString(interfaceGUIDValue, strings.ToLower(guid))},
		{name: "adapter GUID deleted", perturb: deleteValue(interfaceGUIDValue)},
	}
	for _, store := range []struct{ name, base string }{{"local", nrptBase}, {"group policy", gpoNrptBase}} {
		base := store.base
		for _, tc := range cases {
			t.Run(store.name+"/"+tc.name, func(t *testing.T) {
				h := newHarness(t)
				for _, path := range adapterPaths(guid) {
					require.NoError(t, h.reg.CreateKey(path))
				}
				h.resolveInterface = func(string) (string, error) { return guid, nil }
				if base == gpoNrptBase {
					seedForeignGPRule(t, h.reg, "foreign")
				}
				ctx := context.Background()
				cfg := splitConfig(t, 2)
				_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
				require.NoError(t, err)
				want := populatedKeys(h.reg.snapshot())
				key := base + `\` + ruleName(testIdentity, 0)
				require.Equal(t, guid, want[key][interfaceGUIDValue])
				domains, err := h.reg.GetMultiString(key, "Name")
				require.NoError(t, err)
				require.Len(t, domains, 2)

				if tc.perturb == nil {
					assertNoOp(t, h, cfg, backend.Attempt{Converged: true})
					return
				}
				tc.perturb(t, h.reg, key, domains)
				res, err := h.Set(ctx, cfg, backend.Attempt{Converged: true})
				require.NoError(t, err)
				assert.True(t, res.Changed)
				assert.False(t, res.Pending)
				assert.Equal(t, want, populatedKeys(h.reg.snapshot()))
				assertNoOp(t, h, cfg, backend.Attempt{Converged: true})
			})
		}
	}
}

// TestRuleRecordingAnotherAdapterRefusesSet: an owned rule whose recorded
// GUID names a different adapter than this instance's pending cleanup is
// ambiguous about which adapter to clean, so Set refuses rather than
// rewriting it.
func TestRuleRecordingAnotherAdapterRefusesSet(t *testing.T) {
	for _, tc := range []struct {
		store, base, err string
	}{
		{"local", nrptBase, "recorded adapter conflicts with this instance's pending cleanup"},
		{"group policy", gpoNrptBase, "conflicting adapter recovery targets"},
	} {
		t.Run(tc.store, func(t *testing.T) {
			h := newHarness(t)
			if tc.base == gpoNrptBase {
				seedForeignGPRule(t, h.reg, "foreign")
			}
			ctx := context.Background()
			cfg := splitConfig(t, 2)
			_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			require.NoError(t, h.reg.SetString(tc.base+`\`+ruleName(testIdentity, 0), interfaceGUIDValue, otherGUID))
			before := h.reg.snapshot()
			h.reg.writes = nil

			_, err = h.Set(ctx, cfg, backend.Attempt{Converged: true})
			require.ErrorContains(t, err, tc.err)
			assert.Empty(t, h.reg.writes)
			assert.Equal(t, before, h.reg.snapshot())
		})
	}
}

// TestMatchingStagedCopyIsPublished reuses a complete staged copy that an
// interrupted attempt left behind instead of rewriting it.
func TestMatchingStagedCopyIsPublished(t *testing.T) {
	for _, base := range []string{nrptBase, gpoNrptBase} {
		t.Run(base, func(t *testing.T) {
			h := newHarness(t)
			if base == gpoNrptBase {
				seedForeignGPRule(t, h.reg, "foreign")
			}
			ctx := context.Background()
			cfg := splitConfig(t, 1)
			_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			key := base + `\` + ruleName(testIdentity, 0)
			require.NoError(t, h.reg.RenameKey(key, ruleName(testIdentity, 0)+pendingRuleSuffix))
			flushes, notifications := h.sideEffects()
			h.reg.writes = nil
			res, err := h.Set(ctx, cfg, backend.Attempt{})
			require.NoError(t, err)
			assert.True(t, res.Changed)
			assert.Equal(t, []string{"RenameKey " + key + pendingRuleSuffix + " " + ruleName(testIdentity, 0)}, h.reg.writes)
			gotFlushes, gotNotifications := h.sideEffects()
			assert.Equal(t, flushes+1, gotFlushes)
			if base == gpoNrptBase {
				notifications++
			}
			assert.Equal(t, notifications, gotNotifications)
			assertNoOp(t, h, cfg, backend.Attempt{})
		})
	}
}

// failMigration fails one step of leaving the GP store: publishing a local
// copy, retiring the container, deleting the retired container, or deleting
// this identity's first GP or local rule.
func failMigration(fault string) func(op, keyPath, name string) error {
	return func(op, path, _ string) error {
		switch {
		case op == "RenameKey" && fault == "publish" && path != gpoNrptBase,
			op == "RenameKey" && fault == "retire" && path == gpoNrptBase,
			op == "DeleteKey" && fault == "retired-delete" && path == retiredGPBase,
			op == "DeleteKey" && fault == "gp-rule-delete" && path == gpRuleKey(0),
			op == "DeleteKey" && fault == "local-rule-delete" && path == ruleKey(0):
			return errInjectedRegistry
		}
		return nil
	}
}

// TestClearKeepsLocalCopyUntilGPCopyGoes keeps the local copy when its GP
// copy fails to delete: a GP rule without its local twin would keep peers
// from ever retiring the container.
func TestClearKeepsLocalCopyUntilGPCopyGoes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cfg := splitConfig(t, 1)
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	require.True(t, h.reg.hasKey(gpRuleKey(0)))
	require.True(t, h.reg.hasKey(ruleKey(0)))

	h.reg.fail = failMigration("gp-rule-delete")
	require.ErrorIs(t, h.clearGoal(ctx), errInjectedRegistry)
	assert.True(t, h.reg.hasKey(gpRuleKey(0)))
	assert.True(t, h.reg.hasKey(ruleKey(0)), "the local twin stays while the GP copy does")

	h.reg.fail = nil
	require.NoError(t, h.clearGoal(ctx))
	assert.False(t, h.reg.hasKey(gpRuleKey(0)))
	assert.False(t, h.reg.hasKey(ruleKey(0)))
	assert.True(t, h.reg.hasKey(gpoNrptBase+`\foreign`))
}

// TestFailedMigrationKeepsGPRouting leaves the GP copy in place when any step
// of leaving the GP store fails, so a failure before the container is
// retired never strands this identity on suppressed local rules, and a
// retired container left by a failed delete changes no routing and goes on
// retry.
func TestFailedMigrationKeepsGPRouting(t *testing.T) {
	for _, fault := range []string{"publish", "retire", "retired-delete"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			cfg := splitConfig(t, 1)
			seedForeignGPRule(t, h.reg, "foreign")
			_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))
			if fault == "publish" {
				// Without its local copy the migration must publish one.
				require.NoError(t, h.reg.DeleteKey(ruleKey(0)))
			}

			h.reg.fail = failMigration(fault)
			_, err = h.Set(ctx, cfg, backend.Attempt{})
			require.ErrorIs(t, err, errInjectedRegistry)
			if fault == "retired-delete" {
				assert.False(t, h.reg.hasKey(gpoNrptBase), "the rename already took the GP store out of effect")
				assert.True(t, h.reg.hasKey(retiredGPBase))
			} else {
				assert.NotEmpty(t, h.reg.gpRuleNames(), "the GP copy keeps routing until the container is retired")
			}

			h.reg.fail = nil
			_, err = h.Set(ctx, cfg, backend.Attempt{})
			require.NoError(t, err)
			assert.True(t, h.reg.hasKey(ruleKey(0)))
			assert.False(t, h.reg.hasKey(gpoNrptBase), "an empty GP container suppresses the local rules")
			assert.False(t, h.reg.hasKey(retiredGPBase))
			assertNoOp(t, h, cfg, backend.Attempt{})
		})
	}
}

// TestRetiredContainerLeftoverIsRemoved deletes a retired container a crash
// left behind, on Set and on Clear, whichever identity runs next.
func TestRetiredContainerLeftoverIsRemoved(t *testing.T) {
	for _, op := range []string{"set", "clear"} {
		t.Run(op, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			require.NoError(t, h.reg.SetString(retiredGPBase+`\`+ruleName(otherIdentity, 0), "GenericDNSServers", "192.0.2.9"))
			var err error
			if op == "set" {
				_, err = h.Set(ctx, splitConfig(t, 1), backend.Attempt{NewGoal: true})
			} else {
				_, err = h.Clear(ctx, backend.Attempt{NewGoal: true})
			}
			require.NoError(t, err)
			assert.False(t, h.reg.hasKey(retiredGPBase))
		})
	}
}

// writesUnder returns the logged registry writes under base.
func (r *fakeRegistry) writesUnder(base string) []string {
	var out []string
	for _, w := range r.writes {
		if strings.Contains(w, " "+base+`\`) {
			out = append(out, w)
		}
	}
	return out
}

// TestForeignPolicyMigrationFollowsRepeatAttempts adds GP copies when
// foreign policy arrives and removes them when it leaves, each on a repeat
// converge that requests its own notification. The local copies stay in
// place throughout.
func TestForeignPolicyMigrationFollowsRepeatAttempts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cfg := splitConfig(t, maxDomainsPerRule+1)
	_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	adapter := populatedKeys(h.reg.snapshot())[adapterPaths(testGUID)[0]]
	local := populatedKeys(h.reg.snapshot())

	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
	foreign := h.reg.snapshot()[gpoNrptBase+`\{FOREIGN-RULE}`]
	h.reg.writes = nil
	logs := h.captureLogs()
	res, err := h.Set(ctx, cfg, backend.Attempt{})
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.False(t, res.Pending)
	assert.Equal(t, []string{rulePrefix + "0", rulePrefix + "1"}, h.reg.gpRuleNames())
	assert.Equal(t, []string{rulePrefix + "0", rulePrefix + "1"}, h.reg.ourRuleNames())
	assert.Empty(t, h.reg.writesUnder(nrptBase), "arriving policy leaves the local copies alone")
	for i := range 2 {
		assert.Equal(t, local[ruleKey(i)], h.reg.keys[gpRuleKey(i)], "each GP rule matches its local copy")
	}
	assert.Equal(t, foreign, h.reg.keys[gpoNrptBase+`\{FOREIGN-RULE}`])
	assert.Equal(t, adapter, h.reg.keys[adapterPaths(testGUID)[0]], "migration preserves adapter values")
	assert.Contains(t, logs.String(), fmt.Sprintf("store=%q", gpoNrptBase))
	assert.Equal(t, 1, h.notify.calls)
	assertNoOp(t, h, cfg, backend.Attempt{})

	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\{FOREIGN-RULE}`))
	h.reg.writes = nil
	logs.Reset()
	res, err = h.Set(ctx, cfg, backend.Attempt{})
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.False(t, res.Pending)
	assert.Equal(t, []string{rulePrefix + "0", rulePrefix + "1"}, h.reg.ourRuleNames())
	assert.Empty(t, h.reg.writesUnder(nrptBase), "departing policy leaves the local copies alone")
	assert.Equal(t, local, populatedKeys(h.reg.snapshot()))
	assert.False(t, h.reg.hasKey(gpoNrptBase), "the container dnsconfig rules alone held is retired")
	assert.Contains(t, logs.String(), "store="+nrptBase)
	assert.Equal(t, 2, h.notify.calls, "vacating the GP store needs notifying too")
	assertNoOp(t, h, cfg, backend.Attempt{})
}

// TestGPContainerLossLeavesLocalCopiesRouting covers policy processing that
// deletes our GP rules. If the whole container goes, foreign policy went
// with it and the local copies already route, so the next converge writes
// nothing. If foreign policy remains, only the GP copies are rewritten.
func TestGPContainerLossLeavesLocalCopiesRouting(t *testing.T) {
	for _, foreignStays := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreignStays=%t", foreignStays), func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			cfg := splitConfig(t, 1)
			seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
			_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			want := populatedKeys(h.reg.snapshot())
			notifications := h.notify.calls
			logs := h.captureLogs()

			require.NoError(t, h.reg.DeleteKey(gpRuleKey(0)))
			if !foreignStays {
				require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\{FOREIGN-RULE}`))
				require.NoError(t, h.reg.DeleteKey(gpoNrptBase))
			}
			h.reg.writes = nil
			res, err := h.Set(ctx, cfg, backend.Attempt{Converged: true})
			require.NoError(t, err)
			assert.Empty(t, h.reg.writesUnder(nrptBase), "the local copies were already in place")
			if foreignStays {
				assert.True(t, res.Changed)
				assert.Equal(t, want, populatedKeys(h.reg.snapshot()), "the GP copy is rewritten")
				assert.Equal(t, notifications+1, h.notify.calls)
				assert.Contains(t, logs.String(), fmt.Sprintf("store=%q", gpoNrptBase),
					"the rewritten GP copy keeps the placement")
			} else {
				assert.Equal(t, backend.Result{}, res, "nothing is left to write or notify")
				assert.False(t, h.reg.hasKey(gpoNrptBase), "no container is recreated")
				assert.True(t, h.reg.hasKey(ruleKey(0)))
				assert.Equal(t, notifications, h.notify.calls)
			}
			assertNoOp(t, h, cfg, backend.Attempt{})
		})
	}
}

// TestPolicyNotificationPerConverge requests a notification on every attempt
// that changes GP rules, whether it repairs the current goal or is the final
// cleanup.
func TestPolicyNotificationPerConverge(t *testing.T) {
	t.Run("a repair of the current goal notifies again", func(t *testing.T) {
		h := newHarness(t)
		seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
		ctx := context.Background()
		_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
		require.NoError(t, err)
		require.Equal(t, 1, h.notify.calls)

		for i := 2; i <= 3; i++ {
			require.NoError(t, h.reg.DeleteKey(gpRuleKey(0)))
			res, err := h.Set(ctx, catchAll(t), backend.Attempt{Converged: true})
			require.NoError(t, err)
			assert.Equal(t, backend.Result{Changed: true}, res)
			assert.Equal(t, i, h.notify.calls)
			assert.True(t, h.reg.hasKey(gpRuleKey(0)))
		}
		assertNoOp(t, h, catchAll(t), backend.Attempt{Converged: true})
	})
	t.Run("the final cleanup notifies", func(t *testing.T) {
		h := newHarness(t)
		seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
		ctx := context.Background()
		_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
		require.NoError(t, err)
		res, err := h.Clear(ctx, backend.Attempt{Final: true})
		require.NoError(t, err)
		assert.Equal(t, backend.Result{Changed: true}, res)
		assert.Equal(t, 2, h.notify.calls)
	})
}

func TestConflictOnRepeatAttemptRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"lab.example"}}
	_, err := h.Set(ctx, cfg, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	// Another identity claims the namespace while ours is missing.
	require.NoError(t, h.reg.DeleteKey(ruleKey(0)))
	seedPeerGPRule(t, h, ".unrelated.example")
	peer := nrptBase + `\` + ruleName(otherIdentity, 1)
	require.NoError(t, h.populateRule(peer, nrptRule{[]string{".lab.example"}, "192.0.2.2"}, adapterTarget{otherGUID}))

	h.reg.writes = nil
	res, err := h.Set(ctx, cfg, backend.Attempt{})
	var conflict *backend.ConflictError
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, "lab.example.", conflict.Domain)
	assert.Equal(t, otherIdentity, conflict.Holder)
	assert.Equal(t, backend.Result{}, res)
	assert.Empty(t, h.reg.writes)
}

// dropLocalCopy removes identity's first local rule, leaving the GP-only
// state a peer running a single-store library version keeps.
func dropLocalCopy(t *testing.T, h *harness, identity string) {
	t.Helper()
	require.NoError(t, h.reg.DeleteKey(nrptBase+`\`+ruleName(identity, 0)))
}

// TestDamagedPeerTwinKeepsContainer treats a peer's unreadable local copy
// like a missing one: the container stays, and neither this identity's Set
// nor its Clear fails over a rule it does not own.
func TestDamagedPeerTwinKeepsContainer(t *testing.T) {
	h := newHarness(t)
	peer := otherInstance(t, h)
	ctx := context.Background()
	ours := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}}
	theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}}
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := h.Set(ctx, ours, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	_, err = peer.Set(ctx, theirs, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))
	peerLocal := nrptBase + `\` + ruleName(otherIdentity, 0)
	peerGP := gpoNrptBase + `\` + ruleName(otherIdentity, 0)
	h.reg.keys[peerLocal]["GenericDNSServers"] = uint32(1)
	before := h.reg.snapshot()

	_, err = h.Set(ctx, ours, backend.Attempt{})
	require.NoError(t, err)
	assert.True(t, h.reg.hasKey(gpRuleKey(0)), "keep GP routing while the peer's copy is unreadable")
	assert.Equal(t, before[peerLocal], h.reg.keys[peerLocal])
	assert.Equal(t, before[peerGP], h.reg.keys[peerGP])

	require.NoError(t, h.clearGoal(ctx))
	assert.False(t, h.reg.hasKey(ruleKey(0)))
	assert.False(t, h.reg.hasKey(gpRuleKey(0)))
	assert.True(t, h.reg.hasKey(peerGP), "the container stays with the peer")
	assert.Equal(t, before[peerLocal], h.reg.keys[peerLocal])
}

// TestPeerReadinessGatesGPRemoval keeps this identity's GP copy while a peer
// in the GP store has no local copy, since removing the last GP rule changes
// store selection for every identity.
func TestPeerReadinessGatesGPRemoval(t *testing.T) {
	for _, resetPeer := range []bool{false, true} {
		t.Run(fmt.Sprintf("peerCleared=%t", resetPeer), func(t *testing.T) {
			h := newHarness(t)
			peer := otherInstance(t, h)
			ctx := context.Background()
			ours := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}, SearchDomains: []string{"a.example"}}
			theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}, SearchDomains: []string{"b.example"}}
			seedForeignGPRule(t, h.reg, "foreign")
			_, err := h.Set(ctx, ours, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			_, err = peer.Set(ctx, theirs, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			dropLocalCopy(t, h, otherIdentity)
			require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))
			before := h.reg.snapshot()
			peerKey := gpoNrptBase + `\` + ruleName(otherIdentity, 0)

			_, err = h.Set(ctx, ours, backend.Attempt{})
			require.NoError(t, err)
			assert.True(t, h.reg.hasKey(ruleKey(0)))
			assert.True(t, h.reg.hasKey(gpRuleKey(0)), "keep GP routing while a peer has no local copy")
			assert.Equal(t, before[peerKey], h.reg.keys[peerKey])

			if resetPeer {
				require.NoError(t, peer.clearGoal(ctx))
			} else {
				_, err = peer.Set(ctx, theirs, backend.Attempt{})
				require.NoError(t, err)
				assert.False(t, h.reg.hasKey(peerKey), "the peer sees our local copy and leaves")
				assert.False(t, h.reg.hasKey(gpRuleKey(0)), "our redundant GP copy goes with it")
				assert.False(t, h.reg.hasKey(gpoNrptBase), "the peer collapses the container")
			}
			_, err = h.Set(ctx, ours, backend.Attempt{})
			require.NoError(t, err)
			assert.False(t, h.reg.hasKey(gpoNrptBase))
			if !resetPeer {
				peerLocal := nrptBase + `\` + ruleName(otherIdentity, 0)
				assert.Equal(t, before[peerKey], h.reg.keys[peerLocal])
				for _, path := range adapterPaths(otherGUID) {
					assert.Equal(t, before[path], h.reg.keys[path])
				}
				require.NoError(t, h.clearGoal(ctx))
				assert.True(t, h.reg.hasKey(peerLocal))
			}
		})
	}
}

// TestDualWritingPeersCollapseGPTogether removes every identity's GP copy in
// the first converge after foreign policy goes. Leaving one alone would keep
// the container, and with it the GP store, in effect while the identity that
// left routes through suppressed local copies; a stopped peer would make that
// permanent.
func TestDualWritingPeersCollapseGPTogether(t *testing.T) {
	for _, peerRuns := range []bool{true, false} {
		t.Run(fmt.Sprintf("peer runs=%t", peerRuns), func(t *testing.T) {
			h := newHarness(t)
			peer := otherInstance(t, h)
			ctx := context.Background()
			ours := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}}
			theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}}
			seedForeignGPRule(t, h.reg, "foreign")
			_, err := h.Set(ctx, ours, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			_, err = peer.Set(ctx, theirs, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			peerGP := gpoNrptBase + `\` + ruleName(otherIdentity, 0)
			peerLocal := nrptBase + `\` + ruleName(otherIdentity, 0)
			require.Equal(t, h.reg.keys[peerGP], h.reg.keys[peerLocal])
			localBefore := h.reg.keys[peerLocal]
			require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))

			h.reg.writes = nil
			calls := h.notify.calls
			res, err := h.Set(ctx, ours, backend.Attempt{})
			require.NoError(t, err)
			assert.True(t, res.Changed)
			assert.False(t, h.reg.hasKey(gpoNrptBase), "the first identity out removes every GP copy and the container")
			assert.Empty(t, h.reg.writesUnder(nrptBase), "no local copy is rewritten")
			assert.True(t, h.reg.hasKey(ruleKey(0)))
			assert.Equal(t, localBefore, h.reg.keys[peerLocal], "the peer keeps routing through its local copy")
			assert.Equal(t, calls+1, h.notify.calls, "removing GP rules is notified")

			if peerRuns {
				h.reg.writes = nil
				res, err = peer.Set(ctx, theirs, backend.Attempt{})
				require.NoError(t, err)
				assert.False(t, res.Changed, "the peer finds nothing to do")
				assert.Empty(t, h.reg.writes)
			}
		})
	}
}

// TestNewIdentityCollapsesStoppedPeer retires a container held only by a
// stopped peer's copies, even for an identity that never used the GP store.
func TestNewIdentityCollapsesStoppedPeer(t *testing.T) {
	h := newHarness(t)
	peer := otherInstance(t, h)
	ctx := context.Background()
	theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}}
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := peer.Set(ctx, theirs, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))
	peerLocal := nrptBase + `\` + ruleName(otherIdentity, 0)
	before := h.reg.keys[peerLocal]

	_, err = h.Set(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}}, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.False(t, h.reg.hasKey(gpoNrptBase))
	assert.Equal(t, before, h.reg.keys[peerLocal])
}

// TestClearCollapsesDnsconfigContainer retires a container held only by
// dnsconfig copies on Clear too, so the last Clear does not leave the GP store
// in effect for a stopped peer's copies.
func TestClearCollapsesDnsconfigContainer(t *testing.T) {
	h := newHarness(t)
	peer := otherInstance(t, h)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := h.Set(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}}, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	_, err = peer.Set(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}}, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))

	_, err = h.Clear(ctx, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.False(t, h.reg.hasKey(gpoNrptBase))
	assert.Empty(t, h.reg.ourRuleNames())
	assert.True(t, h.reg.hasKey(nrptBase+`\`+ruleName(otherIdentity, 0)))
}

// TestDamagedPeerRuleDoesNotBlock treats a peer GP rule missing values as not
// ready: this identity keeps its copy in both stores instead of failing.
func TestDamagedPeerRuleDoesNotBlock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.reg.SetString(gpoNrptBase+`\`+ruleName(otherIdentity, 0), "GenericDNSServers", "192.0.2.2"))
	_, err := h.Set(ctx, splitConfig(t, 1), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.True(t, h.reg.hasKey(gpRuleKey(0)))
	assert.True(t, h.reg.hasKey(ruleKey(0)))
}

// TestCollapseWaitsForStagedPeer keeps every GP copy while a peer is mid-write.
func TestCollapseWaitsForStagedPeer(t *testing.T) {
	h := newHarness(t)
	peer := otherInstance(t, h)
	ctx := context.Background()
	ours := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}}
	theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}}
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := h.Set(ctx, ours, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	_, err = peer.Set(ctx, theirs, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	peerGP := gpoNrptBase + `\` + ruleName(otherIdentity, 0)
	require.NoError(t, h.reg.RenameKey(peerGP, ruleName(otherIdentity, 0)+pendingRuleSuffix))
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))

	_, err = h.Set(ctx, ours, backend.Attempt{})
	require.NoError(t, err)
	assert.True(t, h.reg.hasKey(gpRuleKey(0)), "our GP copy stays while the peer is mid-write")
	assert.True(t, h.reg.hasKey(gpoNrptBase+`\`+ruleName(otherIdentity, 0)+pendingRuleSuffix))
}

// TestNewIdentityKeepsGPCopyWhilePeerLacksLocal writes both copies when a
// peer's GP rule still suppresses the local store, then converges on local.
func TestNewIdentityKeepsGPCopyWhilePeerLacksLocal(t *testing.T) {
	h := newHarness(t)
	peer := otherInstance(t, h)
	ctx := context.Background()
	theirs := backend.Config{Nameservers: mustAddrs(t, "192.0.2.2"), MatchDomains: []string{"b.example"}}
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := peer.Set(ctx, theirs, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	dropLocalCopy(t, h, otherIdentity)
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))

	ours := catchAll(t)
	_, err = h.Set(ctx, ours, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.True(t, h.reg.hasKey(gpRuleKey(0)), "the peer's GP rule suppresses local rules")
	assert.True(t, h.reg.hasKey(ruleKey(0)), "the local copy lets the peer migrate")
	assertNoOp(t, h, ours, backend.Attempt{})

	changed := catchAll(t)
	changed.Nameservers = mustAddrs(t, "192.0.2.99")
	_, err = h.Set(ctx, changed, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.99", h.reg.keys[gpRuleKey(0)]["GenericDNSServers"], "the retained GP copy follows the goal")
	assert.Equal(t, "192.0.2.99", h.reg.keys[ruleKey(0)]["GenericDNSServers"])

	_, err = peer.Set(ctx, theirs, backend.Attempt{})
	require.NoError(t, err)
	_, err = h.Set(ctx, changed, backend.Attempt{})
	require.NoError(t, err)
	assert.False(t, h.reg.hasKey(gpoNrptBase))
	assert.True(t, h.reg.hasKey(ruleKey(0)))
	assert.True(t, h.reg.hasKey(nrptBase+`\`+ruleName(otherIdentity, 0)))
}

// TestPreexistingEmptyGPContainerSurvives leaves an empty GP container this
// identity did not empty, on every Set attempt and on Clear.
func TestPreexistingEmptyGPContainerSurvives(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.reg.CreateKey(gpoNrptBase))
	reg := &failInjectRegistry{fakeRegistry: h.reg, failAt: 0}
	h.Backend.reg = reg
	ctx := context.Background()
	_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.Error(t, err)
	assert.True(t, h.reg.hasKey(gpoNrptBase))

	reg.arm(-1)
	_, err = h.Set(ctx, catchAll(t), backend.Attempt{})
	require.ErrorIs(t, err, backend.ErrGroupPolicyContainerEmpty)
	assert.True(t, h.reg.hasKey(gpoNrptBase))
	assert.True(t, h.reg.hasKey(ruleKey(0)))

	_, err = h.Clear(ctx, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.True(t, h.reg.hasKey(gpoNrptBase))
	assert.Empty(t, h.reg.ourRuleNames())
}

// TestEmptyGPContainerFailsSet: an empty container makes Windows ignore the
// local table, so Set writes the local copies for when it goes but does not
// converge while it exists. The first attempt still requests the adapter
// reload so the values it wrote take effect; the flush waits for the container.
func TestEmptyGPContainerFailsSet(t *testing.T) {
	ctx := context.Background()
	split := backend.Config{
		Nameservers:   mustAddrs(t, "10.0.0.53"),
		MatchDomains:  []string{"corp.example"},
		SearchDomains: []string{"corp.example"},
	}
	h := newHarness(t)
	require.NoError(t, h.reg.CreateKey(gpoNrptBase))
	// The flush waits for the container to go, so it drops answers cached
	// while the local rules were ignored. One reload covers every attempt.
	assertDeferred := func(res backend.Result) {
		t.Helper()
		assert.True(t, res.Pending)
		assert.Equal(t, 1, h.reloads())
		assert.False(t, h.registerOwed, "a successful reload is not repeated")
		flushes, _ := h.sideEffects()
		assert.Zero(t, flushes)
	}

	res, err := h.Set(ctx, split, backend.Attempt{NewGoal: true})
	require.ErrorIs(t, err, backend.ErrGroupPolicyContainerEmpty)
	assert.ErrorContains(t, err, "reboot", "a manual deletion leaves the cached policy table in place")
	assert.True(t, res.Changed)
	assert.True(t, h.reg.hasKey(ruleKey(0)), "the local copy is ready for when the container goes")
	assert.Empty(t, h.reg.gpRuleNames(), "nothing attributes the container to dnsconfig")
	assert.Zero(t, h.notify.calls)
	assertDeferred(res)

	res, err = h.Set(ctx, split, backend.Attempt{})
	require.ErrorIs(t, err, backend.ErrGroupPolicyContainerEmpty, "every attempt reports it")
	assert.False(t, res.Changed, "the local copies are already installed")
	assert.True(t, h.reg.hasKey(gpoNrptBase), "the container is not ours to remove")
	assertDeferred(res)

	require.NoError(t, h.reg.DeleteKey(gpoNrptBase))
	res, err = h.Set(ctx, split, backend.Attempt{})
	require.NoError(t, err, "the goal converges once the container is gone")
	assert.True(t, h.reg.hasKey(ruleKey(0)))
	assert.False(t, res.Pending)
	assert.Equal(t, 1, h.reloads())
	flushes, _ := h.sideEffects()
	assert.Equal(t, 1, flushes)
}

// TestAdapterReplacementAfterFailedClear keeps records and in-memory cleanup
// state on the same adapter when clearing the replaced one fails, so both a
// retry and a Clear through the same Backend complete.
func TestAdapterReplacementAfterFailedClear(t *testing.T) {
	for _, next := range []string{"retry", "clear"} {
		t.Run(next, func(t *testing.T) {
			ctx := context.Background()
			base := newFakeRegistry()
			b, err := newTestBackend(ctx, Options{Registry: base})
			require.NoError(t, err)
			cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.53"), SearchDomains: []string{"ours.example"}}
			_, err = b.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			for _, path := range adapterPaths(otherGUID) {
				require.NoError(t, base.CreateKey(path))
			}
			b.resolveInterface = func(string) (string, error) { return otherGUID, nil }
			base.fail = failAdapterClear(adapterPaths(testGUID)[0])
			_, err = b.Set(ctx, cfg, backend.Attempt{})
			require.Error(t, err)
			assert.Equal(t, testGUID, base.keys[ruleKey(0)][interfaceGUIDValue], "records still name the adapter being cleared")

			base.fail = nil
			if next == "retry" {
				_, err = b.Set(ctx, cfg, backend.Attempt{})
				require.NoError(t, err)
				assert.Equal(t, otherGUID, base.keys[ruleKey(0)][interfaceGUIDValue])
				for _, path := range adapterPaths(otherGUID) {
					assert.Equal(t, "ours.example", base.keys[path][searchListValue])
				}
			}
			_, err = b.Clear(ctx, backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			assert.Empty(t, base.ourRuleNames())
			for _, guid := range []string{testGUID, otherGUID} {
				for _, path := range adapterPaths(guid) {
					assert.NotContains(t, base.keys[path], searchListValue)
					assert.NotContains(t, base.keys[path], nameServerValue)
				}
			}
		})
	}
}

func TestClearNoOpAndOwedFlush(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)

	h.fr.OnCallErr(ipconfigExe, errors.New("ipconfig failed"))
	res, err := h.Clear(ctx, backend.Attempt{NewGoal: true})
	require.Error(t, err)
	assert.Equal(t, backend.Result{Changed: true, Pending: true}, res)
	assert.Empty(t, h.reg.ourRuleNames())

	flushes, _ := h.sideEffects()
	h.reg.writes = nil
	res, err = h.Clear(ctx, backend.Attempt{})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res, "nothing is left to remove and the flush completed")
	assert.Empty(t, h.reg.writes)
	gotFlushes, _ := h.sideEffects()
	assert.Equal(t, flushes+1, gotFlushes)

	res, err = h.Clear(ctx, backend.Attempt{})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.Empty(t, h.reg.writes)
	gotFlushes, _ = h.sideEffects()
	assert.Equal(t, flushes+1, gotFlushes, "a converged Clear flushes nothing")
}

// raceRegistry runs before once, just before the named operation reaches
// the fake, and after once, just after it; both stand in for the policy
// engine writing between two of our steps.
type raceRegistry struct {
	*fakeRegistry
	op, path      string
	before, after func()
}

func (r *raceRegistry) run(op, path string, call func() error) error {
	if op != r.op || path != r.path {
		return call()
	}
	if f := r.before; f != nil {
		r.before = nil
		f()
	}
	err := call()
	if f := r.after; f != nil {
		r.after = nil
		f()
	}
	return err
}

func (r *raceRegistry) RenameKey(path, name string) error {
	return r.run("rename", path, func() error { return r.fakeRegistry.RenameKey(path, name) })
}

func (r *raceRegistry) DeleteKey(path string) error {
	return r.run("delete", path, func() error { return r.fakeRegistry.DeleteKey(path) })
}

// gpOnlyOurs sets up this identity in both stores, then removes the foreign
// rule, so the next converge retires the container.
func gpOnlyOurs(t *testing.T, h *harness, cfg backend.Config) {
	t.Helper()
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := h.Set(context.Background(), cfg, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`))
}

// TestClearRemovesLocalCopiesAfterFailedContainerDelete lets foreign policy
// leave mid-Clear and fails the delete of the container our deletions
// emptied. No GP copy of ours remains, so the local copies still go.
func TestClearRemovesLocalCopiesAfterFailedContainerDelete(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := h.Set(ctx, splitConfig(t, 1), backend.Attempt{NewGoal: true})
	require.NoError(t, err)

	h.Backend.reg = &raceRegistry{fakeRegistry: h.reg, op: "delete", path: gpRuleKey(0),
		after: func() { require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`)) }}
	h.reg.fail = func(op, path, _ string) error {
		if op == "DeleteKey" && path == gpoNrptBase {
			return errInjectedRegistry
		}
		return nil
	}
	require.ErrorIs(t, h.clearGoal(ctx), errInjectedRegistry)
	assert.False(t, h.reg.hasKey(gpRuleKey(0)))
	assert.False(t, h.reg.hasKey(ruleKey(0)), "with no GP copy left, the local copy goes in the same attempt")
	assert.True(t, h.reg.hasKey(gpoNrptBase), "the emptied container is the documented window")
}

// TestRetirementRacesForeignPolicy covers policy written between the
// collapsibility check and the rename. With no new container the retired one
// is restored with the foreign rule. With a new container the retired key is
// deleted, since it routes nothing and would block every later retirement.
// Either way the attempt fails and the retry places rules for that policy.
func TestRetirementRacesForeignPolicy(t *testing.T) {
	for _, newContainer := range []bool{false, true} {
		t.Run(fmt.Sprintf("new container=%t", newContainer), func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			cfg := splitConfig(t, 1)
			gpOnlyOurs(t, h, cfg)
			reg := &raceRegistry{fakeRegistry: h.reg, op: "rename", path: gpoNrptBase,
				before: func() { seedForeignGPRule(t, h.reg, "late") }}
			if newContainer {
				reg.after = func() { seedForeignGPRule(t, h.reg, "newer") }
			}
			h.Backend.reg = reg
			_, err := h.Set(ctx, cfg, backend.Attempt{})
			require.Error(t, err)
			assert.False(t, h.reg.hasKey(retiredGPBase))
			assert.Equal(t, !newContainer, h.reg.hasKey(gpoNrptBase+`\late`), "only a restore brings back the carried rule")

			_, err = h.Set(ctx, cfg, backend.Attempt{})
			require.NoError(t, err)
			assert.True(t, h.reg.hasKey(gpRuleKey(0)), "foreign policy puts our copy in the GP store")
			assert.True(t, h.reg.hasKey(ruleKey(0)))

			h.Backend.reg = h.reg
			foreign := "late"
			if newContainer {
				foreign = "newer"
			}
			require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\`+foreign))
			_, err = h.Set(ctx, cfg, backend.Attempt{})
			require.NoError(t, err)
			assert.False(t, h.reg.hasKey(gpoNrptBase), "a later retirement is not blocked")
		})
	}
}

// TestAdapterReplacementDuringRetirementStaysRecoverable replaces the
// adapter just as foreign policy leaves, then fails the retirement. Both
// stores were converged first, so their records agree and the retry and a
// fresh identity's Clear both proceed.
func TestAdapterReplacementDuringRetirementStaysRecoverable(t *testing.T) {
	for _, next := range []string{"retry", "clear"} {
		t.Run(next, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			cfg := splitConfig(t, 1)
			gpOnlyOurs(t, h, cfg)
			for _, path := range adapterPaths(otherGUID) {
				require.NoError(t, h.reg.CreateKey(path))
			}
			replaced := func(reg Registry) *Backend {
				b, err := New(ctx, Options{
					Logger:           discardLogger(),
					WatchPolicy:      func() (Watcher, error) { return newFakeWatcher(), nil },
					WatchRegistry:    func([]RegistryWatchKey) (Watcher, error) { return newFakeWatcher(), nil },
					Identity:         testIdentity,
					Registry:         reg,
					Runner:           h.fr,
					Notifier:         h.notify,
					InterfaceName:    testInterface,
					ResolveInterface: func(string) (string, error) { return otherGUID, nil },
				})
				require.NoError(t, err)
				t.Cleanup(func() { _ = b.Close() })
				return b
			}
			h.reg.fail = failMigration("retire")
			_, err := replaced(h.reg).Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.ErrorIs(t, err, errInjectedRegistry)
			h.reg.fail = nil
			for _, key := range []string{ruleKey(0), gpRuleKey(0)} {
				guid, err := h.reg.GetString(key, interfaceGUIDValue)
				require.NoError(t, err)
				assert.Equal(t, otherGUID, guid, "%s names the replacement adapter", key)
			}

			fresh := replaced(h.reg)
			if next == "retry" {
				_, err = fresh.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			} else {
				_, err = fresh.Clear(ctx, backend.Attempt{NewGoal: true})
			}
			require.NoError(t, err)
			assert.False(t, h.reg.hasKey(gpoNrptBase))
		})
	}
}

// TestClearRemovesContainerItEmptied covers foreign policy leaving while
// Clear deletes its GP copy one by one: the container that deletion empties
// is removed in the same Clear.
func TestClearRemovesContainerItEmptied(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "foreign")
	_, err := h.Set(ctx, splitConfig(t, 1), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	h.Backend.reg = &raceRegistry{fakeRegistry: h.reg, op: "delete", path: gpRuleKey(0),
		before: func() { require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\foreign`)) }}

	_, err = h.Clear(ctx, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.False(t, h.reg.hasKey(gpoNrptBase), "an empty container suppresses every local rule")
}

// TestRetiredLeftoverOwesNotification requests a policy notification when a
// crash left a retired container: its rules may still be in the DNS Client's
// cached GP table.
func TestRetiredLeftoverOwesNotification(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.reg.SetString(retiredGPBase+`\`+ruleName(testIdentity, 0), "GenericDNSServers", "192.0.2.9"))
	calls := h.notify.calls
	_, err := h.Clear(context.Background(), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.Equal(t, calls+1, h.notify.calls)
}

// TestClearRetiresBeforeRemovingLocalCopies keeps the local copy until the
// container is retired, so a crash in between never leaves our GP rule
// without the local twin peers wait for.
func TestClearRetiresBeforeRemovingLocalCopies(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gpOnlyOurs(t, h, splitConfig(t, 1))
	h.reg.writes = nil
	_, err := h.Clear(ctx, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	rename := slices.Index(h.reg.writes, "RenameKey "+gpoNrptBase+" "+retiredGPName)
	local := slices.Index(h.reg.writes, "DeleteKey "+ruleKey(0)+" ")
	require.NotEqual(t, -1, rename)
	require.NotEqual(t, -1, local)
	assert.Less(t, rename, local)
}

// TestClearToleratesUnreadablePeerRecord treats a peer GP rule with an
// unreadable recovery record as not ready instead of failing Clear.
func TestClearToleratesUnreadablePeerRecord(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, err := h.Set(ctx, splitConfig(t, 1), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	peerKey := gpoNrptBase + `\` + ruleName(otherIdentity, 0)
	require.NoError(t, h.reg.SetMultiString(peerKey, "Name", []string{".b.example"}))
	require.NoError(t, h.reg.SetString(peerKey, "GenericDNSServers", "192.0.2.2"))
	require.NoError(t, h.reg.SetString(peerKey, interfaceGUIDValue, "not-a-guid"))
	_, err = h.Clear(ctx, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.Empty(t, h.reg.ourRuleNames())
	assert.True(t, h.reg.hasKey(peerKey))
}
