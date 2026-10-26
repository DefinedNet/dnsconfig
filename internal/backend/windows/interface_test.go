package windows

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const otherGUID = "{00000000-0000-0000-0000-000000000002}"

// TestNamelessInstanceRecoversFromRecords permits recovery without caller configuration.
func TestNamelessInstanceRecoversFromRecords(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	for _, path := range adapterPaths(otherGUID) {
		require.NoError(t, h.reg.SetString(path, nameServerValue, "192.0.2.99"))
	}
	fr := &runnertest.FakeRunner{}
	b, err := New(ctx, Options{Logger: discardLogger(), Identity: testIdentity, Registry: h.reg, Runner: fr})
	require.NoError(t, err)
	present, err := b.ownedState()
	require.NoError(t, err)
	assert.True(t, present)
	require.NoError(t, b.clearGoal(ctx))
	assert.Empty(t, h.reg.ourRuleNames())
	for _, path := range adapterPaths(testGUID) {
		assert.NotContains(t, h.reg.keys[path], nameServerValue)
	}
	for _, path := range adapterPaths(otherGUID) {
		assert.Equal(t, "192.0.2.99", h.reg.keys[path][nameServerValue])
	}
}

// TestNamelessRecoveryUnderGroupPolicy recovers from records present in
// both stores, which agree on one adapter, and leaves foreign policy intact.
func TestNamelessRecoveryUnderGroupPolicy(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
	foreign := h.reg.snapshot()[gpoNrptBase+`\{FOREIGN-RULE}`]
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NotEmpty(t, h.reg.ourRuleNames())
	require.NotEmpty(t, h.reg.gpRuleNames())

	notify := &fakeNotifier{delivery: DeliveryNotified}
	b, err := New(ctx, Options{Logger: discardLogger(), Identity: testIdentity, Registry: h.reg, Runner: &runnertest.FakeRunner{}, Notifier: notify})
	require.NoError(t, err)
	require.NoError(t, b.clearGoal(ctx))
	assert.Empty(t, h.reg.ourRuleNames())
	assert.Empty(t, h.reg.gpRuleNames())
	assert.Equal(t, foreign, h.reg.keys[gpoNrptBase+`\{FOREIGN-RULE}`])
	for _, path := range adapterPaths(testGUID) {
		assert.NotContains(t, h.reg.keys[path], nameServerValue)
	}
	assert.Equal(t, 1, notify.calls, "removing GP rules needs a policy notification")
}

// TestNamelessClearSweepsRuleWithoutRecords removes an owned rule that
// records no adapter and, with no recorded target, touches no adapter.
func TestNamelessClearSweepsRuleWithoutRecords(t *testing.T) {
	reg := newFakeRegistry()
	require.NoError(t, reg.CreateKey(ruleKey(0)))
	for _, path := range adapterPaths(testGUID) {
		require.NoError(t, reg.SetString(path, searchListValue, "ours.example"))
	}
	b, err := New(context.Background(), Options{Logger: discardLogger(), Identity: testIdentity, Registry: reg, Runner: &runnertest.FakeRunner{}})
	require.NoError(t, err)
	require.NoError(t, b.clearGoal(context.Background()))
	assert.Empty(t, reg.ourRuleNames())
	for _, path := range adapterPaths(testGUID) {
		assert.Equal(t, "ours.example", reg.keys[path][searchListValue])
	}
}

func TestAdapterValuesReplaceAndClearWithoutSnapshot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.53", "2001:db8::53"), SearchDomains: []string{"first.example", "second.example"}}
	require.NoError(t, h.setGoal(ctx, cfg))
	for i, path := range adapterPaths(testGUID) {
		assert.Equal(t, "first.example,second.example", h.reg.keys[path][searchListValue])
		assert.Equal(t, cfg.Nameservers[i].String(), h.reg.keys[path][nameServerValue])
		require.NoError(t, h.reg.SetString(path, "Domain", "caller-owned.example"))
	}
	cfg.MatchDomains = []string{"example"}
	cfg.SearchDomains = []string{"replacement.example"}
	require.NoError(t, h.setGoal(ctx, cfg))
	for _, path := range adapterPaths(testGUID) {
		assert.Equal(t, "replacement.example", h.reg.keys[path][searchListValue])
		_, err := h.reg.GetString(path, nameServerValue)
		assert.ErrorIs(t, err, ErrValueNotFound, "split must not leave adapter DNS servers from catch-all")
	}
	require.NoError(t, h.clearGoal(ctx))
	for _, path := range adapterPaths(testGUID) {
		assert.Equal(t, map[string]any{"Domain": "caller-owned.example"}, h.reg.keys[path])
	}
}

func TestRecordedTargetSurvivesRenameReplacementAndRemoval(t *testing.T) {
	for _, state := range []string{"renamed", "replaced", "absent"} {
		t.Run(state, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			require.NoError(t, h.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.53"), SearchDomains: []string{"ours.example"}}))
			for _, path := range adapterPaths(otherGUID) {
				require.NoError(t, h.reg.SetString(path, searchListValue, "replacement.example"))
				require.NoError(t, h.reg.SetString(path, nameServerValue, "192.0.2.99"))
			}
			name := testInterface
			resolve := func(string) (string, error) { return otherGUID, nil }
			if state == "renamed" {
				name = "renamed-adapter"
				resolve = func(string) (string, error) { return testGUID, nil }
			}
			if state == "absent" {
				resolve = func(string) (string, error) { return "", ErrInterfaceNotFound }
				for _, path := range adapterPaths(testGUID) {
					delete(h.reg.keys, path)
				}
			}
			b, err := New(ctx, Options{Logger: discardLogger(), Identity: testIdentity, Registry: h.reg, Runner: h.fr, InterfaceName: name, ResolveInterface: resolve})
			require.NoError(t, err)
			present, err := b.ownedState()
			require.NoError(t, err)
			assert.True(t, present)
			require.NoError(t, b.clearGoal(ctx))
			assert.Empty(t, h.reg.ourRuleNames())
			for _, path := range adapterPaths(testGUID) {
				for _, name := range []string{searchListValue, nameServerValue} {
					_, err := h.reg.GetString(path, name)
					assert.ErrorIs(t, err, ErrValueNotFound)
				}
				if state == "absent" {
					assert.False(t, h.reg.hasKey(path))
				}
			}
			for _, path := range adapterPaths(otherGUID) {
				assert.Equal(t, map[string]any{searchListValue: "replacement.example", nameServerValue: "192.0.2.99"}, h.reg.keys[path])
			}
		})
	}
}

func TestInvalidRecoveryTargetRejectsWithoutMutation(t *testing.T) {
	for _, state := range []string{"bad-guid", "conflicting-guid"} {
		t.Run(state, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			require.NoError(t, h.setGoal(ctx, catchAll(t)))
			switch state {
			case "bad-guid":
				require.NoError(t, h.reg.SetString(ruleKey(0), interfaceGUIDValue, `..\Parameters`))
			case "conflicting-guid":
				require.NoError(t, h.writeTarget(gpRuleKey(1), adapterTarget{otherGUID}))
			}
			before := h.reg.snapshot()
			require.Error(t, h.clearGoal(ctx))
			assert.Equal(t, before, h.reg.snapshot())
			require.Error(t, h.setGoal(ctx, catchAll(t)))
			assert.Equal(t, before, h.reg.snapshot())
		})
	}
}

// failAdapterWrite fails writes of path's SearchList value.
func failAdapterWrite(path string) func(op, keyPath, name string) error {
	return failSearchList("SetExistingString", path, errors.New("adapter write failed"))
}

// failAdapterClear fails deletions of path's SearchList value.
func failAdapterClear(path string) func(op, keyPath, name string) error {
	return failSearchList("DeleteValue", path, errors.New("adapter clear failed"))
}

func failSearchList(op, path string, err error) func(op, keyPath, name string) error {
	return func(gotOp, keyPath, name string) error {
		if gotOp == op && keyPath == path && name == searchListValue {
			return err
		}
		return nil
	}
}

// TestFailedAdapterWriteCompletesOnRetry leaves a failed attempt's writes in
// place for the next attempt, for first applies and replacements.
func TestFailedAdapterWriteCompletesOnRetry(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprintf("replacement=%v", replacement), func(t *testing.T) {
			ctx := context.Background()
			paths := adapterPaths(testGUID)
			base := newFakeRegistry()
			b, err := newTestBackend(ctx, Options{Registry: base})
			require.NoError(t, err)
			if replacement {
				require.NoError(t, b.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), SearchDomains: []string{"before.example"}}))
			}
			base.fail = failAdapterWrite(paths[1])
			cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.53", "2001:db8::53"), SearchDomains: []string{"ours.example"}}
			res, err := b.Set(ctx, cfg, backend.Attempt{NewGoal: true})
			require.Error(t, err)
			assert.True(t, res.Changed, "the attempt wrote before failing")
			assert.True(t, res.Pending, "the writes owe a cache flush")
			assert.Equal(t, "192.0.2.53;2001:db8::53", base.keys[ruleKey(0)]["GenericDNSServers"], "published rules stay")
			assert.Equal(t, "ours.example", base.keys[paths[0]][searchListValue], "completed adapter writes stay")
			present, err := b.ownedState()
			require.NoError(t, err)
			assert.True(t, present)

			base.fail = nil
			res, err = b.Set(ctx, cfg, backend.Attempt{})
			require.NoError(t, err)
			assert.True(t, res.Changed)
			assert.False(t, res.Pending)
			for i, path := range paths {
				assert.Equal(t, "ours.example", base.keys[path][searchListValue])
				assert.Equal(t, cfg.Nameservers[i].String(), base.keys[path][nameServerValue])
			}
			require.NoError(t, b.clearGoal(ctx))
			assert.Empty(t, base.ourRuleNames())
		})
	}
	t.Run("stack disappears", func(t *testing.T) {
		ctx := context.Background()
		paths := adapterPaths(testGUID)
		base := newFakeRegistry()
		// The stack's key vanishes just before its SearchList write.
		base.fail = func(op, keyPath, name string) error {
			if op == "SetExistingString" && keyPath == paths[1] && name == searchListValue {
				delete(base.keys, keyPath)
			}
			return nil
		}
		b, err := newTestBackend(ctx, Options{Registry: base})
		require.NoError(t, err)
		cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.53"), SearchDomains: []string{"ours.example"}}
		_, err = b.Set(ctx, cfg, backend.Attempt{NewGoal: true})
		require.Error(t, err)
		_, err = b.Set(ctx, cfg, backend.Attempt{})
		require.ErrorIs(t, err, ErrInterfaceNotFound, "a removed stack is a refusal on the next attempt")
		require.NoError(t, b.clearGoal(ctx), "cleanup skips the removed stack")
		assert.Empty(t, base.ourRuleNames())
		assert.NotContains(t, base.keys[paths[0]], searchListValue)
		assert.False(t, base.hasKey(paths[1]), "a removed device is not recreated")
	})
}

func TestMissingAdapterKeyRejectsBeforeRuleChanges(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
	delete(h.reg.keys, adapterPaths(testGUID)[1])
	before := h.reg.snapshot()
	require.ErrorIs(t, h.setGoal(context.Background(), catchAll(t)), ErrInterfaceNotFound)
	assert.Equal(t, before, h.reg.snapshot())
}

func TestCrashAtEveryApplyWriteRemainsRecoverable(t *testing.T) {
	first := catchAll(t)
	second := backend.Config{Nameservers: mustAddrs(t, "192.0.2.53", "2001:db8::53"), SearchDomains: []string{"ours.example"}, MatchDomains: []string{"ours.example"}}
	// newRegistry seeds foreign policy for the group-policy variants, where
	// every rule is written to both stores.
	newRegistry := func(gp bool) *failInjectRegistry {
		reg := &failInjectRegistry{fakeRegistry: newFakeRegistry(), failAt: -1}
		if gp {
			seedForeignGPRule(t, reg.fakeRegistry, "{FOREIGN-RULE}")
		}
		return reg
	}
	for _, gp := range []bool{false, true} {
		for _, replacement := range []bool{false, true} {
			writes := func() int {
				reg := newRegistry(gp)
				b, err := newTestBackend(context.Background(), Options{Registry: reg})
				require.NoError(t, err)
				if replacement {
					require.NoError(t, b.setGoal(context.Background(), first))
				}
				reg.arm(-1)
				require.NoError(t, b.setGoal(context.Background(), second))
				return reg.seen
			}()
			require.Positive(t, writes)
			for stop := 0; stop <= writes; stop++ {
				t.Run(fmt.Sprintf("gp=%v/replacement=%v/after=%d", gp, replacement, stop), func(t *testing.T) {
					reg := newRegistry(gp)
					b, err := newTestBackend(context.Background(), Options{Registry: reg})
					require.NoError(t, err)
					if replacement {
						require.NoError(t, b.setGoal(context.Background(), first))
					}
					reg.arm(stop)
					reg.crash = true
					func() {
						defer func() { _ = recover() }()
						require.NoError(t, b.setGoal(context.Background(), second))
					}()
					reg.crash = false
					reg.arm(-1)
					restarted, err := newTestBackend(context.Background(), Options{Registry: reg})
					require.NoError(t, err)
					// The probe must see every crash point that left an
					// adapter value, or a startup Recover would skip it.
					writes := len(reg.writes)
					has, err := restarted.HasArtifacts(context.Background())
					require.NoError(t, err)
					assert.Equal(t, writes, len(reg.writes), "the probe writes nothing")
					if !has {
						for _, path := range adapterPaths(testGUID) {
							assert.NotContains(t, reg.keys[path], searchListValue)
							assert.NotContains(t, reg.keys[path], nameServerValue)
						}
					}
					require.NoError(t, restarted.clearGoal(context.Background()))
					require.Empty(t, reg.ourRuleNames())
					require.Empty(t, reg.gpRuleNames())
					assert.Equal(t, gp, reg.hasKey(gpoNrptBase+`\{FOREIGN-RULE}`))
					for _, path := range adapterPaths(testGUID) {
						assert.NotContains(t, reg.keys[path], searchListValue)
						assert.NotContains(t, reg.keys[path], nameServerValue)
					}
				})
			}
		}
	}
}

func TestPendingRecordDeletionFailureCanRetry(t *testing.T) {
	reg := &failInjectRegistry{fakeRegistry: newFakeRegistry(), failAt: -1}
	key := nrptBase + `\` + ruleName(testIdentity, 0) + pendingRuleSuffix
	require.NoError(t, reg.CreateKey(key))
	require.NoError(t, reg.SetString(key, interfaceGUIDValue, "incomplete"))
	// Pending evidence must never authorize clearing existing adapter values.
	for _, path := range adapterPaths(testGUID) {
		require.NoError(t, reg.SetString(path, searchListValue, "untouched.example"))
	}
	b, err := newTestBackend(context.Background(), Options{Registry: reg, Runner: &runnertest.FakeRunner{}})
	require.NoError(t, err)
	reg.arm(0)
	require.ErrorIs(t, b.clearGoal(context.Background()), errInjectedRegistry)
	require.True(t, reg.hasKey(key))
	reg.arm(-1)
	require.NoError(t, b.clearGoal(context.Background()))
	require.False(t, reg.hasKey(key))
	for _, path := range adapterPaths(testGUID) {
		assert.Equal(t, "untouched.example", reg.keys[path][searchListValue])
	}
}

func TestSetFailureMarksOnlyReadOnlyRejection(t *testing.T) {
	reg := &failInjectRegistry{fakeRegistry: newFakeRegistry(), failAt: -1}
	b, err := newTestBackend(context.Background(), Options{Registry: reg, Runner: &runnertest.FakeRunner{}})
	require.NoError(t, err)
	require.NoError(t, b.setGoal(context.Background(), catchAll(t)))
	before := reg.snapshot()
	b.resolveInterface = func(string) (string, error) { return "", ErrInterfaceNotFound }
	res, err := b.Set(context.Background(), catchAll(t), backend.Attempt{NewGoal: true})
	require.Error(t, err)
	assert.False(t, res.Changed)
	assert.Equal(t, before, reg.snapshot())
	b.resolveInterface = func(string) (string, error) { return testGUID, nil }
	reg.arm(1) // the first staged write succeeded before this failure
	replacement := catchAll(t)
	replacement.Nameservers = mustAddrs(t, "192.0.2.99")
	res, err = b.Set(context.Background(), replacement, backend.Attempt{NewGoal: true})
	require.Error(t, err)
	assert.True(t, res.Changed)
}

func TestOnlyCatchAllSetsAdapterServers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		matches  []string
		catchAll bool
	}{
		{"implicit catch-all", nil, true},
		{"suffix only", []string{"corp.example"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			cfg := backend.Config{
				Nameservers:   mustAddrs(t, "192.0.2.53", "2001:db8::53"),
				SearchDomains: []string{"corp.example"},
				MatchDomains:  tc.matches,
			}
			require.NoError(t, h.setGoal(context.Background(), cfg))
			for i, path := range adapterPaths(testGUID) {
				servers, err := h.reg.GetString(path, nameServerValue)
				if tc.catchAll {
					require.NoError(t, err)
					assert.Equal(t, cfg.Nameservers[i].String(), servers)
				} else {
					assert.ErrorIs(t, err, ErrValueNotFound)
				}
			}
		})
	}
}

func TestOwnAdapterCleanupSurvivesMissingRecords(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	dropOwnRules(t, h.reg, nrptBase)

	fresh, err := newTestBackend(ctx, Options{Registry: h.reg, Runner: h.fr})
	require.NoError(t, err)
	before := h.reg.snapshot()
	present, err := fresh.ownedState()
	require.NoError(t, err)
	assert.False(t, present, "a fresh instance must not infer authority from adapter values")
	require.NoError(t, fresh.clearGoal(ctx))
	require.NoError(t, fresh.Close())
	assert.Equal(t, before, h.reg.snapshot())

	present, err = h.ownedState()
	require.NoError(t, err)
	assert.True(t, present, "this instance still has adapter writes to clear")
	require.NoError(t, h.clearGoal(ctx))
	for _, path := range adapterPaths(testGUID) {
		assert.NotContains(t, h.reg.keys[path], searchListValue)
		assert.NotContains(t, h.reg.keys[path], nameServerValue)
		require.NoError(t, h.reg.SetString(path, searchListValue, "later.example"))
	}
	present, err = h.ownedState()
	require.NoError(t, err)
	assert.False(t, present)
	before = h.reg.snapshot()
	require.NoError(t, h.clearGoal(ctx))
	assert.Equal(t, before, h.reg.snapshot(), "successful cleanup releases the remembered target")
}

func TestOwnTargetReapplyAfterRecordsDisappear(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	dropOwnRules(t, h.reg, nrptBase)
	for _, path := range adapterPaths(otherGUID) {
		require.NoError(t, h.reg.CreateKey(path))
	}
	h.resolveInterface = func(string) (string, error) { return otherGUID, nil }
	cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.53"), SearchDomains: []string{"replacement.example"}}
	require.NoError(t, h.setGoal(ctx, cfg))
	for _, path := range adapterPaths(testGUID) {
		assert.NotContains(t, h.reg.keys[path], searchListValue)
		assert.NotContains(t, h.reg.keys[path], nameServerValue)
	}
	for _, path := range adapterPaths(otherGUID) {
		assert.Equal(t, "replacement.example", h.reg.keys[path][searchListValue])
	}
	require.NoError(t, h.clearGoal(ctx))
	for _, path := range adapterPaths(otherGUID) {
		assert.NotContains(t, h.reg.keys[path], searchListValue)
		assert.NotContains(t, h.reg.keys[path], nameServerValue)
	}
}

func TestOwnTargetHonorsSurvivingEvidence(t *testing.T) {
	for _, state := range []string{"renamed", "conflicting", "unreadable"} {
		t.Run(state, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			require.NoError(t, h.setGoal(ctx, catchAll(t)))
			switch state {
			case "renamed":
				h.interfaceName = "renamed"
			case "conflicting":
				// Records agree with each other but not with this instance's
				// pending cleanup target.
				for i := range catchAllRules {
					require.NoError(t, h.reg.SetString(ruleKey(i), interfaceGUIDValue, otherGUID))
				}
			case "unreadable":
				h.reg.fail = func(op, _, _ string) error {
					if op == "SubKeyNames" {
						return errors.New("recovery records unreadable")
					}
					return nil
				}
			}
			before := h.reg.snapshot()
			if state == "renamed" {
				require.NoError(t, h.clearGoal(ctx), "GUID-preserving rename remains valid")
				return
			}
			require.Error(t, h.clearGoal(ctx))
			assert.Equal(t, before, h.reg.snapshot())
			require.Error(t, h.setGoal(ctx, catchAll(t)))
			assert.Equal(t, before, h.reg.snapshot())
			if state == "unreadable" {
				_, err := h.ownedState()
				require.Error(t, err)
			}
		})
	}
}

// TestFailedSetOverPredecessorRecordStaysAttributable replaces a target-only
// record a crashed predecessor left, so adapter values written before a
// failure remain attributable to this identity.
func TestFailedSetOverPredecessorRecordStaysAttributable(t *testing.T) {
	ctx := context.Background()
	paths := adapterPaths(testGUID)
	base := newFakeRegistry()
	b, err := newTestBackend(ctx, Options{Registry: base})
	require.NoError(t, err)
	require.NoError(t, b.writeTarget(ruleKey(0), adapterTarget{testGUID}))
	require.NoError(t, base.SetString(paths[0], nameServerValue, "192.0.2.9"))

	base.fail = failAdapterWrite(paths[0])
	err = b.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.53"), SearchDomains: []string{"ours.example"}})
	require.Error(t, err)
	rec := base.keys[ruleKey(0)]
	assert.Equal(t, testGUID, rec[interfaceGUIDValue])
	assert.Equal(t, []string{"."}, rec["Name"], "the leftover record is replaced by a complete rule")
	assert.Equal(t, "192.0.2.53", base.keys[paths[0]][nameServerValue], "the write before the failure stays")
	present, err := b.ownedState()
	require.NoError(t, err)
	assert.True(t, present)

	base.fail = nil
	require.NoError(t, b.clearGoal(ctx))
	assert.NotContains(t, base.keys[paths[0]], nameServerValue, "Clear clears the attributed adapter value")
	assert.Empty(t, base.ourRuleNames())
}

// TestOwnTargetSurvivesPartialFailureAndRecordLoss retains the adapter target
// in memory so cleanup can finish after external record deletion.
func TestOwnTargetSurvivesPartialFailureAndRecordLoss(t *testing.T) {
	for _, phase := range []string{"failed write", "cross-process recovery"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			paths := adapterPaths(testGUID)
			reg := newFakeRegistry()
			b, err := newTestBackend(ctx, Options{Registry: reg, Runner: &runnertest.FakeRunner{}})
			require.NoError(t, err)
			cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.53"), SearchDomains: []string{"ours.example"}}
			if phase == "failed write" {
				// The second stack's write fails; the first stack's values
				// and the published rules stay for the retry.
				reg.fail = failAdapterWrite(paths[1])
				require.Error(t, b.setGoal(ctx, cfg))
				assert.NotEmpty(t, reg.ourRuleNames(), "rules stay as evidence while adapter values remain")
				present, err := b.ownedState()
				require.NoError(t, err)
				assert.True(t, present)
				reg.fail = failAdapterClear(paths[0])
			} else {
				require.NoError(t, b.setGoal(ctx, cfg))
				b, err = newTestBackend(ctx, Options{Registry: reg, Runner: &runnertest.FakeRunner{}})
				require.NoError(t, err)
				reg.fail = failAdapterClear(paths[0])
			}
			require.Error(t, b.clearGoal(ctx))
			dropOwnRules(t, reg, nrptBase)
			reg.fail = nil
			require.NoError(t, b.clearGoal(ctx))
			for _, path := range paths {
				assert.NotContains(t, reg.keys[path], searchListValue)
				assert.NotContains(t, reg.keys[path], nameServerValue)
			}
		})
	}
}

// TestSuccessfulAdapterClearReleasesTargetBeforeRuleSweep fails a Clear after
// its adapter clear succeeded. Adapter values written before the retry are
// not ours: the retry reads current state rather than a remembered target.
func TestSuccessfulAdapterClearReleasesTargetBeforeRuleSweep(t *testing.T) {
	ctx := context.Background()
	reg := &failInjectRegistry{fakeRegistry: newFakeRegistry(), failAt: -1}
	b, err := newTestBackend(ctx, Options{Registry: reg, Runner: &runnertest.FakeRunner{}})
	require.NoError(t, err)
	require.NoError(t, b.setGoal(ctx, catchAll(t)))
	reg.arm(3) // The adapter value and both reload trigger writes succeed; the first rule deletion fails.
	require.Error(t, b.clearGoal(ctx))
	reg.arm(-1)
	dropOwnRules(t, reg.fakeRegistry, nrptBase)
	for _, path := range adapterPaths(testGUID) {
		require.NoError(t, reg.SetString(path, searchListValue, "later.example"))
		require.NoError(t, reg.SetString(path, nameServerValue, "10.0.0.1"))
	}
	before := reg.snapshot()
	require.NoError(t, b.clearGoal(ctx))
	assert.Equal(t, before, reg.snapshot(), "no stale in-memory authority after successful adapter clear")
}
