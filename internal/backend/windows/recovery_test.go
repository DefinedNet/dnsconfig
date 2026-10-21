package windows

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
)

// TestClearStopsAtFailedRuleDeletion keeps a store's later rules after a
// failed deletion, and the retry removes them all.
func TestClearStopsAtFailedRuleDeletion(t *testing.T) {
	ctx := context.Background()
	reg := &failInjectRegistry{fakeRegistry: newFakeRegistry(), failAt: -1}
	b, err := newTestBackend(ctx, Options{Registry: reg, Runner: &runnertest.FakeRunner{}})
	require.NoError(t, err)
	require.NoError(t, b.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"a.example"}}))
	// A second rule of this identity, as a larger match set would produce.
	require.NoError(t, b.writeStagedRule(nrptBase, 1, nrptRule{[]string{".b.example"}, "192.0.2.1"}, adapterTarget{testGUID}))
	require.NoError(t, reg.RenameKey(nrptBase+`\`+b.ruleName(1, true), b.ruleName(1, false)))

	// Split DNS without search domains owns no adapter values, so the first
	// write is the first rule deletion.
	reg.arm(0)
	err = b.clearGoal(ctx)
	require.ErrorIs(t, err, errInjectedRegistry)
	assert.True(t, reg.hasKey(ruleKey(0)), "the failed key stays")
	assert.True(t, reg.hasKey(ruleKey(1)), "later rules wait for the retry")

	reg.arm(-1)
	present, err := b.ownedState()
	require.NoError(t, err)
	assert.True(t, present, "the surviving key keeps the instance recoverable")
	require.NoError(t, b.clearGoal(ctx))
	assert.Empty(t, reg.ourRuleNames())
}

// TestClearKeepsRulesWhenAdapterClearFails preserves evidence for a cleanup retry.
func TestClearKeepsRulesWhenAdapterClearFails(t *testing.T) {
	ctx := context.Background()
	base := newFakeRegistry()
	b, err := newTestBackend(ctx, Options{Registry: base, Runner: &runnertest.FakeRunner{}})
	require.NoError(t, err)
	require.NoError(t, b.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), SearchDomains: []string{"ours.example"}}))

	base.fail = failAdapterClear(adapterPaths(testGUID)[1])
	require.Error(t, b.clearGoal(ctx))
	assert.Equal(t, catchAllRules, base.ourRuleNames(), "rules stay as evidence")
	assert.NotContains(t, base.keys[adapterPaths(testGUID)[0]], searchListValue, "the independent stack was cleared")

	base.fail = nil
	require.NoError(t, b.clearGoal(ctx))
	assert.Empty(t, base.ourRuleNames())
	for _, path := range adapterPaths(testGUID) {
		assert.NotContains(t, base.keys[path], searchListValue)
	}
}

// TestFailedPriorAdapterClearDoesNotWedge retries a predecessor's adapter
// cleanup through the same Backend after a failed attempt, whether the
// successor was given no interface name, a different one, or one it cannot
// resolve. Cleanup is authorized by the recorded GUID, not the name.
func TestFailedPriorAdapterClearDoesNotWedge(t *testing.T) {
	notFound := func(string) (string, error) { return "", ErrInterfaceNotFound }
	other := func(string) (string, error) { return otherGUID, nil }
	denied := func(string) (string, error) { return "", errors.New("access denied") }
	for _, tc := range []struct {
		name    string
		iface   string
		resolve func(string) (string, error)
	}{
		{name: "nameless", iface: "", resolve: notFound},
		{name: "renamed-successor", iface: "new-tun", resolve: other},
		{name: "unresolvable", iface: testInterface, resolve: denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newHarness(t)
			cfg := backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), SearchDomains: []string{"ours.example"}}
			require.NoError(t, h.setGoal(ctx, cfg))
			for _, path := range adapterPaths(otherGUID) {
				require.NoError(t, h.reg.CreateKey(path))
			}
			b, err := New(ctx, Options{Logger: discardLogger(), Identity: testIdentity, Registry: h.reg, Runner: h.fr, InterfaceName: tc.iface, ResolveInterface: tc.resolve,
				WatchPolicy:   func() (Watcher, error) { return newFakeWatcher(), nil },
				WatchRegistry: func([]RegistryWatchKey) (Watcher, error) { return newFakeWatcher(), nil }})
			require.NoError(t, err)
			t.Cleanup(func() { _ = b.Close() })

			h.reg.fail = failAdapterClear(adapterPaths(testGUID)[1])
			if tc.name == "renamed-successor" {
				require.ErrorContains(t, b.setGoal(ctx, cfg), "adapter clear failed", "clearing the replaced adapter fails first")
			} else {
				require.ErrorContains(t, b.clearGoal(ctx), "adapter clear failed")
			}
			assert.Equal(t, catchAllRules, h.reg.ourRuleNames(), "rules stay as evidence")

			h.reg.fail = nil
			if tc.name == "renamed-successor" {
				require.NoError(t, b.setGoal(ctx, cfg), "a retried Set finishes the replaced adapter's cleanup")
				for _, path := range adapterPaths(otherGUID) {
					assert.Equal(t, "ours.example", h.reg.keys[path][searchListValue])
				}
			}
			require.NoError(t, b.clearGoal(ctx))
			assert.Empty(t, h.reg.ourRuleNames())
			for _, path := range adapterPaths(testGUID) {
				assert.NotContains(t, h.reg.keys[path], searchListValue)
				assert.NotContains(t, h.reg.keys[path], nameServerValue)
			}
		})
	}
}

// TestClearSkipsRecordedAdapterThatNoLongerExists protects a replacement adapter
// that reuses the predecessor's configured name.
func TestClearSkipsRecordedAdapterThatNoLongerExists(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	require.NoError(t, h.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), SearchDomains: []string{"ours.example"}}))
	for _, path := range adapterPaths(testGUID) {
		require.NoError(t, h.reg.DeleteKey(path))
	}
	for _, path := range adapterPaths(otherGUID) {
		require.NoError(t, h.reg.SetString(path, searchListValue, "replacement.example"))
		require.NoError(t, h.reg.SetString(path, nameServerValue, "192.0.2.99"))
	}
	fresh, err := New(ctx, Options{
		Logger:           discardLogger(),
		Identity:         testIdentity,
		Registry:         h.reg,
		Runner:           &runnertest.FakeRunner{},
		InterfaceName:    testInterface,
		ResolveInterface: func(string) (string, error) { return otherGUID, nil },
	})
	require.NoError(t, err)

	require.NoError(t, fresh.clearGoal(ctx))
	assert.Empty(t, h.reg.ourRuleNames())
	for _, path := range adapterPaths(otherGUID) {
		assert.Equal(t, "replacement.example", h.reg.keys[path][searchListValue])
		assert.Equal(t, "192.0.2.99", h.reg.keys[path][nameServerValue])
	}
	for _, path := range adapterPaths(testGUID) {
		assert.False(t, h.reg.hasKey(path), "a removed device is not recreated")
	}
}

// TestFailedClearRetirementKeepsEvidence checks that a Clear whose
// container retirement fails keeps its GP rule, leaving no empty container
// of unknown origin, and that the retry retires it.
func TestFailedClearRetirementKeepsEvidence(t *testing.T) {
	ctx := context.Background()
	base := newFakeRegistry()
	// The first retirement of the container fails, standing in for the
	// policy engine holding the key open.
	failed := false
	base.fail = func(op, keyPath, _ string) error {
		if op == "RenameKey" && keyPath == gpoNrptBase && !failed {
			failed = true
			return errors.New("sharing violation")
		}
		return nil
	}
	b, err := newTestBackend(ctx, Options{Registry: base, Runner: &runnertest.FakeRunner{}, Notifier: &fakeNotifier{delivery: DeliveryNotified}})
	require.NoError(t, err)
	seedForeignGPRule(t, base, "foreign-rule")
	require.NoError(t, b.setGoal(ctx, backend.Config{Nameservers: mustAddrs(t, "192.0.2.1"), MatchDomains: []string{"corp.example"}}))
	require.NotEmpty(t, base.gpRuleNames(), "the apply must have gone to the Group Policy store")
	require.NoError(t, base.DeleteKey(gpoNrptBase+`\foreign-rule`))

	err = b.clearGoal(ctx)
	require.Error(t, err, "the first container retirement fails")
	assert.NotEmpty(t, base.gpRuleNames(), "the rule stays as evidence that the container is ours")

	require.NoError(t, b.clearGoal(ctx))
	assert.False(t, base.hasKey(gpoNrptBase))
	assert.False(t, base.hasKey(retiredGPBase))
}

// TestClearInspectionFailureChangesNothing: when this identity's recovery
// records name different adapters, either might be the one to clean, so a
// fresh instance, which remembers no adapter of its own, writes nothing until
// the records agree.
func TestClearInspectionFailureChangesNothing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.Close())
	require.NoError(t, h.writeTarget(gpRuleKey(1), adapterTarget{otherGUID}))
	before := h.reg.snapshot()

	fresh := newFreshBackend(t, h.reg, testGUID)
	h.reg.writes = nil
	res, err := fresh.Clear(ctx, backend.Attempt{NewGoal: true})
	require.ErrorContains(t, err, "conflicting adapter recovery targets")
	assert.Equal(t, backend.Result{}, res)
	assert.Empty(t, h.reg.writes, "inspection must not write")
	assert.Equal(t, before, h.reg.snapshot())
}

// dropRecoveryValues deletes an active rule's recorded adapter GUID while
// leaving its routing values in place.
func dropRecoveryValues(t *testing.T, reg Registry, key string) {
	t.Helper()
	require.NoError(t, reg.DeleteValue(key, interfaceGUIDValue))
}

// newFreshBackend stands in for a new process: it shares the host registry
// but holds no in-process adapter target.
func newFreshBackend(t *testing.T, reg Registry, guid string) *Backend {
	t.Helper()
	b, err := New(context.Background(), Options{
		Logger:           discardLogger(),
		Identity:         testIdentity,
		Registry:         reg,
		Runner:           &runnertest.FakeRunner{},
		InterfaceName:    testInterface,
		ResolveInterface: func(string) (string, error) { return guid, nil },
		Notifier:         &fakeNotifier{delivery: DeliveryNotified},
		DomainJoined:     func() (bool, error) { return false, nil },
		WatchPolicy:      func() (Watcher, error) { return newFakeWatcher(), nil },
		WatchRegistry:    func([]RegistryWatchKey) (Watcher, error) { return newFakeWatcher(), nil },
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// assertRecoveryValues requires key to record target again.
func assertRecoveryValues(t *testing.T, reg *fakeRegistry, key string, target adapterTarget) {
	t.Helper()
	assert.Equal(t, target.guid, reg.keys[key][interfaceGUIDValue])
}

// TestSetRepairsRuleMissingRecoveryValues: an active rule stripped of its
// recovery values is rewritten on the next repeat attempt instead of
// refusing every attempt.
func TestSetRepairsRuleMissingRecoveryValues(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	cfg := splitConfig(t, 1)
	require.NoError(t, h.setGoal(ctx, cfg))
	want := populatedKeys(h.reg.snapshot())
	flushes, _ := h.sideEffects()

	dropRecoveryValues(t, h.reg, ruleKey(0))
	res, err := h.Set(ctx, cfg, backend.Attempt{Converged: true})
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.False(t, res.Pending)
	assertRecoveryValues(t, h.reg, ruleKey(0), adapterTarget{testGUID})
	assert.Equal(t, want, populatedKeys(h.reg.snapshot()))
	gotFlushes, _ := h.sideEffects()
	assert.Equal(t, flushes+1, gotFlushes, "the rewrite owes a cache flush")
	assertNoOp(t, h, cfg, backend.Attempt{Converged: true})
}

// TestClearRemovesRuleMissingRecoveryValues: the in-process target still
// names the adapter, so Clear removes both the damaged rule and the adapter
// values.
func TestClearRemovesRuleMissingRecoveryValues(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	require.NoError(t, h.setGoal(ctx, splitConfig(t, 1)))
	dropRecoveryValues(t, h.reg, ruleKey(0))

	res, err := h.Clear(ctx, backend.Attempt{Converged: true})
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assert.Empty(t, h.reg.ourRuleNames())
	assert.Empty(t, h.reg.gpRuleNames())
	for _, path := range adapterPaths(testGUID) {
		assert.NotContains(t, h.reg.keys[path], searchListValue)
		assert.NotContains(t, h.reg.keys[path], nameServerValue)
	}
}

// TestFreshSetDiscoversAdapterPastDamagedRule: a new process finds the
// previous adapter from the intact rule, clears it for the replacement
// adapter, and rewrites the damaged rule.
func TestFreshSetDiscoversAdapterPastDamagedRule(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	cfg := splitConfig(t, maxDomainsPerRule+1)
	require.NoError(t, h.setGoal(ctx, cfg))
	require.Len(t, h.reg.ourRuleNames(), 2)
	dropRecoveryValues(t, h.reg, ruleKey(0))
	for _, path := range adapterPaths(otherGUID) {
		require.NoError(t, h.reg.CreateKey(path))
	}

	fresh := newFreshBackend(t, h.reg, otherGUID)
	res, err := fresh.Set(ctx, cfg, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.True(t, res.Changed)
	for _, path := range adapterPaths(testGUID) {
		assert.NotContains(t, h.reg.keys[path], searchListValue, "the intact rule's adapter was found and cleared")
	}
	for _, path := range adapterPaths(otherGUID) {
		assert.Equal(t, "d0.example", h.reg.keys[path][searchListValue])
	}
	for i := range 2 {
		assertRecoveryValues(t, h.reg, ruleKey(i), adapterTarget{otherGUID})
	}
}

// TestFreshManagerWithOnlyDamagedRule: with no readable record, Set takes its
// target from InterfaceName, and Clear sweeps the rule but leaves adapter
// values alone because nothing attributes them to this identity.
func TestFreshManagerWithOnlyDamagedRule(t *testing.T) {
	ctx := context.Background()
	cfg := splitConfig(t, 1)
	damaged := func(t *testing.T) *fakeRegistry {
		h := newHarness(t)
		require.NoError(t, h.setGoal(ctx, cfg))
		dropRecoveryValues(t, h.reg, ruleKey(0))
		return h.reg
	}

	t.Run("set targets the interface", func(t *testing.T) {
		reg := damaged(t)
		fresh := newFreshBackend(t, reg, testGUID)
		res, err := fresh.Set(ctx, cfg, backend.Attempt{NewGoal: true})
		require.NoError(t, err)
		assert.True(t, res.Changed)
		assertRecoveryValues(t, reg, ruleKey(0), adapterTarget{testGUID})
	})

	t.Run("clear sweeps the rule and leaves adapter values", func(t *testing.T) {
		reg := damaged(t)
		fresh := newFreshBackend(t, reg, testGUID)
		res, err := fresh.Clear(ctx, backend.Attempt{NewGoal: true})
		require.NoError(t, err)
		assert.True(t, res.Changed)
		assert.Empty(t, reg.ourRuleNames())
		// Recovery before an apply trusts only recorded GUIDs, so the
		// adapter's values stay for a caller-driven Set or manual cleanup.
		for _, path := range adapterPaths(testGUID) {
			assert.Equal(t, "d0.example", reg.keys[path][searchListValue])
		}
	})
}

var errRecoveryRead = errors.New("access denied")

// TestUnreadableRecoveryValueFailsAttempt: only an absent value is damage;
// a record that exists but cannot be read might name another adapter, so
// neither Set nor Clear writes.
func TestUnreadableRecoveryValueFailsAttempt(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	cfg := splitConfig(t, 1)
	require.NoError(t, h.setGoal(ctx, cfg))
	// Reads of the rule's adapter GUID fail with an error other than
	// ErrValueNotFound.
	h.reg.fail = func(op, keyPath, name string) error {
		if op == "GetString" && keyPath == ruleKey(0) && name == interfaceGUIDValue {
			return errRecoveryRead
		}
		return nil
	}
	fresh := newFreshBackend(t, h.reg, testGUID)
	before := h.reg.snapshot()

	h.reg.writes = nil
	res, err := fresh.Set(ctx, cfg, backend.Attempt{Converged: true})
	require.ErrorIs(t, err, errRecoveryRead)
	assert.Equal(t, backend.Result{}, res, "the attempt wrote nothing")

	res, err = fresh.Clear(ctx, backend.Attempt{NewGoal: true})
	require.ErrorIs(t, err, errRecoveryRead)
	assert.Equal(t, backend.Result{}, res)
	assert.Empty(t, h.reg.writes)
	assert.Equal(t, before, h.reg.snapshot())
}
