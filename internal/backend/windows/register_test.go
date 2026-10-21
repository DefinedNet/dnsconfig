package windows

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshInstance stands in for a new process over reg, targeting guid.
func freshInstance(t *testing.T, reg Registry, guid string) (*Backend, *harness) {
	t.Helper()
	fr := &runnertest.FakeRunner{}
	n := &fakeNotifier{delivery: DeliveryNotified}
	b, err := newTestBackend(context.Background(), Options{Registry: reg, Runner: fr, Notifier: n})
	require.NoError(t, err)
	b.resolveInterface = func(string) (string, error) { return guid, nil }
	t.Cleanup(func() { _ = b.Close() })
	h := &harness{Backend: b, fr: fr, notify: n}
	if holder, ok := reg.(fakeHolder); ok {
		h.reg = holder.fake()
	}
	return b, h
}

// failReload makes the next reload triggers fail until cleared.
func failReload(h *harness) {
	h.reg.failReload = errors.New("reload failed")
}

// TestFirstSetReloadsOnce gives a fresh instance a host whose rules and
// adapter values already match. Its first Set still reloads, once, and later
// matching Sets do not.
func TestFirstSetReloadsOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.Close())

	_, fresh := freshInstance(t, h.reg, testGUID)
	fresh.reg.writes = nil
	res, err := fresh.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res, "matching values need no write")
	assert.Equal(t, []string{
		"SetString " + nrptBase + " " + reloadTriggerValue,
		"DeleteValue " + nrptBase + " " + reloadTriggerValue,
	}, fresh.reg.writes, "the only writes are one reload trigger")
	flushes, _ := fresh.sideEffects()
	assert.Equal(t, 1, flushes, "the reload owes a flush")

	assertNoOp(t, fresh, catchAll(t), backend.Attempt{})
}

// TestSetAfterConvergedClearReloadsAgain has an instance converge a Clear,
// which releases the identity, while another process takes it, writes the
// same goal, and exits with its reload trigger failed. The first instance's
// next Set finds matching values and must still reload once.
func TestSetAfterConvergedClearReloadsAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.clearGoal(ctx))

	_, other := freshInstance(t, h.reg, testGUID)
	failReload(other)
	res, err := other.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.ErrorContains(t, err, "trigger adapter reload")
	assert.True(t, res.Pending)
	other.reg.failReload = nil
	before := h.reloads()

	h.reg.writes = nil
	res, err = h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res, "matching values need no write")
	assert.Equal(t, before+1, h.reloads(), "the predecessor's reload is owed again after the identity was released")
	assert.Equal(t, []string{
		"SetString " + nrptBase + " " + reloadTriggerValue,
		"DeleteValue " + nrptBase + " " + reloadTriggerValue,
	}, h.reg.writes)

	assertNoOp(t, h, catchAll(t), backend.Attempt{})
}

// TestFailedFirstReloadIsRetried fails the first attempt's reload on a host
// that already matches. The reload stays owed until a retry succeeds.
func TestFailedFirstReloadIsRetried(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.Close())
	before := h.reloads()

	_, fresh := freshInstance(t, h.reg, testGUID)
	failReload(fresh)
	res, err := fresh.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.ErrorContains(t, err, "trigger adapter reload")
	assert.Equal(t, backend.Result{Pending: true}, res)
	assert.Equal(t, before, fresh.reloads())

	fresh.reg.failReload = nil
	res, err = fresh.Set(ctx, catchAll(t), backend.Attempt{})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.Equal(t, before+1, fresh.reloads())

	assertNoOp(t, fresh, catchAll(t), backend.Attempt{})
}

// TestHalfWrittenReloadTriggerCountsAsAWrite leaves the trigger value on the
// container key by failing its delete. The attempt reports Changed, since the
// leftover value is a write of ours the registry watcher will report, and the
// next attempt clears it.
func TestHalfWrittenReloadTriggerCountsAsAWrite(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.Close())

	_, fresh := freshInstance(t, h.reg, testGUID)
	fresh.reg.failReloadDelete = errors.New("delete denied")
	res, err := fresh.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.ErrorContains(t, err, "trigger adapter reload")
	assert.Equal(t, backend.Result{Changed: true, Pending: true}, res)
	assert.Contains(t, fresh.reg.keys[nrptBase], reloadTriggerValue, "the trigger value is left behind")

	fresh.reg.failReloadDelete = nil
	res, err = fresh.Set(ctx, catchAll(t), backend.Attempt{})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.NotContains(t, fresh.reg.keys[nrptBase], reloadTriggerValue)

	assertNoOp(t, fresh, catchAll(t), backend.Attempt{})
}

func TestFirstClearWithoutRecoveryTargetDoesNotReload(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.clearGoal(ctx))
	require.NoError(t, h.Close())
	before := h.reloads()

	b, fresh := freshInstance(t, h.reg, testGUID)
	fresh.reg.writes = nil
	res, err := b.Clear(ctx, backend.Attempt{NewGoal: true})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.Empty(t, fresh.reg.writes)
	assert.Equal(t, before, fresh.reloads())
}

// TestEmptyAdapterValuesAreNotDrift leaves the empty NameServer Windows
// creates on interface keys alone: the DNS Client already treats it as
// unset, so deleting it would only cost a reload on every converge.
func TestEmptyAdapterValuesAreNotDrift(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, path := range adapterPaths(testGUID) {
		require.NoError(t, h.reg.SetString(path, nameServerValue, ""))
	}
	cfg := splitConfig(t, 1)
	cfg.SearchDomains = nil
	require.NoError(t, h.setGoal(ctx, cfg))
	assertNoOp(t, h, cfg, backend.Attempt{})
	require.NoError(t, h.clearGoal(ctx))
	assert.Equal(t, 1, h.reloads(), "only the first attempt reloads: an empty value is neither repaired nor cleared")
	for _, path := range adapterPaths(testGUID) {
		assert.Equal(t, "", h.reg.keys[path][nameServerValue], "the empty value stays as Windows wrote it")
	}
}

func TestFailedReloadIsRetried(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	failReload(h)
	res, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.ErrorContains(t, err, "trigger adapter reload")
	assert.True(t, res.Changed)
	assert.True(t, res.Pending)
	flushes, _ := h.sideEffects()
	assert.Equal(t, 1, flushes, "a failed reload does not hold back the flush")

	h.reg.failReload = nil
	res, err = h.Set(ctx, catchAll(t), backend.Attempt{})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.Equal(t, 1, h.reloads())
	flushes, _ = h.sideEffects()
	assert.Equal(t, 2, flushes, "the reload owes another flush")

	assertNoOp(t, h, catchAll(t), backend.Attempt{})
	assert.Equal(t, 1, h.reloads())
}

// TestReloadTriggerLandsOnContainerKey checks the trigger's shape: a value
// set and deleted on the local NRPT container key after the adapter write,
// before the flush, never on a rule and never under the Group Policy key,
// which the DNS Client does not watch.
func TestReloadTriggerLandsOnContainerKey(t *testing.T) {
	h := newHarness(t)
	seedForeignGPRule(t, h.reg, "foreign")
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
	require.NotEmpty(t, h.reg.gpRuleNames(), "the identity holds GP copies")

	adapterWrite := slices.IndexFunc(h.reg.writes, func(w string) bool {
		return strings.HasPrefix(w, "SetString "+adapterPaths(testGUID)[0]+" "+nameServerValue)
	})
	set := slices.Index(h.reg.writes, "SetString "+nrptBase+" "+reloadTriggerValue)
	del := slices.Index(h.reg.writes, "DeleteValue "+nrptBase+" "+reloadTriggerValue)
	require.GreaterOrEqual(t, adapterWrite, 0)
	require.Greater(t, set, adapterWrite, "the trigger follows the adapter write")
	require.Greater(t, del, set)
	for _, w := range h.reg.writes {
		if !strings.HasSuffix(w, " "+reloadTriggerValue) {
			continue
		}
		assert.True(t, strings.HasSuffix(w, " "+nrptBase+" "+reloadTriggerValue), "trigger on the local container only: %s", w)
	}
	assert.NotContains(t, h.reg.keys[nrptBase], reloadTriggerValue)
}

// TestReloadCreatesAbsentContainer triggers on a host whose local NRPT
// container does not exist yet: the write creates it, and an empty local
// container is inert.
func TestReloadCreatesAbsentContainer(t *testing.T) {
	h := newHarness(t)
	require.False(t, h.reg.hasKey(nrptBase))
	h.registerOwed = true
	require.NoError(t, h.reload(context.Background(), &mutation{b: h.Backend}))
	assert.True(t, h.reg.hasKey(nrptBase))
	assert.NotContains(t, h.reg.keys[nrptBase], reloadTriggerValue)
	assert.Equal(t, 1, h.reloads())
	assert.False(t, h.registerOwed)
	assert.True(t, h.flushOwed)
}

// TestClearWithoutLocalRulesStillReloads clears an adapter whose only record
// is a Group Policy copy, or this instance's memory, and still triggers the
// reload from the container key.
func TestClearWithoutLocalRulesStillReloads(t *testing.T) {
	ctx := context.Background()
	t.Run("GP copies only", func(t *testing.T) {
		h := newHarness(t)
		seedForeignGPRule(t, h.reg, "foreign")
		require.NoError(t, h.setGoal(ctx, catchAll(t)))
		for _, name := range h.reg.ourRuleNames() {
			require.NoError(t, h.reg.DeleteKey(nrptBase+`\`+name))
		}
		require.NoError(t, h.Close())
		before := h.reloads()

		fresh, fh := freshInstance(t, h.reg, testGUID)
		res, err := fresh.Clear(ctx, backend.Attempt{NewGoal: true})
		require.NoError(t, err)
		assert.Equal(t, backend.Result{Changed: true}, res)
		assert.Empty(t, h.reg.gpRuleNames())
		assert.NotContains(t, h.reg.keys[adapterPaths(testGUID)[0]], nameServerValue)
		assert.Equal(t, before+1, fh.reloads())
	})
	t.Run("memory only", func(t *testing.T) {
		h := newHarness(t)
		require.NoError(t, h.setGoal(ctx, catchAll(t)))
		dropOwnRules(t, h.reg, nrptBase)
		before := h.reloads()

		res, err := h.Clear(ctx, backend.Attempt{NewGoal: true})
		require.NoError(t, err)
		assert.Equal(t, backend.Result{Changed: true}, res)
		assert.NotContains(t, h.reg.keys[adapterPaths(testGUID)[0]], nameServerValue)
		assert.Equal(t, before+1, h.reloads())
	})
}

// TestClearFinishingInterruptedClearReloads gives a fresh instance a
// recovery target whose adapter values are already gone. Its first Clear
// still reloads, once.
func TestClearFinishingInterruptedClearReloads(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.Close())
	// The interrupted Clear removed the adapter values before exiting.
	for _, path := range adapterPaths(testGUID) {
		require.NoError(t, h.reg.DeleteValue(path, nameServerValue))
		require.NoError(t, h.reg.DeleteValue(path, searchListValue))
	}
	before := h.reloads()

	_, fresh := freshInstance(t, h.reg, testGUID)
	require.NoError(t, fresh.clearGoal(ctx))
	assert.Empty(t, h.reg.ourRuleNames())
	assert.Equal(t, before+1, fresh.reloads())

	require.NoError(t, fresh.clearGoal(ctx))
	assert.Equal(t, before+1, fresh.reloads(), "a Clear that finds nothing does not reload")
}

func TestClearRetryDoesNotRepeatReload(t *testing.T) {
	ctx := context.Background()
	reg := newFakeRegistry()
	b, h := freshInstance(t, reg, testGUID)
	require.NoError(t, b.setGoal(ctx, catchAll(t)))
	before := h.reloads()
	reg.fail = failMigration("local-rule-delete") // The first rule deletion fails after the reload.
	require.ErrorContains(t, b.clearGoal(ctx), "delete NRPT rule")
	reg.fail = nil
	require.NoError(t, b.clearGoal(ctx))
	assert.Equal(t, before+1, h.reloads())
}

// TestAdapterReplacementSurvivesInterruptionAnywhere fails the replacement
// converge at every write. A fresh instance must still clear the previous
// adapter, even when its only record was a staged copy that staging reuses.
func TestAdapterReplacementSurvivesInterruptionAnywhere(t *testing.T) {
	setup := func(t *testing.T) *failInjectRegistry {
		t.Helper()
		h := newHarness(t)
		require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
		require.NoError(t, h.Close())
		// The previous adapter's only records are staged copies.
		for i := range desiredRules(catchAll(t)) {
			require.NoError(t, h.reg.RenameKey(ruleKey(i), h.ruleName(i, true)))
		}
		for _, path := range adapterPaths(otherGUID) {
			require.NoError(t, h.reg.CreateKey(path))
		}
		return &failInjectRegistry{fakeRegistry: h.reg, failAt: -1}
	}
	reg := setup(t)
	b, _ := freshInstance(t, reg, otherGUID)
	reg.arm(-1)
	require.NoError(t, b.setGoal(context.Background(), catchAll(t)))
	writes := reg.seen
	require.Positive(t, writes)

	for stop := range writes {
		t.Run(fmt.Sprintf("fail=%d", stop), func(t *testing.T) {
			reg := setup(t)
			b, _ := freshInstance(t, reg, otherGUID)
			reg.arm(stop)
			require.Error(t, b.setGoal(context.Background(), catchAll(t)))
			require.NoError(t, b.Close())

			reg.arm(-1)
			fresh, _ := freshInstance(t, reg, otherGUID)
			require.NoError(t, fresh.setGoal(context.Background(), catchAll(t)))
			for _, path := range adapterPaths(testGUID) {
				assert.NotContains(t, reg.keys[path], nameServerValue, "previous adapter values are cleared")
			}
			assert.Equal(t, "1.1.1.1", reg.keys[adapterPaths(otherGUID)[0]][nameServerValue])
		})
	}
}

// reloadObserver runs check before each reload trigger write.
type reloadObserver struct {
	Registry
	check func()
}

func (r *reloadObserver) SetString(path, name, data string) error {
	if name == reloadTriggerValue && path == nrptBase {
		r.check()
	}
	return r.Registry.SetString(path, name, data)
}

// observeReloads makes h run check before each reload trigger write.
func observeReloads(h *harness, check func()) {
	h.Backend.reg = &reloadObserver{Registry: h.Backend.reg, check: check}
}

// TestFailedClearReportsItsReload fails both the reload and a rule deletion
// in a non-final Clear, which leaves side effects to the retry. The attempt
// still reports the reload it tried.
func TestFailedClearReportsItsReload(t *testing.T) {
	ctx := context.Background()
	reg := newFakeRegistry()
	b, h := freshInstance(t, reg, testGUID)
	require.NoError(t, b.setGoal(ctx, catchAll(t)))
	failReload(h)
	reg.fail = failMigration("local-rule-delete")
	res, err := b.Clear(ctx, backend.Attempt{NewGoal: true})
	require.ErrorContains(t, err, "delete NRPT rule")
	assert.ErrorContains(t, err, "trigger adapter reload")
	assert.True(t, res.Pending)
	assert.True(t, b.registerOwed)
}

func TestClearReloadsWhileRulesRemain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	reloads := 0
	observeReloads(h, func() {
		reloads++
		// A process that exits during the reload leaves the rules for the
		// next Clear, which then reloads again.
		assert.NotEmpty(t, h.reg.ourRuleNames(), "rules stay until the reload has run")
		assert.NotContains(t, h.reg.keys[adapterPaths(testGUID)[0]], nameServerValue, "adapter values go first")
	})
	require.NoError(t, h.clearGoal(ctx))
	assert.Equal(t, 1, reloads)
	assert.Empty(t, h.reg.ourRuleNames())
}

func TestClearRemovesRulesWhenReloadFails(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(fmt.Sprintf("final=%v", final), func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			require.NoError(t, h.setGoal(ctx, catchAll(t)))
			flushes, _ := h.sideEffects()
			failReload(h)
			res, err := h.Clear(ctx, backend.Attempt{NewGoal: true, Final: final})
			require.ErrorContains(t, err, "trigger adapter reload")
			assert.True(t, res.Pending, "the reload stays owed")
			assert.Empty(t, h.reg.ourRuleNames(), "a failed reload does not keep the rules")
			got, _ := h.sideEffects()
			assert.Equal(t, flushes+1, got, "a failed reload does not hold back the flush")
			if !final {
				h.reg.failReload = nil
				before := h.reloads()
				res, err = h.Clear(ctx, backend.Attempt{})
				require.NoError(t, err)
				assert.Equal(t, backend.Result{}, res, "the retry only completes the reload")
				assert.Equal(t, before+1, h.reloads(), "the retry triggers from the container key")
				got, _ = h.sideEffects()
				assert.Equal(t, flushes+2, got, "the reload owes another flush")
			}
		})
	}
}

var errExit = errors.New("simulated process exit")

// expectExit runs op until it panics with errExit.
func expectExit(t *testing.T, op func()) {
	t.Helper()
	defer func() { require.Equal(t, errExit, recover()) }()
	op()
}

// exitBeforeReload runs op until it reaches the reload trigger, standing in
// for a process that exits there.
func exitBeforeReload(t *testing.T, h *harness, op func()) {
	t.Helper()
	observeReloads(h, func() { panic(errExit) })
	expectExit(t, op)
}

// TestInterruptedAdapterReplacementReloads fails the replacement converge at
// every write. Whenever an adapter value changed, a fresh Clear must reload.
func TestInterruptedAdapterReplacementReloads(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) *failInjectRegistry {
		t.Helper()
		h := newHarness(t)
		require.NoError(t, h.setGoal(ctx, catchAll(t)))
		require.NoError(t, h.Close())
		for _, path := range adapterPaths(otherGUID) {
			require.NoError(t, h.reg.CreateKey(path))
		}
		return &failInjectRegistry{fakeRegistry: h.reg, failAt: -1}
	}
	adapters := func(reg *failInjectRegistry) []map[string]any {
		var out []map[string]any
		for _, guid := range []string{testGUID, otherGUID} {
			for _, path := range adapterPaths(guid) {
				out = append(out, maps.Clone(reg.keys[path]))
			}
		}
		return out
	}
	reg := setup(t)
	b, _ := freshInstance(t, reg, otherGUID)
	require.NoError(t, b.setGoal(ctx, catchAll(t)))
	writes := reg.seen
	require.Positive(t, writes)

	for stop := range writes {
		t.Run(fmt.Sprintf("fail=%d", stop), func(t *testing.T) {
			reg := setup(t)
			before := adapters(reg)
			b, _ := freshInstance(t, reg, otherGUID)
			reg.arm(stop)
			require.Error(t, b.setGoal(ctx, catchAll(t)))
			require.NoError(t, b.Close())
			reg.arm(-1)
			if slices.EqualFunc(before, adapters(reg), maps.Equal) {
				return
			}
			reloads := reg.reloads
			fresh, h := freshInstance(t, reg, otherGUID)
			require.NoError(t, fresh.clearGoal(ctx))
			assert.Equal(t, reloads+1, h.reloads())
		})
	}
}

// TestGPCopyLeadsSuccessorToReload clears an adapter recovered from a GP
// copy whose local twin is gone, then exits before the reload. The GP copy
// gives a fresh Clear the recovery target that owes the reload.
func TestGPCopyLeadsSuccessorToReload(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	seedForeignGPRule(t, h.reg, "foreign")
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.reg.DeleteKey(ruleKey(0)))
	before := h.reloads()
	exitBeforeReload(t, h, func() { _ = h.clearGoal(ctx) })
	require.NotContains(t, h.reg.keys[adapterPaths(testGUID)[0]], nameServerValue)

	fresh, fh := freshInstance(t, h.reg, testGUID)
	require.NoError(t, fresh.clearGoal(ctx))
	assert.Equal(t, before+1, fh.reloads())
}
