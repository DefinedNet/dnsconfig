package windows

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClearCancellationDuringRecoveryReads(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
	before := h.reg.snapshot()
	flushes, notifications := h.sideEffects()
	h.reg.writes = nil
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.reg.fail = func(op, path, name string) error {
		assert.NoError(t, ctx.Err(), "no further registry calls after cancellation")
		if op == "GetString" && name == interfaceGUIDValue {
			cancel()
		}
		return nil
	}

	res, err := h.Clear(ctx, backend.Attempt{Final: true})
	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, res.Changed)
	assert.Equal(t, before, h.reg.snapshot())
	assert.Empty(t, h.reg.writes)
	gotFlushes, gotNotifications := h.sideEffects()
	assert.Equal(t, flushes, gotFlushes)
	assert.Equal(t, notifications, gotNotifications)
}

func TestClearCancellationPreservesAdapterRecovery(t *testing.T) {
	for _, final := range []bool{false, true} {
		for _, tc := range []struct {
			name  string
			op    string
			stack int
			value string
		}{
			{"read first value", "GetString", 0, searchListValue},
			{"delete first value", "DeleteValue", 0, searchListValue},
			{"delete last value", "DeleteValue", 1, nameServerValue},
		} {
			name := tc.name
			if final {
				name += " final"
			}
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				cfg := backend.Config{
					Nameservers:   mustAddrs(t, "192.0.2.53", "2001:db8::53"),
					SearchDomains: []string{"corp.example"},
				}
				require.NoError(t, h.setGoal(context.Background(), cfg))
				flushes, notifications := h.sideEffects()
				reloads := h.reloads()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				h.reg.fail = func(op, path, name string) error {
					assert.NoError(t, ctx.Err(), "cancellation must stop at the next operation")
					if op == tc.op && path == adapterPaths(testGUID)[tc.stack] && name == tc.value {
						cancel()
					}
					return nil
				}

				res, err := h.Clear(ctx, backend.Attempt{Final: final})
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, tc.op == "DeleteValue", res.Changed)
				assert.Equal(t, res.Changed, res.Pending)
				assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
				assert.Equal(t, reloads, h.reloads())
				gotFlushes, gotNotifications := h.sideEffects()
				assert.Equal(t, flushes, gotFlushes)
				assert.Equal(t, notifications, gotNotifications)

				h.reg.fail = nil
				require.NoError(t, h.Close())
				_, fresh := freshInstance(t, h.reg, testGUID)
				require.NoError(t, fresh.clearGoal(context.Background()))
				assert.Empty(t, h.reg.ourRuleNames())
				for _, path := range adapterPaths(testGUID) {
					assert.NotContains(t, h.reg.keys[path], searchListValue)
					assert.NotContains(t, h.reg.keys[path], nameServerValue)
				}
			})
		}
	}
}

func TestClearCancellationDuringReloadFinishesTrigger(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
	flushes, _ := h.sideEffects()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	callsAfterCancel := 0
	h.reg.fail = func(op, path, name string) error {
		if ctx.Err() != nil {
			callsAfterCancel++
			assert.Equal(t, "DeleteValue", op)
			assert.Equal(t, nrptBase, path)
			assert.Equal(t, reloadTriggerValue, name)
		}
		if op == "SetString" && path == nrptBase && name == reloadTriggerValue {
			cancel()
		}
		return nil
	}

	res, err := h.Clear(ctx, backend.Attempt{Final: true})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, strings.Count(err.Error(), context.Canceled.Error()))
	assert.True(t, res.Pending)
	assert.Equal(t, 1, callsAfterCancel)
	assert.NotContains(t, h.reg.keys[nrptBase], reloadTriggerValue)
	assert.False(t, h.registerOwed)
	assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
	gotFlushes, _ := h.sideEffects()
	assert.Equal(t, flushes, gotFlushes)

	h.reg.fail = nil
	require.NoError(t, h.Close())
	_, fresh := freshInstance(t, h.reg, testGUID)
	require.NoError(t, fresh.clearGoal(context.Background()))
	assert.NotContains(t, h.reg.keys[nrptBase], reloadTriggerValue)
	assert.Empty(t, h.reg.ourRuleNames())
}

func TestClearCancellationAfterPolicyRetirement(t *testing.T) {
	h := newHarness(t)
	gpOnlyOurs(t, h, splitConfig(t, 1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.reg.fail = func(op, path, name string) error {
		assert.NoError(t, ctx.Err(), "retired records must stay for recovery")
		if op == "RenameKey" && path == gpoNrptBase {
			cancel()
		}
		return nil
	}
	_, notifications := h.sideEffects()

	res, err := h.Clear(ctx, backend.Attempt{Final: true})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, strings.Count(err.Error(), context.Canceled.Error()))
	assert.True(t, res.Pending)
	assert.True(t, h.reg.hasKey(retiredGPBase))
	assert.NotEmpty(t, h.reg.ourRuleNames())
	_, gotNotifications := h.sideEffects()
	assert.Equal(t, notifications+1, gotNotifications)

	h.reg.fail = nil
	require.NoError(t, h.Close())
	_, fresh := freshInstance(t, h.reg, testGUID)
	require.NoError(t, fresh.clearGoal(context.Background()))
	assert.False(t, h.reg.hasKey(retiredGPBase))
	assert.Empty(t, h.reg.ourRuleNames())
	_, gotNotifications = fresh.sideEffects()
	assert.Equal(t, 1, gotNotifications)
}

func TestClearCancellationAfterRetiredContainerDeletion(t *testing.T) {
	notifyErr := errors.New("policy notification failed")
	for _, tc := range []struct {
		name  string
		final bool
		err   error
	}{
		{name: "ordinary attempt"},
		{name: "final attempt", final: true},
		{name: "final notification fails", final: true, err: notifyErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			gpOnlyOurs(t, h, splitConfig(t, 1))
			flushes, notifications := h.sideEffects()
			if tc.err != nil {
				h.notify.delivery = DeliveryNone
				h.notify.err = tc.err
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.reg.fail = func(op, path, name string) error {
				assert.NoError(t, ctx.Err(), "cancellation stops further registry calls")
				if op == "DeleteKey" && path == retiredGPBase {
					cancel()
				}
				return nil
			}

			res, err := h.Clear(ctx, backend.Attempt{Final: tc.final})
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, 1, strings.Count(err.Error(), context.Canceled.Error()))
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			}
			assert.True(t, res.Pending)
			assert.False(t, h.reg.hasKey(retiredGPBase))
			assert.NotEmpty(t, h.reg.ourRuleNames())
			gotFlushes, gotNotifications := h.sideEffects()
			assert.Equal(t, flushes, gotFlushes)
			if tc.final {
				notifications++
			}
			assert.Equal(t, notifications, gotNotifications)
			assert.Equal(t, !tc.final || tc.err != nil, h.gpDirty)

			h.reg.fail = nil
			if !tc.final || tc.err != nil {
				h.notify.delivery, h.notify.err = DeliveryNotified, nil
				require.NoError(t, h.clearGoal(context.Background()))
				_, gotNotifications = h.sideEffects()
				assert.Equal(t, notifications+1, gotNotifications)
				return
			}
			require.NoError(t, h.Close())
			_, fresh := freshInstance(t, h.reg, testGUID)
			require.NoError(t, fresh.clearGoal(context.Background()))
			assert.Empty(t, h.reg.ourRuleNames())
			_, gotNotifications = fresh.sideEffects()
			assert.Zero(t, gotNotifications, "no GP record remains to notify from recovery")
		})
	}
}

func TestClearCancellationBetweenRules(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.reg.fail = func(op, path, name string) error {
		assert.NoError(t, ctx.Err(), "cancellation must stop before the next rule")
		if op == "DeleteKey" && path == ruleKey(0) {
			cancel()
		}
		return nil
	}

	res, err := h.Clear(ctx, backend.Attempt{Final: true})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, strings.Count(err.Error(), context.Canceled.Error()))
	assert.True(t, res.Pending)
	assert.False(t, h.reg.hasKey(ruleKey(0)))
	assert.True(t, h.reg.hasKey(ruleKey(1)))

	h.reg.fail = nil
	require.NoError(t, h.Close())
	_, fresh := freshInstance(t, h.reg, testGUID)
	require.NoError(t, fresh.clearGoal(context.Background()))
	assert.Empty(t, h.reg.ourRuleNames())
}

func TestClearCancellationDoesNotStrandEmptyPolicyContainer(t *testing.T) {
	h := newHarness(t)
	seedForeignGPRule(t, h.reg, "foreign")
	require.NoError(t, h.setGoal(context.Background(), splitConfig(t, 1)))
	flushes, notifications := h.sideEffects()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.reg.fail = func(op, path, name string) error {
		if op == "DeleteKey" && path == gpRuleKey(0) {
			delete(h.reg.keys, gpoNrptBase+`\foreign`)
			cancel()
		}
		return nil
	}

	res, err := h.Clear(ctx, backend.Attempt{Final: true})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, strings.Count(err.Error(), context.Canceled.Error()))
	assert.True(t, res.Pending)
	assert.False(t, h.reg.hasKey(gpoNrptBase), "an empty active container suppresses local rules")
	assert.NotEmpty(t, h.reg.ourRuleNames(), "cancellation stops before the next store")
	gotFlushes, gotNotifications := h.sideEffects()
	assert.Equal(t, flushes, gotFlushes)
	assert.Equal(t, notifications+1, gotNotifications)

	h.reg.fail = nil
	require.NoError(t, h.Close())
	_, fresh := freshInstance(t, h.reg, testGUID)
	require.NoError(t, fresh.clearGoal(context.Background()))
	assert.Empty(t, h.reg.ourRuleNames())
	_, gotNotifications = fresh.sideEffects()
	assert.Zero(t, gotNotifications, "the final cleanup already notified the GP removal")
}

func TestClearCancellationPreservesReloadFailure(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(fmt.Sprintf("final=%v", final), func(t *testing.T) {
			h := newHarness(t)
			require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
			reloadErr := errors.New("reload denied")
			h.reg.failReload = reloadErr
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.reg.fail = func(op, path, name string) error {
				if op == "SetString" && path == nrptBase && name == reloadTriggerValue {
					cancel()
				}
				return nil
			}

			res, err := h.Clear(ctx, backend.Attempt{Final: final})
			require.ErrorIs(t, err, context.Canceled)
			assert.ErrorIs(t, err, reloadErr)
			assert.Equal(t, 1, strings.Count(err.Error(), context.Canceled.Error()))
			assert.Equal(t, 1, strings.Count(err.Error(), reloadErr.Error()))
			assert.True(t, res.Pending)
			assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
		})
	}
}

type cancelingNotifier struct {
	PolicyNotifier
	cancel context.CancelFunc
}

func (n cancelingNotifier) NotifyPolicyChange() (Delivery, error) {
	d, err := n.PolicyNotifier.NotifyPolicyChange()
	n.cancel()
	return d, err
}

func TestCancellationAfterAcceptedPolicyNotification(t *testing.T) {
	for _, delivery := range []Delivery{DeliveryNotified, DeliveryRefresh} {
		t.Run(delivery.String(), func(t *testing.T) {
			h := newHarness(t)
			logs := h.captureLogs()
			seedForeignGPRule(t, h.reg, "foreign")
			h.notify.delivery = delivery
			h.domainJoined = func() (bool, error) { return true, nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.notifier = cancelingNotifier{PolicyNotifier: h.notify, cancel: cancel}

			res, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, 1, strings.Count(err.Error(), context.Canceled.Error()))
			assert.True(t, res.Pending)
			assert.Equal(t, 0, h.reloads())
			assert.NotContains(t, logs.String(), "notification delivery is unconfirmed")
			flushes, notifications := h.sideEffects()
			assert.Equal(t, 0, flushes)
			assert.Equal(t, 1, notifications)

			h.notifier = h.notify
			require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
			flushes, notifications = h.sideEffects()
			assert.Equal(t, 1, notifications, "an accepted notification is not repeated")
			assert.Equal(t, 1, flushes)
			assert.Equal(t, 1, h.reloads())
		})
	}
}
