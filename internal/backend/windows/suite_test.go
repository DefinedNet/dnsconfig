package windows

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend/backendtest"
	"github.com/DefinedNet/dnsconfig/internal/runner"
	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
)

var errInjectedFlush = errors.New("windows test: injected flush failure")

// failingRunner counts every run and, while armed, fails it without running.
type failingRunner struct {
	inner runner.Runner
	mu    sync.Mutex
	fail  bool
	calls int
}

func (r *failingRunner) Run(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	r.mu.Lock()
	r.calls++
	fail := r.fail
	r.mu.Unlock()
	if fail {
		return nil, []byte("injected"), errInjectedFlush
	}
	return r.inner.Run(ctx, name, args, stdin)
}

func (r *failingRunner) setFail(fail bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = fail
}

func (r *failingRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// TestSuite runs the shared converge contract in both NRPT stores. A foreign
// Group Policy rule selects the GP store, which adds the policy notification
// to the side effects the contract tracks.
func TestSuite(t *testing.T) {
	for _, tc := range []struct {
		name      string
		foreignGP bool
	}{
		{"local store", false},
		{"Group Policy store", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backendtest.Suite(t, func(t *testing.T) backendtest.Fixture {
				return newSuiteBackend(t, tc.foreignGP)
			})
		})
	}
}

func newSuiteBackend(t *testing.T, foreignGP bool) backendtest.Fixture {
	reg := newFakeRegistry()
	if foreignGP {
		seedForeignGPRule(t, reg, "{foreign-rule}")
	}
	freg := &failInjectRegistry{fakeRegistry: reg, failAt: -1}
	fr := &failingRunner{inner: &runnertest.FakeRunner{}}
	notify := &fakeNotifier{delivery: DeliveryNotified}
	b, err := newTestBackend(context.Background(), Options{Registry: freg, Runner: fr, Notifier: notify})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	cfg := catchAll(t)
	cfg.SearchDomains = []string{"corp.example"}
	second := cfg
	second.Nameservers = mustAddrs(t, "1.0.0.1")
	return backendtest.Fixture{
		Backend:      b,
		ValidConfig:  cfg,
		SecondConfig: second,
		Clean: func() (bool, error) {
			if len(reg.ourRuleNames())+len(reg.gpRuleNames()) > 0 {
				return false, nil
			}
			for _, path := range adapterPaths(testGUID) {
				for _, name := range []string{nameServerValue, searchListValue} {
					if _, ok := reg.keys[path][name]; ok {
						return false, nil
					}
				}
			}
			return true, nil
		},
		Snapshot: func() (any, error) { return reg.snapshot(), nil },
		Writes:   func() int { return len(reg.writes) + fr.count() + notify.calls },
		FailSideEffects: func(fail bool) {
			fr.setFail(fail)
			notify.delivery, notify.err = DeliveryNotified, nil
			if fail {
				notify.delivery, notify.err = DeliveryNone, errors.New("windows test: injected notification failure")
			}
		},
		FailInspection: freg.setFailSubKeys,
	}
}
