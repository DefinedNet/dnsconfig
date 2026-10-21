//go:build darwin

package darwin

import (
	"errors"
	"maps"
	"net/netip"
	"os"
	"testing"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/backend/backendtest"
)

var (
	errInjectedFlush = errors.New("darwin test: injected flush failure")
	errInjectedList  = errors.New("darwin test: injected State-key list failure")
)

// TestSuite runs the shared converge contract for a catch-all, which
// publishes State keys only, and for split DNS, which adds resolver files.
func TestSuite(t *testing.T) {
	split := splitConfig()
	split.MatchDomains = append(split.MatchDomains, "lab.example")
	for _, tc := range []struct {
		name string
		cfg  func() backend.Config
	}{
		{"catch-all", func() backend.Config { return catchAllConfig() }},
		{"split", func() backend.Config { return split }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backendtest.Suite(t, func(t *testing.T) backendtest.Fixture {
				fs := newTestFS(t)
				fake := newScutilFake()
				b := newTestBackend(t, fs, fake)
				second := tc.cfg()
				second.Nameservers = []netip.Addr{netip.MustParseAddr("127.0.0.98")}
				return backendtest.Fixture{
					Backend:      b,
					ValidConfig:  tc.cfg(),
					SecondConfig: second,
					Clean: func() (bool, error) {
						files, err := resolverFiles(fs)
						return err == nil && len(files) == 0 && fake.keyCount() == 0, err
					},
					Snapshot: func() (any, error) {
						files, err := resolverFiles(fs)
						fake.mu.Lock()
						defer fake.mu.Unlock()
						return struct {
							keys  map[int]stateKeyConfig
							files map[string]string
						}{maps.Clone(fake.keys), files}, err
					},
					Writes: func() int {
						log := observeHost(fs, fake)
						return len(log.fs) + len(log.scutil)
					},
					FailSideEffects: func(fail bool) {
						fake.mu.Lock()
						defer fake.mu.Unlock()
						fake.flushErr = nil
						if fail {
							fake.flushErr = errInjectedFlush
						}
					},
					FailInspection: func(fail bool) {
						fake.mu.Lock()
						defer fake.mu.Unlock()
						fake.listErr = nil
						if fail {
							fake.listErr = errInjectedList
						}
					},
				}
			})
		})
	}
}

// resolverFiles returns every entry in the test resolver directory by name.
func resolverFiles(fs *testFS) (map[string]string, error) {
	entries, err := os.ReadDir(fs.dir)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		body, err := os.ReadFile(fs.path(e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = string(body)
	}
	return out, nil
}
