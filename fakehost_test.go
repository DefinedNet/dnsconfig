package dnsconfig

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/backend/backendtest"
)

// fakeHost models a backend over a host with one artifact slot and an owed
// cache flush. It follows the converge contract, which the shared suite
// checks, so worker tests that need a realistic backend can rely on it.
type fakeHost struct {
	mu        sync.Mutex
	installed *backend.Config
	flushOwed bool
	failFlush bool
	failWrite bool
	writes    int
	closed    bool
	changes   chan struct{}
}

var (
	errFakeWrite = errors.New("fake: artifact write failed")
	errFakeFlush = errors.New("fake: cache flush failed")
)

func newFakeHost() *fakeHost { return &fakeHost{changes: make(chan struct{}, 1)} }

func (f *fakeHost) Set(_ context.Context, cfg backend.Config, _ backend.Attempt) (backend.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res backend.Result
	if f.installed == nil || !osConfigEqual(*f.installed, cfg) {
		if f.failWrite {
			return backend.Result{Pending: f.flushOwed}, errFakeWrite
		}
		c := cfg
		f.installed = &c
		f.writes++
		f.flushOwed = true
		res.Changed = true
	}
	if f.flushOwed {
		if f.failFlush {
			res.Pending = true
			return res, errFakeFlush
		}
		f.flushOwed = false
		f.writes++
	}
	return res, nil
}

func (f *fakeHost) Clear(_ context.Context, _ backend.Attempt) (backend.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res backend.Result
	if f.installed != nil {
		if f.failWrite {
			return backend.Result{Pending: f.flushOwed}, errFakeWrite
		}
		f.installed = nil
		f.writes++
		f.flushOwed = true
		res.Changed = true
	}
	if f.flushOwed {
		if f.failFlush {
			res.Pending = true
			return res, errFakeFlush
		}
		f.flushOwed = false
		f.writes++
	}
	return res, nil
}

func (f *fakeHost) HasArtifacts(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installed != nil, nil
}

func (f *fakeHost) ValidateConfig(backend.Config) error { return nil }

func (f *fakeHost) Changes() <-chan struct{} { return f.changes }

func (f *fakeHost) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.changes)
	}
	return nil
}

func (f *fakeHost) clean() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.installed == nil, nil
}

func (f *fakeHost) snapshot() (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.installed == nil {
		return nil, nil
	}
	return *f.installed, nil
}

func (f *fakeHost) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

func (f *fakeHost) setFailFlush(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failFlush = fail
}

func (f *fakeHost) setFailWrite(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWrite = fail
}

func osConfigEqual(a, b backend.Config) bool {
	return slices.Equal(a.Nameservers, b.Nameservers) &&
		slices.Equal(a.SearchDomains, b.SearchDomains) &&
		slices.Equal(a.MatchDomains, b.MatchDomains)
}

// TestFakeHostSuite keeps fakeHost honest against the contract the
// native backends satisfy.
func TestFakeHostSuite(t *testing.T) {
	backendtest.Suite(t, func(t *testing.T) backendtest.Fixture {
		f := newFakeHost()
		return backendtest.Fixture{
			Backend: f,
			ValidConfig: backend.Config{
				Nameservers:   []netip.Addr{netip.MustParseAddr("192.0.2.1")},
				SearchDomains: []string{"corp.example"},
			},
			SecondConfig: backend.Config{
				Nameservers: []netip.Addr{netip.MustParseAddr("192.0.2.2")},
			},
			Clean:           f.clean,
			Snapshot:        f.snapshot,
			Writes:          f.writeCount,
			FailSideEffects: f.setFailFlush,
			FailInspection:  f.setFailWrite,
		}
	})
}
