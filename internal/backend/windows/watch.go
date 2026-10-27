package windows

import (
	"errors"
	"fmt"
	"slices"
	"sync"
)

// Watcher delivers coalesced notifications from one change source.
type Watcher interface {
	// Events closes when monitoring fails or Close stops it.
	Events() <-chan struct{}
	// Done closes when monitoring stops, even if an event remains buffered.
	Done() <-chan struct{}
	// Err returns the terminal monitoring error after Done closes.
	Err() error
	// Close stops and joins notification delivery and releases its handles.
	Close() error
}

// RegistryWatchKey names one registry key whose subtree is watched.
type RegistryWatchKey struct {
	// Path is the key to watch, relative to HKEY_LOCAL_MACHINE.
	Path string

	// Floor is the highest ancestor the watch may fall back to while Path is
	// absent, so creating Path is itself observed. Floor equal to Path means
	// an absent key cannot be watched.
	Floor string
}

const (
	// dnscacheParameters always exists and parents the local NRPT.
	dnscacheParameters = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`

	// policiesRoot always exists; the GP NRPT container and its DNSClient
	// parent come and go with policy.
	policiesRoot = `SOFTWARE\Policies`
)

// registryWatchKeys covers every artifact a converge toward target owns:
// both NRPT stores and the controlled adapter on each IP stack.
func registryWatchKeys(target adapterTarget) []RegistryWatchKey {
	keys := []RegistryWatchKey{
		{Path: nrptBase, Floor: dnscacheParameters},
		{Path: gpoNrptBase, Floor: policiesRoot},
	}
	for _, path := range adapterPaths(target.guid) {
		keys = append(keys, RegistryWatchKey{Path: path, Floor: path})
	}
	return keys
}

// source forwards one Watcher's events to Backend.changes.
type source struct {
	w        Watcher
	keys     []RegistryWatchKey
	quit     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	stopErr  error
}

// stopped reports whether the watcher or its forwarder has exited.
func (s *source) stopped() bool {
	select {
	case <-s.w.Done():
		return true
	case <-s.done:
		return true
	default:
		return false
	}
}

// stop closes the watcher and joins the forwarder. It must not be called
// with Backend.mu held, because the forwarder takes it to record failure.
func (s *source) stop() error {
	s.stopOnce.Do(func() {
		close(s.quit)
		s.stopErr = s.w.Close()
		<-s.done
	})
	return s.stopErr
}

// releaseSources stops both change sources and forgets their failures, so
// monitoring reports healthy while nothing needs watching.
func (b *Backend) releaseSources() {
	b.mu.Lock()
	sources := []*source{b.policySrc, b.regSrc}
	b.policySrc, b.regSrc = nil, nil
	b.mu.Unlock()
	for _, s := range sources {
		if s == nil {
			continue
		}
		if err := s.stop(); err != nil {
			b.logger.Warn("windows: release change watcher", "error", err)
		}
	}
}

// signal coalesces a change notification for the caller.
func (b *Backend) signal() {
	select {
	case b.changes <- struct{}{}:
	default:
	}
}

// forward relays events until the watcher stops or quit closes. A watcher
// that dies records its error and raises one signal, so the caller's next
// converge restarts it.
func (b *Backend) forward(s *source, stopped func(error)) {
	defer close(s.done)
	for {
		select {
		case <-s.quit:
			return
		case _, ok := <-s.w.Events():
			if ok {
				b.signal()
				continue
			}
		case <-s.w.Done():
		}
		// Close also ends the stream; only an unrequested stop is a failure.
		select {
		case <-s.quit:
		default:
			stopped(s.w.Err())
			b.signal()
		}
		return
	}
}

// installSource publishes s and starts its forwarder unless Close has run.
// It returns false after closing the watcher itself.
func (b *Backend) installSource(slot **source, s *source, stopped func(error)) bool {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = s.w.Close()
		return false
	}
	*slot = s
	b.mu.Unlock()
	go b.forward(s, stopped)
	return true
}

// ensurePolicyWatch registers before store selection so unavailable
// monitoring can refuse a GP write without changing DNS. A stopped watcher
// is replaced.
func (b *Backend) ensurePolicyWatch() error {
	b.mu.Lock()
	current := b.policySrc
	b.mu.Unlock()
	if current != nil {
		if !current.stopped() {
			return nil
		}
		b.mu.Lock()
		b.policySrc = nil
		b.mu.Unlock()
		if err := current.stop(); err != nil {
			return b.policyUnavailable(fmt.Errorf("windows: release failed policy watcher: %w", err))
		}
	}
	w, err := b.watchFactory()
	if err != nil {
		return b.policyUnavailable(fmt.Errorf("windows: start policy watcher: %w", err))
	}
	s := &source{w: w, quit: make(chan struct{}), done: make(chan struct{})}
	if !b.installSource(&b.policySrc, s, b.policyStopped) {
		return errors.New("windows: backend closed")
	}
	select {
	case <-w.Done():
		return b.policyUnavailable(watchStoppedErr("policy", w.Err()))
	default:
	}
	return nil
}

func (b *Backend) policyUnavailable(err error) error {
	b.logger.Warn("machine-policy watcher unavailable; Group Policy changes require monitoring", "error", err)
	return err
}

func (b *Backend) policyStopped(err error) {
	_ = b.policyUnavailable(watchStoppedErr("policy", err))
}

// ensureRegistryWatch watches the keys a converge toward target owns.
// Failure leaves the caller's periodic check as the only coverage; it does
// not refuse the converge.
func (b *Backend) ensureRegistryWatch(target adapterTarget) {
	keys := registryWatchKeys(target)
	b.mu.Lock()
	current := b.regSrc
	b.mu.Unlock()
	if current != nil {
		if !current.stopped() && slices.Equal(current.keys, keys) {
			return
		}
		b.mu.Lock()
		b.regSrc = nil
		b.mu.Unlock()
		// A close failure leaks at most one handle set; the replacement
		// below still restores coverage.
		if err := current.stop(); err != nil {
			b.logger.Warn("windows: release registry watcher", "error", err)
		}
	}
	w, err := b.regWatchFactory(keys)
	if err != nil {
		b.registryUnavailable(fmt.Errorf("windows: start registry watcher: %w", err))
		return
	}
	s := &source{w: w, keys: keys, quit: make(chan struct{}), done: make(chan struct{})}
	b.installSource(&b.regSrc, s, b.registryStopped)
}

func (b *Backend) registryUnavailable(err error) {
	b.logger.Warn("registry change watcher unavailable; loss of NRPT rules or adapter values relies on periodic checks", "error", err)
}

func (b *Backend) registryStopped(err error) {
	b.registryUnavailable(watchStoppedErr("registry", err))
}

func watchStoppedErr(kind string, err error) error {
	return fmt.Errorf("windows: %s watcher stopped: %w", kind, errors.Join(err, errors.New("notification stream closed")))
}
