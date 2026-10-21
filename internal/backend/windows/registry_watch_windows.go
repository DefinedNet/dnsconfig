//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// regNotifyFilter covers subkeys added or removed and values set or deleted.
// THREAD_AGNOSTIC keeps a registration alive if the registering thread
// exits; the watcher also locks its goroutine to one thread for older hosts.
const regNotifyFilter = windows.REG_NOTIFY_CHANGE_NAME | windows.REG_NOTIFY_CHANGE_LAST_SET | windows.REG_NOTIFY_THREAD_AGNOSTIC

// regSlot is one armed RegNotifyChangeKeyValue registration.
type regSlot struct {
	spec  RegistryWatchKey
	event windows.Handle
	key   registry.Key
	path  string
	open  bool
}

// arm registers a one-shot subtree notification on the deepest existing key
// from spec.Path up to spec.Floor. Watching an ancestor while Path is absent
// observes Path's creation.
//
// Closing a key signals its registrations' event, which would wake the
// watcher again with no change behind it and sustain a notification stream.
// arm therefore re-registers on the key it already holds while the watched
// path is unchanged, and clears the event after closing a key it replaces.
func (s *regSlot) arm() error {
	path := s.spec.Path
	var k registry.Key
	for {
		var err error
		k, err = registry.OpenKey(registry.LOCAL_MACHINE, path, registry.NOTIFY)
		if err == nil {
			break
		}
		if !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("open %s for notification: %w", path, err)
		}
		if strings.EqualFold(path, s.spec.Floor) {
			return fmt.Errorf("watch %s: %w", s.spec.Path, err)
		}
		i := strings.LastIndexByte(path, '\\')
		if i < 0 {
			return fmt.Errorf("watch %s: floor %s is not an ancestor", s.spec.Path, s.spec.Floor)
		}
		path = path[:i]
	}
	// A held key deleted and recreated at the same path refuses
	// registration, so that case falls through to the replacement below.
	if s.open && strings.EqualFold(path, s.path) && register(s.key, s.event) == nil {
		_ = k.Close()
		return nil
	}
	if s.open {
		_ = s.key.Close()
		s.open = false
		if err := windows.ResetEvent(s.event); err != nil {
			_ = k.Close()
			return fmt.Errorf("reset registry watch event: %w", err)
		}
	}
	s.key, s.path, s.open = k, path, true
	if err := register(k, s.event); err != nil {
		return fmt.Errorf("RegNotifyChangeKeyValue %s: %w", path, err)
	}
	return nil
}

func register(k registry.Key, event windows.Handle) error {
	return windows.RegNotifyChangeKeyValue(windows.Handle(k), true, regNotifyFilter, event, true)
}

func (s *regSlot) close() error {
	var errs []error
	if s.open {
		errs = append(errs, s.key.Close())
		s.open = false
	}
	if s.event != 0 {
		errs = append(errs, windows.CloseHandle(s.event))
		s.event = 0
	}
	return errors.Join(errs...)
}

type systemRegistryWatcher struct {
	slots     []*regSlot
	stop      windows.Handle
	events    chan struct{}
	done      chan struct{}
	err       error
	closeOnce sync.Once
	closeErr  error
	stopping  atomic.Bool
}

// newDefaultRegistryWatcher registers change notifications on keys without changing
// them. Each notification re-arms its key before it is delivered, so no
// change between delivery and re-registration is missed.
func newDefaultRegistryWatcher(keys []RegistryWatchKey) (Watcher, error) {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("create registry watch stop event: %w", err)
	}
	w := &systemRegistryWatcher{stop: stop, events: make(chan struct{}, 1), done: make(chan struct{})}
	for _, spec := range keys {
		event, err := windows.CreateEvent(nil, 0, 0, nil)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("create registry watch event: %w", err), w.release())
		}
		w.slots = append(w.slots, &regSlot{spec: spec, event: event})
	}
	ready := make(chan error, 1)
	go w.run(ready)
	if err := <-ready; err != nil {
		<-w.done
		return nil, errors.Join(err, w.release())
	}
	return w, nil
}

func (w *systemRegistryWatcher) Events() <-chan struct{} { return w.events }
func (w *systemRegistryWatcher) Done() <-chan struct{}   { return w.done }

func (w *systemRegistryWatcher) Err() error {
	<-w.done
	return w.err
}

func (w *systemRegistryWatcher) run(ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(w.done)
	defer close(w.events)
	for _, s := range w.slots {
		if err := s.arm(); err != nil {
			ready <- err
			return
		}
	}
	ready <- nil
	handles := []windows.Handle{w.stop}
	for _, s := range w.slots {
		handles = append(handles, s.event)
	}
	for !w.stopping.Load() {
		// The timeout permits shutdown even if signalling the stop event fails.
		result, err := windows.WaitForMultipleObjects(handles, false, 1000)
		switch {
		case result == windows.WAIT_OBJECT_0:
			return
		case result == uint32(windows.WAIT_TIMEOUT):
		case result > windows.WAIT_OBJECT_0 && result < windows.WAIT_OBJECT_0+uint32(len(handles)):
			if err := w.slots[result-windows.WAIT_OBJECT_0-1].arm(); err != nil {
				w.err = err
				return
			}
			select {
			case w.events <- struct{}{}:
			default:
			}
		default:
			w.err = fmt.Errorf("wait for registry change: result %d: %w", result, err)
			return
		}
	}
}

// release closes every handle after run has exited.
func (w *systemRegistryWatcher) release() error {
	var errs []error
	for _, s := range w.slots {
		errs = append(errs, s.close())
	}
	return errors.Join(append(errs, windows.CloseHandle(w.stop))...)
}

func (w *systemRegistryWatcher) Close() error {
	w.closeOnce.Do(func() {
		w.stopping.Store(true)
		stopErr := windows.SetEvent(w.stop)
		<-w.done
		w.closeErr = errors.Join(stopErr, w.release())
	})
	return w.closeErr
}
