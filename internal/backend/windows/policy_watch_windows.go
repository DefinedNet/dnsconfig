//go:build windows

package windows

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

var (
	procRegisterGPNotification   = userenv.NewProc("RegisterGPNotification")
	procUnregisterGPNotification = userenv.NewProc("UnregisterGPNotification")
)

type systemPolicyWatcher struct {
	event     windows.Handle
	stop      windows.Handle
	events    chan struct{}
	done      chan struct{}
	err       error
	closeErr  error
	closeOnce sync.Once
	stopping  atomic.Bool
}

// newDefaultPolicyWatcher registers machine-policy notifications without applying DNS.
func newDefaultPolicyWatcher() (Watcher, error) {
	if err := procRegisterGPNotification.Find(); err != nil {
		return nil, fmt.Errorf("RegisterGPNotification unavailable: %w", err)
	}
	if err := procUnregisterGPNotification.Find(); err != nil {
		return nil, fmt.Errorf("UnregisterGPNotification unavailable: %w", err)
	}
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("create policy event: %w", err)
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("create policy stop event: %w", err), windows.CloseHandle(event))
	}
	result, _, callErr := procRegisterGPNotification.Call(uintptr(event), 1)
	if result == 0 {
		return nil, errors.Join(fmt.Errorf("RegisterGPNotification: %w", callErr), windows.CloseHandle(stop), windows.CloseHandle(event))
	}
	w := &systemPolicyWatcher{
		event: event, stop: stop,
		events: make(chan struct{}, 1), done: make(chan struct{}),
	}
	go w.run()
	return w, nil
}

func (w *systemPolicyWatcher) Events() <-chan struct{} { return w.events }
func (w *systemPolicyWatcher) Done() <-chan struct{}   { return w.done }

func (w *systemPolicyWatcher) Err() error {
	<-w.done
	return w.err
}

func (w *systemPolicyWatcher) run() {
	defer close(w.done)
	defer close(w.events)
	for !w.stopping.Load() {
		// The timeout permits shutdown even if signalling the stop event fails.
		result, err := windows.WaitForMultipleObjects([]windows.Handle{w.stop, w.event}, false, 1000)
		switch result {
		case windows.WAIT_OBJECT_0:
			return
		case windows.WAIT_OBJECT_0 + 1:
			select {
			case w.events <- struct{}{}:
			default:
			}
		case uint32(windows.WAIT_TIMEOUT):
		default:
			w.err = fmt.Errorf("wait for machine policy: result %d: %w", result, err)
			return
		}
	}
}

func (w *systemPolicyWatcher) Close() error {
	w.closeOnce.Do(func() {
		w.stopping.Store(true)
		stopErr := windows.SetEvent(w.stop)
		<-w.done
		var unregisterErr error
		result, _, callErr := procUnregisterGPNotification.Call(uintptr(w.event))
		if result == 0 {
			unregisterErr = fmt.Errorf("UnregisterGPNotification: %w", callErr)
		}
		w.closeErr = errors.Join(stopErr, unregisterErr, windows.CloseHandle(w.event), windows.CloseHandle(w.stop))
	})
	return w.closeErr
}
