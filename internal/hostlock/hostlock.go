// Package hostlock provides named advisory locks shared by every process on a
// host and released by the operating system when the holder exits. The
// Manager uses one lock per application identity for the lifetime of its
// cleanup responsibility and one host-wide lock as a critical section around
// cross-identity conflict checks and the writes they authorize.
package hostlock

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrHeld reports that another holder owns the lock.
var ErrHeld = errors.New("hostlock: held elsewhere")

// Locker acquires named host-wide locks. Names are restricted to
// [A-Za-z0-9._-] because implementations map them to file names.
type Locker interface {
	// TryLock acquires name without waiting. It returns ErrHeld when another
	// holder owns the lock, including another Handle in this process.
	TryLock(name string) (Handle, error)
	// Lock waits for name until acquired or ctx ends.
	Lock(ctx context.Context, name string) (Handle, error)
}

// Handle is a held lock. Unlock releases it even when it returns an error,
// which callers rely on to log rather than propagate a release failure. The
// backing file is never removed, because a holder unlinking it would let a
// later waiter lock a different inode while the original stays held.
type Handle interface {
	Unlock() error
}

// pollInterval limits how often Lock retries a held file lock.
const pollInterval = 50 * time.Millisecond

// lockWithRetry implements Lock for Lockers whose primitive is non-blocking.
func lockWithRetry(ctx context.Context, tryLock func() (Handle, error)) (Handle, error) {
	for {
		h, err := tryLock()
		if !errors.Is(err, ErrHeld) {
			return h, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// Fake is an in-process Locker for tests. It reproduces ErrHeld for a name
// already held by any of its Handles and lets a test mark a name as held by
// a process it does not model.
type Fake struct {
	mu   sync.Mutex
	held map[string]bool
	// UnlockErr, when set, is returned by the next Unlock and then cleared.
	// The lock is still released so later operations in a test proceed.
	UnlockErr error
}

// NewFake returns an empty Fake.
func NewFake() *Fake { return &Fake{held: map[string]bool{}} }

// HoldExternally marks name as held by a process outside the test until
// Release is called.
func (f *Fake) HoldExternally(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.held[name] = true
}

// Release drops an external hold.
func (f *Fake) Release(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.held, name)
}

// Held reports whether any holder currently owns name.
func (f *Fake) Held(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held[name]
}

// TryLock implements Locker.
func (f *Fake) TryLock(name string) (Handle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.held[name] {
		return nil, ErrHeld
	}
	f.held[name] = true
	return fakeHandle{f: f, name: name}, nil
}

// Lock implements Locker.
func (f *Fake) Lock(ctx context.Context, name string) (Handle, error) {
	return lockWithRetry(ctx, func() (Handle, error) { return f.TryLock(name) })
}

type fakeHandle struct {
	f    *Fake
	name string
}

func (h fakeHandle) Unlock() error {
	h.f.mu.Lock()
	defer h.f.mu.Unlock()
	delete(h.f.held, h.name)
	err := h.f.UnlockErr
	h.f.UnlockErr = nil
	return err
}
