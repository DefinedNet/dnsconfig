package windows

import (
	"sync"
)

// failInjectRegistry fails or panics before the failAt-th intercepted mutation
// (zero-based). Reads and inherited fakeRegistry methods are not counted.
type failInjectRegistry struct {
	*fakeRegistry
	mu     sync.Mutex
	failAt int // -1 disables injection
	seen   int
	crash  bool
	// failSubKeys fails every SubKeyNames read. Set and Clear both list the
	// NRPT rules before they mutate anything.
	failSubKeys bool
}

func (r *failInjectRegistry) arm(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failAt = n
	r.seen = 0
}

func (r *failInjectRegistry) shouldFail() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := r.seen
	r.seen++
	if r.crash && idx == r.failAt {
		panic("simulated process crash")
	}
	return r.failAt >= 0 && idx == r.failAt
}

var errInjectedRegistry = &registryInjectErr{}

type registryInjectErr struct{}

func (*registryInjectErr) Error() string { return "windows test: injected registry failure" }

func (r *failInjectRegistry) CreateKey(keyPath string) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.CreateKey(keyPath)
}

func (r *failInjectRegistry) SetString(keyPath, name, data string) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.SetString(keyPath, name, data)
}

func (r *failInjectRegistry) SetExistingString(path, name, data string) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.SetExistingString(path, name, data)
}

func (r *failInjectRegistry) SetMultiString(keyPath, name string, data []string) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.SetMultiString(keyPath, name, data)
}

func (r *failInjectRegistry) SetDWord(keyPath, name string, data uint32) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.SetDWord(keyPath, name, data)
}

func (r *failInjectRegistry) DeleteValue(keyPath, name string) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.DeleteValue(keyPath, name)
}

func (r *failInjectRegistry) DeleteKey(keyPath string) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.DeleteKey(keyPath)
}

func (r *failInjectRegistry) RenameKey(path, name string) error {
	if r.shouldFail() {
		return errInjectedRegistry
	}
	return r.fakeRegistry.RenameKey(path, name)
}

func (r *failInjectRegistry) setFailSubKeys(fail bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failSubKeys = fail
}

func (r *failInjectRegistry) SubKeyNames(keyPath string) ([]string, error) {
	r.mu.Lock()
	fail := r.failSubKeys
	r.mu.Unlock()
	if fail {
		return nil, errInjectedRegistry
	}
	return r.fakeRegistry.SubKeyNames(keyPath)
}
