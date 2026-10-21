//go:build !windows

package windows

import "errors"

// newDefaultRegistryWatcher reports monitoring as unavailable off Windows;
// tests inject Options.WatchRegistry.
func newDefaultRegistryWatcher([]RegistryWatchKey) (Watcher, error) {
	return nil, errors.New("windows: registry change notification is not available off Windows")
}
