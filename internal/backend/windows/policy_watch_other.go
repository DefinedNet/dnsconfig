//go:build !windows

package windows

import "errors"

// newDefaultPolicyWatcher reports monitoring as unavailable off Windows;
// tests inject Options.WatchPolicy.
func newDefaultPolicyWatcher() (Watcher, error) {
	return nil, errors.New("windows: policy change notification is not available off Windows")
}
