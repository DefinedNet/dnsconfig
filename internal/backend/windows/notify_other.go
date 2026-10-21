//go:build !windows

package windows

import "errors"

// inertNotifier permits off-Windows backend tests without native policy APIs.
type inertNotifier struct{}

func newDefaultNotifier() PolicyNotifier { return inertNotifier{} }

func newDefaultLocalSystemCheck() func() (bool, error) { return nil }

func (inertNotifier) NotifyPolicyChange() (Delivery, error) {
	return DeliveryNone, errors.New("windows: Group Policy notification is not available off Windows")
}

// newDefaultDomainJoin reports false off Windows; tests can inject membership.
func newDefaultDomainJoin() func() (bool, error) {
	return func() (bool, error) { return false, nil }
}
