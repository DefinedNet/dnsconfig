//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemNotifier uses GenerateGPNotification for LocalSystem and RefreshPolicyEx
// for elevated administrators. GenerateGPNotification's internal access check
// requires LocalSystem even when the caller is elevated.
type systemNotifier struct{}

func newDefaultNotifier() PolicyNotifier { return systemNotifier{} }

func newDefaultLocalSystemCheck() func() (bool, error) {
	return func() (bool, error) {
		system, _, err := privilegeTier()
		return system, err
	}
}

// rpForce is RefreshPolicyEx's RP_FORCE: reapply all policy, not just what
// changed.
const rpForce = 0x1

// notifyProduct is the management-product name GenerateGPNotification records
// with the notification. It is informational.
const notifyProduct = "dnsconfig"

var (
	userenv = windows.NewLazySystemDLL("userenv.dll")

	// Find turns missing exports into errors instead of a panic from Call.
	procGenerateGPNotification = userenv.NewProc("GenerateGPNotification")
	procRefreshPolicyEx        = userenv.NewProc("RefreshPolicyEx")
)

// NotifyPolicyChange implements PolicyNotifier.
func (systemNotifier) NotifyPolicyChange() (Delivery, error) {
	system, elevated, err := privilegeTier()
	if err != nil {
		return DeliveryNone, fmt.Errorf("windows: determine process privilege: %w", err)
	}
	if system {
		if err := generateGPNotification(); err != nil {
			return DeliveryNone, err
		}
		return DeliveryNotified, nil
	}
	if !elevated {
		return DeliveryNone, fmt.Errorf("windows: process is neither LocalSystem nor elevated")
	}
	if err := refreshPolicy(); err != nil {
		return DeliveryNone, err
	}
	// RefreshPolicyEx also reports success on workgroup hosts without delivering
	// the change. The backend uses domain membership to decide whether to retain
	// this warning.
	return DeliveryRefresh, fmt.Errorf(
		"windows: not LocalSystem, so a full policy refresh was forced instead of a direct notification; on a workgroup host this does not take effect until the next refresh or reboot")
}

// privilegeTier reports whether the process runs as LocalSystem and whether
// it is elevated, from the process token's user SID and elevation flag.
func privilegeTier() (system, elevated bool, err error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return false, false, err
	}
	return user.User.Sid.IsWellKnown(windows.WinLocalSystemSid), tok.IsElevated(), nil
}

// generateGPNotification signals a machine policy change directly to the
// policy-notification clients, the DNS Client among them.
func generateGPNotification() error {
	if err := procGenerateGPNotification.Find(); err != nil {
		return fmt.Errorf("windows: GenerateGPNotification unavailable: %w", err)
	}
	product, err := windows.UTF16PtrFromString(notifyProduct)
	if err != nil {
		return err
	}
	// GenerateGPNotification returns a Win32 error code directly rather than
	// a BOOL, so GetLastError says nothing about it.
	rc, _, _ := procGenerateGPNotification.Call(
		1, // bMachine: machine policy, which is where the NRPT lives
		uintptr(unsafe.Pointer(product)),
		0,
	)
	if rc != 0 {
		return fmt.Errorf("windows: GenerateGPNotification: %w", windows.Errno(rc))
	}
	return nil
}

// refreshPolicy requests a full machine policy refresh. RP_FORCE includes
// directly written NRPT rules, but delivery requires a reachable domain controller.
func refreshPolicy() error {
	if err := procRefreshPolicyEx.Find(); err != nil {
		return fmt.Errorf("windows: RefreshPolicyEx unavailable: %w", err)
	}
	// Unlike GenerateGPNotification this one is a normal BOOL API, so a zero
	// return means consult GetLastError.
	ret, _, callErr := procRefreshPolicyEx.Call(1, rpForce)
	if ret == 0 {
		return fmt.Errorf("windows: RefreshPolicyEx: %w", callErr)
	}
	return nil
}

// newDefaultDomainJoin returns the production domain-join check.
func newDefaultDomainJoin() func() (bool, error) { return machineIsDomainJoined }

// machineIsDomainJoined supplies a heuristic for RefreshPolicyEx delivery.
// It reads join state only, so it reports true for a joined host that cannot
// reach a domain controller, such as while the secure channel settles after
// join or boot, or while the host is offline.
func machineIsDomainJoined() (bool, error) {
	var name *uint16
	var joinType uint32
	if err := windows.NetGetJoinInformation(nil, &name, &joinType); err != nil {
		return false, fmt.Errorf("windows: NetGetJoinInformation: %w", err)
	}
	// name is a NetApi-allocated buffer; NetApiBufferFree takes *byte.
	defer func() { _ = windows.NetApiBufferFree((*byte)(unsafe.Pointer(name))) }()
	return joinType == windows.NetSetupDomainName, nil
}
