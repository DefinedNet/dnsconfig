//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func resolveSystemInterface(name string) (string, error) {
	size := uint32(15000)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, first, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if errors.Is(err, windows.ERROR_NO_DATA) {
			return "", ErrInterfaceNotFound
		}
		if err != nil {
			return "", err
		}
		// Every match is collected: the listing includes hidden interfaces and
		// the comparison ignores case, so taking the first could write DNS
		// settings onto an adapter the caller never named.
		var guids []string
		for adapter := first; adapter != nil; adapter = adapter.Next {
			if strings.EqualFold(windows.UTF16PtrToString(adapter.FriendlyName), name) {
				guids = append(guids, windows.BytePtrToString(adapter.AdapterName))
			}
		}
		switch len(guids) {
		case 0:
			return "", ErrInterfaceNotFound
		case 1:
			return canonicalGUID(guids[0])
		default:
			return "", fmt.Errorf("interface name matches %d adapters: %s", len(guids), strings.Join(guids, ", "))
		}
	}
}
