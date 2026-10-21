//go:build windows

package windows

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.org/x/sys/windows/registry"
)

// systemRegistry is the production Registry, backed by the live Windows
// registry under HKEY_LOCAL_MACHINE.
type systemRegistry struct{}

// NewSystemRegistry returns a Registry backed by the live Windows
// registry. It is the Registry the Windows backend uses outside tests.
func NewSystemRegistry() Registry { return systemRegistry{} }

func (systemRegistry) GetString(keyPath, name string) (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", ErrValueNotFound
	}
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	s, _, err := k.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", ErrValueNotFound
	}
	return s, err
}

func (systemRegistry) SetString(keyPath, name, data string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetStringValue(name, data)
}

func (systemRegistry) SetExistingString(keyPath, name, data string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return ErrValueNotFound
	}
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetStringValue(name, data)
}

func (systemRegistry) KeyExists(keyPath string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, k.Close()
}

func (systemRegistry) GetMultiString(keyPath, name string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, ErrValueNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	s, _, err := k.GetStringsValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, ErrValueNotFound
	}
	return s, err
}

func (systemRegistry) SetMultiString(keyPath, name string, data []string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetStringsValue(name, data)
}

func (systemRegistry) SetDWord(keyPath, name string, data uint32) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetDWordValue(name, data)
}

func (systemRegistry) GetDWord(keyPath, name string) (uint32, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, ErrValueNotFound
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = k.Close() }()
	n, typ, err := k.GetIntegerValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, ErrValueNotFound
	}
	if err == nil && typ != registry.DWORD {
		return 0, registry.ErrUnexpectedType
	}
	return uint32(n), err
}

func (systemRegistry) DeleteValue(keyPath, name string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func (systemRegistry) CreateKey(keyPath string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, keyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	return k.Close()
}

func (systemRegistry) DeleteKey(keyPath string) error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, keyPath)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

func (systemRegistry) ValueNames(keyPath string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	return k.ReadValueNames(-1)
}

func (systemRegistry) SubKeyNames(keyPath string) ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = k.Close() }()
	return k.ReadSubKeyNames(-1)
}

var regRenameKey = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegRenameKey")

func (systemRegistry) RenameKey(keyPath, newName string) error {
	i := strings.LastIndexByte(keyPath, '\\')
	if i < 0 {
		return errors.New("windows: registry key has no parent")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath[:i], registry.WRITE|windows.DELETE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	oldPtr, err := windows.UTF16PtrFromString(keyPath[i+1:])
	if err != nil {
		return err
	}
	newPtr, err := windows.UTF16PtrFromString(newName)
	if err != nil {
		return err
	}
	status, _, _ := regRenameKey.Call(uintptr(k), uintptr(unsafe.Pointer(oldPtr)), uintptr(unsafe.Pointer(newPtr)))
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}
