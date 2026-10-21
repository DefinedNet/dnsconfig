//go:build !windows

package windows

func resolveSystemInterface(string) (string, error) {
	return "", ErrInterfaceNotFound
}
