//go:build darwin

package darwin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

const (
	// resolverFileHeaderPrefix opens every resolver file this library writes.
	// The identity that follows it scopes cleanup; a file with the prefix
	// and another identity is a conflict, not a foreign file.
	resolverFileHeaderPrefix = "# Managed by github.com/DefinedNet/dnsconfig identity="
	maxResolverHeaderBytes   = 256
)

func renderResolverFile(identity string, nameservers []netip.Addr) []byte {
	var b bytes.Buffer
	b.WriteString(resolverFileHeaderPrefix + identity + "\n")
	for _, ns := range nameservers {
		fmt.Fprintf(&b, "nameserver %s\n", ns)
	}
	return b.Bytes()
}

func isValidResolverFileName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, "/\\:") && !strings.Contains(name, "..")
}

// resolverFileOwner returns the identity in path's header, or "" for a
// missing or irregular path or a file the library did not write.
func (b *Backend) resolverFileOwner(path string) (string, error) {
	f, exists, regular, err := b.openResolverFile(path)
	if err != nil || !exists || !regular {
		return "", err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, maxResolverHeaderBytes)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}
	return headerIdentity(head[:n]), nil
}

// headerIdentity extracts the identity from a resolver file's first line.
func headerIdentity(head []byte) string {
	line, _, _ := bytes.Cut(head, []byte("\n"))
	if !bytes.HasPrefix(line, []byte(resolverFileHeaderPrefix)) {
		return ""
	}
	return string(bytes.TrimPrefix(line, []byte(resolverFileHeaderPrefix)))
}

// inspectResolverFile returns the file's body when the library wrote it, and
// the identity in its header. A foreign file reports an empty owner and no
// body; its contents are never compared or reused.
func (b *Backend) inspectResolverFile(path string) (body []byte, exists bool, owner string, err error) {
	f, exists, regular, err := b.openResolverFile(path)
	if err != nil || !exists || !regular {
		return nil, exists, "", err
	}
	defer func() { _ = f.Close() }()
	body, err = io.ReadAll(io.LimitReader(f, maxScutilOutput))
	if err != nil {
		return nil, true, "", err
	}
	owner = headerIdentity(body)
	if owner == "" {
		return nil, true, "", nil
	}
	return body, true, owner, nil
}

func (b *Backend) openResolverFile(path string) (f io.ReadCloser, exists, regular bool, err error) {
	regular, err = b.fs.IsRegularFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	if !regular {
		return nil, true, false, nil
	}
	f, err = b.fs.Open(path)
	if err != nil {
		return nil, true, false, err
	}
	return f, true, true, nil
}
