package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// sentinelName uses the reserved .example suffix so public DNS cannot
// supply the sentinel answer.
const sentinelName = "sentinel.dnsconfig-smoke.example."

// sentinelSearchDomain is sentinelName's parent. macOS rows and Windows
// catch-all rows install it as the search suffix so a short-name lookup
// reaches the sentinel; split rows route it so expanded short names remain
// within the split domain.
const sentinelSearchDomain = "dnsconfig-smoke.example."

// sentinelAddr is the A record the sentinel returns for sentinelName. It is
// taken from TEST-NET-1 (RFC 5737) so it cannot collide with a real host.
const sentinelAddr = "192.0.2.42"

// sentinelReverseZone covers sentinelAddr's /24. Split rows route this zone
// to the sentinel so PTR queries reach the same server as forward queries.
const sentinelReverseZone = "2.0.192.in-addr.arpa."

// sentinelPTRName is the reverse name a PTR lookup of sentinelAddr asks for.
// Derived rather than written out so it cannot drift from the address, and
// used where a platform's resolver tool takes the query name instead of the
// address (Windows).
func sentinelPTRName() string {
	octets := strings.Split(sentinelAddr, ".")
	slices.Reverse(octets)
	return strings.Join(octets, ".") + ".in-addr.arpa."
}

// Resolution checks retry to allow asynchronous OS resolver updates to settle.
const (
	resolutionMaxAttempts = 5
	resolutionBackoff     = 500 * time.Millisecond
)

// rowOutcome is the per-row return value of executeRow. It feeds the final
// summary printed by main.
type rowOutcome int

const (
	// outcomePassed means every assertion in the row succeeded.
	outcomePassed rowOutcome = iota

	// outcomeFailed means at least one assertion failed. Details are written
	// to the logger before this is returned.
	outcomeFailed
)

func (o rowOutcome) String() string {
	switch o {
	case outcomePassed:
		return "PASSED"
	case outcomeFailed:
		return "FAILED"
	}
	return "?"
}

// runConfig bundles everything executeRow needs that is shared across rows.
type runConfig struct {
	// Driver executes commands and copies files on the runner.
	Driver Driver

	// Binary is the local path to the freshly built dnsconfigctl binary.
	Binary string

	// KeepOnFailure preserves the failed row's DNS state for inspection.
	KeepOnFailure bool

	// Log writes human-readable progress messages.
	Log func(format string, args ...any)
}

// indent prefixes every line of s with prefix. It is used to render
// nested command output and diffs.
func indent(prefix, s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for i, line := range lines {
		if i == len(lines)-1 && line == "" {
			// Don't append the prefix on the last "line" of a string that
			// ends in newline.
			break
		}
		b.WriteString(prefix)
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// tempBinaryPath keeps the native binary separate from other invocations' artifacts.
func tempBinaryPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("dnsconfigctl-smoketest-%d", os.Getpid()))
}

// semanticResetOK reports whether the post-reset snapshot excludes the sentinel.
func semanticResetOK(post []byte, sentinel string) bool {
	return !bytes.Contains(post, []byte(sentinel))
}
