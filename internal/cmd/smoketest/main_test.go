package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSentinelReverseComposition guards the relation the reverse-zone check
// depends on: sentinelAddr must fall inside sentinelReverseZone, or the row
// would install a match domain that does not cover the address it looks up.
func TestSentinelReverseComposition(t *testing.T) {
	octets := strings.Split(sentinelAddr, ".")
	require.Len(t, octets, 4, "sentinelAddr must be dotted-quad IPv4")
	want := octets[2] + "." + octets[1] + "." + octets[0] + ".in-addr.arpa."
	assert.Equal(t, want, sentinelReverseZone,
		"sentinelReverseZone must be the /24 reverse zone containing sentinelAddr")
}

// TestSentinelPTRName pins the reverse name Windows queries: it must be
// sentinelAddr's octets reversed under in-addr.arpa, and must sort beneath
// sentinelReverseZone so the row's match domain actually routes it.
func TestSentinelPTRName(t *testing.T) {
	assert.Equal(t, "42.2.0.192.in-addr.arpa.", sentinelPTRName())
	assert.True(t, strings.HasSuffix(sentinelPTRName(), "."+sentinelReverseZone),
		"PTR name %q must fall under %q", sentinelPTRName(), sentinelReverseZone)
}

// TestParseRowsExplicit checks comma-separated macOS row selection.
func TestParseRowsExplicit(t *testing.T) {
	got, err := parseRowsSelectionFor("darwin", "M1,m2,M3")
	require.NoError(t, err)
	assert.Equal(t, []string{"M1", "M2", "M3"}, rowIDs(got))
}

// TestParseRowsEmpty confirms the empty string returns every macOS
// row in matrix-declaration order.
func TestParseRowsEmpty(t *testing.T) {
	got, err := parseRowsSelectionFor("darwin", "")
	require.NoError(t, err)
	assert.Equal(t, macosMatrix(), got)
}

// rowIDs returns the IDs of rows in order.
func rowIDs(rows []Row) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}

// TestParseRowsWhitespace tolerates surrounding spaces in the flag value.
func TestParseRowsWhitespace(t *testing.T) {
	got, err := parseRowsSelectionFor("darwin", " M5 , M6 ")
	require.NoError(t, err)
	assert.Equal(t, []string{"M5", "M6"}, rowIDs(got))
}

// TestParseRowsUnknown rejects row numbers that have no matrix entry.
func TestParseRowsUnknown(t *testing.T) {
	_, err := parseRowsSelectionFor("darwin", "M99")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "row M99")
}

// TestParseRowsBadFormat rejects tokens that are not a prefix plus a number.
func TestParseRowsBadFormat(t *testing.T) {
	_, err := parseRowsSelectionFor("darwin", "five")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid row "five"`)

	_, err = parseRowsSelectionFor("darwin", "6")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rows are prefixed by matrix",
		"a bare number is the ambiguity the prefix exists to remove")
}

// TestParseRowsWrongMatrix rejects a row id whose prefix names a different
// matrix than the host selects - the mistake of copying a -rows value out of
// another platform's workflow.
func TestParseRowsWrongMatrix(t *testing.T) {
	_, err := parseRowsSelectionFor("darwin", "W1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "belongs to the W matrix")

	_, err = parseRowsSelectionFor("windows", "M1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "belongs to the M matrix")
}

// exitErr runs a process that exits with the given code and returns the
// resulting *exec.ExitError, so tests can feed a fake runner a realistic
// error whose ExitCode() Local.run can extract.
func exitErr(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	var ee *exec.ExitError
	require.ErrorAs(t, err, &ee)
	require.Equal(t, code, ee.ExitCode())
	return err
}

// TestIndentMultiline confirms indent prefixes every line including blank
// ones but does not append an extra prefix when the input ends in newline.
func TestIndentMultiline(t *testing.T) {
	got := indent(">> ", "one\ntwo\nthree\n")
	assert.Equal(t, ">> one\n>> two\n>> three\n", got)
}

// TestParseRowsSelectionForWindows confirms the empty -rows value resolves
// against the Windows matrix and that a number with no Windows row is rejected.
func TestParseRowsSelectionForWindows(t *testing.T) {
	got, err := parseRowsSelectionFor("windows", "")
	require.NoError(t, err)
	assert.Equal(t, windowsMatrix(), got)

	// The Windows matrix stops at W7; W8 must not validate.
	_, err = parseRowsSelectionFor("windows", "W8")
	require.Error(t, err)
	assert.ErrorIs(t, err, errUnknownRow)
}

// TestRealMainRejectsForeignRow confirms a row from another platform's
// matrix is a usage error (exit 2) reported before the build starts.
func TestRealMainRejectsForeignRow(t *testing.T) {
	var foreign string
	switch runtime.GOOS {
	case "darwin":
		foreign = "W1"
	case "windows":
		foreign = "M1"
	default:
		t.Skip("no host matrix on this OS")
	}
	stderr, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	require.NoError(t, err)
	defer stderr.Close()
	code := realMain([]string{"-rows", foreign}, mustDevNull(t), stderr)
	assert.Equal(t, 2, code)
	out, err := os.ReadFile(stderr.Name())
	require.NoError(t, err)
	assert.Contains(t, string(out), "belongs to the "+foreign[:1]+" matrix")
}

// mustDevNull opens /dev/null as an *os.File for tests that need to pass a
// writer to realMain without polluting test output.
func mustDevNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestParseRowsHostDefaults checks the native matrix defaults.
func TestParseRowsHostDefaults(t *testing.T) {
	got, err := parseRowsSelectionFor(runtime.GOOS, "")
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		require.EqualError(t, err, "smoke tests require macOS or Windows")
		assert.Empty(t, got)
		return
	}
	require.NoError(t, err)
	assert.NotEmpty(t, got)
}
