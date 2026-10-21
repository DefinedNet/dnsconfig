package main

import (
	"encoding/base64"
	"encoding/binary"
	"maps"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWindowsSetArgsReverseSplit pins that a reverse-zone row asks for both
// match domains in one set: the forward sentinel parent and the in-addr.arpa
// zone whose NRPT rule has to carry the PTR query.
func TestWindowsSetArgsReverseSplit(t *testing.T) {
	plain := windowsSetArgs(Row{Split: true}, sentinelSearchDomain)
	assert.Contains(t, plain, sentinelSearchDomain)
	assert.NotContains(t, strings.Join(plain, " "), sentinelReverseZone)

	reverse := windowsSetArgs(Row{Split: true, ReverseSplit: true}, sentinelSearchDomain)
	assert.Contains(t, reverse, sentinelSearchDomain+","+sentinelReverseZone,
		"--match is comma-separated; repeating the flag would drop the forward domain")
}

// TestAsSystemQuoting pins the double-quoting the LocalSystem wrapper needs:
// each argv element is quoted for the cmd.exe shim, and the whole command line
// is then quoted as one PowerShell argument.
func TestAsSystemQuoting(t *testing.T) {
	got := asSystem(`C:\repo\run-as-system.ps1`, []string{`C:\Windows\Temp\dnsconfigctl.exe`, "reset"})
	require.Equal(t, []string{"powershell", "-NoProfile", "-NonInteractive", "-Command"}, got[:4])
	assert.Equal(t,
		`& 'C:\repo\run-as-system.ps1' -Command '"C:\Windows\Temp\dnsconfigctl.exe" "reset"'`,
		got[4])
}

// TestNormalizeRegDump confirms the verbatim comparison of the foreign rule
// ignores only formatting: reg query's blank lines and indentation vary, a
// changed value must not.
func TestNormalizeRegDump(t *testing.T) {
	a := []byte("\r\nHKEY_LOCAL_MACHINE\\k\r\n    GenericDNSServers    REG_SZ    203.0.113.53\r\n\r\n")
	b := []byte("HKEY_LOCAL_MACHINE\\k\n  GenericDNSServers    REG_SZ    203.0.113.53\n")
	assert.Equal(t, normalizeRegDump(a), normalizeRegDump(b))

	changed := []byte("HKEY_LOCAL_MACHINE\\k\n  GenericDNSServers    REG_SZ    127.0.0.1\n")
	assert.NotEqual(t, normalizeRegDump(a), normalizeRegDump(changed))
}

// TestWindowsResetOK pins the post-reset check: a snapshot containing a
// dnsconfig- NRPT rule key fails; one without passes.
func TestWindowsResetOK(t *testing.T) {
	clean := []byte("=== nrpt ===\n(exit 1: key not found)\n=== searchlist ===\n")
	assert.True(t, windowsResetOK(clean), "a snapshot with no dnsconfig- key is a clean reset")

	dirty := []byte("=== nrpt ===\n" +
		`HKLM\...\DnsPolicyConfig\dnsconfig-0` + "\n    GenericDNSServers    REG_SZ    127.0.0.1\n")
	assert.False(t, windowsResetOK(dirty), "a surviving dnsconfig- NRPT key is a failed reset")
}

// A foreign rule can contain "dnsconfig-" in a value. Only key names
// identify owned rules; searching the whole dump would reject a clean reset.
func TestWindowsResetOKIgnoresForeignNamespaceSubstring(t *testing.T) {
	foreign := []byte(`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\{6F5E4D3C-SMOKE-FOREIGN-RULE}` + "\n" +
		"    Version    REG_DWORD    0x1\n" +
		"    Name    REG_MULTI_SZ    " + gpForeignNamespace + "\n" +
		"    GenericDNSServers    REG_SZ    203.0.113.53\n")
	assert.True(t, windowsResetOK(foreign),
		"a foreign rule whose namespace contains our prefix is not our leaked state")
	assert.False(t, windowsHasRuleKey(foreign, windowsOurRulePrefix),
		"the foreign seed must not read as one of our rule keys")

	ours := []byte(`HKLM\...\DnsPolicyConfig\dnsconfig-0` + "\n    GenericDNSServers    REG_SZ    127.0.0.1\n")
	assert.True(t, windowsHasRuleKey(ours, windowsOurRulePrefix), "our own rule key must still be found")

	globalSearch := []byte(`HKLM\...\Tcpip\Parameters` + "\n    SearchList    REG_SZ    " + sentinelSearchDomain + "\n")
	assert.True(t, windowsResetOK(globalSearch), "global SearchList stays administrator-owned even when its text matches our suffix")
}

// TestWindowsOwnedRulesComparesCopiesAcrossStores pins the dual-placement
// check: identical rules in the two stores compare equal whatever their
// store path and value order, the foreign seed is ignored, and a changed
// value is caught.
func TestWindowsOwnedRulesComparesCopiesAcrossStores(t *testing.T) {
	gp := []byte(gpNrptRegPath + `\` + gpForeignRuleName + "\r\n" +
		"    Name    REG_MULTI_SZ    " + gpForeignNamespace + "\r\n\r\n" +
		gpNrptRegPath + `\dnsconfig-dnsconfigctl-0` + "\r\n" +
		"    Name    REG_MULTI_SZ    .dnsconfig-smoke.example\r\n" +
		"    GenericDNSServers    REG_SZ    127.0.0.1\r\n")
	local := []byte(nrptRegPath + `\dnsconfig-dnsconfigctl-0` + "\n" +
		"  GenericDNSServers    REG_SZ    127.0.0.1\n" +
		"  Name    REG_MULTI_SZ    .dnsconfig-smoke.example\n")
	gpRules := windowsOwnedRules(gp)
	assert.Equal(t, []string{"dnsconfig-dnsconfigctl-0"}, slices.Collect(maps.Keys(gpRules)))
	assert.Equal(t, gpRules, windowsOwnedRules(local))

	changed := []byte(strings.Replace(string(local), "127.0.0.1", "127.0.0.2", 1))
	assert.NotEqual(t, gpRules, windowsOwnedRules(changed))
	assert.Empty(t, windowsOwnedRules([]byte("ERROR: The system was unable to find the specified registry key or value.\r\n")))
}

// TestParseEffectiveNRPT pins the effective-table parse the container-loss
// check depends on.
func TestParseEffectiveNRPT(t *testing.T) {
	got := parseEffectiveNRPT([]byte(".Dnsconfig-Smoke.example->127.0.0.1\r\n" +
		gpForeignNamespace + "->203.0.113.53\r\n\r\nnoise\r\n"))
	assert.Equal(t, map[string]string{
		ownNamespace():     "127.0.0.1",
		gpForeignNamespace: "203.0.113.53",
	}, got)
}

// TestPSEncodedCommand checks the UTF-16LE base64 form -EncodedCommand
// expects.
func TestPSEncodedCommand(t *testing.T) {
	got := psEncodedCommand("Write-Output 'x'")
	require.Equal(t, []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand"}, got[:4])
	raw, err := base64.StdEncoding.DecodeString(got[4])
	require.NoError(t, err)
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	assert.Equal(t, "Write-Output 'x'", string(utf16.Decode(units)))
}

// TestLastWatchChanged pins the parse the repair row's wait depends on: the
// last status line wins, and output without one reports false.
func TestLastWatchChanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want string
		ok   bool
	}{
		{"no status yet", "WATCH: ready applied=true\n", "", false},
		{"first converge", "WATCH: ready applied=true\nWATCH: status converged=true changed=2026-09-24T10:00:00Z err=<nil>\n", "2026-09-24T10:00:00Z", true},
		{
			"last line wins",
			"WATCH: status converged=true changed=2026-09-24T10:00:00Z err=<nil>\r\n" +
				"WATCH: status converged=true changed=2026-09-24T10:00:07.5Z err=<nil>\r\n",
			"2026-09-24T10:00:07.5Z", true,
		},
		{"never changed", "WATCH: status converged=false changed=none err=boom\n", "none", true},
		{"not a status line", "note: WATCH: status changed=x\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := lastWatchChanged([]byte(tc.out))
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestWindowsCtrlBreakScript pins that the console-attach script targets the
// given process.
func TestWindowsCtrlBreakScript(t *testing.T) {
	assert.Contains(t, windowsCtrlBreakScript("4242"), "AttachConsole(4242)")
}
