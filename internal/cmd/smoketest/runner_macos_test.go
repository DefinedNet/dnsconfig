package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testGoalLog = `time=t0 level=DEBUG msg="dnsconfig: attempt finished" trigger=goal duration=1s changed=true failed=false
WATCH: ready applied=true
time=t1 level=DEBUG msg="dnsconfig: change signal" opened=true
time=t2 level=DEBUG msg="dnsconfig: attempt finished" trigger=signal duration=1s changed=false failed=false
`
	testRecreated = `time=t3 level=INFO msg="darwin: converge recreated dynamic-store keys" new_goal=false converged=true
`
	// testSignalRepair is the log of a repair the change signal drove.
	testSignalRepair = testRecreated +
		`time=t4 level=DEBUG msg="dnsconfig: attempt finished" trigger=signal duration=1s changed=true failed=false
`
	// testDeliveryRepair is the log of a signal-driven repair of the removed
	// catch-all key.
	testDeliveryRepair = `time=t6 level=INFO msg="darwin: converge recreated dynamic-store keys" new_goal=false converged=true
time=t7 level=DEBUG msg="dnsconfig: attempt finished" trigger=signal duration=1s changed=true failed=false
`
	testChildExited = `time=t5 level=WARN msg="darwin: scutil notification child exited; restarted it" err=EOF restarted=true
`
)

// fastPacing shortens macosPacingWait for one test.
func fastPacing(t *testing.T) {
	t.Helper()
	saved := macosPacingWait
	macosPacingWait = 10 * time.Millisecond
	t.Cleanup(func() { macosPacingWait = saved })
}

type macosWatchTestDriver struct {
	Driver
	t              *testing.T
	closeResult    ExecResult
	repairLog      string
	deliveryLog    string
	killed         bool
	removed        bool
	stopped        bool
	waitedForClose bool
	checkedAbsent  bool
}

func (d *macosWatchTestDriver) Exec(_ context.Context, argv ...string) ExecResult {
	command := strings.Join(argv, " ")
	switch {
	case strings.Contains(command, "pkill -TERM"):
		d.stopped = true
	case strings.Contains(command, "WATCH: closed teardown-ok"):
		assert.True(d.t, d.stopped, "shutdown must be requested before joining it")
		d.waitedForClose = true
		return d.closeResult
	case strings.Contains(command, "list State:/Network/Service/dnsconfig-"):
		if d.stopped {
			d.checkedAbsent = true
			assert.True(d.t, d.waitedForClose, "key absence alone does not prove completed teardown")
			return ExecResult{Stdout: []byte("  no keys.\n")}
		}
		return ExecResult{Stdout: []byte("  subKey [0] = " + macosWatchCatchAllKey + "\n")}
	case command == "pgrep -x configd":
		if d.killed {
			return ExecResult{Stdout: []byte("456\n")}
		}
		return ExecResult{Stdout: []byte("123\n")}
	case command == "cat "+macosWatchLog:
		log := testGoalLog
		if d.killed {
			log += d.repairLog
		}
		if d.removed {
			log += d.deliveryLog
		}
		return ExecResult{Stdout: []byte(log)}
	case command == "sudo killall configd":
		d.killed = true
	case strings.Contains(command, "remove "+macosWatchCatchAllKey):
		assert.True(d.t, d.killed, "the removal follows the restart repair")
		assert.False(d.t, d.stopped, "the removal needs the live watch")
		d.removed = true
	case strings.Contains(command, "nohup /tmp/dnsconfigctl"),
		strings.Contains(command, "WATCH: ready applied=true"):
	default:
		d.t.Fatalf("unexpected smoke command: %s", command)
	}
	return ExecResult{}
}

func TestMacosWatcherWaitsForCompletedClose(t *testing.T) {
	for _, failedClose := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed close=%t", failedClose), func(t *testing.T) {
			fastPacing(t)
			driver := &macosWatchTestDriver{t: t, repairLog: testSignalRepair, deliveryLog: testDeliveryRepair}
			if failedClose {
				driver.closeResult = ExecResult{ExitCode: 1, Stdout: []byte("watch: close: cleanup failed\n")}
			}
			var logs strings.Builder
			cfg := runConfig{
				Driver: driver,
				Log:    func(format string, args ...any) { fmt.Fprintf(&logs, format, args...) },
			}
			stage := watcherCheckMacos(context.Background(), cfg, nil)
			assert.True(t, driver.waitedForClose)
			if failedClose {
				assert.Equal(t, "watch-close", stage)
				assert.Contains(t, logs.String(), "cleanup failed")
				assert.False(t, driver.checkedAbsent)
			} else {
				assert.Empty(t, stage)
				assert.True(t, driver.checkedAbsent)
			}
		})
	}
}

// TestMacosWatcherRejectsPeriodicRepair checks that a restart repaired only by
// the periodic check fails M3 and names the trigger.
func TestMacosWatcherRejectsPeriodicRepair(t *testing.T) {
	periodic := `time=t4 level=DEBUG msg="dnsconfig: attempt finished" trigger=periodic duration=1s changed=true failed=false`
	driver := &macosWatchTestDriver{t: t, repairLog: testRecreated + periodic + "\n"}
	var logs strings.Builder
	cfg := runConfig{
		Driver: driver,
		Log:    func(format string, args ...any) { fmt.Fprintf(&logs, format, args...) },
	}
	assert.Equal(t, "watch-signal", watcherCheckMacos(context.Background(), cfg, nil))
	assert.Contains(t, logs.String(), periodic)
}

// TestMacosWatcherDelivery checks that M3 fails when the notification child
// exited after the restart, or when a key removed after the restart repair is
// repaired only by the periodic check.
func TestMacosWatcherDelivery(t *testing.T) {
	periodic := `time=t7 level=DEBUG msg="dnsconfig: attempt finished" trigger=periodic duration=1s changed=true failed=false`
	for _, tc := range []struct {
		name      string
		repairLog string
		delivery  string
		want      string
		wantLog   string
	}{
		{name: "live child", repairLog: testSignalRepair, delivery: testDeliveryRepair, wantLog: "after the key removal"},
		{
			name:      "deaf child",
			repairLog: testSignalRepair,
			delivery:  "time=t6 level=INFO msg=\"darwin: converge recreated dynamic-store keys\" new_goal=false converged=true\n" + periodic + "\n",
			want:      "watch-deaf",
			wantLog:   periodic,
		},
		{name: "child exited at restart", repairLog: testChildExited + testSignalRepair, want: "watch-child-exited", wantLog: macosChildExited},
		{name: "child exited after removal", repairLog: testSignalRepair, delivery: testChildExited + testDeliveryRepair, want: "watch-child-exited", wantLog: macosChildExited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fastPacing(t)
			driver := &macosWatchTestDriver{t: t, repairLog: tc.repairLog, deliveryLog: tc.delivery}
			var logs strings.Builder
			cfg := runConfig{
				Driver: driver,
				Log:    func(format string, args ...any) { fmt.Fprintf(&logs, format, args...) },
			}
			assert.Equal(t, tc.want, watcherCheckMacos(context.Background(), cfg, nil))
			assert.Contains(t, logs.String(), tc.wantLog)
			assert.True(t, driver.stopped, "the watcher is stopped")
		})
	}
}

func TestMacosWorkerIdle(t *testing.T) {
	finished, idle := macosWorkerIdle([]byte(testGoalLog))
	assert.Equal(t, 2, finished)
	assert.True(t, idle)

	finished, idle = macosWorkerIdle([]byte(testGoalLog + `time=t3 level=DEBUG msg="dnsconfig: change signal" opened=true` + "\n"))
	assert.Equal(t, 2, finished)
	assert.False(t, idle, "an open debounce window means an attempt is due")

	finished, idle = macosWorkerIdle([]byte(testGoalLog + `time=t3 level=DEBUG msg="dnsconfig: change signal" opened=false` + "\n"))
	assert.Equal(t, 2, finished)
	assert.True(t, idle, "a signal that opened no window schedules nothing")

	finished, idle = macosWorkerIdle([]byte(testGoalLog + `time=t3 level=DEBUG msg="dnsconfig: attempt finished" trigger=periodic duration=1s changed=false failed=true` + "\n"))
	assert.Equal(t, 3, finished)
	assert.False(t, idle, "a failed attempt has a retry due")
}

func TestMacosSignalRepair(t *testing.T) {
	line := func(trigger, changed string) string {
		return `time=t level=DEBUG msg="dnsconfig: attempt finished" trigger=` + trigger +
			` duration=1s changed=` + changed + ` failed=false`
	}
	for _, tc := range []struct {
		name string
		log  string
		done bool
		want bool
	}{
		{name: "signal", log: testRecreated + line("signal", "true"), done: true, want: true},
		{
			name: "retry after failed signal attempt",
			log:  line("signal", "false") + "\n" + testRecreated + line("retry", "true"),
			done: true, want: true,
		},
		{
			name: "second signal after failed signal attempt",
			log:  line("signal", "false") + "\n" + testRecreated + line("signal", "true"),
			done: true, want: true,
		},
		{name: "retry first", log: testRecreated + line("retry", "true"), done: true},
		{name: "periodic", log: testRecreated + line("periodic", "true"), done: true},
		{
			name: "retry after periodic attempt",
			log:  line("periodic", "false") + "\n" + testRecreated + line("retry", "true"),
			done: true,
		},
		{name: "recreating attempt not finished", log: line("signal", "false") + "\n" + testRecreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts, done := macosRepairAttempts([]byte(testGoalLog+tc.log), 2)
			require.Equal(t, tc.done, done)
			assert.Equal(t, tc.want, done && macosSignalRepair(attempts))
		})
	}
}

// TestMacosRepairAttemptsSkipsEarlierRecreation checks that a recreated-keys
// line before the skipped attempts does not end a later repair wait.
func TestMacosRepairAttemptsSkipsEarlierRecreation(t *testing.T) {
	log := testGoalLog + testSignalRepair +
		`time=t5 level=DEBUG msg="dnsconfig: attempt finished" trigger=signal duration=1s changed=false failed=false` + "\n"
	_, done := macosRepairAttempts([]byte(log), 3)
	assert.False(t, done)

	attempts, done := macosRepairAttempts([]byte(log+testDeliveryRepair), 3)
	require.True(t, done)
	assert.True(t, macosSignalRepair(attempts))
}

func TestMacosKeyListAnswered(t *testing.T) {
	for out, want := range map[string]bool{
		"  no keys.\n": true,
		"  subKey [0] = " + macosStatePrefix + "a-0/DNS\n": true,
		"":               false,
		"  subKey [0]\n": false,
		"  Configuration daemon not (no longer) available\n":                                          false,
		"  subKey [0] = " + macosStatePrefix + "a-0/DNS\n  Configuration daemon session not active\n": false,
	} {
		assert.Equal(t, want, macosKeyListAnswered([]byte(out)), "%q", out)
	}
}

// TestMacosUnscopedSearch reads the base list from the first unscoped
// resolver without a domain and never from a scoped or supplemental one.
func TestMacosUnscopedSearch(t *testing.T) {
	const scoped = "DNS configuration (for scoped queries)\n\n" +
		"resolver #1\n  search domain[0] : scoped.example\n  nameserver[0] : 192.0.2.1\n"
	for _, tc := range []struct {
		name string
		body string
		want []string
	}{
		{
			name: "base first",
			body: "DNS configuration\n\nresolver #1\n" +
				"  search domain[0] : lan.example\n  search domain[1] : Corp.Example.\n" +
				"  nameserver[0] : 192.0.2.53\n\nresolver #2\n  domain   : local\n  order    : 300000\n\n" + scoped,
			want: []string{"lan.example", "Corp.Example"},
		},
		{
			name: "supplemental domain first",
			body: "DNS configuration\n\nresolver #1\n  domain   : corp.example\n" +
				"  search domain[0] : wrong.example\n\nresolver #2\n  search domain[0] : lan.example\n\n" + scoped,
			want: []string{"lan.example"},
		},
		{
			name: "no search list",
			body: "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.0.2.53\n\n" + scoped,
			want: nil,
		},
		{
			name: "only scoped resolvers",
			body: scoped,
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, macosUnscopedSearch([]byte(tc.body)))
		})
	}
}

func TestMacosWatcherFailsOnAfterRepair(t *testing.T) {
	driver := &macosWatchTestDriver{t: t, repairLog: testSignalRepair}
	cfg := runConfig{Driver: driver, Log: func(string, ...any) {}}
	called := false
	stage := watcherCheckMacos(context.Background(), cfg, func() string {
		called = true
		return "watch-overlap-compiled-search"
	})
	assert.True(t, called)
	assert.Equal(t, "watch-overlap-compiled-search", stage)
	assert.True(t, driver.stopped, "the watcher is still stopped")
}

// TestMacosSearchUnderSet states the expected compiled list as configd
// builds it: the requested domains first in configured order, then the base
// list without exact-spelling duplicates of them.
func TestMacosSearchUnderSet(t *testing.T) {
	const d = "dnsconfig-smoke.example"
	for _, tc := range []struct {
		name      string
		requested []string
		base      []string
		want      []string
	}{
		{"added to empty", []string{sentinelSearchDomain}, nil, []string{d}},
		{"added ahead", []string{sentinelSearchDomain}, []string{"lan.example"}, []string{d, "lan.example"}},
		{"canonical form", []string{"DNSConfig-Smoke.Example."}, []string{"lan.example"}, []string{d, "lan.example"}},
		{
			"configured order kept", []string{d, "zz." + d, "aa." + d}, []string{"lan.example"},
			[]string{d, "zz." + d, "aa." + d, "lan.example"},
		},
		{
			"exact duplicate moves to the front", []string{d}, []string{"lead.example", d, "tail.example"},
			[]string{d, "lead.example", "tail.example"},
		},
		{
			"case-different duplicate stays", []string{d}, []string{"lead.example", "Dnsconfig-Smoke.Example", "tail.example"},
			[]string{d, "lead.example", "Dnsconfig-Smoke.Example", "tail.example"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, macosSearchUnderSet(tc.requested, tc.base))
		})
	}
}

// TestMacosOverlapSearch requires the injected spelling to sit between the
// two fillers, so the compiled list shows where it stays, and the exact
// duplicate to follow them, so folding it moves it.
func TestMacosOverlapSearch(t *testing.T) {
	const exact = "zz.dnsconfig-smoke.example"
	mixed, want := macosOverlapSearch([]string{"lan.example", "dnsconfig-smoke.example", exact, macosOverlapTail}, sentinelSearchDomain, exact+".")
	assert.Equal(t, "Dnsconfig-smoke.Example", mixed)
	assert.Equal(t, []string{macosOverlapLead, mixed, macosOverlapTail, exact, "lan.example"}, want)

	mixed, want = macosOverlapSearch(nil, sentinelSearchDomain, macosOverlapExact)
	assert.Equal(t, []string{macosOverlapLead, mixed, macosOverlapTail, exact}, want)
}

// TestMacosOverlapUnderSet pins the overlap cycle's expected compiled list:
// the requested suffixes first, the mixed-case spelling kept between the
// fillers, and the exact duplicate folded into the requested copy.
func TestMacosOverlapUnderSet(t *testing.T) {
	mixed, base := macosOverlapSearch([]string{"lan.example"}, sentinelSearchDomain, macosOverlapExact)
	want := append(macosPublished(macosOrderSearch), macosOverlapLead, mixed, macosOverlapTail, "lan.example")
	assert.Equal(t, want, macosSearchUnderSet(macosOrderSearch, base))
}

// TestMacosSearchListsAgainstLineLimit keeps macosOrderSearch unsorted and
// within the backend's one-line limit for a search list (2047 bytes), and
// macosOverLimitSearch valid for Config but over it.
func TestMacosSearchListsAgainstLineLimit(t *testing.T) {
	const lineLimit = 2047
	line := func(search []string) int {
		n := len("d.add SupplementalMatchDomains *")
		for _, d := range macosPublished(search) {
			n += 1 + len(d)
		}
		return n
	}
	assert.False(t, slices.IsSorted(macosOrderSearch))
	assert.False(t, slices.IsSorted(macosLongSearch()))
	assert.LessOrEqual(t, line(macosOrderSearch), lineLimit)
	assert.Greater(t, line(macosOverLimitSearch()), lineLimit)
	for _, d := range macosPublished(macosOverLimitSearch()) {
		require.LessOrEqual(t, len(d)+1, 254, "a domain with its trailing dot fits Config")
		for label := range strings.SplitSeq(d, ".") {
			require.LessOrEqual(t, len(label), 63)
		}
	}
}

func TestMacosOwnKeyCount(t *testing.T) {
	out := []byte("  subKey [0] = State:/Network/Service/dnsconfig-dnsconfigctl-0/DNS\n" +
		"  subKey [1] = State:/Network/Service/dnsconfig-dnsconfigctl-1/DNS\n" +
		"  subKey [2] = State:/Network/Service/dnsconfig-net-a-0/DNS\n")
	assert.Equal(t, 2, macosOwnKeyCount(out))
	assert.Zero(t, macosOwnKeyCount([]byte("no keys.\n")))
}

func TestMacosOverlapCaseKept(t *testing.T) {
	const mixed = "Dnsconfig-smoke.Example"
	for _, tc := range []struct {
		name string
		base []string
		want bool
	}{
		{"kept", []string{macosOverlapLead, mixed, macosOverlapTail}, true},
		{"lowercased", []string{macosOverlapLead, "dnsconfig-smoke.example", macosOverlapTail}, false},
		{"uppercased", []string{macosOverlapLead, "DNSCONFIG-SMOKE.EXAMPLE", macosOverlapTail}, false},
		{"missing", []string{macosOverlapLead, macosOverlapTail}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, macosOverlapCaseKept(tc.base, mixed))
		})
	}
}

func TestMacosPrimaryInterface(t *testing.T) {
	out := "<dictionary> {\n  PrimaryInterface : en0\n  PrimaryService : 1A2B\n  Router : 192.0.2.1\n}\n"
	assert.Equal(t, "en0", macosPrimaryInterface([]byte(out)))
	assert.Empty(t, macosPrimaryInterface([]byte("  No such key\n")))
}

func TestMacosServiceForDevice(t *testing.T) {
	order := "An asterisk (*) denotes that a network service is disabled.\n" +
		"(1) Ethernet\n(Hardware Port: Ethernet, Device: en0)\n\n" +
		"(2) Wi-Fi (Office)\n(Hardware Port: Wi-Fi, Device: en01)\n\n" +
		"(*) Spare\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n"
	for device, want := range map[string]string{
		"en0":     "Ethernet",
		"en01":    "Wi-Fi (Office)",
		"bridge0": "Spare",
		"en1":     "",
		"":        "",
	} {
		assert.Equal(t, want, macosServiceForDevice([]byte(order), device), device)
	}
}

func TestMacosParseSearchDomains(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want []string
		ok   bool
	}{
		{"list", "lan.example\ncorp.example\n", []string{"lan.example", "corp.example"}, true},
		{"none", "There aren't any Search Domains set on Ethernet.\n", nil, true},
		{"silent", "", nil, false},
		{"unknown service", "Ethernet 2 is not a recognized network service.\n", nil, false},
		{"error", "** Error: The parameters were not valid.\n", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := macosParseSearchDomains([]byte(tc.out))
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestPairMacosSearchOrder reports either relative order of the two
// identities' suffixes but requires both to lead the primary service's list.
func TestPairMacosSearchOrder(t *testing.T) {
	pub := macosPublished([]string{pairSearchA, pairSearchB})
	a, b := pub[0], pub[1]
	base := []string{"lan.example", a}
	for _, tc := range []struct {
		name      string
		under     []string
		wantOrder string
		wantOK    bool
	}{
		{"a first", []string{a, b, "lan.example"}, pairIdentityA + "-first", true},
		{"b first", []string{b, a, "lan.example"}, pairIdentityB + "-first", true},
		{"behind the base", []string{"lan.example", a, b}, pairIdentityA + "-first", false},
		{"duplicate kept", []string{a, b, "lan.example", a}, pairIdentityA + "-first", false},
		{"one missing", []string{a, "lan.example"}, "missing", false},
		{"base lost", []string{b, a}, pairIdentityB + "-first", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			order, ok := pairMacosSearchOrder(tc.under, base)
			assert.Equal(t, tc.wantOrder, order)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}
