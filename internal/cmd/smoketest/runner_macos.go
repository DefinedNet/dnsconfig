package main

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// macosSentinelAddr is explicitly aliased onto lo0 before the sentinel binds.
const macosSentinelAddr = "127.0.0.99"

const (
	macosAltSentinelName = "sentinel." + altSearchDomain
	macosAltSentinelAddr = "192.0.2.43"
)

const (
	macosWatchLog    = "/tmp/dnsconfig-watch.log"
	macosStatePrefix = "State:/Network/Service/dnsconfig-"

	// macosWatchCatchAllKey is the catch-all State key of M3's watch, which
	// runs under dnsconfigctl's default identity; the backend publishes a
	// catch-all at index 0.
	macosWatchCatchAllKey = macosStatePrefix + "dnsconfigctl-0/DNS"

	// macosOwnKeyPrefix names the State keys of dnsconfigctl's default
	// identity, which the base rows run under.
	macosOwnKeyPrefix = macosStatePrefix + "dnsconfigctl-"
)

// macosOrderSearch is each cycle's search list. It is neither sorted
// nor reverse-sorted, so the compiled list shows whether configd keeps
// configured order. The sentinel domain leads so a short name reaches the
// sentinel on its first expansion.
var macosOrderSearch = []string{
	sentinelSearchDomain, macosOverlapExact, "aa." + sentinelSearchDomain,
	"mm." + sentinelSearchDomain, "bb." + sentinelSearchDomain,
}

// macosOverlapExact is the requested suffix the overlap cycle also puts in
// the primary service's list in the same spelling.
const macosOverlapExact = "zz." + sentinelSearchDomain

// macosLongSearchCount long suffixes after macosOrderSearch overflow the
// backend's one-line limit for a search list (maxScutilLineBytes, 2047
// bytes), so Set must refuse macosOverLimitSearch.
const macosLongSearchCount = 9

// macosOverLimitError is the platform-limit error Set returns for a search
// list that does not fit one scutil line.
const macosOverLimitError = "macOS accepts at most 2047 bytes"

// macosLongSearch returns macosLongSearchCount suffixes of three 63-byte
// labels under the sentinel domain, in an order that is not sorted.
func macosLongSearch() []string {
	label := strings.Repeat("x", 63)
	out := make([]string, macosLongSearchCount)
	for i := range out {
		out[i] = fmt.Sprintf("%s.%s.%s.k%d.%s", label, label, label, (i*5)%macosLongSearchCount, sentinelSearchDomain)
	}
	return out
}

// macosOverLimitSearch is macosOrderSearch followed by macosLongSearch, a
// list one byte-limited State key cannot hold.
func macosOverLimitSearch() []string {
	return append(slices.Clone(macosOrderSearch), macosLongSearch()...)
}

// macosOwnKeyCount counts the State keys of dnsconfigctl's default identity
// in an answered scutil list output.
func macosOwnKeyCount(stdout []byte) int {
	n := 0
	for line := range strings.SplitSeq(string(stdout), "\n") {
		if strings.Contains(line, "] = "+macosOwnKeyPrefix) {
			n++
		}
	}
	return n
}

func macosSetArgs(row Row, search []string) []string {
	args := []string{
		"sudo", "/tmp/dnsconfigctl", "-backend", "darwin",
		"set", "--ns", macosSentinelAddr,
	}
	if row.Split {
		args = append(args, "--match", splitMatchArg(row))
	}
	args = append(args, "--search", strings.Join(search, ","), "--detach")
	return args
}

func macosSentinelLog(ctx context.Context, cfg runConfig) string {
	res := cfg.exec(ctx, 10*time.Second, "cat", "/tmp/sentinel.log")
	if !res.Successful() {
		return "(no sentinel log: " + res.String() + ")"
	}
	return string(res.Stdout)
}

func macosSnapshot(ctx context.Context, cfg runConfig) ([]byte, ExecResult) {
	script := strings.Join([]string{
		`echo "=== scutil --dns ==="`,
		`scutil --dns 2>&1 || true`,
		`echo "=== /etc/resolver ==="`,
		`ls -la /etc/resolver 2>/dev/null || echo "(absent)"`,
		`echo "=== dnsconfig State keys ==="`,
		`sudo scutil <<< 'list State:/Network/Service/dnsconfig-.*' 2>&1 || true`,
		`echo "=== resolv.conf ==="`,
		`cat /etc/resolv.conf 2>&1 || true`,
	}, "; ")
	res := cfg.exec(ctx, 30*time.Second, "sh", "-c", script)
	if !res.Successful() {
		return nil, res
	}
	return res.Stdout, res
}

func macosStateKeys(ctx context.Context, cfg runConfig) ExecResult {
	return cfg.exec(ctx, 15*time.Second, "sh", "-c",
		`sudo scutil <<< 'list State:/Network/Service/dnsconfig-.*'`)
}

func macosAssertKeysPresent(ctx context.Context, cfg runConfig, tag string) bool {
	res := macosStateKeys(ctx, cfg)
	if !res.Successful() || !strings.Contains(string(res.Stdout), macosStatePrefix) {
		cfg.Log("    %s: dnsconfig State key missing: %s", tag, res.String())
		return false
	}
	return true
}

// macosKeyListAnswered reports whether scutil's list output is one of the
// forms it prints for a completed request. scutil exits 0 and prints an
// error line when configd does not answer, which must not pass for a clean
// host; any other output is rejected too.
func macosKeyListAnswered(stdout []byte) bool {
	out := strings.TrimSpace(string(stdout))
	if out == "no keys." {
		return true
	}
	for line := range strings.SplitSeq(out, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "subKey [")
		var key string
		if ok {
			_, key, ok = strings.Cut(rest, "] = ")
		}
		if !ok || key == "" {
			return false
		}
	}
	return true
}

// macosKeyListed reports whether an answered scutil list output names key.
func macosKeyListed(stdout []byte, key string) bool {
	if !macosKeyListAnswered(stdout) {
		return false
	}
	for line := range strings.SplitSeq(string(stdout), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), "] = "+key) {
			return true
		}
	}
	return false
}

func macosAssertKeysAbsent(ctx context.Context, cfg runConfig, tag string) bool {
	res := macosStateKeys(ctx, cfg)
	if !res.Successful() {
		cfg.Log("    %s: State-key list failed: %s", tag, res.String())
		return false
	}
	out := strings.TrimSpace(string(res.Stdout))
	if strings.Contains(out, macosStatePrefix) {
		cfg.Log("    %s: State keys survived cleanup: %s", tag, out)
		return false
	}
	if !macosKeyListAnswered(res.Stdout) {
		cfg.Log("    %s: State-key list was not answered: %q", tag, out)
		return false
	}
	return true
}

func macosCompiledHasSearch(body []byte, domain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	for line := range strings.SplitSeq(string(body), "\n") {
		if !strings.Contains(line, "search domain[") {
			continue
		}
		_, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(value, ".")), domain) {
			return true
		}
	}
	return false
}

// macosUnscopedSearch returns the search list configd compiled for the first
// unscoped resolver without a domain, the list short names expand against.
func macosUnscopedSearch(body []byte) []string {
	var search []string
	inResolver, hasDomain, scoped := false, false, false
	for raw := range strings.SplitSeq(string(body), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "DNS configuration (for scoped"):
			if inResolver && !hasDomain {
				return search
			}
			inResolver, scoped = false, true
		case scoped:
		case strings.HasPrefix(line, "resolver #"):
			if inResolver && !hasDomain {
				return search
			}
			search, inResolver, hasDomain = nil, true, false
		case !inResolver:
		case strings.HasPrefix(line, "domain"):
			_, value, _ := strings.Cut(line, ":")
			hasDomain = strings.TrimSpace(value) != ""
		case strings.HasPrefix(line, "search domain["):
			_, value, _ := strings.Cut(line, ":")
			search = append(search, strings.TrimSuffix(strings.TrimSpace(value), "."))
		}
	}
	if inResolver && !hasDomain {
		return search
	}
	return nil
}

// withoutDomain drops domain from list, ignoring case and a trailing dot.
func withoutDomain(list []string, domain string) []string {
	domain = strings.TrimSuffix(domain, ".")
	var out []string
	for _, d := range list {
		if !strings.EqualFold(strings.TrimSuffix(d, "."), domain) {
			out = append(out, d)
		}
	}
	return out
}

// countDomain counts domain in list, ignoring case and a trailing dot.
func countDomain(list []string, domain string) int {
	return len(list) - len(withoutDomain(list, domain))
}

// macosPublished returns domains as Set publishes them: lowercase, without
// the trailing dot.
func macosPublished(domains []string) []string {
	out := make([]string, len(domains))
	for i, d := range domains {
		out[i] = strings.ToLower(strings.TrimSuffix(d, "."))
	}
	return out
}

// macosSearchUnderSet returns the compiled unscoped search list expected
// while the library publishes requested, given the list read before Set.
// configd compiles supplemental search domains ahead of the primary
// service's list, so requested comes first in configured order. A base entry
// with the same spelling is folded into the library's copy; one that differs
// only in case is not, and stays where the base list put it.
func macosSearchUnderSet(requested, base []string) []string {
	want := macosPublished(requested)
	published := slices.Clone(want)
	for _, d := range base {
		if !slices.Contains(published, d) {
			want = append(want, d)
		}
	}
	return want
}

// macosWaitSearch polls the compiled unscoped search list until ok accepts
// it or timeout passes, and returns the last list read.
func macosWaitSearch(ctx context.Context, cfg runConfig, timeout time.Duration, ok func([]string) bool) ([]string, bool) {
	deadline := time.Now().Add(timeout)
	for {
		compiled := cfg.exec(ctx, 15*time.Second, "scutil", "--dns")
		var search []string
		if compiled.Successful() && strings.HasPrefix(string(compiled.Stdout), "DNS configuration") {
			search = macosUnscopedSearch(compiled.Stdout)
			if ok(search) {
				return search, true
			}
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			if !compiled.Successful() {
				cfg.Log("    scutil --dns failed: %s", compiled.String())
			}
			return search, false
		}
		time.Sleep(resolutionBackoff)
	}
}

// macosCheckSearchContribution requires the compiled unscoped search list
// under Set to equal macosSearchUnderSet for requested and the pre-Set list
// base. While base lacks the sentinel domain, the primary service's DNS
// dictionary must not name it either, so the library's State key is its only
// source.
func macosCheckSearchContribution(ctx context.Context, cfg runConfig, requested, base []string, timeout time.Duration) string {
	if countDomain(base, sentinelSearchDomain) == 0 {
		script := `svc=$(printf 'show State:/Network/Global/IPv4\n' | scutil | awk '/PrimaryService/{print $3}'); ` +
			`if [ -z "$svc" ]; then echo "(no primary service)"; exit 0; fi; ` +
			`printf 'show State:/Network/Service/%s/DNS\n' "$svc" | scutil`
		primary := cfg.exec(ctx, 15*time.Second, "sh", "-c", script)
		if !primary.Successful() ||
			strings.Contains(strings.ToLower(string(primary.Stdout)), strings.TrimSuffix(sentinelSearchDomain, ".")) {
			cfg.Log("    primary service DNS names the library's search domain: %s", primary.String())
			return "primary-search"
		}
	}
	want := macosSearchUnderSet(requested, base)
	under, ok := macosWaitSearch(ctx, cfg, timeout, func(under []string) bool {
		return slices.Equal(under, want)
	})
	if !ok {
		cfg.Log("    compiled search list under set is not the expected one; before=%q want=%q under-set=%q", base, want, under)
		return "compiled-search"
	}
	return ""
}

// The overlap cycle puts the row's search domain between these in the
// primary service's list, so the compiled list shows where the primary
// service's spelling stays while the library's copy leads.
const (
	macosOverlapLead = "lead.dnsconfig-smoke.example"
	macosOverlapTail = "tail.dnsconfig-smoke.example"
)

// macosOverlap is the second cycle's change to the primary service: its own
// search list carries the row's search domain in a different case and
// macosOverlapExact in the library's spelling. The library publishes every
// search domain, including one the primary service already supplies; configd
// lists both spellings of the first and folds the second into the library's
// copy at the front, and this step asserts that layout live.
type macosOverlap struct {
	service  string
	original []string
	// base is the compiled unscoped search list once configd applied the
	// overlap, before Set.
	base []string
}

// macosPrimaryInterface returns PrimaryInterface from a scutil show of
// State:/Network/Global/IPv4.
func macosPrimaryInterface(out []byte) string {
	for line := range strings.SplitSeq(string(out), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "PrimaryInterface : "); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// macosServiceForDevice returns the service networksetup
// -listnetworkserviceorder lists for device. Each service is a "(n) Name"
// line followed by a "(Hardware Port: ..., Device: dev)" line.
func macosServiceForDevice(order []byte, device string) string {
	var name string
	for raw := range strings.SplitSeq(string(order), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "(Hardware Port:") {
			if device != "" && strings.HasSuffix(line, "Device: "+device+")") {
				return name
			}
			continue
		}
		name = ""
		if rest, ok := strings.CutPrefix(line, "("); ok {
			if _, svc, ok := strings.Cut(rest, ") "); ok {
				name = svc
			}
		}
	}
	return ""
}

// macosParseSearchDomains reads networksetup -getsearchdomains. networksetup
// can exit 0 on failure, so any line that is not a domain or the no-domains
// sentence fails the read.
func macosParseSearchDomains(out []byte) ([]string, bool) {
	var domains []string
	for raw := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
		case strings.HasPrefix(line, "There aren't any Search Domains set on "):
			if len(domains) > 0 {
				return nil, false
			}
			return nil, true
		case strings.ContainsAny(line, " \t*:"):
			return nil, false
		default:
			domains = append(domains, line)
		}
	}
	return domains, len(domains) > 0
}

// setSearchArgs builds a networksetup call that sets service's search list;
// "Empty" clears it.
func setSearchArgs(service string, domains []string) []string {
	if len(domains) == 0 {
		domains = []string{"Empty"}
	}
	return append([]string{"sudo", "networksetup", "-setsearchdomains", service}, domains...)
}

// macosOverlapSearch returns the primary service's search list for the
// overlap cycle and the mixed-case spelling of domain it carries. The list is
// macosOverlapLead, that spelling, macosOverlapTail, and exact in the
// library's spelling, then the rest of preSet, the compiled list before any
// overlap.
func macosOverlapSearch(preSet []string, domain, exact string) (string, []string) {
	domain = strings.TrimSuffix(domain, ".")
	exact = strings.TrimSuffix(exact, ".")
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		labels[i] = strings.ToUpper(label[:1]) + label[1:]
	}
	mixed := strings.Join(labels, ".")
	rest := preSet
	for _, d := range []string{domain, exact, macosOverlapLead, macosOverlapTail} {
		rest = withoutDomain(rest, d)
	}
	return mixed, append([]string{macosOverlapLead, mixed, macosOverlapTail, exact}, rest...)
}

// macosOverlapCaseKept reports whether the compiled list carries the
// primary service's spelling byte for byte, so the overlap under Set
// differs from the library's lowercase copy only in case.
func macosOverlapCaseKept(base []string, mixed string) bool {
	return slices.Contains(base, mixed)
}

// macosBeginOverlap records the primary service's search list, registers its
// restore, and applies macosOverlapSearch.
func macosBeginOverlap(ctx context.Context, cfg runConfig, ri *rowInstance, preSet []string) (*macosOverlap, string) {
	global := cfg.exec(ctx, 15*time.Second, "sh", "-c", `printf 'show State:/Network/Global/IPv4\n' | scutil`)
	device := macosPrimaryInterface(global.Stdout)
	order := cfg.exec(ctx, 15*time.Second, "networksetup", "-listnetworkserviceorder")
	service := macosServiceForDevice(order.Stdout, device)
	if !global.Successful() || !order.Successful() || service == "" {
		cfg.Log("    overlap: no network service for primary interface %q: %s\n%s", device, global.String(), order.String())
		return nil, "overlap-service"
	}
	got := cfg.exec(ctx, 15*time.Second, "networksetup", "-getsearchdomains", service)
	original, ok := macosParseSearchDomains(got.Stdout)
	if !got.Successful() || !ok {
		cfg.Log("    overlap: could not read %q search domains: %s", service, got.String())
		return nil, "overlap-read"
	}
	o := &macosOverlap{service: service, original: original}
	ri.addRecovery(func() { _ = o.restore(context.Background(), cfg) })

	// The primary service gets a mixed-case spelling while the library
	// publishes the lowercase canonical form; configd does not fold the two.
	mixed, want := macosOverlapSearch(preSet, sentinelSearchDomain, macosOverlapExact)
	if res := cfg.exec(ctx, 15*time.Second, setSearchArgs(service, want)...); !res.Successful() {
		cfg.Log("    overlap: networksetup -setsearchdomains failed: %s", res.String())
		return nil, "overlap-set"
	}
	base, ok := macosWaitSearch(ctx, cfg, 10*time.Second, func(list []string) bool {
		return countDomain(list, sentinelSearchDomain) == 1 && countDomain(list, macosOverlapExact) == 1 &&
			countDomain(list, macosOverlapLead) == 1 && countDomain(list, macosOverlapTail) == 1
	})
	if !ok {
		cfg.Log("    overlap: compiled search list never took the primary service's entry: %q", base)
		return nil, "overlap-apply"
	}
	if !macosOverlapCaseKept(base, mixed) {
		cfg.Log("    overlap: compiled search list does not keep the primary service's spelling %q: %q", mixed, base)
		return nil, "overlap-case"
	}
	cfg.Log("    overlap: %q searches %q; compiled base %q", service, want, base)
	o.base = base
	return o, ""
}

// restore puts back the primary service's recorded search list.
func (o *macosOverlap) restore(ctx context.Context, cfg runConfig) ExecResult {
	return cfg.exec(ctx, 15*time.Second, setSearchArgs(o.service, o.original)...)
}

// Lines M3 reads from the watch log, in the form -v's slog text handler
// prints them.
const (
	macosAttemptFinished = `msg="dnsconfig: attempt finished"`
	macosSignalOpened    = `msg="dnsconfig: change signal" opened=true`
	macosKeysRecreated   = "darwin: converge recreated dynamic-store keys"
	macosChildExited     = "scutil notification child exited"
)

const (
	// macosKillSettle is how long after the ready line M3 waits before it
	// may restart configd. Notifications for the first converge's own writes
	// arrive within it, so their debounce window shows in the log before
	// the idle check reads it.
	macosKillSettle = time.Second

	// macosRepairWait bounds the wait for repair after the restart. It
	// spans several periodic checks so a repair the change signal missed
	// still lands and its trigger is reported.
	macosRepairWait = 90 * time.Second

	// macosQuietMax bounds how long before the key removal the latest
	// attempt may have been seen to finish. The harness sees a finish up to
	// about 1.5s late (a 1s poll plus the log and pgrep execs) and removes the
	// key after the check, so the periodic check that attempt scheduled is
	// still about 13s away or more.
	macosQuietMax = 15 * time.Second
)

// macosPacingWait matches the worker's repeatChangeInterval: an attempt that
// changed the host after the goal converged defers signal-driven attempts
// that long. Tests shorten it.
var macosPacingWait = 10 * time.Second

var macosTriggerRE = regexp.MustCompile(`\btrigger=(\S+)`)

// macosWorkerIdle counts the finished attempts in a watch log and reports
// whether the latest worker scheduling line is a successful one, so neither a
// debounced change signal nor a failure retry is waiting to run. A failed
// attempt's retry comes due before signalDebounce, so it would become the
// first attempt after the restart and hide the signal's trigger.
func macosWorkerIdle(log []byte) (finished int, idle bool) {
	for line := range strings.SplitSeq(string(log), "\n") {
		switch {
		case strings.Contains(line, macosAttemptFinished):
			finished++
			idle = strings.Contains(line, " failed=false")
		case strings.Contains(line, macosSignalOpened):
			idle = false
		}
	}
	return finished, idle
}

// macosRepairAttempts returns the attempt-finished lines after the first skip,
// through the first one that follows a recreated-keys line logged after them.
// done reports that the recreating attempt has finished.
func macosRepairAttempts(log []byte, skip int) (attempts []string, done bool) {
	seen, recreated := 0, false
	for line := range strings.SplitSeq(string(log), "\n") {
		if strings.Contains(line, macosKeysRecreated) {
			recreated = recreated || seen >= skip
			continue
		}
		if !strings.Contains(line, macosAttemptFinished) {
			continue
		}
		seen++
		if seen <= skip {
			continue
		}
		attempts = append(attempts, strings.TrimSpace(line))
		if recreated {
			return attempts, true
		}
	}
	return attempts, false
}

// macosChildExit returns the first notification-child exit warning after the
// first skip attempt-finished lines, or "" when there is none.
func macosChildExit(log []byte, skip int) string {
	seen := 0
	for line := range strings.SplitSeq(string(log), "\n") {
		switch {
		case strings.Contains(line, macosAttemptFinished):
			seen++
		case seen >= skip && strings.Contains(line, macosChildExited):
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// macosSignalRepair reports whether a repair started from a change signal:
// the first attempt after the restart was signal-triggered, later ones up to
// the recreating one were failure retries or further signals, and the
// recreating one changed the host. A periodic trigger anywhere means the
// notification child did not report the restart.
func macosSignalRepair(attempts []string) bool {
	if len(attempts) == 0 {
		return false
	}
	for i, line := range attempts {
		m := macosTriggerRE.FindStringSubmatch(line)
		if m == nil || m[1] != "signal" && (i == 0 || m[1] != "retry") {
			return false
		}
	}
	return strings.Contains(attempts[len(attempts)-1], " changed=true")
}

// macosCheckDelivery proves that the notification child still hears key
// changes after the configd restart. scutil prints a reconnect line after any
// restart and the child forwards every line as a change signal, so a
// signal-driven restart repair shows only that the child survived. The step
// waits until the worker is idle, macosPacingWait has passed since the
// repair finished at repairAt, and the latest attempt finished within
// macosQuietMax, then removes the catch-all key and requires a repair that
// starts from a change signal, as after the restart. A live child repairs
// within signalDebounce of the removal; a deaf one leaves it to the periodic
// check. A stray signal within tens of milliseconds of the removal could
// start the repair instead, and that race is accepted as for the restart.
// Attempt ages count from when the harness saw them, so a log read that
// stalls near its 10s timeout shortens the margin; that is accepted too.
// killSkip and repairCount are the finished-attempt counts before the
// restart and through its repair.
func macosCheckDelivery(ctx context.Context, cfg runConfig, readLog func() []byte, killSkip, repairCount int, repairAt time.Time) string {
	childExited := func(log []byte) bool {
		if line := macosChildExit(log, killSkip); line != "" {
			cfg.Log("    watcher: notification child exited after the restart: %s", line)
			return true
		}
		return false
	}

	// lastAt is when the latest finished attempt was seen, zero while that
	// is unknown because it finished before the first read here.
	count, _ := macosWorkerIdle(readLog())
	var lastAt time.Time
	if count == repairCount {
		lastAt = repairAt
	}
	var skip int
	// The deadline spans two periodic intervals, so an attempt finishes
	// while the loop watches and sets lastAt.
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		log := readLog()
		if childExited(log) {
			return "watch-child-exited"
		}
		finished, idle := macosWorkerIdle(log)
		if finished != count {
			count, lastAt = finished, time.Now()
		}
		if idle && time.Since(repairAt) >= macosPacingWait && !lastAt.IsZero() && time.Since(lastAt) <= macosQuietMax {
			skip = finished
			break
		}
		if time.Now().After(deadline) {
			cfg.Log("    watcher: worker did not go idle before the key removal:\n%s", indent("        ", string(log)))
			return "watch-settle"
		}
	}

	res := cfg.exec(ctx, 15*time.Second, "sh", "-c", "sudo scutil <<< 'remove "+macosWatchCatchAllKey+"'")
	if !res.Successful() || strings.TrimSpace(string(res.Stdout)) != "" {
		cfg.Log("    watcher: removing %s failed: %s", macosWatchCatchAllKey, res.String())
		return "watch-remove"
	}
	removedAt := time.Now()

	var attempts []string
	for deadline := removedAt.Add(macosRepairWait); ; time.Sleep(time.Second) {
		log := readLog()
		if childExited(log) {
			return "watch-child-exited"
		}
		var done bool
		attempts, done = macosRepairAttempts(log, skip)
		if done && macosKeyListed(macosStateKeys(ctx, cfg).Stdout, macosWatchCatchAllKey) {
			break
		}
		if time.Now().After(deadline) {
			cfg.Log("    watcher: %s was not repaired after its removal:\n%s",
				macosWatchCatchAllKey, indent("        ", string(log)))
			return "watch-deaf"
		}
	}
	if !macosSignalRepair(attempts) {
		cfg.Log("    watcher: key removal after the restart was not repaired from a change signal; "+
			"the scutil notification child may have reconnected deaf. Attempts after the removal:\n%s",
			indent("        ", strings.Join(attempts, "\n")))
		return "watch-deaf"
	}
	cfg.Log("    watcher: signal-driven repair seen %s after the key removal: %s",
		time.Since(removedAt).Round(time.Second), attempts[len(attempts)-1])
	return ""
}

// watcherCheckMacos proves that a configd restart drops the State key and
// that the scutil notification child's change signal, not the periodic check,
// drives the long-lived Manager's repair. The backend's recreated-keys line
// shows the keys were created again rather than surviving the restart, and
// the worker's attempt-finished lines, which -v sends to the log through
// stderr, carry the trigger of each attempt.
//
// Every finished attempt schedules the next periodic check
// periodicCheckInterval (30s) later, and a change signal runs an attempt
// signalDebounce (2s) after it opens. The restart therefore waits until the
// log shows the latest attempt finished with no debounce window open, so no
// attempt is due when the keys vanish and the next periodic check is still
// about 28s away. A live notification child repairs within signalDebounce of
// configd answering again; a deaf one leaves the repair to the periodic check.
// An echo of the watch's own writes that lands within tens of milliseconds of
// the restart could still start the repair; that race is accepted because a
// deaf child stays deaf and fails a later run. The backend restarts a child
// that exited, and the replacement's echo of the recreating write would pass
// for a signal-driven repair, so an exit warning after the restart fails the
// check. macosCheckDelivery then proves the surviving child still hears key
// changes.
// afterRepair, when set, runs once the keys are back and its non-empty result
// fails the check.
func watcherCheckMacos(ctx context.Context, cfg runConfig, afterRepair func() string) string {
	// The hold must outlast the sum of the stage waits below, or the watch
	// closes and clears its keys mid-check.
	spawn := "sudo nohup /tmp/dnsconfigctl -v -backend darwin watch" +
		" --ns " + macosSentinelAddr +
		" --search " + sentinelSearchDomain +
		" --timeout 600s > " + macosWatchLog + " 2>&1 < /dev/null &"
	res := cfg.exec(ctx, 30*time.Second, "sh", "-c", spawn)
	if !res.Successful() {
		cfg.Log("    watcher: spawn failed: %s", res.String())
		return "watch-spawn"
	}
	stop := func() {
		_ = cfg.exec(context.Background(), 15*time.Second, "sudo", "pkill", "-TERM", "-f", "dnsconfigctl.*watch.*127.0.0.99")
	}
	defer stop()
	readLog := func() []byte {
		return cfg.exec(ctx, 10*time.Second, "cat", macosWatchLog).Stdout
	}
	configdPid := func() string { return macosConfigdPid(ctx, cfg) }

	readyScript := `for i in $(seq 1 30); do grep -q 'WATCH: ready applied=true' ` + macosWatchLog + ` && exit 0; sleep 1; done; cat ` + macosWatchLog + `; exit 1`
	res = cfg.exec(ctx, 45*time.Second, "sh", "-c", readyScript)
	readyAt := time.Now()
	if !res.Successful() || !macosAssertKeysPresent(ctx, cfg, "watcher-ready") {
		cfg.Log("    watcher: apply did not become ready: %s", res.String())
		return "watch-ready"
	}

	pidBefore := configdPid()
	if pidBefore == "" {
		cfg.Log("    watcher: could not read configd pid")
		return "watch-pid"
	}

	time.Sleep(time.Until(readyAt.Add(macosKillSettle)))
	var skip int
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		var idle bool
		if skip, idle = macosWorkerIdle(readLog()); idle {
			break
		}
		if time.Now().After(deadline) {
			cfg.Log("    watcher: worker did not go idle before the restart:\n%s", indent("        ", string(readLog())))
			return "watch-settle"
		}
	}
	res = cfg.exec(ctx, 15*time.Second, "sudo", "killall", "configd")
	if !res.Successful() {
		cfg.Log("    watcher: configd restart failed: %s", res.String())
		return "watch-restart"
	}
	restartAt := time.Now()

	var attempts []string
	var repairAt time.Time
	for deadline := restartAt.Add(macosRepairWait); ; time.Sleep(time.Second) {
		log := readLog()
		if line := macosChildExit(log, skip); line != "" {
			cfg.Log("    watcher: notification child exited after the restart: %s", line)
			return "watch-child-exited"
		}
		var done bool
		attempts, done = macosRepairAttempts(log, skip)
		repairAt = time.Now()
		pidAfter := configdPid()
		if done && pidAfter != "" && pidAfter != pidBefore {
			break
		}
		if time.Now().After(deadline) {
			cfg.Log("    watcher: key was not re-healed after configd restart; before=%s after=%s\n%s",
				pidBefore, pidAfter, indent("        ", string(readLog())))
			return "watch-repair"
		}
	}
	if !macosSignalRepair(attempts) {
		cfg.Log("    watcher: configd restart was not repaired from a change signal; "+
			"the scutil notification child may have stopped reporting. Attempts after the restart:\n%s",
			indent("        ", strings.Join(attempts, "\n")))
		return "watch-signal"
	}
	cfg.Log("    watcher: signal-driven repair seen %s after the restart: %s",
		time.Since(restartAt).Round(time.Second), attempts[len(attempts)-1])
	if !macosAssertKeysPresent(ctx, cfg, "watcher-repair") {
		return "watch-repair"
	}
	if afterRepair != nil {
		if stage := afterRepair(); stage != "" {
			return stage
		}
	}
	if stage := macosCheckDelivery(ctx, cfg, readLog, skip, skip+len(attempts), repairAt); stage != "" {
		return stage
	}
	stop()
	// State keys disappear before Close finishes cache flushing and teardown.
	closeScript := `for i in $(seq 1 15); do grep -q '^WATCH: closed teardown-ok$' ` + macosWatchLog + ` && exit 0; sleep 1; done; cat ` + macosWatchLog + `; exit 1`
	res = cfg.exec(ctx, 20*time.Second, "sh", "-c", closeScript)
	if !res.Successful() {
		cfg.Log("    watcher: teardown did not complete successfully: %s", res.String())
		return "watch-close"
	}
	if !macosAssertKeysAbsent(ctx, cfg, "watcher-close") {
		return "watch-close"
	}
	cfg.Log("    watcher re-healed State key after configd restart")
	return ""
}

// macosOwnedSnapshotScript prints every State key of dnsconfigctl's
// default identity with its dictionary, then every resolver file whose
// header names that identity with its contents.
const macosOwnedSnapshotScript = `keys=$(printf 'list ` + macosOwnKeyPrefix + `.*\n' | sudo scutil); ` +
	`echo "$keys"; ` +
	`for k in $(echo "$keys" | awk '/subKey/{print $4}'); do echo "== $k"; printf 'show %s\n' "$k" | sudo scutil; done; ` +
	`for f in /etc/resolver/* /etc/resolver/.*; do ` +
	`[ -f "$f" ] && head -1 "$f" | grep -q 'identity=dnsconfigctl$' && { echo "== $f"; cat "$f"; }; done; true`

// macosOwnedSnapshot returns macosOwnedSnapshotScript's output, and whether
// it shows at least one key, each listed key as a dictionary.
func macosOwnedSnapshot(ctx context.Context, cfg runConfig) (string, ExecResult, bool) {
	res := cfg.exec(ctx, 30*time.Second, "sh", "-c", macosOwnedSnapshotScript)
	out := string(res.Stdout)
	keys := macosOwnKeyCount(res.Stdout)
	ok := res.Successful() && keys > 0 &&
		strings.Count(out, "== "+macosOwnKeyPrefix) == keys && strings.Count(out, "<dictionary> {") == keys
	return out, res, ok
}

// macosCheckOverLimit requires a Set whose search list does not fit one
// State key to exit 1 with the platform-limit error and leave this
// identity's State keys, their dictionaries, its resolver files, and the
// compiled search list exactly as they were.
func macosCheckOverLimit(ctx context.Context, cfg runConfig, row Row) string {
	before, beforeRes, ok := macosOwnedSnapshot(ctx, cfg)
	if !ok {
		cfg.Log("    over-limit: owned artifacts unreadable before the Set: %s", beforeRes.String())
		return "over-limit-snapshot"
	}
	compiled := cfg.exec(ctx, 15*time.Second, "scutil", "--dns")
	if !compiled.Successful() || !strings.HasPrefix(string(compiled.Stdout), "DNS configuration") {
		cfg.Log("    over-limit: scutil --dns failed before the Set: %s", compiled.String())
		return "over-limit-snapshot"
	}
	searchBefore := macosUnscopedSearch(compiled.Stdout)

	res := cfg.exec(ctx, 60*time.Second, macosSetArgs(row, macosOverLimitSearch())...)
	if res.ExitCode != 1 || !strings.Contains(string(res.Stderr), macosOverLimitError) {
		cfg.Log("    over-limit search list was not refused with exit 1 and %q: %s", macosOverLimitError, res.String())
		return "over-limit-refusal"
	}

	after, afterRes, ok := macosOwnedSnapshot(ctx, cfg)
	if !ok || after != before {
		cfg.Log("    over-limit Set changed owned artifacts:\n--- before ---\n%s\n--- after ---\n%s",
			indent("        ", before), indent("        ", afterRes.String()))
		return "over-limit-artifacts"
	}
	compiled = cfg.exec(ctx, 15*time.Second, "scutil", "--dns")
	if searchAfter := macosUnscopedSearch(compiled.Stdout); !compiled.Successful() || !slices.Equal(searchAfter, searchBefore) {
		cfg.Log("    over-limit Set changed the compiled search list; before=%q after=%q", searchBefore, searchAfter)
		return "over-limit-search"
	}
	cfg.Log("    over-limit search list refused; owned keys, resolver files, and compiled search list unchanged")
	return ""
}

// macosConfigdPid returns configd's pid, or "" when pgrep finds none.
func macosConfigdPid(ctx context.Context, cfg runConfig) string {
	out := strings.TrimSpace(string(cfg.exec(ctx, 10*time.Second, "pgrep", "-x", "configd").Stdout))
	first, _, _ := strings.Cut(out, "\n")
	return first
}

// executeRowMacos runs the macOS smoke flow.
func executeRowMacos(ctx context.Context, cfg runConfig, row Row) rowOutcome {
	if row.Pair {
		return executeRowMacosPair(ctx, cfg, row)
	}
	cfg.Log("=== macos row %s (%s) ===", row.ID, row.Name)
	ri := &rowInstance{cfg: cfg}

	res := pushBinary(cfg, "/tmp/dnsconfigctl")
	if !res.Successful() {
		cfg.Log("    binary push failed: %s", res.String())
		return ri.failOrKeep("push")
	}
	res = cfg.exec(ctx, 30*time.Second, "chmod", "0755", "/tmp/dnsconfigctl")
	if !res.Successful() {
		cfg.Log("    chmod failed: %s", res.String())
		return ri.failOrKeep("chmod")
	}

	res = cfg.exec(ctx, 30*time.Second, "/tmp/dnsconfigctl", "detect")
	if !res.Successful() || strings.TrimSpace(string(res.Stdout)) != "darwin" {
		cfg.Log("    detect failed or mismatched: %s", res.String())
		return ri.failOrKeep("detect")
	}

	preBytes, snapRes := macosSnapshot(ctx, cfg)
	if !snapRes.Successful() {
		cfg.Log("    pre-snapshot failed: %s", snapRes.String())
		return ri.failOrKeep("pre-snapshot")
	}
	res = cfg.exec(ctx, 60*time.Second, "sudo", "/tmp/dnsconfigctl", "-backend", "darwin", "reset")
	if !res.Successful() || !assertResetRefused(cfg, res) {
		cfg.Log("    preset-reset failed: %s", res.String())
		return ri.failOrKeep("preset-reset")
	}
	baseCompiled := cfg.exec(ctx, 15*time.Second, "scutil", "--dns")
	if !baseCompiled.Successful() {
		cfg.Log("    pre-set scutil --dns failed: %s", baseCompiled.String())
		return ri.failOrKeep("preset-search")
	}
	baseSearch := macosUnscopedSearch(baseCompiled.Stdout)

	res = cfg.exec(ctx, 15*time.Second, "sudo", "ifconfig", "lo0", "alias", macosSentinelAddr, "up")
	if !res.Successful() {
		cfg.Log("    lo0-alias failed: %s", res.String())
		return ri.failOrKeep("lo0-alias")
	}
	ri.addRecovery(func() {
		_ = cfg.exec(context.Background(), 15*time.Second, "sudo", "ifconfig", "lo0", "-alias", macosSentinelAddr)
	})

	res = cfg.exec(ctx, 30*time.Second, "sh", "-c",
		"sudo nohup /tmp/dnsconfigctl serve --addr "+macosSentinelAddr+":53 "+
			"--record "+sentinelName+"="+sentinelAddr+" "+
			"--record "+macosAltSentinelName+"="+macosAltSentinelAddr+" > /tmp/sentinel.log 2>&1 < /dev/null &")
	if !res.Successful() {
		cfg.Log("    sentinel-spawn failed: %s", res.String())
		return ri.failOrKeep("sentinel-spawn")
	}
	ri.addRecovery(func() {
		_ = cfg.exec(context.Background(), 15*time.Second, "sudo", "pkill", "-f", "dnsconfigctl serve")
	})
	res = cfg.exec(ctx, 15*time.Second, "/tmp/dnsconfigctl", "probe-dns",
		"--addr", macosSentinelAddr+":53", "--name", sentinelName, "--timeout", "10s")
	if !res.Successful() {
		cfg.Log("    sentinel probe failed: %s\n%s", res.String(), macosSentinelLog(ctx, cfg))
		return ri.failOrKeep("sentinel-probe")
	}

	queryName := strings.TrimSuffix(sentinelName, ".")
	_ = cfg.exec(ctx, 15*time.Second, "dscacheutil", "-q", "host", "-a", "name", queryName)

	res = cfg.exec(ctx, 60*time.Second, macosSetArgs(row, macosOrderSearch)...)
	if !res.Successful() {
		cfg.Log("    set failed: %s", res.String())
		return ri.failOrKeep("set")
	}
	ri.addRecovery(func() {
		_ = cfg.exec(context.Background(), 60*time.Second, "sudo", "/tmp/dnsconfigctl", "-backend", "darwin", "reset")
	})
	if !macosAssertKeysPresent(ctx, cfg, "post-set") {
		return ri.failOrKeep("state-key")
	}
	if !row.Split {
		rc := cfg.exec(ctx, 15*time.Second, "awk", `/^nameserver/{print $2; exit}`, "/etc/resolv.conf")
		if !rc.Successful() || strings.TrimSpace(string(rc.Stdout)) != macosSentinelAddr {
			cfg.Log("    resolv.conf did not mirror catch-all State key: %s", rc.String())
			return ri.failOrKeep("resolvconf-mirror")
		}
	}

	// An idle Manager in a separate process must leave this apply intact; the
	// key check here and the resolution checks below prove it.
	res = cfg.exec(ctx, 30*time.Second,
		append([]string{"sudo", "/tmp/dnsconfigctl", "-backend", "darwin"}, idleWatchArgs(macosSentinelAddr)...)...)
	if !idleWatchOK(res) || !macosAssertKeysPresent(ctx, cfg, "post-idle") {
		cfg.Log("    idle Manager under set failed: %s", res.String())
		return ri.failOrKeep("idle-under-set")
	}
	if tag := macosCheckSearchContribution(ctx, cfg, macosOrderSearch, baseSearch, 10*time.Second); tag != "" {
		return ri.failOrKeep(tag)
	}
	if tag := macosCheckOverLimit(ctx, cfg, row); tag != "" {
		return ri.failOrKeep(tag)
	}

	resolve := func(name string) bool {
		result, ok := retryResolution(func() ExecResult {
			return cfg.exec(ctx, 10*time.Second, "dscacheutil", "-q", "host", "-a", "name", name)
		}, func(r ExecResult) bool {
			return r.Successful() && strings.Contains(string(r.Stdout), sentinelAddr)
		})
		if !ok {
			cfg.Log("    resolution failed for %s: %s\n%s", name, result.String(), macosSentinelLog(ctx, cfg))
		}
		return ok
	}
	if !resolve(queryName) {
		return ri.failOrKeep("resolution")
	}
	short := strings.SplitN(queryName, ".", 2)[0]
	lookupResult, lookupOK := retryResolution(func() ExecResult {
		return cfg.exec(ctx, 10*time.Second, "/tmp/dnsconfigctl", "lookup", "--timeout", "8s", short)
	}, func(r ExecResult) bool {
		return r.Successful() && strings.Contains(string(r.Stdout), sentinelAddr)
	})
	if !lookupOK {
		cfg.Log("    split/catch-all search-domain check failed: %s", lookupResult.String())
		return ri.failOrKeep("short-name-search")
	}

	if row.Split {
		ctrl := cfg.exec(ctx, 15*time.Second, "dscacheutil", "-q", "host", "-a", "name", "apple.com")
		if !ctrl.Successful() || !strings.Contains(string(ctrl.Stdout), "ip_address") || strings.Contains(string(ctrl.Stdout), sentinelAddr) {
			return ri.failOrKeep("split-control")
		}

		// Reverse-zone routing. The match domain installs a second
		// /etc/resolver file named for the in-addr.arpa zone, and a reverse
		// lookup of sentinelAddr must come back with sentinelName - only the
		// sentinel serves that PTR. Whether mDNSResponder honors a resolver
		// file for PTR queries is not documented; this row is the measurement.
		if row.ReverseSplit {
			ptrResult, ptrOK := retryResolution(func() ExecResult {
				return cfg.exec(ctx, 10*time.Second,
					"dscacheutil", "-q", "host", "-a", "ip_address", sentinelAddr)
			}, func(r ExecResult) bool {
				return r.Successful() &&
					strings.Contains(string(r.Stdout), strings.TrimSuffix(sentinelName, "."))
			})
			if !ptrOK {
				cfg.Log("    reverse-zone check failed after %d attempts: %s",
					resolutionMaxAttempts, ptrResult.String())
				cfg.Log("    sentinel log:\n%s", indent("        ", macosSentinelLog(ctx, cfg)))
				return ri.failOrKeep("reverse-zone")
			}
			cfg.Log("    reverse-zone OK: %s -> %s", sentinelAddr,
				strings.TrimSpace(string(ptrResult.Stdout)))
		}
	}

	res = cfg.exec(ctx, 60*time.Second, macosSetArgs(row, []string{altSearchDomain})...)
	if !res.Successful() || !resolve(queryName) {
		cfg.Log("    set-over-set failed: %s", res.String())
		return ri.failOrKeep("set-over-set")
	}
	altLookup, altLookupOK := retryResolution(func() ExecResult {
		return cfg.exec(ctx, 10*time.Second, "/tmp/dnsconfigctl", "lookup", "--timeout", "8s", short)
	}, func(r ExecResult) bool {
		return r.Successful() && strings.Contains(string(r.Stdout), macosAltSentinelAddr) &&
			!strings.Contains(string(r.Stdout), sentinelAddr)
	})
	if !altLookupOK {
		cfg.Log("    set-over-set search replacement failed: %s", altLookup.String())
		return ri.failOrKeep("set-over-set-search")
	}
	compiled := cfg.exec(ctx, 15*time.Second, "scutil", "--dns")
	stale := slices.ContainsFunc(macosOrderSearch, func(d string) bool { return macosCompiledHasSearch(compiled.Stdout, d) })
	if !compiled.Successful() || !macosCompiledHasSearch(compiled.Stdout, altSearchDomain) || stale {
		cfg.Log("    set-over-set compiled search list is stale: %s", compiled.String())
		return ri.failOrKeep("set-over-set-compiled-search")
	}

	_ = cfg.exec(ctx, 15*time.Second, "sudo", "pkill", "-f", "dnsconfigctl serve")

	// cleanup is "reset" or "recover"; both must remove what the detached
	// set left.
	resetAndVerify := func(tag, cleanup string) string {
		r := cfg.exec(ctx, 60*time.Second, "sudo", "/tmp/dnsconfigctl", "-backend", "darwin", cleanup)
		var removed bool
		if cleanup == "recover" {
			removed = assertRecover(cfg, r, true)
		} else {
			removed = r.Successful() && assertResetPerformedRevert(cfg, r)
		}
		if !removed {
			return cleanup
		}
		if !macosAssertKeysAbsent(ctx, cfg, tag) {
			return "state-key-cleanup"
		}

		staleResult, staleGone := retryResolution(func() ExecResult {
			return cfg.exec(ctx, 10*time.Second, "dscacheutil", "-q", "host", "-a", "name", queryName)
		}, func(r ExecResult) bool {
			return !strings.Contains(string(r.Stdout), sentinelAddr)
		})
		if !staleGone {
			cfg.Log("    stale overlay survived %s: %s", cleanup, staleResult.String())
			return "stale-cache"
		}

		for attempt := 1; attempt <= resolutionMaxAttempts; attempt++ {
			post, snap := macosSnapshot(ctx, cfg)
			if !snap.Successful() {
				return "post-snapshot"
			}
			if semanticResetOK(post, macosSentinelAddr) {
				return ""
			}
			if attempt < resolutionMaxAttempts {
				_ = cfg.exec(ctx, 15*time.Second, "sh", "-c", "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder")
				time.Sleep(resolutionBackoff)
			}
		}
		cfg.Log("    %s did not settle; pre-state was:\n%s", cleanup, indent("        ", string(preBytes)))
		return "semantic-reset"
	}

	// Catch-all rows clean up the first cycle through Recover, as a consumer
	// starting after a crash would, and a second Recover must find nothing.
	firstCleanup := "reset"
	if !row.Split {
		firstCleanup = "recover"
	}
	if stage := resetAndVerify("post", firstCleanup); stage != "" {
		return ri.failOrKeep(stage)
	}
	if !row.Split {
		r := cfg.exec(ctx, 60*time.Second, "sudo", "/tmp/dnsconfigctl", "-backend", "darwin", "recover")
		if !assertRecover(cfg, r, false) {
			return ri.failOrKeep("recover-again")
		}
		cfg.Log("    recover removed the detached set's configuration; a second recover found nothing")
	}
	if after, ok := macosWaitSearch(ctx, cfg, 10*time.Second, func(list []string) bool {
		return slices.Equal(list, baseSearch)
	}); !ok {
		cfg.Log("    %s did not restore the pre-Set search list; before=%q after=%q", firstCleanup, baseSearch, after)
		return ri.failOrKeep("post-reset-search")
	}

	// The second cycle runs with the row's search domain already in the
	// primary service's list; see macosOverlap.
	overlap, stage := macosBeginOverlap(ctx, cfg, ri, baseSearch)
	if stage != "" {
		return ri.failOrKeep(stage)
	}
	res = cfg.exec(ctx, 60*time.Second, macosSetArgs(row, macosOrderSearch)...)
	if !res.Successful() {
		cfg.Log("    cycle2-set failed: %s", res.String())
		return ri.failOrKeep("cycle2-set")
	}
	if tag := macosCheckSearchContribution(ctx, cfg, macosOrderSearch, overlap.base, 10*time.Second); tag != "" {
		return ri.failOrKeep("overlap-" + tag)
	}
	if stage := resetAndVerify("post2", "reset"); stage != "" {
		return ri.failOrKeep("cycle2-" + stage)
	}
	if after, ok := macosWaitSearch(ctx, cfg, 10*time.Second, func(list []string) bool {
		return slices.Equal(list, overlap.base)
	}); !ok {
		cfg.Log("    overlap: reset changed the primary service's search list; before=%q after=%q", overlap.base, after)
		return ri.failOrKeep("overlap-reset")
	}

	// M3 carries the restart watcher proof on Sonoma, where killall restarts
	// configd promptly; on macOS 15 it takes effect about 16s late.
	// The overlap stays in place, so the repaired keys must compile into the
	// same layout. configd drops the primary service's DNS until the network
	// agents republish it, hence the longer wait.
	if row.ID == "M3" {
		if stage := watcherCheckMacos(ctx, cfg, func() string {
			if tag := macosCheckSearchContribution(ctx, cfg, []string{sentinelSearchDomain}, overlap.base, 60*time.Second); tag != "" {
				return "watch-overlap-" + tag
			}
			return ""
		}); stage != "" {
			return ri.failOrKeep(stage)
		}
	}
	if res := overlap.restore(ctx, cfg); !res.Successful() {
		cfg.Log("    overlap: restoring %q search domains failed: %s", overlap.service, res.String())
		return ri.failOrKeep("overlap-restore")
	}

	res = cfg.exec(ctx, 15*time.Second, "sudo", "ifconfig", "lo0", "-alias", macosSentinelAddr)
	if !res.Successful() {
		cfg.Log("    lo0 alias cleanup failed: %s", res.String())
		return ri.failOrKeep("lo0-alias-cleanup")
	}

	// A configd restart drops the primary service's DNS until the network
	// configuration agents republish it, and the live Manager's repair and
	// Close can finish within seconds of the restart, so M3 waits for the
	// base resolver to return.
	finalWait := time.Duration(0)
	if row.ID == "M3" {
		finalWait = 60 * time.Second
	}
	start := time.Now()
	for {
		res = cfg.exec(ctx, 30*time.Second, "dscacheutil", "-q", "host", "-a", "name", "apple.com")
		if (res.Successful() && strings.Contains(string(res.Stdout), "ip_address")) || time.Since(start) >= finalWait {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if finalWait > 0 {
		cfg.Log("    final resolution waited %s for the base resolver", time.Since(start).Round(time.Second))
	}
	if !res.Successful() || !strings.Contains(string(res.Stdout), "ip_address") {
		cfg.Log("    final-resolution failed: %s", res.String())
		_, snapshot := macosSnapshot(ctx, cfg)
		cfg.Log("    final resolver state: %s", snapshot.String())
		if row.ID == "M3" {
			watchLog := cfg.exec(ctx, 10*time.Second, "cat", macosWatchLog)
			cfg.Log("    watcher log: %s", watchLog.String())
		}
		return ri.failOrKeep("final-resolution")
	}
	return outcomePassed
}
