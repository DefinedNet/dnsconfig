package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	pairMacosSentinelAddr = "127.0.0.98"
	pairMacosSentinelLog  = "/tmp/sentinel-b.log"
	pairMacosWatchLog     = "/tmp/watch-pair.log"

	// pairMacosMeasure prefixes the log-only lines that record where the two
	// identities' search suffixes compile relative to each other.
	pairMacosMeasure = "MEASURE: pair search order"

	// pairSharedDomain is searched by both identities and routed by B, the
	// shape of one organization's catch-all and split networks on one host.
	// Both sentinels answer pairSharedName, each with its own address, so
	// the answer names the resolver that won.
	pairSharedDomain = "shared.dnsconfig-smoke.example."
	pairSharedName   = "pairprobe." + pairSharedDomain
	pairSharedAddrA  = "192.0.2.45"
	pairSharedAddrB  = "192.0.2.46"
)

// pairMacosSearchOrder reports which identity's search suffix configd
// compiled first, and whether the two lead the list with the rest equal to
// base minus exact-spelling duplicates of them. Their relative order is a
// measurement; only the head shape is asserted.
func pairMacosSearchOrder(under, base []string) (order string, ok bool) {
	pub := macosPublished([]string{pairSearchA, pairSearchB})
	a, b := slices.Index(under, pub[0]), slices.Index(under, pub[1])
	switch {
	case a < 0 || b < 0:
		order = "missing"
	case a < b:
		order = pairIdentityA + "-first"
	default:
		order = pairIdentityB + "-first"
	}
	if len(under) < 2 || !slices.Contains(under[:2], pub[0]) || !slices.Contains(under[:2], pub[1]) {
		return order, false
	}
	var rest []string
	for _, d := range base {
		if !slices.Contains(pub, d) {
			rest = append(rest, d)
		}
	}
	return order, slices.Equal(under[2:], rest)
}

// pairMacosWatchArgs is a shell command that runs a long-lived Manager under
// identity with the configuration its detached Set applied.
func pairMacosWatchArgs(identity, ns, match, search, logPath string) string {
	return "sudo nohup /tmp/dnsconfigctl -v -backend darwin -identity " + identity + " watch" +
		" --ns " + ns + " --match " + match + " --search " + search +
		" --timeout 300s > " + logPath + " 2>&1 < /dev/null &"
}

// pairMacosArgs builds a sudo dnsconfigctl invocation under identity.
func pairMacosArgs(identity string, rest ...string) []string {
	return append([]string{"sudo", "/tmp/dnsconfigctl", "-backend", "darwin", "-identity", identity}, rest...)
}

// pairMacosKeysFor reports whether the dynamic store holds a key for
// identity, by the parsed shape the backend writes.
func pairMacosKeysFor(res ExecResult, identity string) bool {
	return strings.Contains(string(res.Stdout), "State:/Network/Service/dnsconfig-"+identity+"-")
}

// executeRowMacosPair runs the two-instance flow on macOS.
func executeRowMacosPair(ctx context.Context, cfg runConfig, row Row) rowOutcome {
	cfg.Log("=== macos row %s (%s) ===", row.ID, row.Name)
	ri := &rowInstance{cfg: cfg}

	exec := func(timeout time.Duration, argv ...string) ExecResult {
		return cfg.exec(ctx, timeout, argv...)
	}
	sh := func(timeout time.Duration, script string) ExecResult { return exec(timeout, "sh", "-c", script) }

	if res := pushBinary(cfg, "/tmp/dnsconfigctl"); !res.Successful() {
		cfg.Log("    binary push failed: %s", res.String())
		return ri.failOrKeep("push")
	}
	if res := exec(30*time.Second, "chmod", "0755", "/tmp/dnsconfigctl"); !res.Successful() {
		cfg.Log("    chmod failed: %s", res.String())
		return ri.failOrKeep("chmod")
	}
	if res := exec(30*time.Second, "/tmp/dnsconfigctl", "detect"); !res.Successful() || strings.TrimSpace(string(res.Stdout)) != "darwin" {
		cfg.Log("    detect failed or mismatched: %s", res.String())
		return ri.failOrKeep("detect")
	}
	preBytes, snapRes := macosSnapshot(ctx, cfg)
	if !snapRes.Successful() {
		cfg.Log("    pre-snapshot failed: %s", snapRes.String())
		return ri.failOrKeep("pre-snapshot")
	}
	if res := exec(60*time.Second, pairMacosArgs(pairIdentityA, "reset")...); !res.Successful() || !assertResetRefused(cfg, res) {
		cfg.Log("    preset-reset failed: %s", res.String())
		return ri.failOrKeep("preset-reset")
	}
	baseCompiled := exec(15*time.Second, "scutil", "--dns")
	if !baseCompiled.Successful() {
		cfg.Log("    pre-set scutil --dns failed: %s", baseCompiled.String())
		return ri.failOrKeep("preset-search")
	}
	baseSearch := macosUnscopedSearch(baseCompiled.Stdout)

	// Two loopback aliases, one sentinel each.
	for _, addr := range []string{macosSentinelAddr, pairMacosSentinelAddr} {
		if res := exec(15*time.Second, "sudo", "ifconfig", "lo0", "alias", addr, "up"); !res.Successful() {
			cfg.Log("    lo0-alias failed: %s", res.String())
			return ri.failOrKeep("lo0-alias")
		}
		ri.addRecovery(func() {
			_ = cfg.exec(context.Background(), 15*time.Second, "sudo", "ifconfig", "lo0", "-alias", addr)
		})
	}
	spawn := func(addr, record, logPath string) bool {
		res := sh(30*time.Second, "sudo nohup /tmp/dnsconfigctl serve --addr "+addr+":53 --record "+record+" > "+logPath+" 2>&1 < /dev/null &")
		if !res.Successful() {
			cfg.Log("    sentinel-spawn failed: %s", res.String())
			return false
		}
		return true
	}
	if !spawn(macosSentinelAddr, sentinelName+"="+sentinelAddr+" --record "+pairSharedName+"="+pairSharedAddrA, "/tmp/sentinel.log") ||
		!spawn(pairMacosSentinelAddr, pairSentinelName+"="+pairSentinelAddr+" --record "+pairSharedName+"="+pairSharedAddrB, pairMacosSentinelLog) {
		return ri.failOrKeep("sentinel-spawn")
	}
	ri.addRecovery(func() {
		_ = cfg.exec(context.Background(), 15*time.Second, "sudo", "pkill", "-f", "dnsconfigctl serve")
	})
	for _, probe := range [][2]string{{macosSentinelAddr, sentinelName}, {pairMacosSentinelAddr, pairSentinelName}} {
		if res := exec(15*time.Second, "/tmp/dnsconfigctl", "probe-dns", "--addr", probe[0]+":53", "--name", probe[1], "--timeout", "10s"); !res.Successful() {
			cfg.Log("    sentinel probe failed: %s", res.String())
			return ri.failOrKeep("sentinel-probe")
		}
	}

	setA := pairMacosArgs(pairIdentityA, "set", "--ns", macosSentinelAddr, "--match", sentinelName, "--search", pairSearchA, "--detach")
	setB := pairMacosArgs(pairIdentityB, "set", "--ns", pairMacosSentinelAddr, "--match", pairSentinelName, "--search", pairSearchB, "--detach")
	for _, identity := range []string{pairIdentityA, pairIdentityB} {
		ri.addRecovery(func() {
			_ = cfg.exec(context.Background(), 60*time.Second, pairMacosArgs(identity, "reset")...)
		})
	}
	if res := exec(60*time.Second, setA...); !res.Successful() {
		cfg.Log("    set A failed: %s", res.String())
		return ri.failOrKeep("set-a")
	}
	if res := exec(60*time.Second, setB...); !res.Successful() {
		cfg.Log("    set B failed: %s", res.String())
		return ri.failOrKeep("set-b")
	}

	resolvesTo := func(name, addr string) bool {
		result, ok := retryResolution(func() ExecResult {
			return exec(10*time.Second, "dscacheutil", "-q", "host", "-a", "name", strings.TrimSuffix(name, "."))
		}, func(r ExecResult) bool { return r.Successful() && strings.Contains(string(r.Stdout), addr) })
		if !ok {
			cfg.Log("    %s did not resolve to %s: %s", name, addr, result.String())
		}
		return ok
	}
	gone := func(name, addr string) bool {
		result, ok := retryResolution(func() ExecResult {
			return exec(10*time.Second, "dscacheutil", "-q", "host", "-a", "name", strings.TrimSuffix(name, "."))
		}, func(r ExecResult) bool { return !strings.Contains(string(r.Stdout), addr) })
		if !ok {
			cfg.Log("    %s still resolves to %s: %s", name, addr, result.String())
		}
		return ok
	}
	keysAre := func(tag string, wantA, wantB bool) bool {
		res := macosStateKeys(ctx, cfg)
		if !res.Successful() || !macosKeyListAnswered(res.Stdout) ||
			pairMacosKeysFor(res, pairIdentityA) != wantA || pairMacosKeysFor(res, pairIdentityB) != wantB {
			cfg.Log("    %s: State keys want a=%v b=%v: %s", tag, wantA, wantB, res.String())
			return false
		}
		return true
	}
	filesAre := func(tag string, wantA, wantB bool) bool {
		res := sh(15*time.Second, "for f in /etc/resolver/"+strings.TrimSuffix(sentinelName, ".")+" /etc/resolver/"+strings.TrimSuffix(pairSentinelName, ".")+"; do "+
			"if [ -f \"$f\" ]; then echo \"$f: $(head -1 \"$f\")\"; else echo \"$f: absent\"; fi; done")
		out := string(res.Stdout)
		haveA := strings.Contains(out, strings.TrimSuffix(sentinelName, ".")+": # Managed by github.com/DefinedNet/dnsconfig identity="+pairIdentityA)
		haveB := strings.Contains(out, strings.TrimSuffix(pairSentinelName, ".")+": # Managed by github.com/DefinedNet/dnsconfig identity="+pairIdentityB)
		if !res.Successful() || haveA != wantA || haveB != wantB {
			cfg.Log("    %s: resolver files want a=%v b=%v: %s", tag, wantA, wantB, res.String())
			return false
		}
		return true
	}

	if !resolvesTo(sentinelName, sentinelAddr) || !resolvesTo(pairSentinelName, pairSentinelAddr) {
		return ri.failOrKeep("pair-resolution")
	}
	if !keysAre("both applied", true, true) || !filesAre("both applied", true, true) {
		return ri.failOrKeep("pair-artifacts")
	}
	cfg.Log("    both identities applied and resolving")
	if stage := pairMacosMeasureRestart(ctx, cfg, ri, baseSearch, [][]string{setA, setB}); stage != "" {
		return ri.failOrKeep(stage)
	}

	// Identity B claiming A's domain is refused whole, before mutation.
	conflict := pairMacosArgs(pairIdentityB, "set", "--ns", pairMacosSentinelAddr, "--match", sentinelName+","+pairSentinelName, "--search", pairSearchB, "--detach")
	if res := exec(60*time.Second, conflict...); !assertConflictRefused(cfg, res, pairIdentityA) {
		return ri.failOrKeep("conflict-refusal")
	}
	if !resolvesTo(sentinelName, sentinelAddr) || !resolvesTo(pairSentinelName, pairSentinelAddr) || !keysAre("after conflict", true, true) || !filesAre("after conflict", true, true) {
		return ri.failOrKeep("conflict-untouched")
	}
	cfg.Log("    conflicting Set refused naming %s; both configurations untouched", pairIdentityA)

	// A live Manager under identity A refuses a second Set under the same
	// identity. It is then killed without Close, standing in for a crash.
	watch := "sudo nohup /tmp/dnsconfigctl -backend darwin -identity " + pairIdentityA + " watch" +
		" --ns " + macosSentinelAddr + " --match " + sentinelName + " --search " + pairSearchA +
		" --timeout 300s > " + pairMacosWatchLog + " 2>&1 < /dev/null &"
	if res := sh(30*time.Second, watch); !res.Successful() {
		cfg.Log("    watcher spawn failed: %s", res.String())
		return ri.failOrKeep("pair-watch-spawn")
	}
	killWatch := func() {
		_ = sh(15*time.Second, "sudo pkill -KILL -f 'dnsconfigctl.*-identity "+pairIdentityA+" watch' || true")
	}
	ri.addRecovery(killWatch)
	ready := `for i in $(seq 1 30); do grep -q 'WATCH: ready applied=true' ` + pairMacosWatchLog + ` && exit 0; sleep 1; done; cat ` + pairMacosWatchLog + `; exit 1`
	if res := sh(45*time.Second, ready); !res.Successful() {
		cfg.Log("    watcher did not become ready: %s", res.String())
		return ri.failOrKeep("pair-watch-ready")
	}
	if res := exec(60*time.Second, setA...); !assertAlreadyRunningRefused(cfg, res) {
		return ri.failOrKeep("same-identity-refusal")
	}
	cfg.Log("    same-identity Set refused while the watcher holds %s", pairIdentityA)
	killWatch()
	if res := sh(30*time.Second, `for i in $(seq 1 20); do pgrep -f 'dnsconfigctl.*-identity `+pairIdentityA+` watch' > /dev/null || exit 0; sleep 1; done; exit 1`); !res.Successful() {
		cfg.Log("    watcher did not die: %s", res.String())
		return ri.failOrKeep("pair-watch-kill")
	}
	if !resolvesTo(sentinelName, sentinelAddr) || !keysAre("after crash", true, true) {
		return ri.failOrKeep("crash-artifacts")
	}

	// Recovery under A clears only A; B keeps resolving.
	if res := exec(60*time.Second, pairMacosArgs(pairIdentityA, "reset")...); !res.Successful() || !assertResetPerformedRevert(cfg, res) {
		cfg.Log("    recovery reset A failed: %s", res.String())
		return ri.failOrKeep("recovery-reset-a")
	}
	if !gone(sentinelName, sentinelAddr) || !resolvesTo(pairSentinelName, pairSentinelAddr) {
		return ri.failOrKeep("recovery-isolation")
	}
	if !keysAre("after A reset", false, true) || !filesAre("after A reset", false, true) {
		return ri.failOrKeep("recovery-artifacts")
	}
	cfg.Log("    recovery reset under %s left %s intact", pairIdentityA, pairIdentityB)

	if res := exec(60*time.Second, pairMacosArgs(pairIdentityB, "reset")...); !res.Successful() || !assertResetPerformedRevert(cfg, res) {
		cfg.Log("    reset B failed: %s", res.String())
		return ri.failOrKeep("reset-b")
	}
	if !gone(pairSentinelName, pairSentinelAddr) || !macosAssertKeysAbsent(ctx, cfg, "after B reset") || !filesAre("after B reset", false, false) {
		return ri.failOrKeep("reset-b-cleanup")
	}
	if stage := pairMacosSharedSuffix(ctx, cfg); stage != "" {
		return ri.failOrKeep(stage)
	}
	_ = sh(15*time.Second, "sudo pkill -f 'dnsconfigctl serve' || true")
	for attempt := 1; attempt <= resolutionMaxAttempts; attempt++ {
		post, snap := macosSnapshot(ctx, cfg)
		if !snap.Successful() {
			return ri.failOrKeep("post-snapshot")
		}
		if semanticResetOK(post, macosSentinelAddr) && semanticResetOK(post, pairMacosSentinelAddr) {
			break
		}
		if attempt == resolutionMaxAttempts {
			cfg.Log("    reset did not settle; pre-state was:\n%s", indent("        ", string(preBytes)))
			return ri.failOrKeep("semantic-reset")
		}
		_ = sh(15*time.Second, "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder")
		time.Sleep(resolutionBackoff)
	}
	for _, addr := range []string{macosSentinelAddr, pairMacosSentinelAddr} {
		if res := exec(15*time.Second, "sudo", "ifconfig", "lo0", "-alias", addr); !res.Successful() {
			cfg.Log("    lo0 alias cleanup failed: %s", res.String())
			return ri.failOrKeep("lo0-alias-cleanup")
		}
	}
	// A configd restart drops the primary service's DNS until the network
	// agents republish it.
	var res ExecResult
	for start := time.Now(); ; time.Sleep(2 * time.Second) {
		res = exec(30*time.Second, "dscacheutil", "-q", "host", "-a", "name", "apple.com")
		if res.Successful() && strings.Contains(string(res.Stdout), "ip_address") || time.Since(start) >= 60*time.Second {
			break
		}
	}
	if !res.Successful() || !strings.Contains(string(res.Stdout), "ip_address") {
		cfg.Log("    final-resolution failed: %s", res.String())
		return ri.failOrKeep("final-resolution")
	}
	return outcomePassed
}

// pairMacosMeasureRestart logs the compiled order of the two identities'
// search suffixes, restarts configd under a live Manager for each identity,
// waits for both identities' keys to compile again, and logs the order
// again. Both suffixes must lead the primary service's list each time; their
// relative order is only logged. A restart that root cannot perform is
// logged as unmeasured. The Managers are then killed without Close and the
// detached Sets in reapply run again, so the rest of the row starts from both
// identities applied whatever the kill left; the key lists around the kill
// are logged.
func pairMacosMeasureRestart(ctx context.Context, cfg runConfig, ri *rowInstance, base []string, reapply [][]string) string {
	read := func(timeout time.Duration) ([]string, string, bool) {
		var order string
		under, ok := macosWaitSearch(ctx, cfg, timeout, func(list []string) bool {
			var ok bool
			order, ok = pairMacosSearchOrder(list, base)
			return ok
		})
		order, _ = pairMacosSearchOrder(under, base)
		return under, order, ok
	}
	before, orderBefore, ok := read(10 * time.Second)
	cfg.Log("%s: %s list=%q", pairMacosMeasure, orderBefore, before)
	if !ok {
		cfg.Log("    both search suffixes do not lead the primary service's list %q", base)
		return "pair-search-order"
	}

	type watcher struct{ identity, ns, match, search, log string }
	watchers := []watcher{
		{pairIdentityA, macosSentinelAddr, sentinelName, pairSearchA, "/tmp/watch-pair-restart-a.log"},
		{pairIdentityB, pairMacosSentinelAddr, pairSentinelName, pairSearchB, "/tmp/watch-pair-restart-b.log"},
	}
	kill := func() {
		for _, w := range watchers {
			_ = cfg.exec(context.Background(), 15*time.Second, "sh", "-c",
				"sudo pkill -KILL -f 'dnsconfigctl.*-identity "+w.identity+" watch' || true")
		}
	}
	ri.addRecovery(kill)
	for _, w := range watchers {
		if res := cfg.exec(ctx, 30*time.Second, "sh", "-c", pairMacosWatchArgs(w.identity, w.ns, w.match, w.search, w.log)); !res.Successful() {
			cfg.Log("    restart watcher %s spawn failed: %s", w.identity, res.String())
			kill()
			return "pair-restart-watch"
		}
	}
	for _, w := range watchers {
		ready := `for i in $(seq 1 30); do grep -q 'WATCH: ready applied=true' ` + w.log + ` && exit 0; sleep 1; done; cat ` + w.log + `; exit 1`
		if res := cfg.exec(ctx, 45*time.Second, "sh", "-c", ready); !res.Successful() {
			cfg.Log("    restart watcher %s did not become ready: %s", w.identity, res.String())
			kill()
			return "pair-restart-watch"
		}
	}

	stage := func() string {
		pidBefore := macosConfigdPid(ctx, cfg)
		res := cfg.exec(ctx, 15*time.Second, "sudo", "killall", "configd")
		if !res.Successful() {
			cfg.Log("%s after configd restart: not measured; killall configd failed: %s", pairMacosMeasure, res.String())
			return ""
		}
		// A restart shows as a new configd pid or as the identities' keys
		// leaving the store. On macOS 15 the store has emptied about 16s
		// after killall, so the wait spans well beyond that.
		pidAfter, vanished := pidBefore, false
		for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
			pidAfter = macosConfigdPid(ctx, cfg)
			keys := macosStateKeys(ctx, cfg)
			if keys.Successful() && macosKeyListAnswered(keys.Stdout) &&
				(!pairMacosKeysFor(keys, pairIdentityA) || !pairMacosKeysFor(keys, pairIdentityB)) {
				vanished = true
			}
			if vanished || pidAfter != "" && pidAfter != pidBefore {
				break
			}
		}
		restart := fmt.Sprintf("configd pid before=%q after=%q keys-vanished=%v", pidBefore, pidAfter, vanished)
		if !vanished && (pidAfter == "" || pidAfter == pidBefore) {
			cfg.Log("%s after configd restart: not measured; %s", pairMacosMeasure, restart)
			return ""
		}
		// The Managers repair on the restart's change signal or, failing
		// that, on the periodic check.
		after, orderAfter, ok := read(90 * time.Second)
		cfg.Log("%s after configd restart: %s changed=%v list=%q (%s)",
			pairMacosMeasure, orderAfter, orderAfter != orderBefore, after, restart)
		if !ok {
			for _, w := range watchers {
				cfg.Log("    restart watcher %s log:\n%s", w.identity,
					indent("        ", string(cfg.exec(ctx, 10*time.Second, "cat", w.log).Stdout)))
			}
			cfg.Log("    both search suffixes did not lead the primary service's list %q after the restart", base)
			return "pair-restart-search-order"
		}
		return ""
	}()
	keysBefore := macosStateKeys(ctx, cfg)
	kill()
	if stage != "" {
		return stage
	}
	if res := cfg.exec(ctx, 30*time.Second, "sh", "-c",
		`for i in $(seq 1 20); do pgrep -f 'dnsconfigctl.*-identity (`+pairIdentityA+`|`+pairIdentityB+`) watch' > /dev/null || exit 0; sleep 1; done; exit 1`); !res.Successful() {
		cfg.Log("    restart watchers did not die: %s", res.String())
		return "pair-restart-kill"
	}
	keysAfter := macosStateKeys(ctx, cfg)
	if !pairMacosKeysFor(keysAfter, pairIdentityA) || !pairMacosKeysFor(keysAfter, pairIdentityB) {
		cfg.Log("    restart watchers killed: keys before kill:\n%s\n    keys after kill:\n%s",
			indent("        ", string(keysBefore.Stdout)), indent("        ", string(keysAfter.Stdout)))
		for _, w := range watchers {
			cfg.Log("    restart watcher %s log:\n%s", w.identity,
				indent("        ", string(cfg.exec(ctx, 10*time.Second, "cat", w.log).Stdout)))
		}
	}
	for _, argv := range reapply {
		if res := cfg.exec(ctx, 60*time.Second, argv...); !res.Successful() {
			cfg.Log("    reapply after the restart measurement failed: %s", res.String())
			return "pair-restart-reapply"
		}
	}
	return ""
}

// pairMacosSharedSuffix checks that B's resolver file lets B and A share a
// search suffix. A, a catch-all, searches pairSharedDomain. B searching it
// under a parent match domain, with no file for it, is refused naming A. B
// then routes it and later also searches it; neither Set may be refused, B's
// file must answer both the full name and the short name the shared suffix
// expands, and the suffix appears once in the compiled search list. Both
// identities start and end cleared.
func pairMacosSharedSuffix(ctx context.Context, cfg runConfig) string {
	exec := func(timeout time.Duration, argv ...string) ExecResult {
		return cfg.exec(ctx, timeout, argv...)
	}
	shared := strings.TrimSuffix(pairSharedDomain, ".")
	short := strings.SplitN(pairSharedName, ".", 2)[0]
	answeredByB := func(r ExecResult) bool {
		out := string(r.Stdout)
		return r.Successful() && strings.Contains(out, pairSharedAddrB) && !strings.Contains(out, pairSharedAddrA)
	}
	resolvesToB := func(tag string) bool {
		full, ok := retryResolution(func() ExecResult {
			return exec(10*time.Second, "dscacheutil", "-q", "host", "-a", "name", strings.TrimSuffix(pairSharedName, "."))
		}, answeredByB)
		if !ok {
			cfg.Log("    %s: %s was not answered by %s's resolver file (want %s only): %s",
				tag, pairSharedName, pairIdentityB, pairSharedAddrB, full.String())
			return false
		}
		expanded, ok := retryResolution(func() ExecResult {
			return exec(10*time.Second, "/tmp/dnsconfigctl", "lookup", "--timeout", "8s", short)
		}, answeredByB)
		if !ok {
			cfg.Log("    %s: short name %s did not expand through %s to %s only: %s",
				tag, short, shared, pairSharedAddrB, expanded.String())
			return false
		}
		return true
	}
	set := func(tag string, argv ...string) bool {
		if res := exec(60*time.Second, argv...); !res.Successful() {
			cfg.Log("    %s was refused: %s", tag, res.String())
			return false
		}
		return true
	}

	if !set(pairIdentityA+" searching "+shared,
		pairMacosArgs(pairIdentityA, "set", "--ns", macosSentinelAddr, "--search", pairSharedDomain, "--detach")...) {
		return "shared-set-a"
	}
	// Searching the suffix under a parent match domain gives net-b a key for
	// it with no file of its own, so neither key holder covers the domain.
	uncovered := pairMacosArgs(pairIdentityB, "set", "--ns", pairMacosSentinelAddr,
		"--match", sentinelSearchDomain, "--search", pairSharedDomain, "--detach")
	if res := exec(60*time.Second, uncovered...); !assertConflictRefused(cfg, res, pairIdentityA) {
		return "shared-uncovered-refusal"
	}
	cfg.Log("    %s searching %s without its file was refused naming %s", pairIdentityB, shared, pairIdentityA)
	if !set(pairIdentityB+" routing "+shared,
		pairMacosArgs(pairIdentityB, "set", "--ns", pairMacosSentinelAddr, "--match", pairSharedDomain, "--detach")...) {
		return "shared-set-b-route"
	}
	if !resolvesToB("file beside a search key") {
		return "shared-file-wins"
	}
	cfg.Log("    %s routes %s beside %s's search key; the file answers", pairIdentityB, shared, pairIdentityA)

	if !set(pairIdentityB+" routing and searching "+shared,
		pairMacosArgs(pairIdentityB, "set", "--ns", pairMacosSentinelAddr, "--match", pairSharedDomain, "--search", pairSharedDomain, "--detach")...) {
		return "shared-set-b-search"
	}
	if !resolvesToB("file beside two search keys") {
		return "shared-two-keys-file-wins"
	}
	under, ok := macosWaitSearch(ctx, cfg, 10*time.Second, func(list []string) bool { return countDomain(list, shared) == 1 })
	if !ok {
		cfg.Log("    shared suffix %s is not listed exactly once: %q", shared, under)
		return "shared-search-folded"
	}
	cfg.Log("    %s also searches %s beside %s; compiled search list %q", pairIdentityB, shared, pairIdentityA, under)

	for _, identity := range []string{pairIdentityA, pairIdentityB} {
		if res := exec(60*time.Second, pairMacosArgs(identity, "reset")...); !res.Successful() || !assertResetPerformedRevert(cfg, res) {
			cfg.Log("    shared reset %s failed: %s", identity, res.String())
			return "shared-reset"
		}
	}
	if !macosAssertKeysAbsent(ctx, cfg, "after shared resets") {
		return "shared-reset-cleanup"
	}
	if res := exec(15*time.Second, "test", "!", "-e", "/etc/resolver/"+shared); !res.Successful() {
		cfg.Log("    /etc/resolver/%s survived reset", shared)
		return "shared-reset-cleanup"
	}
	return ""
}
