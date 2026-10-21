package main

import (
	"context"
	"strings"
	"time"
)

const (
	// The workflow creates both owned adapters before the row runs; identity
	// A takes the preferred one the single-identity rows also use.
	pairWindowsInterfaceB = "dnsconfig-smoke-b"

	// Windows answers on every 127/8 address without aliasing, so the second
	// sentinel binds its own loopback address on the same port.
	pairWindowsSentinelAddr = "127.0.0.2"

	pairWindowsWatchOut = `C:\Windows\Temp\watch-pair.out`
	pairWindowsWatchErr = `C:\Windows\Temp\watch-pair.err`
)

// pairWindowsArgs builds a dnsconfigctl.exe invocation under identity on iface.
func pairWindowsArgs(identity, iface string, rest ...string) []string {
	return append([]string{windowsBinaryExec, "-backend", "windows", "-identity", identity, "-interface", iface}, rest...)
}

// executeRowWindowsPair runs the two-instance flow on Windows.
func executeRowWindowsPair(ctx context.Context, cfg runConfig, row Row) rowOutcome {
	cfg.Log("=== windows row %s (%s) ===", row.ID, row.Name)
	ri := &rowInstance{cfg: cfg}

	exec := func(timeout time.Duration, argv ...string) ExecResult {
		return cfg.exec(ctx, timeout, argv...)
	}
	ps := func(timeout time.Duration, script string) ExecResult { return exec(timeout, psCommand(script)...) }

	if res := pushBinary(cfg, windowsBinaryPush); !res.Successful() {
		cfg.Log("    binary push failed: %s", res.String())
		return ri.failOrKeep("push")
	}
	if res := exec(60*time.Second, windowsBinaryExec, "detect"); !res.Successful() || strings.TrimSpace(string(res.Stdout)) != "windows" {
		cfg.Log("    detect failed or mismatched: %s", res.String())
		return ri.failOrKeep("detect")
	}
	preBytes := windowsSnapshot(ctx, cfg)
	if res := exec(90*time.Second, pairWindowsArgs(pairIdentityA, windowsInterfaceName, "reset")...); !res.Successful() || !assertResetRefused(cfg, res) {
		cfg.Log("    preset-reset failed: %s", res.String())
		return ri.failOrKeep("preset-reset")
	}

	// Two foreground sentinels held open by this goroutine, as the
	// single-identity rows do for their one sentinel.
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	for _, s := range [][2]string{{windowsSentinelAddr, sentinelName + "=" + sentinelAddr}, {pairWindowsSentinelAddr, pairSentinelName + "=" + pairSentinelAddr}} {
		go func() {
			_ = cfg.Driver.Exec(serveCtx, windowsBinaryExec, "serve", "--addr", s[0]+":53", "--record", s[1])
		}()
	}
	killSentinels := func() {
		_ = exec(30*time.Second, "taskkill", "/F", "/IM", "dnsconfigctl.exe")
		serveCancel()
	}
	ri.addRecovery(killSentinels)
	for _, probe := range [][2]string{{windowsSentinelAddr, sentinelName}, {pairWindowsSentinelAddr, pairSentinelName}} {
		if res := exec(20*time.Second, windowsBinaryExec, "probe-dns", "--addr", probe[0]+":53", "--name", probe[1], "--timeout", "15s"); !res.Successful() {
			cfg.Log("    sentinel probe failed: %s", res.String())
			return ri.failOrKeep("sentinel-probe")
		}
	}

	setA := pairWindowsArgs(pairIdentityA, windowsInterfaceName, "set", "--ns", windowsSentinelAddr, "--match", sentinelName, "--search", pairSearchA, "--detach")
	setB := pairWindowsArgs(pairIdentityB, pairWindowsInterfaceB, "set", "--ns", pairWindowsSentinelAddr, "--match", pairSentinelName, "--search", pairSearchB, "--detach")
	for _, id := range [][2]string{{pairIdentityA, windowsInterfaceName}, {pairIdentityB, pairWindowsInterfaceB}} {
		ri.addRecovery(func() {
			_ = cfg.exec(context.Background(), 90*time.Second, pairWindowsArgs(id[0], id[1], "reset")...)
		})
	}
	if res := exec(90*time.Second, setA...); !res.Successful() {
		cfg.Log("    set A failed: %s", res.String())
		return ri.failOrKeep("set-a")
	}
	if res := exec(90*time.Second, setB...); !res.Successful() {
		cfg.Log("    set B failed: %s", res.String())
		return ri.failOrKeep("set-b")
	}

	resolveScript := func(name string) string {
		return "Clear-DnsClientCache; Resolve-DnsName -Name " + strings.TrimSuffix(name, ".") +
			" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List"
	}
	resolvesTo := func(name, addr string) bool {
		result, ok := retryResolution(func() ExecResult { return ps(30*time.Second, resolveScript(name)) },
			func(r ExecResult) bool { return r.Successful() && strings.Contains(string(r.Stdout), addr) })
		if !ok {
			cfg.Log("    %s did not resolve to %s: %s", name, addr, result.String())
		}
		return ok
	}
	gone := func(name, addr string) bool {
		result, ok := retryResolution(func() ExecResult { return ps(30*time.Second, resolveScript(name)) },
			func(r ExecResult) bool { return !strings.Contains(string(r.Stdout), addr) })
		if !ok {
			cfg.Log("    %s still resolves to %s: %s", name, addr, result.String())
		}
		return ok
	}
	keysAre := func(tag string, wantA, wantB bool) bool {
		post := windowsSnapshot(ctx, cfg)
		if windowsHasRuleKey(post, windowsOurRulePrefix+pairIdentityA+"-") != wantA ||
			windowsHasRuleKey(post, windowsOurRulePrefix+pairIdentityB+"-") != wantB {
			cfg.Log("    %s: NRPT rules want a=%v b=%v:\n%s", tag, wantA, wantB, indent("        ", string(post)))
			return false
		}
		return true
	}
	adapterSuffix := func(iface string) string {
		script := "$guid = ([guid](Get-NetAdapter -Name " + psQuote(iface) + ").InterfaceGuid).ToString('B'); " +
			`$v = (Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $guid) -Name SearchList -ErrorAction SilentlyContinue).SearchList; ` +
			"if ($null -eq $v) { Write-Output '<absent>' } else { Write-Output $v }"
		return strings.TrimSpace(string(ps(30*time.Second, script).Stdout))
	}
	suffixesAre := func(tag, wantA, wantB string) bool {
		gotA, gotB := adapterSuffix(windowsInterfaceName), adapterSuffix(pairWindowsInterfaceB)
		if gotA != wantA || gotB != wantB {
			cfg.Log("    %s: adapter suffixes want a=%q b=%q, got a=%q b=%q", tag, wantA, wantB, gotA, gotB)
			return false
		}
		return true
	}
	suffixA, suffixB := strings.TrimSuffix(pairSearchA, "."), strings.TrimSuffix(pairSearchB, ".")

	if !resolvesTo(sentinelName, sentinelAddr) || !resolvesTo(pairSentinelName, pairSentinelAddr) {
		return ri.failOrKeep("pair-resolution")
	}
	if !keysAre("both applied", true, true) || !suffixesAre("both applied", suffixA, suffixB) {
		return ri.failOrKeep("pair-artifacts")
	}
	cfg.Log("    both identities applied and resolving")

	conflict := pairWindowsArgs(pairIdentityB, pairWindowsInterfaceB, "set", "--ns", pairWindowsSentinelAddr, "--match", sentinelName+","+pairSentinelName, "--search", pairSearchB, "--detach")
	if res := exec(90*time.Second, conflict...); !assertConflictRefused(cfg, res, pairIdentityA) {
		return ri.failOrKeep("conflict-refusal")
	}
	if !resolvesTo(sentinelName, sentinelAddr) || !resolvesTo(pairSentinelName, pairSentinelAddr) || !keysAre("after conflict", true, true) || !suffixesAre("after conflict", suffixA, suffixB) {
		return ri.failOrKeep("conflict-untouched")
	}
	cfg.Log("    conflicting Set refused naming %s; both configurations untouched", pairIdentityA)

	// A live Manager under identity A, killed below without Close to stand
	// in for a crash.
	watchArgs := []string{"-backend", "windows", "-identity", pairIdentityA, "-interface", windowsInterfaceName, "watch",
		"--ns", windowsSentinelAddr, "--match", sentinelName, "--search", pairSearchA, "--timeout", "300s"}
	pid, res := spawnWindowsWatch(ps, watchArgs, pairWindowsWatchOut, pairWindowsWatchErr)
	if !res.Successful() || pid == "" {
		cfg.Log("    watcher spawn failed: %s", res.String())
		return ri.failOrKeep("pair-watch-spawn")
	}
	killWatch := func() {
		_ = ps(15*time.Second, "Stop-Process -Id "+pid+" -Force -ErrorAction SilentlyContinue")
	}
	ri.addRecovery(killWatch)
	ready := "for ($i = 0; $i -lt 30; $i++) { if ((Get-Content " + psQuote(pairWindowsWatchOut) + " -ErrorAction SilentlyContinue) -match 'WATCH: ready applied=true') { exit 0 }; Start-Sleep -Seconds 1 }; " +
		"Get-Content " + psQuote(pairWindowsWatchOut) + "," + psQuote(pairWindowsWatchErr) + " -ErrorAction SilentlyContinue; exit 1"
	if res := ps(45*time.Second, ready); !res.Successful() {
		cfg.Log("    watcher did not become ready: %s", res.String())
		return ri.failOrKeep("pair-watch-ready")
	}
	if res := exec(90*time.Second, setA...); !assertAlreadyRunningRefused(cfg, res) {
		return ri.failOrKeep("same-identity-refusal")
	}
	cfg.Log("    same-identity Set refused while the watcher holds %s", pairIdentityA)
	killWatch()
	if res := ps(30*time.Second, "for ($i = 0; $i -lt 20; $i++) { if (-not (Get-Process -Id "+pid+" -ErrorAction SilentlyContinue)) { exit 0 }; Start-Sleep -Seconds 1 }; exit 1"); !res.Successful() {
		cfg.Log("    watcher did not die: %s", res.String())
		return ri.failOrKeep("pair-watch-kill")
	}
	if !resolvesTo(sentinelName, sentinelAddr) || !keysAre("after crash", true, true) {
		return ri.failOrKeep("crash-artifacts")
	}

	if res := exec(90*time.Second, pairWindowsArgs(pairIdentityA, windowsInterfaceName, "reset")...); !res.Successful() || !assertResetPerformedRevert(cfg, res) {
		cfg.Log("    recovery reset A failed: %s", res.String())
		return ri.failOrKeep("recovery-reset-a")
	}
	if !gone(sentinelName, sentinelAddr) || !resolvesTo(pairSentinelName, pairSentinelAddr) {
		return ri.failOrKeep("recovery-isolation")
	}
	if !keysAre("after A reset", false, true) || !suffixesAre("after A reset", "<absent>", suffixB) {
		return ri.failOrKeep("recovery-artifacts")
	}
	cfg.Log("    recovery reset under %s left %s intact", pairIdentityA, pairIdentityB)

	if res := exec(90*time.Second, pairWindowsArgs(pairIdentityB, pairWindowsInterfaceB, "reset")...); !res.Successful() || !assertResetPerformedRevert(cfg, res) {
		cfg.Log("    reset B failed: %s", res.String())
		return ri.failOrKeep("reset-b")
	}
	if !gone(pairSentinelName, pairSentinelAddr) || !suffixesAre("after B reset", "<absent>", "<absent>") {
		return ri.failOrKeep("reset-b-cleanup")
	}
	post := windowsSnapshot(ctx, cfg)
	if !windowsResetOK(post) {
		cfg.Log("    a dnsconfig- NRPT rule survived both resets")
		cfg.Log("    pre:\n%s", indent("        ", string(preBytes)))
		cfg.Log("    post:\n%s", indent("        ", string(post)))
		return ri.failOrKeep("reset-check")
	}
	killSentinels()
	ctrl := ps(30*time.Second, "Resolve-DnsName -Name "+windowsControlName+" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List")
	if !ctrl.Successful() || !strings.Contains(string(ctrl.Stdout), "IPAddress") {
		cfg.Log("    final-resolution failed: %s", ctrl.String())
		return ri.failOrKeep("final-resolution")
	}
	return outcomePassed
}
