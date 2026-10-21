package main

import (
	"context"
	"regexp"
	"strings"
	"time"
)

const (
	repairWindowsWatchOut = `C:\Windows\Temp\watch-repair.out`
	repairWindowsWatchErr = `C:\Windows\Temp\watch-repair.err`

	// repairWindowsWait bounds the wait for the repair. It covers the
	// worker's 30s periodic check twice, so a missed registry notification
	// still repairs inside the bound; the logged latency tells the two apart.
	repairWindowsWait = 90 * time.Second

	// repairWindowsRulePrefix names the rules the default dnsconfigctl
	// identity owns.
	repairWindowsRulePrefix = windowsOurRulePrefix + "dnsconfigctl-"

	// repairAdapterKeyPS is the IPv4 adapter parameters parent key in
	// PowerShell provider syntax; the adapter GUID follows it.
	repairAdapterKeyPS = `HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`
)

// watchChangedRE captures the changed= field of a watch status line.
var watchChangedRE = regexp.MustCompile(`(?m)^WATCH: status .*\bchanged=(\S+)`)

// lastWatchChanged returns the changed= value of the last watch status line
// in out, or false when no status line has been printed yet.
func lastWatchChanged(out []byte) (string, bool) {
	all := watchChangedRE.FindAllSubmatch(out, -1)
	if len(all) == 0 {
		return "", false
	}
	return string(all[len(all)-1][1]), true
}

// windowsCtrlBreakScript delivers CTRL_BREAK_EVENT to the console pid is
// attached to, which Go reports to the process as os.Interrupt. The helper
// detaches from its own console first so the event reaches only the target
// console; the helper shares that console and dies with the event, so its exit
// status is meaningless. CTRL_C_EVENT is not used because a process created
// in a new process group ignores it.
func windowsCtrlBreakScript(pid string) string {
	return "Add-Type -Namespace DnsconfigSmoke -Name Console -MemberDefinition '" +
		`[DllImport("kernel32.dll")] public static extern bool FreeConsole(); ` +
		`[DllImport("kernel32.dll")] public static extern bool AttachConsole(uint pid); ` +
		`[DllImport("kernel32.dll")] public static extern bool GenerateConsoleCtrlEvent(uint ev, uint group);` +
		"'; [void][DnsconfigSmoke.Console]::FreeConsole(); " +
		"if (-not [DnsconfigSmoke.Console]::AttachConsole(" + pid + ")) { Write-Error 'AttachConsole failed'; exit 1 }; " +
		"[void][DnsconfigSmoke.Console]::GenerateConsoleCtrlEvent(1, 0)"
}

// executeRowWindowsRepair proves that a live Manager repairs Windows DNS it
// did not remove: with watch holding a split configuration, the harness
// deletes one owned NRPT rule and the adapter's SearchList, then requires the
// status line's changed= to advance, both artifacts to return, and the
// sentinel to resolve again. An interrupt must then run Close to a clean host.
func executeRowWindowsRepair(ctx context.Context, cfg runConfig, row Row) rowOutcome {
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
	if res := exec(90*time.Second, windowsResetArgs()...); !res.Successful() || !assertResetRefused(cfg, res) {
		cfg.Log("    preset-reset failed: %s", res.String())
		return ri.failOrKeep("preset-reset")
	}

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	go func() {
		_ = cfg.Driver.Exec(serveCtx, windowsBinaryExec, "serve",
			"--addr", windowsSentinelAddr+":53", "--record", sentinelName+"="+sentinelAddr)
	}()
	ri.addRecovery(func() {
		_ = cfg.exec(context.Background(), 30*time.Second, "taskkill", "/F", "/IM", "dnsconfigctl.exe")
		serveCancel()
	})
	if res := exec(20*time.Second, windowsBinaryExec, "probe-dns", "--addr", windowsSentinelAddr+":53", "--name", sentinelName, "--timeout", "15s"); !res.Successful() {
		cfg.Log("    sentinel probe failed: %s", res.String())
		return ri.failOrKeep("sentinel-probe")
	}
	ri.addRecovery(func() {
		_ = cfg.exec(context.Background(), 90*time.Second, windowsResetArgs()...)
	})

	search := strings.TrimSuffix(sentinelSearchDomain, ".")
	watchArgs := []string{"-v", "-backend", "windows", "-interface", windowsInterfaceName, "watch",
		"--ns", windowsSentinelAddr, "--match", search, "--search", search,
		"--timeout", "300s", "--status-interval", "2s"}
	pid, res := spawnWindowsWatch(ps, watchArgs, repairWindowsWatchOut, repairWindowsWatchErr)
	if !res.Successful() || pid == "" {
		cfg.Log("    watcher spawn failed: %s", res.String())
		return ri.failOrKeep("repair-watch-spawn")
	}
	ri.addRecovery(func() {
		_ = cfg.exec(context.Background(), 15*time.Second, psCommand("Stop-Process -Id "+pid+" -Force -ErrorAction SilentlyContinue")...)
	})
	readLog := func(path string) []byte {
		return ps(15*time.Second, "Get-Content -Raw -LiteralPath "+psQuote(path)+" -ErrorAction SilentlyContinue").Stdout
	}
	logWatch := func() {
		cfg.Log("    watch stdout:\n%s", indent("        ", string(readLog(repairWindowsWatchOut))))
		cfg.Log("    watch stderr:\n%s", indent("        ", string(readLog(repairWindowsWatchErr))))
	}
	// waitFor polls the watch stdout until ok accepts it or bound elapses.
	waitFor := func(bound time.Duration, ok func([]byte) bool) bool {
		for deadline := time.Now().Add(bound); ; time.Sleep(time.Second) {
			if ok(readLog(repairWindowsWatchOut)) {
				return true
			}
			if time.Now().After(deadline) {
				return false
			}
		}
	}
	if !waitFor(45*time.Second, func(out []byte) bool { return hasLine(out, "WATCH: ready applied=true") }) {
		cfg.Log("    watcher did not become ready")
		logWatch()
		return ri.failOrKeep("repair-watch-ready")
	}

	resolveScript := "Clear-DnsClientCache; Resolve-DnsName -Name " + strings.TrimSuffix(sentinelName, ".") +
		" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List"
	resolves := func() bool {
		result, ok := retryResolution(func() ExecResult { return ps(30*time.Second, resolveScript) },
			func(r ExecResult) bool { return r.Successful() && strings.Contains(string(r.Stdout), sentinelAddr) })
		if !ok {
			cfg.Log("    %s did not resolve to %s: %s", sentinelName, sentinelAddr, result.String())
		}
		return ok
	}
	// artifacts reports the owned local rule names and the adapter SearchList.
	artifacts := func() string {
		script := "$rules = @(Get-ChildItem -LiteralPath " + psQuote(`HKLM:\`+strings.TrimPrefix(nrptRegPath, `HKLM\`)) +
			" -ErrorAction SilentlyContinue | Where-Object PSChildName -like " + psQuote(repairWindowsRulePrefix+"*") + " | ForEach-Object PSChildName); " +
			"$guid = ([guid](Get-NetAdapter -Name " + psQuote(windowsInterfaceName) + ").InterfaceGuid).ToString('B'); " +
			"$v = (Get-ItemProperty -LiteralPath (" + psQuote(repairAdapterKeyPS) + " + $guid) -Name SearchList -ErrorAction SilentlyContinue).SearchList; " +
			"if ($null -eq $v) { $v = '<absent>' }; Write-Output ('rules=' + ($rules -join ',') + ' search=' + $v)"
		return strings.TrimSpace(string(ps(30*time.Second, script).Stdout))
	}
	want := "rules=" + repairWindowsRulePrefix + "0 search=" + search
	if got := artifacts(); got != want || !resolves() {
		cfg.Log("    applied state: want %q, got %q", want, got)
		return ri.failOrKeep("repair-applied")
	}

	var baseline string
	if !waitFor(15*time.Second, func(out []byte) bool {
		var ok bool
		baseline, ok = lastWatchChanged(out)
		return ok
	}) || baseline == "none" {
		cfg.Log("    no status line recording the first converge (changed=%q)", baseline)
		logWatch()
		return ri.failOrKeep("repair-baseline")
	}
	cfg.Log("    applied; status changed=%s", baseline)

	// Get-NetAdapter can take as long as signalDebounce, so resolve the GUID
	// first: both deletions must land in one debounce window, or the first
	// repair sees only one and repeatChangeInterval delays the second past
	// the repair-state check.
	disturb := "$ErrorActionPreference = 'Stop'; " +
		"$guid = ([guid](Get-NetAdapter -Name " + psQuote(windowsInterfaceName) + ").InterfaceGuid).ToString('B'); " +
		"Remove-Item -LiteralPath " + psQuote(`HKLM:\`+strings.TrimPrefix(nrptRegPath, `HKLM\`)+`\`+repairWindowsRulePrefix+"0") + "; " +
		"Remove-ItemProperty -LiteralPath (" + psQuote(repairAdapterKeyPS) + " + $guid) -Name SearchList"
	disturbedAt := time.Now()
	if res := ps(30*time.Second, disturb); !res.Successful() {
		cfg.Log("    disturbance failed: %s", res.String())
		return ri.failOrKeep("repair-disturb")
	}
	var changed string
	if !waitFor(repairWindowsWait, func(out []byte) bool {
		changed, _ = lastWatchChanged(out)
		return changed != baseline
	}) {
		cfg.Log("    changed= did not advance within %s after deleting the rule and SearchList (still %s; artifacts %s)",
			repairWindowsWait, changed, artifacts())
		logWatch()
		return ri.failOrKeep("repair-wait")
	}
	cfg.Log("    repaired: changed=%s about %s after the disturbance", changed, time.Since(disturbedAt).Round(time.Second))
	if got := artifacts(); got != want || !resolves() {
		cfg.Log("    repaired state: want %q, got %q", want, got)
		logWatch()
		return ri.failOrKeep("repair-state")
	}

	if res := ps(30*time.Second, windowsCtrlBreakScript(pid)); !res.Successful() {
		// The helper shares the target console and usually dies with the event.
		cfg.Log("    interrupt helper exited %d (expected when it received the event too)", res.ExitCode)
	}
	if !waitFor(30*time.Second, func(out []byte) bool { return hasLine(out, "WATCH: closed teardown-ok") }) {
		cfg.Log("    watch did not report teardown-ok after the interrupt")
		logWatch()
		return ri.failOrKeep("repair-close")
	}
	if got := artifacts(); got != "rules= search=<absent>" || !windowsResetOK(windowsSnapshot(ctx, cfg)) {
		cfg.Log("    Close left artifacts: %s", got)
		return ri.failOrKeep("repair-clean")
	}
	cfg.Log("    interrupt ran Close to a clean host")

	_ = exec(30*time.Second, "taskkill", "/F", "/IM", "dnsconfigctl.exe")
	serveCancel()
	ctrl := ps(30*time.Second, "Resolve-DnsName -Name "+windowsControlName+" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List")
	if !ctrl.Successful() || !strings.Contains(string(ctrl.Stdout), "IPAddress") {
		cfg.Log("    final-resolution failed: %s", ctrl.String())
		return ri.failOrKeep("final-resolution")
	}
	return outcomePassed
}
