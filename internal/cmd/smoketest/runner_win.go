package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The _win.go suffix keeps these definitions available to tests on both hosts.

const (
	// windowsBinaryPush is the local binary destination on the system drive.
	windowsBinaryPush = `/Windows/Temp/dnsconfigctl.exe`

	// windowsBinaryExec is the absolute path used to execute the binary.
	windowsBinaryExec = `C:\Windows\Temp\dnsconfigctl.exe`

	// The workflow creates this owned adapter before running the local row.
	windowsInterfaceName = "dnsconfig-smoke"

	// windowsSentinelAddr is the loopback listener used by the NRPT rules.
	windowsSentinelAddr = "127.0.0.1"

	// windowsControlName lies outside the split suffix and must resolve through
	// an upstream resolver.
	windowsControlName = "microsoft.com"

	// windowsNCSIProbeHost is NCSI's default web probe host, which a
	// catch-all's exemption rule leaves on the interfaces' DNS.
	windowsNCSIProbeHost = "www.msftconnecttest.com"

	// nrptRegPath holds machine-local NRPT rules.
	nrptRegPath = `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

	// tcpipRegPath is the registry key holding the global Tcpip SearchList
	// value the Windows backend preserves.
	tcpipRegPath = `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

	// tcpipPSPath is tcpipRegPath in PowerShell provider syntax, for the
	// Get/Set/Remove-ItemProperty calls that capture and restore the
	// harness's SearchList seed.
	tcpipPSPath = `HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

	// A non-empty global list makes preservation through apply/reset observable.
	windowsSeedSearchList = "smokeseed.example"

	// windowsSearchListAbsent is the marker the seed-capture step prints
	// when the runner has no pre-existing SearchList value to put back.
	windowsSearchListAbsent = "<absent>"
)

// windowsSetArgs builds the dnsconfigctl.exe set invocation. Split rows
// route the sentinel's parent domain via --match; catch-all rows install
// searchDomain via --search (varied by the set-over-set step).
func windowsSetArgs(row Row, searchDomain string) []string {
	args := []string{
		windowsBinaryExec,
		"-backend", "windows", "-interface", windowsInterfaceName,
		"set", "--ns", windowsSentinelAddr,
	}
	if row.Split {
		args = append(args, "--match", splitMatchArg(row))
	} else {
		args = append(args, "--search", searchDomain)
	}
	return append(args, "--detach")
}

// windowsResetArgs is the dnsconfigctl.exe reset invocation, shared by the
// pre-set refusal check and both apply/revert cycles.
func windowsResetArgs() []string {
	return []string{windowsBinaryExec, "-backend", "windows", "-interface", windowsInterfaceName, "reset"}
}

// psQuote single-quotes s for embedding in a PowerShell command, doubling
// any embedded single quotes per PowerShell's escaping rule.
func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// spawnWindowsWatch starts dnsconfigctl.exe with args, stdout to out and
// stderr to errPath, and returns the dnsconfigctl process ID. The process is
// created through WMI so it inherits none of the calling exec's pipes: a
// Start-Process child keeps the harness's stdout open and the exec never
// completes. cmd.exe supplies the output redirection and the console the
// process shares. No path or argument may contain a space, so the command
// line needs no inner quoting, which would otherwise pass through both Go's
// argv escaping and PowerShell's parser.
func spawnWindowsWatch(ps func(time.Duration, string) ExecResult, args []string, out, errPath string) (string, ExecResult) {
	cmdLine := "cmd.exe /c " + windowsBinaryExec + " " + strings.Join(args, " ") +
		" > " + out + " 2> " + errPath
	spawn := "$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = " + psQuote(cmdLine) + " }; " +
		"if ($r.ReturnValue -ne 0) { Write-Error ('create failed: ' + $r.ReturnValue); exit 1 }; " +
		"$f = 'ParentProcessId=' + $r.ProcessId + ' AND Name=''dnsconfigctl.exe'''; " +
		"for ($i = 0; $i -lt 30; $i++) { $c = Get-CimInstance Win32_Process -Filter $f; " +
		"if ($c) { Write-Output $c.ProcessId; exit 0 }; Start-Sleep -Milliseconds 500 }; Write-Error 'watcher child did not appear'; exit 1"
	res := ps(45*time.Second, spawn)
	return strings.TrimSpace(string(res.Stdout)), res
}

// psCommand wraps a PowerShell one-liner into the argv the local runner executes.
// -NoProfile keeps startup fast and deterministic; -NonInteractive prevents
// any prompt from hanging the exec.
func psCommand(script string) []string {
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-Command", script}
}

// windowsSnapshot captures NRPT and global SearchList diagnostics.
// Missing registry keys are recorded in the output rather than failing the row.
func windowsSnapshot(ctx context.Context, cfg runConfig) []byte {
	var b strings.Builder
	section := func(title string, argv ...string) {
		res := cfg.exec(ctx, 30*time.Second, argv...)
		fmt.Fprintf(&b, "=== %s ===\n", title)
		if len(res.Stdout) > 0 {
			b.Write(res.Stdout)
			if res.Stdout[len(res.Stdout)-1] != '\n' {
				b.WriteByte('\n')
			}
		}
		if !res.Successful() {
			fmt.Fprintf(&b, "(exit %d: %s)\n", res.ExitCode, strings.TrimSpace(string(res.Stderr)))
		}
	}
	section("nrpt", "reg", "query", nrptRegPath, "/s")
	section("searchlist", "reg", "query", tcpipRegPath, "/v", "SearchList")
	return []byte(b.String())
}

// windowsOurRulePrefix is the name prefix the windows backend gives every
// NRPT rule key it creates.
const windowsOurRulePrefix = "dnsconfig-"

// windowsHasRuleKey reports whether a reg query dump holds an NRPT key whose
// name starts with prefix. Key paths start at column zero; indented values may
// contain the same prefix without identifying an owned rule.
func windowsHasRuleKey(post []byte, prefix string) bool {
	for _, raw := range strings.Split(string(post), "\n") {
		line := strings.TrimRight(raw, "\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		name := line
		if i := strings.LastIndex(line, `\`); i >= 0 {
			name = line[i+1:]
		}
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// windowsResetOK reports whether cleanup removed the owned NRPT records.
// Global SearchList values remain administrator-owned even with our suffix text.
func windowsResetOK(post []byte) bool { return !windowsHasRuleKey(post, windowsOurRulePrefix) }

// executeRowWindows checks apply, replacement, recovery, and a second cycle
// on the local Windows runner. A seeded global SearchList must survive cleanup.
//
// Resolve-DnsName checks real resolution through NRPT. Split rows omit adapter
// DNS servers to isolate that route; catch-all rows also set adapter servers,
// so their lookups cannot distinguish the two paths.
func executeRowWindows(ctx context.Context, cfg runConfig, row Row) rowOutcome {
	if row.GroupPolicy {
		// The Group Policy row asserts against a different registry store and
		// drives every dnsconfigctl call as LocalSystem; it gets its own flow
		// rather than threading a flag through this one.
		return executeRowWindowsGroupPolicy(ctx, cfg, row)
	}
	if row.Pair {
		return executeRowWindowsPair(ctx, cfg, row)
	}
	if row.Repair {
		return executeRowWindowsRepair(ctx, cfg, row)
	}
	cfg.Log("=== windows row %s (%s) ===", row.ID, row.Name)
	ri := &rowInstance{cfg: cfg}

	// Copy the native Windows binary to the fixture path.
	res := pushBinary(cfg, windowsBinaryPush)
	if !res.Successful() {
		cfg.Log("    binary push failed: %s", res.String())
		return ri.failOrKeep("push")
	}

	// Detect.
	res = cfg.exec(ctx, 60*time.Second, windowsBinaryExec, "detect")
	if !res.Successful() {
		cfg.Log("    detect failed: %s", res.String())
		return ri.failOrKeep("detect")
	}
	got := strings.TrimSpace(string(res.Stdout))
	if got != "windows" {
		cfg.Log("    detect mismatch: want=windows got=%q", got)
		return ri.failOrKeep("detect-mismatch")
	}
	cfg.Log("    detect OK: %s", got)

	// Seed a non-empty global list so library preservation is observable.
	// The fixture restores the runner's captured value after both cycles.
	origRes := cfg.exec(ctx, 30*time.Second, psCommand(
		"$v = (Get-ItemProperty -Path "+psQuote(tcpipPSPath)+" -Name SearchList -ErrorAction SilentlyContinue).SearchList; "+
			"if ($null -eq $v -or $v -eq '') { Write-Output "+psQuote(windowsSearchListAbsent)+" } else { Write-Output $v }")...)
	if !origRes.Successful() {
		cfg.Log("    SearchList capture failed: %s", origRes.String())
		return ri.failOrKeep("searchlist-capture")
	}
	origSearchList := strings.TrimSpace(string(origRes.Stdout))
	restoreSearchListSeed := func(tag string) {
		script := "Set-ItemProperty -Path " + psQuote(tcpipPSPath) + " -Name SearchList -Value " + psQuote(origSearchList)
		if origSearchList == windowsSearchListAbsent {
			script = "Remove-ItemProperty -Path " + psQuote(tcpipPSPath) + " -Name SearchList -ErrorAction SilentlyContinue"
		}
		if r := cfg.exec(context.Background(), 30*time.Second, psCommand(script)...); !r.Successful() {
			cfg.Log("    %s: restoring the runner's original SearchList failed: %s", tag, r.String())
		}
	}
	ri.addRecovery(func() { restoreSearchListSeed("recovery") })

	res = cfg.exec(ctx, 30*time.Second,
		"reg", "add", tcpipRegPath, "/v", "SearchList", "/t", "REG_SZ", "/d", windowsSeedSearchList, "/f")
	if !res.Successful() {
		cfg.Log("    SearchList seed failed: %s", res.String())
		return ri.failOrKeep("searchlist-seed")
	}
	cfg.Log("    SearchList seeded: %q (was %q)", windowsSeedSearchList, origSearchList)

	// Pre-state snapshot (taken after seeding, so the seed is part
	// of the state reset must reproduce).
	preBytes := windowsSnapshot(ctx, cfg)

	// A pristine row must not claim cleanup responsibility.
	res = cfg.exec(ctx, 90*time.Second, windowsResetArgs()...)
	if !res.Successful() {
		cfg.Log("    pre-set reset failed: %s", res.String())
		return ri.failOrKeep("preset-reset")
	}
	if !assertResetRefused(cfg, res) {
		return ri.failOrKeep("preset-reset-not-refused")
	}
	cfg.Log("    pre-set reset refused OK")

	// Spawn the sentinel DNS server. Unlike the macOS path,
	// which detaches the sentinel with `nohup ... &`, the Windows sentinel
	// runs as a foreground process inside a long-lived subprocess
	// held open by this goroutine. That sidesteps any uncertainty about
	// whether a Start-Process child survives when its parent
	// exec exits. The taskkill below ends the foreground process; serveCancel
	// is the backstop.
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	serveDone := make(chan ExecResult, 1)
	go func() {
		serveDone <- cfg.Driver.Exec(serveCtx, windowsBinaryExec,
			"serve",
			"--addr", windowsSentinelAddr+":53",
			"--record", sentinelName+"="+sentinelAddr)
	}()
	// serveDiag reports the sentinel's state for failure logging: if the
	// serve process has already exited, its captured output; otherwise a
	// note that it is still running.
	serveDiag := func() string {
		select {
		case r := <-serveDone:
			return "sentinel serve exited early: " + r.String()
		default:
			return "(sentinel serve still running)"
		}
	}

	res = cfg.exec(ctx, 20*time.Second,
		windowsBinaryExec, "probe-dns",
		"--addr", windowsSentinelAddr+":53",
		"--name", sentinelName,
		"--timeout", "15s")
	if !res.Successful() {
		cfg.Log("    sentinel probe failed: %s", res.String())
		cfg.Log("    %s", serveDiag())
		return ri.failOrKeep("sentinel-probe")
	}
	cfg.Log("    sentinel ready")

	// Apply NRPT rules and DNS settings on the owned adapter.
	res = cfg.exec(ctx, 90*time.Second, windowsSetArgs(row, sentinelSearchDomain)...)
	if !res.Successful() {
		cfg.Log("    set failed: %s", res.String())
		return ri.failOrKeep("set")
	}
	cfg.Log("    set OK")
	// The runner outlives this row, so failure recovery must remove its
	// NRPT rules and adapter settings before restoring the harness's seed.
	ri.addRecovery(func() {
		if r := cfg.exec(context.Background(), 90*time.Second, windowsResetArgs()...); !r.Successful() {
			cfg.Log("    recovery: reset failed - NRPT rules may still point at the (now dead) sentinel: %s", r.String())
		} else {
			cfg.Log("    recovery: system DNS restored")
		}
	})

	// An idle Manager in a separate process while the config is
	// applied. The SearchList readback and resolution checks below prove its
	// Close left the applied state intact.
	res = cfg.exec(ctx, 60*time.Second, append([]string{
		windowsBinaryExec, "-backend", "windows", "-interface", windowsInterfaceName,
	}, idleWatchArgs(windowsSentinelAddr)...)...)
	if !idleWatchOK(res) {
		cfg.Log("    idle Manager under applied state failed: %s", res.String())
		return ri.failOrKeep("idle-under-set")
	}
	cfg.Log("    idle Manager under applied state OK")

	// Read the owned adapter's suffix; the global list stays at the seed.
	if !row.Split {
		wantSuffix := strings.TrimSuffix(sentinelSearchDomain, ".")
		script := "$guid = ([guid](Get-NetAdapter -Name " + psQuote(windowsInterfaceName) + ").InterfaceGuid).ToString('B'); " +
			`Get-ItemPropertyValue -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\' + $guid) -Name SearchList`
		sl := cfg.exec(ctx, 30*time.Second, psCommand(script)...)
		if !sl.Successful() || !strings.Contains(string(sl.Stdout), wantSuffix) {
			cfg.Log("    SearchList readback failed: want %q in SearchList, got: %s",
				wantSuffix, sl.String())
			return ri.failOrKeep("searchlist")
		}
		cfg.Log("    SearchList readback OK: %q present", wantSuffix)
	}

	// Flush the DNS client cache so stale negative entries cannot
	// mask the sentinel. The windows backend flushes on apply too; this is a
	// belt-and-braces second flush from the harness side.
	res = cfg.exec(ctx, 30*time.Second, "ipconfig", "/flushdns")
	if !res.Successful() {
		cfg.Log("    cache flush non-fatal: %s", res.String())
	}

	// Real resolution test. Resolve-DnsName honors NRPT (nslookup
	// does not). A sentinel answer proves resolution through our settings;
	// split isolates NRPT, while catch-all also has the adapter-server path.
	queryName := strings.TrimSuffix(sentinelName, ".")
	resolveScript := "Resolve-DnsName -Name " + queryName +
		" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List"
	lastResolve, resolvedOK := retryResolution(func() ExecResult {
		return cfg.exec(ctx, 30*time.Second, psCommand(resolveScript)...)
	}, func(r ExecResult) bool {
		return r.Successful() && strings.Contains(string(r.Stdout), sentinelAddr)
	})
	if !resolvedOK {
		cfg.Log("    resolution check failed after %d attempts: %s",
			resolutionMaxAttempts, lastResolve.String())
		cfg.Log("    %s", serveDiag())
		return ri.failOrKeep("resolution")
	}
	cfg.Log("    resolution OK: %s -> %s", queryName, sentinelAddr)

	// The sentinel also serves the adapter, so resolution cannot tell the
	// exemption from the catch-all; the effective table shows what the DNS
	// Client loaded.
	if !row.Split {
		out, ok := waitEffectiveNRPT(ctx, cfg, func(eff map[string]string) bool {
			servers, has := eff[windowsNCSIProbeHost]
			return has && servers == ""
		})
		if !ok {
			cfg.Log("    NCSI exemption check failed: effective NRPT has no server-less rule for %s:\n%s",
				windowsNCSIProbeHost, indent("        ", out))
			return ri.failOrKeep("ncsi-exemption")
		}
		cfg.Log("    NCSI exemption OK: %s has no servers in the effective NRPT", windowsNCSIProbeHost)
	}

	// The control name must resolve through an upstream outside the split suffix;
	// a sentinel-only check would also pass with an unintended catch-all.
	if row.Split {
		ctrlScript := "Resolve-DnsName -Name " + windowsControlName +
			" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List"
		r := cfg.exec(ctx, 30*time.Second, psCommand(ctrlScript)...)
		if !r.Successful() || !strings.Contains(string(r.Stdout), "IPAddress") {
			cfg.Log("    split control check failed: %s did not resolve: %s",
				windowsControlName, r.String())
			cfg.Log("    %s", serveDiag())
			return ri.failOrKeep("split-control")
		}
		if strings.Contains(string(r.Stdout), sentinelAddr) {
			cfg.Log("    split control check failed: %s resolved to the sentinel address %s - split routing leaked to catch-all",
				windowsControlName, sentinelAddr)
			return ri.failOrKeep("split-control-leak")
		}
		cfg.Log("    split control OK: %s -> real upstream (not the sentinel)", windowsControlName)

		// Reverse-zone routing. The match domain becomes a second NRPT rule
		// whose namespace is the in-addr.arpa suffix, and a PTR query lands
		// beneath it. NRPT's documented use is forward namespaces, so whether
		// a reverse query takes the rule is the measurement this row makes;
		// only the sentinel answers this PTR.
		if row.ReverseSplit {
			ptrScript := "Resolve-DnsName -Name " + sentinelPTRName() +
				" -Type PTR -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List"
			ptrResult, ptrOK := retryResolution(func() ExecResult {
				return cfg.exec(ctx, 30*time.Second, psCommand(ptrScript)...)
			}, func(r ExecResult) bool {
				return r.Successful() &&
					strings.Contains(string(r.Stdout), strings.TrimSuffix(sentinelName, "."))
			})
			if !ptrOK {
				cfg.Log("    reverse-zone check failed after %d attempts: %s",
					resolutionMaxAttempts, ptrResult.String())
				cfg.Log("    %s", serveDiag())
				return ri.failOrKeep("reverse-zone")
			}
			cfg.Log("    reverse-zone OK: %s -> %s", sentinelPTRName(),
				strings.TrimSuffix(sentinelName, "."))
		}
	}

	// Replace configuration from a fresh process without a reset.
	// Catch-all rows change the adapter search domain; split rows keep the
	// same match. The global SearchList must remain untouched throughout.
	res = cfg.exec(ctx, 90*time.Second, windowsSetArgs(row, altSearchDomain)...)
	if !res.Successful() {
		cfg.Log("    second set failed: %s", res.String())
		return ri.failOrKeep("set-over-set")
	}
	// Prove the updated config still routes, not merely that set exited 0.
	lastResolve, resolvedOK = retryResolution(func() ExecResult {
		return cfg.exec(ctx, 30*time.Second, psCommand(resolveScript)...)
	}, func(r ExecResult) bool {
		return r.Successful() && strings.Contains(string(r.Stdout), sentinelAddr)
	})
	if !resolvedOK {
		cfg.Log("    resolution after second set failed: %s", lastResolve.String())
		cfg.Log("    %s", serveDiag())
		return ri.failOrKeep("set-over-set-resolution")
	}
	cfg.Log("    set-over-set OK (still routing)")

	// Kill the sentinel before reset so it cannot answer a
	// follow-up query and mask a real regression. At this point set,
	// detect and probe-dns have all exited, so the only dnsconfigctl.exe
	// process left is the serve sentinel.
	res = cfg.exec(ctx, 30*time.Second, "taskkill", "/F", "/IM", "dnsconfigctl.exe")
	if !res.Successful() {
		cfg.Log("    sentinel kill non-zero (probably already gone): %s", res.String())
	}
	serveCancel()

	// Reset.
	res = cfg.exec(ctx, 90*time.Second, windowsResetArgs()...)
	if !res.Successful() {
		cfg.Log("    reset failed: %s", res.String())
		return ri.failOrKeep("reset")
	}
	if !assertResetPerformedRevert(cfg, res) {
		return ri.failOrKeep("reset-no-op")
	}
	cfg.Log("    reset OK")

	// Both cycles must remove our rules while preserving the global seed.
	postResetCheck := func(tag string) string {
		postBytes := windowsSnapshot(ctx, cfg)
		if !windowsResetOK(postBytes) {
			cfg.Log("    post-reset check failed (%s): a dnsconfig- NRPT rule survived", tag)
			cfg.Log("    pre:\n%s", indent("        ", string(preBytes)))
			cfg.Log("    post:\n%s", indent("        ", string(postBytes)))
			return "reset-check"
		}
		if !strings.Contains(string(postBytes), windowsSeedSearchList) {
			cfg.Log("    post-reset check failed (%s): the global SearchList seed %q was not preserved", tag, windowsSeedSearchList)
			cfg.Log("    post:\n%s", indent("        ", string(postBytes)))
			return "searchlist-preservation"
		}
		cfg.Log("    post-reset check OK (no dnsconfig- rule; global SearchList preserved)")
		return ""
	}

	// Post-state snapshot + checks.
	if stage := postResetCheck("post"); stage != "" {
		return ri.failOrKeep(stage)
	}

	// A second apply/revert cycle must leave no target records or adapter DNS.
	res = cfg.exec(ctx, 90*time.Second, windowsSetArgs(row, sentinelSearchDomain)...)
	if !res.Successful() {
		cfg.Log("    second-cycle set failed: %s", res.String())
		return ri.failOrKeep("cycle2-set")
	}
	res = cfg.exec(ctx, 90*time.Second, windowsResetArgs()...)
	if !res.Successful() {
		cfg.Log("    second-cycle reset failed: %s", res.String())
		return ri.failOrKeep("cycle2-reset")
	}
	if !assertResetPerformedRevert(cfg, res) {
		return ri.failOrKeep("cycle2-reset-no-op")
	}
	if stage := postResetCheck("post2"); stage != "" {
		return ri.failOrKeep("cycle2-" + stage)
	}
	cfg.Log("    second apply/revert cycle OK")

	// Put the runner's original SearchList back. The seed has
	// served its purpose; the next row on this runner (or the machine's
	// owner, outside CI) should see the pre-row value.
	restoreSearchListSeed("cleanup")

	// Final resolution sanity - a real name must resolve again now
	// that NRPT is back to its pre-set state.
	finalScript := "Resolve-DnsName -Name " + windowsControlName +
		" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List"
	res = cfg.exec(ctx, 30*time.Second, psCommand(finalScript)...)
	if !res.Successful() || !strings.Contains(string(res.Stdout), "IPAddress") {
		cfg.Log("    final resolution check failed: %s did not resolve: %s",
			windowsControlName, res.String())
		return ri.failOrKeep("final-resolution")
	}
	cfg.Log("    final resolution OK")

	return outcomePassed
}
