package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
)

// This file implements the LocalSystem Group Policy NRPT smoke row.

const (
	// gpNrptRegPath is the Group Policy NRPT container. Rules here displace
	// the machine-local table at nrptRegPath wholesale, which is why the
	// backend writes here when someone else already has.
	gpNrptRegPath = `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// gpRetiredRegPath is where the library renames a container it retires;
	// it must be gone once a converge that retired one returns.
	gpRetiredRegPath = `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig-dnsconfig-retired`

	// gpDNSClientRegPath is gpNrptRegPath's parent. The row asserts it is
	// never removed: it is not what suppresses the local NRPT, and on a real
	// domain-joined machine it carries a GPO's other DNS settings.
	gpDNSClientRegPath = `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`

	// gpForeignRuleName is the seeded rule standing in for a real NRPT GPO or
	// another DNS manager (Tailscale writes rules here). Deliberately carries
	// no "dnsconfig-" prefix -- that is exactly what makes it foreign, and
	// what the sweep must leave alone.
	gpForeignRuleName = `{6F5E4D3C-SMOKE-FOREIGN-RULE}`

	// gpForeignNamespace and gpForeignServer populate the seed. The namespace
	// is a suffix nothing resolves, so the seeded rule cannot affect the
	// runner's own name resolution while it is in force.
	gpForeignNamespace = ".foreign.dnsconfig-gp-smoke.invalid"
	gpForeignServer    = "203.0.113.53"

	// runAsSystemScript is the schtasks-based LocalSystem wrapper, relative to
	// the repo root (the harness's working directory under `go run`).
	// GenerateGPNotification rejects an elevated administrator, which is all a
	// GitHub runner is, so every dnsconfigctl invocation in this row goes
	// through it.
	runAsSystemScript = `.github\scripts\run-as-system.ps1`

	// effectivePolicyAttempts and effectivePolicyInterval bound the wait for
	// the DNS Client to reload NRPT after a policy notification. A delivered
	// notification normally takes effect within a second; the bound only
	// keeps a lost one from hanging the row.
	effectivePolicyAttempts = 30
	effectivePolicyInterval = 2 * time.Second

	// effectiveNRPTScript prints the DNS Client's effective NRPT as one
	// "namespace->servers" line per namespace. Unlike the registry, it shows
	// which store the DNS Client is using. A cmdlet error exits nonzero, so a
	// check that our namespace is absent cannot pass on empty output.
	effectiveNRPTScript = `Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | ` +
		`ForEach-Object { $s = @($_.NameServers) -join ','; foreach ($n in @($_.Namespace)) { "$n->$s" } }`

	// bareContainerScript creates the policy container with no values or
	// subkeys and prints its counts.
	bareContainerScript = `$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig'; ` +
		`New-Item -Path $k -Force | Out-Null; $i = Get-Item -Path $k; ` +
		`"VALUES=$($i.ValueCount) SUBKEYS=$($i.SubKeyCount)"`

	// gpNotifyScript sends the machine policy change notification that the
	// policy engine sends after applying or removing a GPO. It must run as
	// LocalSystem: GenerateGPNotification rejects any other caller. The call
	// returns a Win32 error code, not a BOOL, so zero is success.
	gpNotifyScript = `$sig = '[DllImport("userenv.dll", CharSet = CharSet.Unicode)] ` +
		`public static extern uint GenerateGPNotification(bool bMachine, string product, uint options);'
$gp = Add-Type -MemberDefinition $sig -Name GPNotify -Namespace DnsconfigSmoke -PassThru
$rc = $gp::GenerateGPNotification($true, 'dnsconfig-smoke', 0)
if ($rc -ne 0) {
  Write-Output ('GenerateGPNotification failed: ' + $rc)
  exit 1
}
Write-Output 'GP-NOTIFY: OK'`
)

// gpForeignRuleKey is the full registry path of the seeded foreign rule.
func gpForeignRuleKey() string { return gpNrptRegPath + `\` + gpForeignRuleName }

// ownNamespace is the NRPT namespace W5's split configuration routes.
func ownNamespace() string { return "." + strings.TrimSuffix(sentinelSearchDomain, ".") }

// psEncodedCommand runs script through -EncodedCommand, so a multi-line
// script survives the LocalSystem wrapper's single-command .cmd shim
// without any quoting.
func psEncodedCommand(script string) []string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	return []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
		base64.StdEncoding.EncodeToString(raw)}
}

// windowsOwnedRules maps each owned NRPT rule key in a `reg query /s` dump
// to its sorted, whitespace-normalized value lines, so the copies in the two
// stores compare independently of their store path and value order.
func windowsOwnedRules(dump []byte) map[string]string {
	values := map[string][]string{}
	current := ""
	for _, raw := range strings.Split(string(dump), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			current = ""
			if name := line[strings.LastIndex(line, `\`)+1:]; strings.HasPrefix(name, windowsOurRulePrefix) {
				current = name
				values[name] = nil
			}
			continue
		}
		if current != "" {
			values[current] = append(values[current], strings.Join(strings.Fields(line), " "))
		}
	}
	out := make(map[string]string, len(values))
	for name, lines := range values {
		slices.Sort(lines)
		out[name] = strings.Join(lines, "\n")
	}
	return out
}

// parseEffectiveNRPT maps each namespace in effectiveNRPTScript output,
// lowercased, to its comma-separated servers.
func parseEffectiveNRPT(out []byte) map[string]string {
	m := map[string]string{}
	for _, raw := range strings.Split(string(out), "\n") {
		ns, servers, ok := strings.Cut(strings.TrimSpace(raw), "->")
		if ok && ns != "" {
			m[strings.ToLower(ns)] = servers
		}
	}
	return m
}

// windowsDualPlacement requires every owned GP rule to have an identical
// local copy and at least one rule naming the sentinel. It returns the local
// rules for comparison after later steps.
func windowsDualPlacement(ctx context.Context, cfg runConfig) (map[string]string, bool) {
	gpDump := cfg.exec(ctx, 30*time.Second, "reg", "query", gpNrptRegPath, "/s")
	locDump := cfg.exec(ctx, 30*time.Second, "reg", "query", nrptRegPath, "/s")
	gpRules, locRules := windowsOwnedRules(gpDump.Stdout), windowsOwnedRules(locDump.Stdout)
	if !gpDump.Successful() || len(gpRules) == 0 || !strings.Contains(string(gpDump.Stdout), windowsSentinelAddr) {
		cfg.Log("    GP placement check failed: no dnsconfig- rule pointing at %s under %s: %s",
			windowsSentinelAddr, gpNrptRegPath, gpDump.String())
		return nil, false
	}
	if !maps.Equal(gpRules, locRules) {
		cfg.Log("    GP placement check failed: the local store must hold an identical copy of every GP rule\n    group policy:\n%s\n    local:\n%s",
			indent("        ", string(gpDump.Stdout)), indent("        ", string(locDump.Stdout)))
		return nil, false
	}
	return locRules, true
}

// waitEffectiveNRPT polls the effective NRPT until ok accepts it.
func waitEffectiveNRPT(ctx context.Context, cfg runConfig, ok func(map[string]string) bool) (string, bool) {
	var last ExecResult
	for attempt := 1; attempt <= effectivePolicyAttempts; attempt++ {
		last = cfg.exec(ctx, 30*time.Second, psCommand(effectiveNRPTScript)...)
		if last.Successful() && ok(parseEffectiveNRPT(last.Stdout)) {
			return string(last.Stdout), true
		}
		if attempt < effectivePolicyAttempts {
			time.Sleep(effectivePolicyInterval)
		}
	}
	return last.String(), false
}

// asSystem wraps argv into a PowerShell invocation of run-as-system.ps1. The
// wrapper takes ONE command line (it builds a .cmd shim around it), so argv is
// flattened with each element quoted for cmd.exe, then the whole thing quoted
// again for PowerShell.
func asSystem(script string, argv []string) []string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = `"` + a + `"`
	}
	return psCommand("& " + psQuote(script) + " -Command " + psQuote(strings.Join(parts, " ")))
}

// normalizeRegDump collapses a `reg query` dump to a comparable form: trimmed
// lines, blank lines dropped. Used for the verbatim before/after comparison of
// the foreign rule, whose values must come through our apply and reset
// untouched.
func normalizeRegDump(b []byte) string {
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}

// executeRowWindowsGroupPolicy applies and resets as LocalSystem with a
// foreign GP rule present. It checks that owned rules sit in both stores,
// live resolution through the GP store, that the local copies route
// unchanged when the GP container disappears or foreign policy leaves, that
// an empty container fails Set without being removed, and preservation of
// the foreign rule and parent DNSClient key.
func executeRowWindowsGroupPolicy(ctx context.Context, cfg runConfig, row Row) rowOutcome {
	cfg.Log("=== windows row %s (%s) ===", row.ID, row.Name)

	wrapper, err := filepath.Abs(runAsSystemScript)
	if err != nil {
		cfg.Log("    cannot resolve %s: %v", runAsSystemScript, err)
		return outcomeFailed
	}
	if _, err := os.Stat(wrapper); err != nil {
		cfg.Log("    LocalSystem wrapper not found at %s: %v (run the harness from the repo root)", wrapper, err)
		return outcomeFailed
	}

	ri := &rowInstance{cfg: cfg}

	if res := pushBinary(cfg, windowsBinaryPush); !res.Successful() {
		cfg.Log("    binary push failed: %s", res.String())
		return ri.failOrKeep("push")
	}
	res := cfg.exec(ctx, 60*time.Second, windowsBinaryExec, "detect")
	if !res.Successful() || strings.TrimSpace(string(res.Stdout)) != "windows" {
		cfg.Log("    detect failed or mismatched (want windows): %s", res.String())
		return ri.failOrKeep("detect")
	}
	cfg.Log("    detect OK: windows")

	// Step 2: prove the wrapper delivers LocalSystem. A green row that had
	// silently run as the elevated administrator would be testing the
	// RefreshPolicyEx fallback, not the notification path this row exists for.
	res = cfg.exec(ctx, 180*time.Second, asSystem(wrapper, []string{"whoami"})...)
	if !res.Successful() || !strings.Contains(strings.ToLower(string(res.Stdout)), `nt authority\system`) {
		cfg.Log("    LocalSystem wrapper check failed: %s", res.String())
		return ri.failOrKeep("localsystem-wrapper")
	}
	cfg.Log("    LocalSystem wrapper OK")

	// Step 3: seed the foreign Group Policy rule. From here the machine is in
	// Group Policy NRPT mode, so the seed must be removed on every exit path.
	seedKey := gpForeignRuleKey()
	seedValues := [][]string{
		{"/v", "Version", "/t", "REG_DWORD", "/d", "1"},
		{"/v", "Name", "/t", "REG_MULTI_SZ", "/d", gpForeignNamespace},
		{"/v", "GenericDNSServers", "/t", "REG_SZ", "/d", gpForeignServer},
		{"/v", "ConfigOptions", "/t", "REG_DWORD", "/d", "8"},
	}
	seed := func() bool {
		for _, v := range seedValues {
			argv := append([]string{"reg", "add", seedKey}, v...)
			if r := cfg.exec(ctx, 30*time.Second, append(argv, "/f")...); !r.Successful() {
				cfg.Log("    foreign GP rule seed failed: %s", r.String())
				return false
			}
		}
		return true
	}
	if !seed() {
		return ri.failOrKeep("gp-seed")
	}
	ri.addRecovery(func() {
		recCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cfg.Driver.Exec(recCtx, "reg", "delete", seedKey, "/f")
		// The container last: an EMPTY one suppresses the local NRPT
		// machine-wide, so leaving it behind would poison the runner.
		cfg.Driver.Exec(recCtx, "reg", "delete", gpNrptRegPath, "/f")
	})
	cfg.Log("    foreign GP rule seeded: %s", gpForeignRuleName)

	seedDump := cfg.exec(ctx, 30*time.Second, "reg", "query", seedKey, "/s")
	if !seedDump.Successful() {
		cfg.Log("    foreign GP rule readback failed: %s", seedDump.String())
		return ri.failOrKeep("gp-seed-readback")
	}
	seedBefore := normalizeRegDump(seedDump.Stdout)

	// Step 4: a pre-set reset must be refused. The only NRPT state on the
	// machine is somebody else's, and an over-broad pre-state probe that
	// counted it would make reset trample a foreign GPO.
	res = cfg.exec(ctx, 180*time.Second, asSystem(wrapper, windowsResetArgs())...)
	if !res.Successful() {
		cfg.Log("    pre-set reset failed: %s", res.String())
		return ri.failOrKeep("preset-reset")
	}
	if !assertResetRefused(cfg, res) {
		return ri.failOrKeep("preset-reset-not-refused")
	}
	cfg.Log("    pre-set reset refused OK (a foreign GP rule is not our pre-state)")

	// Step 5: sentinel, then apply as LocalSystem. Split, not catch-all: a
	// catch-all Group Policy rule would route the runner's every query to a
	// sentinel that only knows one name.
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	serveDone := make(chan ExecResult, 1)
	go func() {
		serveDone <- cfg.Driver.Exec(serveCtx, windowsBinaryExec,
			"serve",
			"--addr", windowsSentinelAddr+":53",
			"--record", sentinelName+"="+sentinelAddr)
	}()
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

	setAsSystem := func() bool {
		r := cfg.exec(ctx, 300*time.Second, asSystem(wrapper, windowsSetArgs(row, sentinelSearchDomain))...)
		if !r.Successful() {
			cfg.Log("    set failed: %s", r.String())
			return false
		}
		return true
	}
	if !setAsSystem() {
		return ri.failOrKeep("set")
	}
	ri.addRecovery(func() {
		if r := cfg.exec(context.Background(), 300*time.Second, asSystem(wrapper, windowsResetArgs())...); !r.Successful() {
			cfg.Log("    recovery: reset failed - GP NRPT rules may still point at the (now dead) sentinel: %s", r.String())
		}
	})
	cfg.Log("    set OK (as LocalSystem)")

	// Step 6: placement. Group Policy suppresses the local store, so our
	// rules must be in the GP store to route, with identical local copies
	// ready for when that store goes away. Rule KEYS are matched, not the
	// prefix anywhere in the dump: the foreign seed's namespace carries our
	// prefix too.
	localRules, placed := windowsDualPlacement(ctx, cfg)
	if !placed {
		return ri.failOrKeep("gp-placement")
	}
	cfg.Log("    placement OK: our rules are in both stores with identical values")

	queryName := strings.TrimSuffix(sentinelName, ".")
	resolveSentinel := func(via string) bool {
		if r := cfg.exec(ctx, 30*time.Second, "ipconfig", "/flushdns"); !r.Successful() {
			cfg.Log("    cache flush non-fatal: %s", r.String())
		}
		resolveScript := "Resolve-DnsName -Name " + queryName +
			" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List"
		last, ok := retryResolution(func() ExecResult {
			return cfg.exec(ctx, 30*time.Second, psCommand(resolveScript)...)
		}, func(r ExecResult) bool {
			return r.Successful() && strings.Contains(string(r.Stdout), sentinelAddr)
		})
		if !ok {
			cfg.Log("    resolution through %s failed after %d attempts: %s", via, resolutionMaxAttempts, last.String())
			cfg.Log("    %s", serveDiag())
			return false
		}
		cfg.Log("    resolution OK through %s: %s -> %s", via, queryName, sentinelAddr)
		return true
	}
	// effectiveIs waits for the DNS Client's effective table to hold our
	// namespace on the sentinel, and the foreign namespace only when
	// foreign is true. The foreign namespace is present only while the GP
	// store is in use, so its presence tells which store is routing.
	effectiveIs := func(stage string, foreign bool) bool {
		out, ok := waitEffectiveNRPT(ctx, cfg, func(eff map[string]string) bool {
			_, hasForeign := eff[gpForeignNamespace]
			return hasForeign == foreign && strings.Contains(eff[ownNamespace()], windowsSentinelAddr)
		})
		if !ok {
			cfg.Log("    %s: effective NRPT never showed %s on %s with the foreign namespace present=%t:\n%s",
				stage, ownNamespace(), windowsSentinelAddr, foreign, indent("        ", out))
		}
		return ok
	}
	localUnchanged := func(stage string) bool {
		dump := cfg.exec(ctx, 30*time.Second, "reg", "query", nrptRegPath, "/s")
		if got := windowsOwnedRules(dump.Stdout); !maps.Equal(got, localRules) {
			cfg.Log("    %s: the local copies changed:\n%s", stage, indent("        ", dump.String()))
			return false
		}
		return true
	}

	// Step 6b: it must actually resolve. A Group Policy rule is inert until
	// the DNS Client is told policy changed, so this is the end-to-end proof
	// that GenerateGPNotification was delivered -- not merely called.
	if !effectiveIs("gp-effective", true) {
		return ri.failOrKeep("gp-effective")
	}
	if !resolveSentinel("the Group Policy NRPT") {
		return ri.failOrKeep("gp-resolution")
	}

	// Step 6c: removing a GPO can delete the whole container, our rules with
	// it. The row sends the notification the policy engine would, and no
	// dnsconfig process runs until resolution is checked, so only the local
	// copies already in place can route the sentinel. The foreign namespace
	// leaving the effective table shows the DNS Client dropped the GP store.
	if r := cfg.exec(ctx, 30*time.Second, "reg", "delete", gpNrptRegPath, "/f"); !r.Successful() {
		cfg.Log("    container loss: could not delete %s: %s", gpNrptRegPath, r.String())
		return ri.failOrKeep("container-loss-delete")
	}
	notifyPolicy := func(stage string) bool {
		r := cfg.exec(ctx, 180*time.Second, asSystem(wrapper, psEncodedCommand(gpNotifyScript))...)
		if !r.Successful() || !strings.Contains(string(r.Stdout), "GP-NOTIFY: OK") {
			cfg.Log("    %s: policy notification failed: %s", stage, r.String())
			return false
		}
		return true
	}
	if !notifyPolicy("container loss") {
		return ri.failOrKeep("container-loss-notify")
	}
	if !effectiveIs("container-loss", false) {
		return ri.failOrKeep("container-loss-effective")
	}
	if !resolveSentinel("the local copies after the GP container vanished") {
		return ri.failOrKeep("container-loss-resolution")
	}
	if !localUnchanged("container loss") {
		return ri.failOrKeep("container-loss-local")
	}

	// Step 6d: back in Group Policy mode, remove only the foreign seed and
	// converge again. The Manager must retire the container its rules now
	// hold, and leave the local copies as they were.
	if !seed() || !setAsSystem() {
		return ri.failOrKeep("gp-reenter")
	}
	if _, ok := windowsDualPlacement(ctx, cfg); !ok {
		return ri.failOrKeep("gp-reenter-placement")
	}
	if !effectiveIs("gp-reenter", true) {
		return ri.failOrKeep("gp-reenter-effective")
	}
	if r := cfg.exec(ctx, 30*time.Second, "reg", "delete", seedKey, "/f"); !r.Successful() {
		cfg.Log("    foreign departure: could not delete the seed: %s", r.String())
		return ri.failOrKeep("foreign-departure-delete")
	}
	if !setAsSystem() {
		return ri.failOrKeep("foreign-departure-set")
	}
	if r := cfg.exec(ctx, 30*time.Second, "reg", "query", gpNrptRegPath); r.Successful() {
		cfg.Log("    foreign departure: the Group Policy container survived our last rule leaving it:\n%s",
			indent("        ", string(r.Stdout)))
		return ri.failOrKeep("foreign-departure-container")
	}
	if r := cfg.exec(ctx, 30*time.Second, "reg", "query", gpRetiredRegPath); r.Successful() {
		cfg.Log("    foreign departure: the retired container was not deleted:\n%s", indent("        ", string(r.Stdout)))
		return ri.failOrKeep("foreign-departure-retired")
	}
	if !localUnchanged("foreign departure") {
		return ri.failOrKeep("foreign-departure-local")
	}
	if !effectiveIs("foreign-departure", false) {
		return ri.failOrKeep("foreign-departure-effective")
	}
	if !resolveSentinel("the local copies after foreign policy left") {
		return ri.failOrKeep("foreign-departure-resolution")
	}

	// Step 6e: an empty container nothing attributes to dnsconfig still makes
	// the DNS Client ignore the local store. Set must leave it in place and
	// fail instead of reporting Converged, then route through the local
	// copies once it goes. --wait bounds the expected failure. The harness
	// notification after the delete stands in for the reboot the error text
	// asks for: dnsconfig sends none for a key it did not remove, and the
	// DNS Client keeps its cached policy table without one.
	// A key-only GPO entry leaves a bare key. Any value, even an empty
	// default, counts as foreign policy and takes the dual-store path.
	if r := cfg.exec(ctx, 30*time.Second, psCommand(bareContainerScript)...); !r.Successful() ||
		!strings.Contains(string(r.Stdout), "VALUES=0 SUBKEYS=0") {
		cfg.Log("    empty container: could not create a bare %s: %s", gpNrptRegPath, r.String())
		return ri.failOrKeep("empty-container-create")
	}
	if !notifyPolicy("empty container") {
		return ri.failOrKeep("empty-container-notify")
	}
	if out, ok := waitEffectiveNRPT(ctx, cfg, func(eff map[string]string) bool {
		_, has := eff[ownNamespace()]
		return !has
	}); !ok {
		cfg.Log("    empty container: the local copies still route, so the container did not suppress them:\n%s",
			indent("        ", out))
		return ri.failOrKeep("empty-container-effective")
	}
	res = cfg.exec(ctx, 300*time.Second,
		asSystem(wrapper, append(windowsSetArgs(row, sentinelSearchDomain), "--wait", "20s"))...)
	if res.Successful() || !strings.Contains(res.String(), "empty Group Policy NRPT container") {
		dump := cfg.exec(ctx, 30*time.Second, "reg", "query", gpNrptRegPath, "/s")
		cfg.Log("    empty container: set must fail naming the container: %s\n    container:\n%s",
			res.String(), indent("        ", dump.String()))
		return ri.failOrKeep("empty-container-set")
	}
	if r := cfg.exec(ctx, 30*time.Second, "reg", "query", gpNrptRegPath); !r.Successful() {
		cfg.Log("    empty container: set removed a container it cannot attribute: %s", r.String())
		return ri.failOrKeep("empty-container-removed")
	}
	if !localUnchanged("empty container") {
		return ri.failOrKeep("empty-container-local")
	}
	if r := cfg.exec(ctx, 30*time.Second, "reg", "delete", gpNrptRegPath, "/f"); !r.Successful() {
		cfg.Log("    empty container: could not delete %s: %s", gpNrptRegPath, r.String())
		return ri.failOrKeep("empty-container-delete")
	}
	if !notifyPolicy("empty container removal") || !setAsSystem() {
		return ri.failOrKeep("empty-container-recover")
	}
	if !effectiveIs("empty-container-recover", false) {
		return ri.failOrKeep("empty-container-recover-effective")
	}
	if !resolveSentinel("the local copies after the empty container went") {
		return ri.failOrKeep("empty-container-recover-resolution")
	}
	cfg.Log("    empty container OK: set failed naming it, left it in place, and converged once it went")

	// Step 6f: Group Policy mode once more, for the cleanup checks below.
	if !seed() || !setAsSystem() {
		return ri.failOrKeep("gp-restore")
	}
	if _, ok := windowsDualPlacement(ctx, cfg); !ok {
		return ri.failOrKeep("gp-restore-placement")
	}
	cfg.Log("    container loss and foreign departure OK: the local copies routed with their values unchanged")

	// Step 7: kill the sentinel so it cannot mask a failed teardown, then
	// reset as LocalSystem.
	if r := cfg.exec(ctx, 30*time.Second, "taskkill", "/F", "/IM", "dnsconfigctl.exe"); !r.Successful() {
		cfg.Log("    sentinel kill non-zero (probably already gone): %s", r.String())
	}
	serveCancel()

	res = cfg.exec(ctx, 300*time.Second, asSystem(wrapper, windowsResetArgs())...)
	if !res.Successful() {
		cfg.Log("    reset failed: %s", res.String())
		return ri.failOrKeep("reset")
	}
	if !assertResetPerformedRevert(cfg, res) {
		return ri.failOrKeep("reset-no-op")
	}

	// Step 7a: our rules are gone from both stores.
	postGP := cfg.exec(ctx, 30*time.Second, "reg", "query", gpNrptRegPath, "/s")
	if !postGP.Successful() {
		cfg.Log("    post-reset check failed: the Group Policy container must SURVIVE while the foreign seed is still in it: %s",
			postGP.String())
		return ri.failOrKeep("gp-container-deleted")
	}
	if !windowsResetOK(postGP.Stdout) {
		cfg.Log("    post-reset check failed: a dnsconfig- rule survived in the Group Policy store:\n%s",
			indent("        ", string(postGP.Stdout)))
		return ri.failOrKeep("gp-reset-check")
	}
	postLoc := cfg.exec(ctx, 30*time.Second, "reg", "query", nrptRegPath, "/s")
	if !windowsResetOK(postLoc.Stdout) {
		cfg.Log("    post-reset check failed: a dnsconfig- rule survived in the local store:\n%s",
			indent("        ", string(postLoc.Stdout)))
		return ri.failOrKeep("local-reset-check")
	}

	// Step 7b: the foreign seed survives verbatim -- the sweep must remove
	// only rules bearing our prefix, and must not rewrite what it spares.
	afterDump := cfg.exec(ctx, 30*time.Second, "reg", "query", seedKey, "/s")
	if !afterDump.Successful() {
		cfg.Log("    post-reset check failed: the foreign GP rule was deleted: %s", afterDump.String())
		return ri.failOrKeep("foreign-rule-deleted")
	}
	if got := normalizeRegDump(afterDump.Stdout); got != seedBefore {
		cfg.Log("    post-reset check failed: the foreign GP rule was modified\n    before:\n%s\n    after:\n%s",
			indent("        ", seedBefore), indent("        ", got))
		return ri.failOrKeep("foreign-rule-modified")
	}

	// Step 7c: the parent DNSClient key is never a casualty of the sweep.
	parent := cfg.exec(ctx, 30*time.Second, "reg", "query", gpDNSClientRegPath)
	if !parent.Successful() {
		cfg.Log("    post-reset check failed: the parent DNSClient key was removed: %s", parent.String())
		return ri.failOrKeep("dnsclient-parent-deleted")
	}
	cfg.Log("    post-reset check OK (our rules swept from both stores; foreign seed and container intact)")

	// Step 8: remove the seed, then the container it was keeping alive, and
	// confirm the machine is back to no Group Policy NRPT at all. Order
	// matters: an empty container suppresses the local NRPT just as a
	// populated one does, so it must not outlive its last rule.
	for _, key := range []string{seedKey, gpNrptRegPath} {
		res = cfg.exec(ctx, 30*time.Second, "reg", "delete", key, "/f")
		if !res.Successful() {
			cfg.Log("    teardown failed: could not delete %s: %s", key, res.String())
			return ri.failOrKeep("gp-teardown")
		}
	}
	gone := cfg.exec(ctx, 30*time.Second, "reg", "query", gpNrptRegPath)
	if gone.Successful() {
		cfg.Log("    teardown failed: the Group Policy NRPT container is still present and would suppress the local NRPT:\n%s",
			indent("        ", string(gone.Stdout)))
		return ri.failOrKeep("gp-container-teardown")
	}

	// Step 9: a real name resolves again now that the store is empty.
	res = cfg.exec(ctx, 30*time.Second, psCommand("Resolve-DnsName -Name "+windowsControlName+
		" -Type A -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue | Format-List")...)
	if !res.Successful() || !strings.Contains(string(res.Stdout), "IPAddress") {
		cfg.Log("    final resolution check failed: %s did not resolve: %s", windowsControlName, res.String())
		return ri.failOrKeep("final-resolution")
	}
	cfg.Log("    final resolution OK")

	return outcomePassed
}
