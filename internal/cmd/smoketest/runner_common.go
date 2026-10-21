package main

import (
	"context"
	"strings"
	"time"
)

// pushBinary copies cfg.Binary to dst.
func pushBinary(cfg runConfig, dst string) ExecResult {
	return cfg.Driver.CopyFile(cfg.Binary, dst)
}

// rowInstance tracks a row's failure recovery.
type rowInstance struct {
	cfg runConfig

	// recovery holds cleanup steps for a failed local row, run in LIFO order.
	recovery []func()
}

// addRecovery registers a cleanup step to run if the row fails. Steps return
// nothing, so a failing step cannot stop the ones after it.
func (ri *rowInstance) addRecovery(f func()) { ri.recovery = append(ri.recovery, f) }

// runRecovery runs the registered recovery steps newest-first and clears
// the list so they run at most once.
func (ri *rowInstance) runRecovery() {
	for i := len(ri.recovery) - 1; i >= 0; i-- {
		ri.recovery[i]()
	}
	ri.recovery = nil
}

// failOrKeep runs recovery unless KeepOnFailure requests preserving DNS
// state for inspection.
func (ri *rowInstance) failOrKeep(stage string) rowOutcome {
	if ri.cfg.KeepOnFailure {
		ri.cfg.Log("    keep-on-failure: DNS state retained (stage=%s)", stage)
		return outcomeFailed
	}
	ri.cfg.Log("    failed at stage %s", stage)
	ri.runRecovery()
	return outcomeFailed
}

// Replies of dnsconfigctl reset. Both exit zero, so only the reply
// distinguishes a Clear that removed artifacts from one that found none.
// resetNothingLine starts with resetRemovedLine, so matching is by whole line.
const (
	resetRemovedLine = "reset OK"
	resetNothingLine = "reset OK (nothing to reset)"
)

// hasLine reports whether out contains want as a complete line.
func hasLine(out []byte, want string) bool {
	for line := range strings.Lines(string(out)) {
		if strings.TrimRight(line, "\r\n") == want {
			return true
		}
	}
	return false
}

// assertResetPerformedRevert requires the exact line "reset OK" after an
// apply: discovery must have attributed the applied artifacts to the identity.
func assertResetPerformedRevert(cfg runConfig, res ExecResult) bool {
	if hasLine(res.Stdout, resetRemovedLine) {
		return true
	}
	cfg.Log("    reset removed nothing (got %q) - discovery did not see the applied state",
		strings.TrimSpace(string(res.Stdout)))
	return false
}

// assertResetRefused requires the exact line "reset OK (nothing to reset)"
// before an apply. A plain "reset OK" means discovery attributed state this
// identity never applied.
func assertResetRefused(cfg runConfig, res ExecResult) bool {
	if hasLine(res.Stdout, resetNothingLine) {
		return true
	}
	cfg.Log("    pre-set reset found something to remove (got %q) - discovery attributed state we never applied",
		strings.TrimSpace(string(res.Stdout)))
	return false
}

// altSearchDomain distinguishes the replacement configuration so cleanup
// checks can detect artifacts from either apply.
const altSearchDomain = "alt.dnsconfig-smoke.example."

// idleWatchArgs runs a Manager under the row's identity that never records a
// goal, holding it briefly before Close. The checks that follow it prove that
// a separate process's New/Close cycle leaves another process's applied
// configuration intact: a Manager never given a goal must not clean it up.
func idleWatchArgs(ns string) []string {
	return []string{"watch", "--expect-apply=false", "--ns", ns, "--timeout", "2s"}
}

// idleWatchOK requires the clean exit and the line watch prints only after
// confirming its Manager recorded no goal and converged nothing.
func idleWatchOK(res ExecResult) bool {
	return res.Successful() && strings.Contains(string(res.Stdout), "WATCH: negative-ok")
}

// splitMatchArg combines the forward and optional reverse match domains.
// --match accepts one comma-separated value; repeating it loses earlier values.
// The forward domain is sentinelSearchDomain, not sentinelName, so the
// search suffix is routed and the short-name check stays meaningful.
func splitMatchArg(row Row) string {
	if row.ReverseSplit {
		return sentinelSearchDomain + "," + sentinelReverseZone
	}
	return sentinelSearchDomain
}

// retryResolution retries an idempotent query while resolver updates settle.
func retryResolution(query func() ExecResult, ok func(ExecResult) bool) (ExecResult, bool) {
	var last ExecResult
	for attempt := 1; attempt <= resolutionMaxAttempts; attempt++ {
		last = query()
		if ok(last) {
			return last, true
		}
		if attempt < resolutionMaxAttempts {
			time.Sleep(resolutionBackoff)
		}
	}
	return last, false
}

// exec releases each command's deadline when its subprocess returns.
func (cfg runConfig) exec(ctx context.Context, timeout time.Duration, argv ...string) ExecResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return cfg.Driver.Exec(ctx, argv...)
}
