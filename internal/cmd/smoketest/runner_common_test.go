package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFailOrKeepRunsRecoveryLIFOOnce checks that cleanup runs once in reverse
// registration order, allowing reset to precede sentinel shutdown.
func TestFailOrKeepRunsRecoveryLIFOOnce(t *testing.T) {
	ri := &rowInstance{cfg: runConfig{Log: func(string, ...any) {}}}
	var order []string
	ri.addRecovery(func() { order = append(order, "kill-sentinel") })
	ri.addRecovery(func() { order = append(order, "reset") })

	out := ri.failOrKeep("resolution")
	assert.Equal(t, outcomeFailed, out)
	assert.Equal(t, []string{"reset", "kill-sentinel"}, order,
		"recovery must run newest-first")

	ri.failOrKeep("again")
	assert.Len(t, order, 2, "recovery steps must run at most once")
}

// TestFailOrKeepSkipsRecoveryWhenKeeping pins that -keep-on-failure keeps the
// failed state intact for inspection: recovery must not run.
func TestFailOrKeepSkipsRecoveryWhenKeeping(t *testing.T) {
	ri := &rowInstance{cfg: runConfig{
		KeepOnFailure: true,
		Log:           func(string, ...any) {},
	}}
	ran := false
	ri.addRecovery(func() { ran = true })

	out := ri.failOrKeep("set")
	assert.Equal(t, outcomeFailed, out)
	assert.False(t, ran, "keep-on-failure must preserve the failed state, recovery skipped")
}

// TestResetReplyAssertions pins the two reset-reply checks against
// dnsconfigctl reset's actual replies. Both exits are 0; only the reply line
// distinguishes a Clear that removed artifacts from one that found none, and
// the nothing-to-reset line starts with the removed line.
func TestResetReplyAssertions(t *testing.T) {
	cfg := runConfig{Log: func(string, ...any) {}}
	for _, tc := range []struct {
		name      string
		stdout    string
		performed bool
		refused   bool
	}{
		{"removed", "reset OK\n", true, false},
		{"removed with CRLF", "reset OK\r\n", true, false},
		{"nothing to reset", "reset OK (nothing to reset)\n", false, true},
		{"nothing to reset without newline", "reset OK (nothing to reset)", false, true},
		{"prefix inside another line", "note: reset OK soon\n", false, false},
		{"empty", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := ExecResult{Stdout: []byte(tc.stdout)}
			assert.Equal(t, tc.performed, assertResetPerformedRevert(cfg, res))
			assert.Equal(t, tc.refused, assertResetRefused(cfg, res))
		})
	}
}

// TestIdleWatch pins the idle Manager's arguments and its success proof.
func TestIdleWatch(t *testing.T) {
	args := idleWatchArgs("127.0.0.1")
	assert.Equal(t, "watch", args[0])
	assert.Contains(t, args, "--expect-apply=false", "the idle Manager must never call Set")

	for _, tc := range []struct {
		name string
		res  ExecResult
		want bool
	}{
		{"negative ok", ExecResult{Stdout: []byte("WATCH: ready applied=false\nWATCH: negative-ok nothing converged while unapplied\n")}, true},
		{"clean exit without proof", ExecResult{Stdout: []byte("WATCH: ready applied=false\n")}, false},
		{"failed", ExecResult{ExitCode: 1, Stdout: []byte("WATCH: negative-ok\n")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, idleWatchOK(tc.res))
		})
	}
}

func TestMacosCompiledHasSearch(t *testing.T) {
	body := []byte("  domain   : dnsconfig-smoke.example\n" +
		"  search domain[0] : alt.dnsconfig-smoke.example\n")
	assert.True(t, macosCompiledHasSearch(body, altSearchDomain))
	assert.False(t, macosCompiledHasSearch(body, sentinelSearchDomain),
		"a routing domain must not be mistaken for a search domain")
}

// TestMacosSetArgs pins the hybrid split shape: split routing uses --match,
// while --search publishes the requested domain through a State key.
func TestMacosSetArgs(t *testing.T) {
	catchAll := macosSetArgs(Row{}, []string{sentinelSearchDomain})
	assert.NotContains(t, catchAll, "--match")
	assert.Contains(t, catchAll, "--search")

	reverse := macosSetArgs(Row{Split: true, ReverseSplit: true}, []string{sentinelSearchDomain})
	assert.Equal(t, 1, strings.Count(strings.Join(reverse, " "), "--match"),
		"--match must be passed once; it is comma-separated, not repeatable")
	assert.Contains(t, reverse, sentinelSearchDomain+","+sentinelReverseZone)

	multi := macosSetArgs(Row{}, macosOrderSearch)
	assert.Contains(t, multi, strings.Join(macosOrderSearch, ","), "--search is comma-separated in configured order")

	split := macosSetArgs(Row{Split: true}, []string{sentinelSearchDomain})
	assert.Contains(t, split, "--match")
	assert.Contains(t, split, "--search")
	assert.Contains(t, split, sentinelSearchDomain, "split rows route the search suffix's covering domain")
	assert.Equal(t, "--detach", split[len(split)-1])
}

// TestPsQuote pins PowerShell single-quote escaping (doubling).
func TestPsQuote(t *testing.T) {
	assert.Equal(t, "'corp.example'", psQuote("corp.example"))
	assert.Equal(t, "'it''s'", psQuote("it's"))
}

// TestAssertConflictRefusedMatchesOnlyNamespaceConflicts: a Windows adapter
// refusal also names a holder, but must not pass as a namespace conflict.
func TestAssertConflictRefusedMatchesOnlyNamespaceConflicts(t *testing.T) {
	cfg := runConfig{Log: func(string, ...any) {}}
	for _, tc := range []struct {
		stderr string
		want   bool
	}{
		{`dnsconfig: Set: domain corp.example held by identity "net-a"`, true},
		{`dnsconfig: Set: catch-all held by identity "net-a"`, true},
		{`dnsconfig: Set: catch-all held by identity "net-b"`, false},
		{`adapter "smoke" ({0F2A...}) held by identity "net-a"`, false},
	} {
		t.Run(tc.stderr, func(t *testing.T) {
			res := ExecResult{ExitCode: 1, Stderr: []byte(tc.stderr)}
			assert.Equal(t, tc.want, assertConflictRefused(cfg, res, "net-a"))
		})
	}
}
