package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Two-instance rows run two application identities side by side on one host,
// as two networks of one client would: each with its own tunnel, resolver,
// split domain, and search domain. They are the live proof for the
// identity-scoped contract that the fake-backed unit tests model.
//
// Each row checks, in order: both identities apply and resolve through their
// own sentinel; a Set under identity B that claims identity A's domain is
// refused before mutation and names A as the holder; a live Manager under
// identity A refuses a second Set under the same identity; that live Manager
// is killed without Close, and a fresh reset (a Clear) under identity A clears
// only A's artifacts while B keeps resolving; and B's own reset leaves the host
// clean. macOS then checks that a search domain both identities share is
// admitted when B's resolver file routes it and refused without that file,
// and that the file answers.
const (
	pairIdentityA = "net-a"
	pairIdentityB = "net-b"

	// pairSentinelName is identity B's sentinel record. It sits beside, not
	// under, identity A's sentinelName so the two split domains are
	// disjoint rather than overlapping suffixes.
	pairSentinelName = "sentinel.two.dnsconfig-smoke.example."
	pairSentinelAddr = "192.0.2.44"

	// Each identity searches the domain it routes; the namespaces stay
	// disjoint, so neither can search a sibling or parent.
	pairSearchA = sentinelName
	pairSearchB = pairSentinelName
)

// assertConflictRefused checks that a Set exited non-zero because holder
// already publishes the requested domain. The pattern is the public
// ConflictError's text, which a Windows adapter refusal does not match, so a
// refusal for any other reason fails the row.
func assertConflictRefused(cfg runConfig, res ExecResult, holder string) bool {
	want := regexp.MustCompile(`(?:domain \S+|catch-all) held by identity ` + regexp.QuoteMeta(strconv.Quote(holder)))
	if res.ExitCode != 0 && want.Match(res.Stderr) {
		return true
	}
	cfg.Log("    conflicting Set was not refused as a conflict (want %q): %s", want, res.String())
	return false
}

// assertAlreadyRunningRefused checks that a Set exited non-zero because
// another live Manager holds the identity.
func assertAlreadyRunningRefused(cfg runConfig, res ExecResult) bool {
	const want = "another Manager holds this identity"
	if res.ExitCode != 0 && strings.Contains(string(res.Stderr), want) {
		return true
	}
	cfg.Log("    same-identity Set was not refused as already running (want %q): %s", want, res.String())
	return false
}
