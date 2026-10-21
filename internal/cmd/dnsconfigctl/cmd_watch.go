package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/DefinedNet/dnsconfig"
)

// runWatch applies a configuration and holds a live Manager so the harness
// can disturb the host and observe repair and teardown. The hold ends on
// SIGTERM or SIGINT; --timeout bounds it so a harness that forgets to stop
// the process fails instead of hanging.
//
// The harness relies on these stdout tokens:
//   - "WATCH: ready applied=<true|false>" gates the disturbance. With
//     --expect-apply it follows the first converge.
//   - "WATCH: status converged=<bool> changed=<RFC3339|none> err=<err>"
//     repeats every --status-interval while holding. changed is
//     Status.LastChangedAt, so a repair shows up as a new value.
//   - "WATCH: closed teardown-ok" confirms Close completed on the signal path.
//   - "WATCH: negative-ok ..." confirms the unapplied window changed nothing.
//
// With -v the backend's log lines, including repairs, go to stderr.
func runWatch(g *globalFlags, args []string) int {
	fs := newSubFlagSet("watch", g.stderr)
	nsFlag := fs.String("ns", "", "comma-separated nameserver addresses (required)")
	searchFlag := fs.String("search", "", "comma-separated search domains")
	matchFlag := fs.String("match", "", "comma-separated match domains (split DNS)")
	timeout := fs.Duration("timeout", 60*time.Second, "bound on the hold; expiry exits non-zero")
	wait := fs.Duration("wait", defaultWait, "bound on waiting for the first converge")
	interval := fs.Duration("status-interval", 5*time.Second, "how often to print a status line while holding")
	expectApply := fs.Bool("expect-apply", true, "false = negative mode: construct the Manager but never Set, then prove nothing converged")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(g.stderr, "%s watch: unexpected argument %q\n", progName, fs.Arg(0))
		return exitUsage
	}
	if strings.TrimSpace(*nsFlag) == "" {
		fmt.Fprintf(g.stderr, "%s watch: --ns is required\n", progName)
		fs.Usage()
		return exitUsage
	}
	if *interval <= 0 {
		fmt.Fprintf(g.stderr, "%s watch: --status-interval must be positive\n", progName)
		return exitUsage
	}

	cfg, err := buildSetConfig(*nsFlag, *searchFlag, *matchFlag)
	if err != nil {
		fmt.Fprintf(g.stderr, "%s watch: %v\n", progName, err)
		return exitUsage
	}

	opts, err := g.options()
	if err != nil {
		fmt.Fprintf(g.stderr, "%s watch: %v\n", progName, err)
		return exitUsage
	}

	m, err := dnsconfig.New(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(g.stderr, "%s watch: new manager: %v\n", progName, err)
		return exitFail
	}
	// Retain the first Close result for both signal handling and deferred cleanup.
	var closeOnce sync.Once
	var closeErr error
	closeM := func() error {
		closeOnce.Do(func() { closeErr = m.Close() })
		return closeErr
	}
	defer func() { _ = closeM() }()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	if !*expectApply {
		fmt.Fprintln(g.stdout, "WATCH: ready applied=false")
		select {
		case <-time.After(*timeout):
			if s := m.Status(); s.Goal != dnsconfig.GoalNone {
				fmt.Fprintf(g.stderr, "WATCH: negative-fail goal=%q recorded while unapplied\n", s.Goal)
				return exitFail
			}
			fmt.Fprintln(g.stdout, "WATCH: negative-ok nothing converged while unapplied")
			return exitOK
		case <-sigs:
			return finishWatchSignal(g, closeM)
		}
	}

	before := m.Status()
	if err := m.Set(cfg); err != nil {
		fmt.Fprintf(g.stderr, "%s watch: set: %v\n", progName, err)
		return exitFail
	}
	if _, err := awaitGoal(m, dnsconfig.GoalSet, before, *wait); err != nil {
		fmt.Fprintf(g.stderr, "%s watch: set: %v\n", progName, err)
		return exitFail
	}
	// Strictly after the first converge: the harness gates its disturbance on
	// this line so it can never race the apply.
	fmt.Fprintln(g.stdout, "WATCH: ready applied=true")

	deadline := time.NewTimer(*timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			printWatchStatus(g, m.Status())
		case <-deadline.C:
			fmt.Fprintf(g.stderr, "WATCH: timeout hold expired after %s\n", *timeout)
			return exitFail
		case <-sigs:
			return finishWatchSignal(g, closeM)
		}
	}
}

func printWatchStatus(g *globalFlags, s dnsconfig.Status) {
	changed := "none"
	if !s.LastChangedAt.IsZero() {
		changed = s.LastChangedAt.UTC().Format(time.RFC3339Nano)
	}
	fmt.Fprintf(g.stdout, "WATCH: status converged=%t changed=%s err=%v\n",
		s.Converged, changed, s.LastError)
}

func finishWatchSignal(g *globalFlags, closeM func() error) int {
	if err := closeM(); err != nil {
		fmt.Fprintf(g.stderr, "%s watch: close: %v\n", progName, err)
		return exitFail
	}
	fmt.Fprintln(g.stdout, "WATCH: closed teardown-ok")
	return exitOK
}
