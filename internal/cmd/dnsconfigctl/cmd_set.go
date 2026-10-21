package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/DefinedNet/dnsconfig"
)

// runSet implements `dnsconfigctl set --ns <addr>[,...] [--search ...]
// [--match ...] [--wait d] [--detach | --close-immediately]`.
//
// set records the goal, waits for the worker to converge, and prints
// "set OK". By default it then holds until SIGINT or SIGTERM
// and calls Close, which removes the configuration. --detach exits without
// Close, success or failure, so a separate process can inspect the host and
// recover with reset; process exit releases the identity lock.
// --close-immediately calls Close right after converging and prints
// "close OK".
func runSet(g *globalFlags, args []string) int {
	fs := newSubFlagSet("set", g.stderr)
	nsFlag := fs.String("ns", "", "comma-separated nameserver addresses (required)")
	searchFlag := fs.String("search", "", "comma-separated search domains")
	matchFlag := fs.String("match", "", "comma-separated match domains (split DNS)")
	detach := fs.Bool("detach", false, "exit after converging without Close (leaves OS state changed)")
	closeImmediately := fs.Bool("close-immediately", false, "test-only: Close right after converging")
	wait := fs.Duration("wait", defaultWait, "bound on waiting for the configuration to converge")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(g.stderr, "%s set: unexpected argument %q\n", progName, fs.Arg(0))
		return exitUsage
	}
	if *closeImmediately && *detach {
		fmt.Fprintln(g.stderr, "set: --close-immediately cannot be combined with --detach")
		return exitUsage
	}
	if strings.TrimSpace(*nsFlag) == "" {
		fmt.Fprintf(g.stderr, "%s set: --ns is required\n", progName)
		fs.Usage()
		return exitUsage
	}

	cfg, err := buildSetConfig(*nsFlag, *searchFlag, *matchFlag)
	if err != nil {
		fmt.Fprintf(g.stderr, "%s set: %v\n", progName, err)
		return exitUsage
	}

	opts, err := g.options()
	if err != nil {
		fmt.Fprintf(g.stderr, "%s set: %v\n", progName, err)
		return exitUsage
	}

	m, err := dnsconfig.New(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(g.stderr, "%s set: new manager: %v\n", progName, err)
		return exitFail
	}
	before := m.Status()
	err = m.Set(cfg)
	if err == nil {
		_, err = awaitGoal(m, dnsconfig.GoalSet, before, *wait)
	}
	if err != nil {
		fmt.Fprintf(g.stderr, "%s set: %v\n", progName, err)
		// Close would clear this identity's artifacts, including ones an
		// earlier detached set left for the harness to inspect.
		if !*detach {
			closeQuietly(m)
		}
		return exitFail
	}
	fmt.Fprintln(g.stdout, "set OK")

	switch {
	case *closeImmediately:
		if err := m.Close(); err != nil {
			fmt.Fprintln(g.stderr, "set: close:", err)
			return exitFail
		}
		fmt.Fprintln(g.stdout, "close OK")
		return exitOK
	case *detach:
		return exitOK
	}
	return waitAndClose(g, m)
}

// buildSetConfig parses the CLI flag values into a dnsconfig.Config. It
// returns a usage-friendly error message on the first parse failure.
func buildSetConfig(nsRaw, searchRaw, matchRaw string) (dnsconfig.Config, error) {
	var cfg dnsconfig.Config
	addrs, err := parseAddrList(nsRaw)
	if err != nil {
		return cfg, fmt.Errorf("--ns: %w", err)
	}
	cfg.Nameservers = addrs

	if strings.TrimSpace(searchRaw) != "" {
		domains, err := parseDomainList(searchRaw)
		if err != nil {
			return cfg, fmt.Errorf("--search: %w", err)
		}
		cfg.SearchDomains = domains
	}
	if strings.TrimSpace(matchRaw) != "" {
		domains, err := parseDomainList(matchRaw)
		if err != nil {
			return cfg, fmt.Errorf("--match: %w", err)
		}
		cfg.MatchDomains = domains
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// waitAndClose blocks on SIGINT/SIGTERM, then closes m, which removes the
// configuration. It returns 0 on clean shutdown and 1 if Close failed.
func waitAndClose(g *globalFlags, m *dnsconfig.Manager) int {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	sig := <-ch
	signal.Stop(ch)
	if g.verbose {
		fmt.Fprintf(g.stderr, "received signal %v, removing DNS configuration\n", sig)
	}
	if err := m.Close(); err != nil {
		fmt.Fprintf(g.stderr, "%s set: close failed: %v\n", progName, err)
		return exitFail
	}
	return exitOK
}

// closeQuietly closes m, ignoring the error. Used on failure paths where we
// have already reported the primary cause.
func closeQuietly(m *dnsconfig.Manager) {
	_ = m.Close()
}
