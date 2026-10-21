package main

import (
	"context"
	"fmt"

	"github.com/DefinedNet/dnsconfig"
)

// runReset implements `dnsconfigctl reset [--wait d]`. It constructs a
// Manager, records the Clear goal, waits for it to converge, and closes.
// Clear discovers this identity's artifacts, including a crashed
// predecessor's. It prints "reset OK" when the Clear removed something and
// "reset OK (nothing to reset)" when discovery found nothing attributable.
func runReset(g *globalFlags, args []string) int {
	fs := newSubFlagSet("reset", g.stderr)
	wait := fs.Duration("wait", defaultWait, "bound on waiting for the cleanup to converge")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(g.stderr, "%s reset: unexpected argument %q\n", progName, fs.Arg(0))
		return exitUsage
	}

	opts, err := g.options()
	if err != nil {
		fmt.Fprintf(g.stderr, "%s reset: %v\n", progName, err)
		return exitUsage
	}
	m, err := dnsconfig.New(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(g.stderr, "%s reset: new manager: %v\n", progName, err)
		return exitFail
	}
	rc := exitOK
	before := m.Status()
	err = m.Clear()
	var s dnsconfig.Status
	if err == nil {
		s, err = awaitGoal(m, dnsconfig.GoalClear, before, *wait)
	}
	switch {
	case err != nil:
		fmt.Fprintf(g.stderr, "%s reset: %v\n", progName, err)
		rc = exitFail
	case s.LastChangedAt.IsZero():
		// This Manager made only the one Clear, so no recorded change means
		// discovery found nothing attributable to the identity.
		fmt.Fprintln(g.stdout, "reset OK (nothing to reset)")
	default:
		fmt.Fprintln(g.stdout, "reset OK")
	}
	if cerr := m.Close(); cerr != nil && rc == exitOK {
		fmt.Fprintf(g.stderr, "%s reset: close: %v\n", progName, cerr)
		rc = exitFail
	}
	return rc
}
