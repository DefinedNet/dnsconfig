package main

import (
	"context"
	"fmt"

	"github.com/DefinedNet/dnsconfig"
)

// runRecover implements `dnsconfigctl recover`, a startup recovery through
// dnsconfig.Recover. It prints "recover OK" when Recover changed the host and
// "recover OK (nothing to recover)" when it found nothing of this identity's.
func runRecover(g *globalFlags, args []string) int {
	fs := newSubFlagSet("recover", g.stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(g.stderr, "%s recover: unexpected argument %q\n", progName, fs.Arg(0))
		return exitUsage
	}
	opts, err := g.options()
	if err != nil {
		fmt.Fprintf(g.stderr, "%s recover: %v\n", progName, err)
		return exitUsage
	}
	changed, err := dnsconfig.Recover(context.Background(), opts)
	switch {
	case err != nil:
		fmt.Fprintf(g.stderr, "%s recover: %v\n", progName, err)
		return exitFail
	case changed:
		fmt.Fprintln(g.stdout, "recover OK")
	default:
		fmt.Fprintln(g.stdout, "recover OK (nothing to recover)")
	}
	return exitOK
}
