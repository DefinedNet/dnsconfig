package main

import (
	"fmt"

	"github.com/DefinedNet/dnsconfig"
)

// runDetect prints the forced or native backend on a single line.
func runDetect(g *globalFlags, args []string) int {
	fs := newSubFlagSet("detect", g.stderr)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(g.stderr, "%s detect: unexpected argument %q\n", progName, fs.Arg(0))
		return exitUsage
	}
	opts, err := g.options()
	if err != nil {
		fmt.Fprintf(g.stderr, "%s detect: %v\n", progName, err)
		return exitUsage
	}
	kind := opts.ForceBackend
	if kind == dnsconfig.BackendAuto {
		kind = dnsconfig.Detect()
	}
	// Print the bare kind string. The smoke harness greps this output, so we
	// deliberately emit no decoration.
	fmt.Fprintln(g.stdout, string(kind))
	return exitOK
}
