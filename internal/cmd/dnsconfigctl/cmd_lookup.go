package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// runLookup resolves a hostname through Go's net.Resolver and prints one
// address per line. The smoke harness uses it to check search-domain expansion;
// platform executors use native tools for their split-DNS assertions.
func runLookup(g *globalFlags, args []string) int {
	fs := newSubFlagSet("lookup", g.stderr)
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for resolution")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	if len(rest) != 1 || rest[0] == "" {
		fmt.Fprintln(g.stderr, "lookup: exactly one name argument is required")
		return exitUsage
	}
	name := rest[0]

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	if err != nil || len(addrs) == 0 {
		fmt.Fprintf(g.stderr, "lookup: %s did not resolve: %v\n", name, err)
		return exitFail
	}
	for _, a := range addrs {
		fmt.Fprintln(g.stdout, a)
	}
	return exitOK
}
