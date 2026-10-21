package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// runProbeDNS polls an A query against the specified server until it answers
// or the timeout expires. The harness uses it to wait for sentinel readiness
// without requiring an external DNS client.
func runProbeDNS(g *globalFlags, args []string) int {
	fs := newSubFlagSet("probe-dns", g.stderr)
	addr := fs.String("addr", "127.0.0.99:53", "ip:port to probe")
	name := fs.String("name", "", "DNS name to query (required)")
	timeout := fs.Duration("timeout", 5*time.Second, "max time to wait for an answer")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *name == "" {
		fmt.Fprintln(g.stderr, "probe-dns: --name is required")
		return exitUsage
	}
	qname := dns.Fqdn(strings.ToLower(*name))

	client := &dns.Client{Timeout: 500 * time.Millisecond}
	msg := &dns.Msg{}
	msg.SetQuestion(qname, dns.TypeA)

	deadline := time.Now().Add(*timeout)
	for time.Now().Before(deadline) {
		resp, _, err := client.Exchange(msg, *addr)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			fmt.Fprintf(g.stdout, "probe-dns: %s answered for %s\n", *addr, qname)
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(g.stderr, "probe-dns: timed out probing %s for %s\n", *addr, qname)
	return exitFail
}
