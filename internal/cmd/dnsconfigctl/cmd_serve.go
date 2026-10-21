package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// runServe answers configured A, AAAA, and corresponding PTR records over
// UDP and TCP; a served name queried for a type it lacks gets NOERROR with no
// answers (NODATA), and only an unknown name gets NXDOMAIN. The smoke harness
// uses these answers to verify that OS queries reach the configured resolver.
//
// Repeated --record flags can supply multiple addresses per name. --delay
// simulates a slow resolver. The server runs until SIGINT/SIGTERM.
func runServe(g *globalFlags, args []string) int {
	fs := newSubFlagSet("serve", g.stderr)
	addr := fs.String("addr", "127.0.0.99:53", "ip:port to listen on")
	delay := fs.Duration("delay", 0, "fixed pause before each response is written")
	var records recordMap
	fs.Var(&records, "record", "name=addr; may be repeated; addr may be IPv4 or IPv6")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if len(records.byName) == 0 {
		fmt.Fprintln(g.stderr, "serve: at least one --record is required")
		return exitUsage
	}
	if *delay < 0 {
		fmt.Fprintln(g.stderr, "serve: --delay must not be negative")
		return exitUsage
	}

	log := g.resolveLogger()
	log.Debug("serve start", "addr", *addr, "records", records.byName, "delay", *delay)

	handler := newServeHandler(records.byName, *delay, log)

	udpSrv := &dns.Server{Addr: *addr, Net: "udp", Handler: handler}
	tcpSrv := &dns.Server{Addr: *addr, Net: "tcp", Handler: handler}

	errs := make(chan error, 2)
	go func() { errs <- udpSrv.ListenAndServe() }()
	go func() { errs <- tcpSrv.ListenAndServe() }()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-errs:
		// Either UDP or TCP failed; tear down the other and report.
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(g.stderr, "serve: listen error: %v\n", err)
			return exitFail
		}
		return 0
	case sig := <-sigs:
		g.resolveLogger().Debug("serve signal", "sig", sig.String())
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
		// Drain any residual errors so the goroutines don't leak.
		<-errs
		<-errs
		return 0
	}
}

// newServeHandler builds the serve subcommand's DNS responder over the given
// name-to-address map. Split out of runServe so the answer and delay logic
// are unit-testable without binding sockets.
//
// A nonzero delay holds every response for that duration before writing it.
func newServeHandler(records map[string][]netip.Addr, delay time.Duration, log *slog.Logger) dns.Handler {
	ptrs := reverseRecords(records)
	return dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := &dns.Msg{}
		resp.SetReply(req)
		resp.Authoritative = true
		// NXDOMAIN tells a stub the name has no records of any type, which it
		// may cache negatively and apply to a parallel A lookup, so a served
		// name without the queried type gets NODATA instead.
		known := false
		for _, q := range req.Question {
			name := strings.ToLower(q.Name)
			if q.Qtype == dns.TypePTR {
				if len(ptrs[name]) > 0 {
					known = true
				}
				for _, target := range ptrs[name] {
					resp.Answer = append(resp.Answer, &dns.PTR{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypePTR,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						Ptr: target,
					})
				}
				continue
			}
			addrs, ok := records[name]
			if !ok {
				continue
			}
			known = true
			for _, a := range addrs {
				switch {
				case q.Qtype == dns.TypeA && a.Is4():
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						A: net.IP(a.AsSlice()),
					})
				case q.Qtype == dns.TypeAAAA && a.Is6() && !a.Is4In6():
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   q.Name,
							Rrtype: dns.TypeAAAA,
							Class:  dns.ClassINET,
							Ttl:    30,
						},
						AAAA: net.IP(a.AsSlice()),
					})
				}
			}
		}
		if !known {
			resp.Rcode = dns.RcodeNameError
		}
		// Query traces help diagnose lookups without adding noise at normal verbosity.
		for _, q := range req.Question {
			log.Debug("serve query",
				"name", q.Name,
				"qtype", dns.TypeToString[q.Qtype],
				"do", req.IsEdns0() != nil && req.IsEdns0().Do(),
				"rcode", dns.RcodeToString[resp.Rcode])
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		if err := w.WriteMsg(resp); err != nil {
			log.Warn("serve write reply failed", "err", err)
		}
	})
}

// reverseRecords indexes records by reverse name so PTR queries answer with
// the names their addresses were configured under. Targets are sorted so a
// shared address answers in a stable order regardless of map iteration.
func reverseRecords(records map[string][]netip.Addr) map[string][]string {
	out := map[string][]string{}
	for name, addrs := range records {
		for _, a := range addrs {
			arpa, err := dns.ReverseAddr(a.String())
			if err != nil {
				continue
			}
			arpa = strings.ToLower(arpa)
			out[arpa] = append(out[arpa], name)
		}
	}
	for _, targets := range out {
		slices.Sort(targets)
	}
	return out
}

// recordMap implements flag.Value so the --record flag can be repeated.
// The key is the FQDN with a single trailing dot, lowercased; values are
// the parsed addresses in argument order.
type recordMap struct {
	byName map[string][]netip.Addr
}

func (rm *recordMap) String() string {
	if rm == nil {
		return ""
	}
	var b strings.Builder
	first := true
	for k, vs := range rm.byName {
		if !first {
			b.WriteString(", ")
		}
		first = false
		for i, v := range vs {
			if i > 0 {
				b.WriteString(",")
			} else {
				fmt.Fprintf(&b, "%s=", k)
			}
			b.WriteString(v.String())
		}
	}
	return b.String()
}

func (rm *recordMap) Set(val string) error {
	eq := strings.IndexByte(val, '=')
	if eq <= 0 || eq == len(val)-1 {
		return fmt.Errorf("expected name=addr, got %q", val)
	}
	name := strings.ToLower(strings.TrimSpace(val[:eq]))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(val[eq+1:]))
	if err != nil {
		return fmt.Errorf("invalid address in %q: %w", val, err)
	}
	if rm.byName == nil {
		rm.byName = make(map[string][]netip.Addr)
	}
	rm.byName[name] = append(rm.byName[name], addr)
	return nil
}
