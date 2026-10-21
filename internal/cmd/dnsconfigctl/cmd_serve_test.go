package main

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeResponseWriter is a minimal dns.ResponseWriter that captures the
// message WriteMsg was called with, so newServeHandler can be exercised
// in-process without binding sockets.
type fakeResponseWriter struct {
	msg *dns.Msg
}

func (f *fakeResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (f *fakeResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}

func (f *fakeResponseWriter) WriteMsg(m *dns.Msg) error { f.msg = m; return nil }
func (f *fakeResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}
func (f *fakeResponseWriter) Close() error        { return nil }
func (f *fakeResponseWriter) TsigStatus() error   { return nil }
func (f *fakeResponseWriter) TsigTimersOnly(bool) {}
func (f *fakeResponseWriter) Hijack()             {}

// discardLogger is the nil-safe logger the handler tests inject.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// serveTestRecords is the record map the handler tests share.
func serveTestRecords() map[string][]netip.Addr {
	return map[string][]netip.Addr{
		"sentinel.dnsconfig-smoke.example.": {netip.MustParseAddr("192.0.2.42")},
	}
}

// query runs one A query through the handler and returns the captured reply.
func query(t *testing.T, h dns.Handler, name string) *dns.Msg {
	t.Helper()
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	w := &fakeResponseWriter{}
	h.ServeDNS(w, req)
	require.NotNil(t, w.msg, "handler never wrote a reply")
	return w.msg
}

// TestServeHandlerAnswers confirms a matching A query gets the configured
// address back with rcode NOERROR.
func TestServeHandlerAnswers(t *testing.T) {
	h := newServeHandler(serveTestRecords(), 0, discardLogger())
	resp := query(t, h, "sentinel.dnsconfig-smoke.example")
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok, "answer is %T, want *dns.A", resp.Answer[0])
	assert.Equal(t, "192.0.2.42", a.A.String())
}

// TestServeHandlerNXDOMAIN confirms an unknown name gets NXDOMAIN.
func TestServeHandlerNXDOMAIN(t *testing.T) {
	h := newServeHandler(serveTestRecords(), 0, discardLogger())
	resp := query(t, h, "other.example")
	assert.Equal(t, dns.RcodeNameError, resp.Rcode)
	assert.Empty(t, resp.Answer)
}

// TestServeHandlerPTR confirms the reverse name of a configured record
// answers with the name that record was given for. The reverse-zone smoke row
// routes in-addr.arpa to the sentinel and asserts the PTR arrives, so the two
// halves must be derived from one another rather than configured separately.
func TestServeHandlerPTR(t *testing.T) {
	h := newServeHandler(serveTestRecords(), 0, discardLogger())

	req := &dns.Msg{}
	req.SetQuestion("42.2.0.192.in-addr.arpa.", dns.TypePTR)
	w := &fakeResponseWriter{}
	h.ServeDNS(w, req)
	require.NotNil(t, w.msg, "handler never wrote a reply")

	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
	require.Len(t, w.msg.Answer, 1)
	ptr, ok := w.msg.Answer[0].(*dns.PTR)
	require.True(t, ok, "answer is %T, want *dns.PTR", w.msg.Answer[0])
	assert.Equal(t, "sentinel.dnsconfig-smoke.example.", ptr.Ptr)
}

// TestServeHandlerPTRUnknownAddress confirms an unserved address still gets
// NXDOMAIN: the reverse zone the smoke row routes covers a whole /24, so the
// sentinel must not answer for addresses it was not given.
func TestServeHandlerPTRUnknownAddress(t *testing.T) {
	h := newServeHandler(serveTestRecords(), 0, discardLogger())

	req := &dns.Msg{}
	req.SetQuestion("43.2.0.192.in-addr.arpa.", dns.TypePTR)
	w := &fakeResponseWriter{}
	h.ServeDNS(w, req)
	require.NotNil(t, w.msg, "handler never wrote a reply")

	assert.Equal(t, dns.RcodeNameError, w.msg.Rcode)
	assert.Empty(t, w.msg.Answer)
}

// TestServeHandlerDelay confirms a nonzero delay holds the reply for at least
// that long. Only the lower bound is asserted; an upper bound would flake on
// a loaded test machine.
func TestServeHandlerDelay(t *testing.T) {
	const delay = 50 * time.Millisecond
	h := newServeHandler(serveTestRecords(), delay, discardLogger())
	start := time.Now()
	resp := query(t, h, "sentinel.dnsconfig-smoke.example")
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, delay, "reply written before the delay elapsed")
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

// TestServeHandlerNODATA confirms a served name queried for a type it has no
// record of gets NOERROR with no answers rather than NXDOMAIN, which a stub
// may cache as the name not existing and apply to the parallel lookup.
func TestServeHandlerNODATA(t *testing.T) {
	records := map[string][]netip.Addr{
		"v4.dnsconfig-smoke.example.": {netip.MustParseAddr("192.0.2.42")},
		"v6.dnsconfig-smoke.example.": {netip.MustParseAddr("2001:db8::42")},
	}
	h := newServeHandler(records, 0, discardLogger())

	cases := []struct {
		name  string
		qname string
		qtype uint16
	}{
		{name: "AAAA for IPv4-only name", qname: "v4.dnsconfig-smoke.example.", qtype: dns.TypeAAAA},
		{name: "A for IPv6-only name", qname: "v6.dnsconfig-smoke.example.", qtype: dns.TypeA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dns.Msg{}
			req.SetQuestion(tc.qname, tc.qtype)
			w := &fakeResponseWriter{}
			h.ServeDNS(w, req)
			require.NotNil(t, w.msg, "handler never wrote a reply")

			assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
			assert.Empty(t, w.msg.Answer)
		})
	}
}

// TestServeHandlerCaseInsensitive confirms a mixed-case query matches the
// record, since resolvers may randomize query-name case.
func TestServeHandlerCaseInsensitive(t *testing.T) {
	h := newServeHandler(serveTestRecords(), 0, discardLogger())
	resp := query(t, h, "Sentinel.DNSConfig-Smoke.Example")
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok, "answer is %T, want *dns.A", resp.Answer[0])
	assert.Equal(t, "192.0.2.42", a.A.String())
}
