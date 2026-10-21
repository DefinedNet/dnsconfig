package windows

// Network Connectivity Status Indicator (NCSI) detects a captive portal when
// its HTTP probe returns unexpected content. NCSI treats a failed probe lookup
// as no internet and opens no sign-in prompt. An unreachable catch-all resolver
// would capture those lookups, so every catch-all goal publishes an NRPT
// exemption with no servers that leaves the fixed probe hosts on the
// interfaces' DNS.

// ncsiExemptHosts lists the sorted exact hostnames for Windows' current and
// earlier default probes. The sign-in prompt opens
// http://www.msftconnecttest.com/redirect. An administrator's custom probe
// host may resolve only internally, so it stays under the catch-all; exempting
// it could break detection by sending the probe to the network's DNS.
var ncsiExemptHosts = []string{
	"dns.msftncsi.com",
	"ipv6.msftconnecttest.com",
	"ipv6.msftncsi.com",
	"www.msftconnecttest.com",
	"www.msftncsi.com",
}
