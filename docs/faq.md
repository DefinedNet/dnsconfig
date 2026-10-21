# Frequently asked questions

Answers describe current macOS and Windows behavior. Each ends with the
evidence behind it; claims taken from reading OS or browser source rather than
from a live test say so.

## Do search domains expand names that contain a dot?

For example, does `service.host` expand to `service.host.example.com` with a search domain of `example.com`?

In general, no. Resolvers apply search domains only to single-label names such as `host`.

- **macOS / iOS**: No.
- **Windows**: No, by default. The "Allow DNS suffix appending to unqualified multi-label name queries" policy (`HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\AppendToMultiLabelName = 1`) changes this. Suffixes are then appended only if the dotted name fails to resolve as typed.

Instead, use the fully qualified name (`service.host.example.com`) or a single-label name.

For SSH, `CanonicalizeHostname yes` with `CanonicalDomains example.com` in `~/.ssh/config` expands dotted names on every platform.

Evidence: Microsoft's [DNS Client policy reference](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-dnsclient).

## Are CNAMEs in a public resolver which point into a match domain resolved?

For example, public DNS has `app.example.com CNAME app.corp.example`, and `corp.example` is a match domain.

The public resolver follows the CNAME first. If it can't resolve the record, it returns the CNAME with NXDOMAIN or no address. Whether the name resolves depends on whether the OS follows the CNAME again itself.

- **macOS / iOS**: Yes. mDNSResponder restarts the query using the CNAME target and picks a resolver for that new name, so the `corp.example` resolver answers it. It will follow up to 10 hops. This applies to `getaddrinfo` and the dnssd APIs, but not `dig`, `nslookup`, or apps that have their own DNS resolution code.
- **Windows**: No. The DNS Client doesn't look up the CNAME target again.

For names that must work on both, serve `app.example.com` from the private resolver, and make `app.example.com` (or `example.com`, if the private resolver answers the whole zone) a match domain.

Evidence: macOS from reading [mDNSResponder's source](https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSCore/mDNS.c) (`FollowCNAME` and `AnswerQuestionByFollowingCNAME` in `mDNSCore/mDNS.c`); not tested live.

## Does reverse DNS (PTR) for overlay IPs work?

Yes, if the reverse zones are match domains. Without them, PTR queries for overlay IPs go to the default resolver, which can't answer them and learns which addresses you looked up.

Reverse zones follow octet boundaries for IPv4 (`2.0.192.in-addr.arpa` for `192.0.2.0/24`) and nibble boundaries for IPv6 (`ip6.arpa`). A range that doesn't fall on a boundary needs one match domain per zone. For example, `100.64.0.0/10` needs 64 zones, from `64.100.in-addr.arpa` to `127.100.in-addr.arpa`.

Evidence: the split-DNS [smoke rows](testing.md) on both OSes route and verify the sentinel's reverse zone.

## Why does `dig`/`nslookup` fail while the browser works?

On macOS, `dig` and `nslookup` skip mDNSResponder and read `/etc/resolv.conf`, so they ignore match domains. `scutil --dns` and `dscacheutil -q host -a name <name>` show what the system resolves. Apps that read `resolv.conf` directly, including `dig`, only work with catch-all DNS (no match domains). Your resolver then receives every query, so it must answer or forward queries for all zones.

On Windows, `nslookup` skips NRPT, so it also ignores match domains. `Resolve-DnsName` shows what the system resolves.

Evidence: Apple's [dig manual](https://github.com/apple-oss-distributions/bind9/blob/main/bind9/bin/dig/dig.1) and [nslookup manual](https://github.com/apple-oss-distributions/bind9/blob/main/bind9/bin/dig/nslookup.1), and Microsoft's [Resolve-DnsName and nslookup comparison](https://techcommunity.microsoft.com/blog/networkingblog/resolve-dnsname-vs-nslookup-in-windows/4483858). The `nslookup` behavior on both OSes is documented tool behavior, not tested here.

## Why does my Go, Java, or Node app fail when the browser works?

The app is probably sending DNS queries itself instead of asking the OS. Split DNS lives in the OS resolver, so an app that queries servers directly never sees match domains.

- **Go**: The default resolver uses the system on macOS, even with `CGO_ENABLED=0`, and on Windows. A forced pure-Go resolver (`netgo` build tag, `GODEBUG=netdns=go`, or `Resolver.PreferGo`) reads `/etc/resolv.conf` on macOS instead. Run with `GODEBUG=netdns=1` to see which resolver is selected.
- **Node**: `dns.lookup()`, which `http` and most libraries use, asks the OS. `dns.resolve*()` sends queries itself and ignores match domains.
- **Java**: `InetAddress` asks the OS. JNDI DNS and dnsjava send queries themselves. So does Netty's DNS resolver; on macOS it follows match domains only when `io.netty:netty-resolver-dns-native-macos` is on the classpath (otherwise it logs "incorrect DNS resolutions on MacOS").

Evidence: [Go name resolution](https://pkg.go.dev/net#hdr-Name_Resolution), [Node.js DNS implementation](https://nodejs.org/api/dns.html#implementation-considerations), [JEP 418](https://openjdk.org/jeps/418), and Netty's [resolver selection](https://netty.io/4.1/xref/io/netty/resolver/dns/DnsServerAddressStreamProviders.html).

## Why do Chrome or Firefox ignore split DNS?

Usually they don't. Current versions of both browsers normally use the OS resolver when split DNS is configured. Some Secure DNS (DNS over HTTPS) settings bypass it:

- **Chrome / Edge**: In current versions, the default automatic mode uses the OS resolver when split DNS is configured. A custom Secure DNS provider sends every lookup to that provider, with no fallback.
- **Firefox**: With default or increased protection, private names go to the DoH provider first and usually fall back to the OS if it has no answer. Not every failure triggers the fallback, and the name is still sent to the provider. With max protection they fail. Current versions still use the OS for names under your search domains, and on Windows they turn default DoH off when split DNS is configured.

If a private name also exists publicly with a different address, any browser using DoH gets the public answer.

To fix it, turn off Secure DNS by policy: `DnsOverHttpsMode` set to `off` for Chrome and Edge, or `DNSOverHTTPS` with `Enabled: false` for Firefox.

Evidence: vendor documentation for [Chrome Secure DNS policy](https://chromeenterprise.google/policies/dns-over-https-mode/), [Firefox protection levels](https://support.mozilla.org/en-US/kb/dns-over-https), and [Firefox DNS policy](https://mozilla.github.io/policy-templates/#dnsoverhttps). The "current versions" claims come from reading Chromium and Firefox source and can change between releases; no browser is tested live.

## Why did internal names stop working with a DoH or DoT profile (MDM, NextDNS, corporate)?

System-wide encrypted DNS settings can take precedence over split DNS.

- **macOS**: An encrypted DNS configuration profile can bypass match domains entirely. The match domain still appears in `scutil --dns`, but queries never reach its resolver. Remove the profile, or ask whoever manages it to exclude your domains.
- **Windows**: The "Require DoH" policy blocks plain-DNS lookups, including split DNS. Set the policy to "Allow DoH" instead.

Evidence: Microsoft's [DoH policy settings](https://learn.microsoft.com/en-us/windows-server/networking/dns/doh-client-support#configuring-doh-through-group-policy). Apple's [DNS settings payload](https://developer.apple.com/documentation/devicemanagement/dnssettings/dnssettings-data.dictionary) documents domain selection for encrypted DNS.

## Does it work alongside another VPN (Tailscale, WireGuard, OpenVPN)?

Split DNS usually does. A catch-all often doesn't.

- **Your split domains, their catch-all**: This works. The OS uses the most specific match, so your domains still reach your resolver. Tailscale, for example, can install a catch-all. On Windows, a dnsconfig catch-all also exempts five exact NCSI hostnames. That exemption outranks a peer's suffix rule for those names.
- **Both claim the catch-all**: Only one is used, and neither OS decides by install order. macOS picks by its own internal ranking, which differed between macOS versions in testing; Windows picks by how each product names its rule. The other does nothing, with no error.
- **Both claim the same domain**: Only one is used, decided the same way. dnsconfig refuses this only between applications that use dnsconfig.
- **VPNs that filter DNS traffic**: WireGuard's Windows kill switch, OpenVPN's `block-outside-dns`, and similar filters drop DNS sent to any server but their own, including yours. DNS settings can't override a packet filter.
- **Windows Group Policy**: If an administrator or another product installs NRPT rules through Group Policy, Windows ignores locally installed rules. dnsconfig detects this and installs its rules through Group Policy too.
- **macOS**: When another resolver overrides one of dnsconfig's domains, dnsconfig leaves its own settings in place and does not report the override.

Evidence: Microsoft's [NRPT rule processing](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn593632%28v%3Dws.11%29#nrpt-rule-processing) documents namespace matching and policy precedence. [WireGuard firewall behavior](https://git.zx2c4.com/wireguard-windows/about/docs/netquirk.md) and [OpenVPN's Windows-specific options](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html#windows-specific-options-177179) document DNS filtering.

## Why can't I log into hotel or airport Wi-Fi while connected?

Captive portals need DNS before you've signed in. A catch-all that points at a resolver reachable only through the tunnel can't answer anything until the tunnel is up, and the tunnel can't come up until you sign in.

- **Split DNS** usually doesn't interfere, provided its match domains do not cover the probe or portal names.
- **On Windows**, a catch-all exempts five fixed Microsoft connectivity probe hosts, so Windows can detect the portal and open its sign-in prompt. The interfaces' DNS servers see those lookups. An administrator's custom probe host stays under the catch-all. A portal served from its own hostname still needs the catch-all removed or a forwarder that can reach the local network's DNS.
- **For catch-all**, if your application permits temporarily removing its DNS settings, call `Clear` and wait for `Status` to report `GoalClear` and `Converged`. Call `Set` again when the resolver and its network path are ready. Alternatively, use a forwarder that sends unmatched names to the local network's DNS server without going through the tunnel.

Evidence: [Windows captive-portal behavior](captive-portals.md#captive-portal-detection-on-windows) and the
[caller responsibilities](design.md#a-catch-all-needs-your-resolver-and-recovery-policy).

## How do I send different names to different resolvers?

For example: everything to `10.0.0.53`, but `corp.example` to `10.1.0.53`.

A `Config` sends every name it covers to one set of nameservers. It is either a catch-all (no match domains) or split DNS (one or more match domains). There are two ways to combine them.

### Multiple identities

Run one Manager for each set of nameservers, each with its own `Options.Identity`: for example, one catch-all identity and one split identity for `corp.example`. The OS picks which nameservers answer each name.

- dnsconfig does not sit in the query path, so installed settings keep sending queries to your resolvers until cleanup completes, even after a crash. Recover with a fresh Manager's Clear under the same identity.
- The OS keeps its caching, per-interface resolvers, and encrypted DNS settings.
- Two identities can't claim the same match domain, and only one can hold the catch-all. The second is refused with `ErrConflict` and retried. On Windows each identity also needs its own `InterfaceName` adapter, refused the same way when shared.
- A catch-all identity alongside a split identity has not been tested on either OS.

The OS limits described above still apply. Windows doesn't follow a public CNAME into a match domain, and macOS apps that read `/etc/resolv.conf` see only the catch-all.

### A catch-all forwarder

Install one catch-all that points at a DNS forwarder you run. The forwarder routes by name and sends unmatched names to the host's original resolver.

- It works around the OS limits: it follows CNAMEs into match domains itself, and apps that read `resolv.conf` get the same routing as everything else.
- A forwarder that reaches the local network's resolver before sign-in lets a portal served from its own hostname load. Your application still needs to handle network changes and test the sign-in flow.
- On Windows, a forwarder does not replace the NCSI exemption. NCSI resolves its probe hosts scoped to the interface it is probing, and under a catch-all those scoped lookups cannot reach a loopback forwarder (Windows 10 19045 failed them locally in testing), so the exemption is what keeps portal detection working.
- When its upstream is unreachable, the forwarder should answer at once, even with an error. On Windows, a preferred adapter whose resolver stays silent delayed exempt lookups, including the sign-in page, by about 12 seconds on Windows 10 19045 and Windows 11 26100.
- The forwarder handles queries routed through the catch-all. If it stops while those settings remain installed, those lookups can fail. Applications using their own resolvers may take a different path.
- It has to find the host's original resolver itself and re-read it when the network changes. dnsconfig doesn't report it. On Windows, a machine with several uplinks has no single answer.
- It must not forward to itself. Drop your own listen addresses from the upstream list, and answer SERVFAIL rather than falling back to the system resolver, which on a catch-all host is you.
- Queries sent onward to the original resolver are plain DNS, even if the uplink was configured for encrypted DNS.

### Which to choose

Use multiple identities if you only need routing. Use a forwarder if you need CNAMEs into match domains, `resolv.conf` apps, or captive portals to work while a catch-all is installed.
