# Captive portals

## Terminology

- **NRPT**: Name Resolution Policy Table, where Windows stores DNS routing
  rules.
- **NCSI**: Network Connectivity Status Indicator, the Windows component that
  determines network connectivity status (Internet, local only, captive).

## Captive portal types

There are different kinds of captive portals. Primarily:

| Name            | Use case                                                            | Typical vendors                                                           |
| --------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Restricted**  | Firewall-based portals, transit, campus Wi-Fi                       | Aruba (reference design), pfSense, OPNsense, CoovaChilli (default)        |
| **Intercepted** | Small-venue and hotel gateways                                      | UniFi, MikroTik Hotspot, Nomadix                                          |
| **Open**        | Enterprise guest Wi-Fi                                              | Cisco Catalyst 9800 (default ACL), Meraki (with "allow non-HTTP traffic") |
| **Forged**      | Setup portals on IoT and embedded devices (e.g. ESP32 example code) | No hotspot vendors                                                        |

They differ by how they behave before and after login:

| Name            | DNS before login                                                                                       | HTTP before login                                   | Everything else before login                                  | After login                                                 |
| --------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------- |
| **Restricted**  | Traffic to any resolver other than the network's is dropped                                            | Port 80 is intercepted and redirected to the portal | Dropped, except walled-garden destinations                    | Unrestricted, including any resolver                        |
| **Intercepted** | Queries to any resolver are transparently DNATed to the network's resolver, which returns real answers | Port 80 is intercepted and redirected to the portal | Dropped, except walled-garden destinations                    | DNS redirection often continues, other traffic unrestricted |
| **Open**        | Queries to any resolver are allowed and return real answers                                            | Port 80 is intercepted and redirected to the portal | Dropped, or allowed in Meraki's "allow non-HTTP traffic" mode | Unrestricted                                                |
| **Forged**      | Queries to the network's resolver all resolve to the portal address, other resolver traffic dropped    | The portal answers every request to any host        | Dropped, there is no Internet route                           | Typically an IoT device: no Internet connection             |

## Captive portal detection on Windows

On network changes and periodically afterwards, NCSI resolves
`www.msftconnecttest.com` (by default) using the Windows DNS Client, which
applies NRPT rules, and fetches `connecttest.txt`. It asserts that the device
is captive if the response comes back wrong (redirect, portal HTML, any
unexpected content) and opens a browser to `www.msftconnecttest.com/redirect`.
While the probe domain can be overridden using a registry key
(`HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet`), the
browser always opens to `www.msftconnecttest.com/redirect`.

A failure to resolve the probe domain is not considered captive. If the
installed DNS resolver is unreachable due to network captivity, NCSI reports
"No Internet access" instead of "Action needed."

On a new network, Windows 10's NCSI stops after its second failed probe,
measured 32-43s after link-up, until the next network change. If it previously
saw Internet on the network, it continues to probe indefinitely. In order to
get a login prompt to appear on a new network, you must act quickly to fix the
situation (e.g. temporarily removing an unreachable catch-all DNS resolver from
the system) - or make an additional network change to trigger NCSI detection
(e.g. disable/re-enable an adapter).

### Split DNS vs. catch-all

Split DNS configurations (installed using match domains) do not affect captive
portal detection or login - as long as they don't register
`msftconnecttest.com`, `msftncsi.com`, the portal's hostname, anything its
login page loads as a match domain, or a parent of any of them (e.g. `.com`).

Catch-all DNS configurations consist of two settings: a `.` rule in the NRPT
table and DNS servers on the consumer's controlled adapter. This routes all
domains, including the probe domain.

### Catch-all captive portal detection issues

A catch-all DNS resolver other than the network's creates issues with captive
portal detection:

- On **Restricted** networks, captive portal checks will fail if the system
  has any DNS resolver configured other than the network's, because Windows
  will fail to resolve the probe domain through the configured resolver; in
  this case Windows shows "No Internet access."
- On **Open** networks, captive portal checks fail the same way when the
  configured DNS resolver is only reachable over the tunnel, because queries
  will not traverse the network. If resolution _does_ succeed, the probe will
  successfully detect captivity because of port 80 interception, but
  redirect-based login flows can still fail - since Windows resolves the
  portal domain without interface scoping, the DNS resolver must also be able
  to resolve the captive login domain (often only resolvable from the
  network's resolver); some **Open** networks redirect to a public hostname or
  an IP address to avoid this issue.
- On **Intercepted** networks, captive portal checks fail the same way when
  the configured DNS resolver is only reachable over the tunnel, because its
  queries never reach the gateway. A resolver reached over the network
  performs best: the gateway redirects every port-53 query to its own
  resolver, so the probe domain resolves, captivity is detected, and the
  portal's hostname resolves for the sign-in page.

### NRPT exemption

You can exempt NCSI's names from a catch-all by registering an NRPT rule for
them with no nameservers. The most specific rule wins, so these names skip the
`.` rule and fall through to ordinary adapter resolution, which on a captive
network reaches the network's DNS. The rule must use the generic form
(`ConfigOptions=8` with an empty `GenericDNSServers`) or the DirectAccess form
(`ConfigOptions=4`). On hosts where Group Policy NRPT rules exist, the
exemption must be in the policy store, followed by a policy refresh
notification. The exempt names should cover both the probe hosts (default or
overridden) and `www.msftconnecttest.com` for the prompt. Exempting an
overridden name can be dangerous if NRPT rules already exist for it.
dnsconfig exempts only the exact default hosts `www.msftconnecttest.com`,
`ipv6.msftconnecttest.com`, and `dns.msftncsi.com`, plus the earlier defaults
`www.msftncsi.com` and `ipv6.msftncsi.com`. A custom probe host may resolve only
internally, so it stays under the catch-all. The interfaces' DNS servers see
the exempt lookups.

With this exemption in place, Windows 10 and Windows 11 both detected the
portal about a second after joining (with the tunnel adapter not preferred)
and opened the sign-in prompt, with the catch-all still installed. On
Windows 10, adding the exemption also revived detection after NCSI had stopped
probing, without a network change.

The exemption only covers NCSI's names. A portal that redirects to its own
hostname instead of an IP address, or a login page that loads from other
hosts, still fails to load until the catch-all is removed.

NCSI scopes its own lookups to the interface it is probing, so detection works
even when the tunnel adapter is preferred (measured on Windows 10 and
Windows 11). The browser's lookup for the prompt page is not scoped: if the
preferred tunnel adapter also has the catch-all's unreachable resolver as its
DNS server, Windows waits for that resolver to time out, and the sign-in page
opens about 12s late. Leaving the adapter's DNS servers unset removed the
delay in testing; dnsconfig keeps them for catch-all DNS.
