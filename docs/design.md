# Design notes

dnsconfig installs DNS settings for your application's resolver. Your
application owns that resolver and its network path; the library owns applying,
repairing, and removing its settings. The [package documentation](../doc.go)
defines the API contract.

## One worker applies, retries, and repairs

`Set` and `Clear` record a goal for one worker, which handles application,
retries, and drift repair. Initial application and repair use the same path:
read the host, write only differences, and verify installation. Matching
settings with no owed side effects cause no writes, cache flushes, or policy
notifications. This prevents the library's own change notifications from
sustaining a write loop. Windows also needs a reload to cover an interrupted
predecessor; see [adapter reloads][adapter-reloads].

[adapter-reloads]: #windows-reloads-adapter-dns-through-the-local-nrpt-key

Change signals and periodic checks trigger repair. Backoff and repair pacing
limit repeated writes when something keeps undoing the configuration. An equal
`Set` or repeated `Clear` leaves the retry schedule intact; callers do not need
a second retry loop. Timing constants live in [manager.go](../manager.go).

## Failed attempts do not roll back

A failed attempt can leave some requested settings installed alongside settings
from the configuration it replaces. The worker retries toward the latest goal.
Restoring a snapshot would add another write path that can fail and would
restore superseded input. Replacement is not atomic, and the library does not
promise uninterrupted queries during it.

Owed cache flushes, adapter reloads, and policy notifications stay pending in
memory until completed. Three cases run them despite a failure: a Windows
Clear whose reload fails still deletes its rules and flushes (see
[adapter reloads][adapter-reloads]); a Windows Set failing only on an empty
Group Policy NRPT container still reloads the adapter, while its cache flush
waits for the container to go; and Close's final cleanup requests them despite
earlier failures (see [attribution][attribution]).

[attribution]: #clear-removes-only-what-it-can-attribute

## Identities are equal and exact conflicts are refused

A stable `Options.Identity` scopes configuration and recovery across restarts.
Use different identities for independently managed instances. Identities are
lowercase only: the lock file and the Windows registry resolve names
case-insensitively while artifact ownership compares exactly, so two spellings
of one identity would share a lock yet strand each other's artifacts. A
lifetime lock allows one applying Manager per identity; each attempt also
takes a host-wide lock around conflict checks and writes, including Windows
adapter reloads.

Another identity's exact routing-domain or catch-all claim refuses the whole
Set attempt before any write, including during repair. The worker reports
`ErrConflict` and retries. Windows checks match domains and the adapter.
Adapter values record no owner, so the adapter claim comes from another
identity's active or staged rule recording the same GUID.

On macOS, a search domain is also a State-key routing entry for that exact
domain, so it is checked too. An `/etc/resolver` file answers queries for its
domain and subdomains ahead of every State key for the same domain, regardless
of write order or the `order` shown by `scutil --dns`. This gives four cases:

- two match domains (resolver files) for one domain conflict;
- two catch-alls conflict;
- a search domain beside another identity's match domain for it does not;
- two identities may search the same domain only when one of them owns its
  resolver file, including a file the attempting identity is about to write.

A third identity's file cannot admit the pair: it could leave while both keys
stay. A parent domain's file does not cover a more specific search domain.

Set writes resolver files before State keys, and Set's cleanup and Clear
remove keys before files. This order avoids leaving a key beside a peer's
without the file that admitted the pair.

If key removal fails, or Close's final Clear cannot list the keys, Clear still
removes the files: holding them back would keep routing the domain to a
resolver that is likely gone. A peer whose key shares that domain is then
refused until this identity's next Clear, a configd restart, or a reboot
removes the key.

Parent and child domains may coexist; both platforms route a name by its most
specific match. A Windows catch-all's exemption is an exact-host rule for the
NCSI probe names, so it outranks any identity's suffix rule for those names.
Unequal priority is not supported.

These locks coordinate dnsconfig users. They do not exclude unrelated DNS
writers or guarantee compatibility with another VPN. Conflict detection covers
identifiable claims, not every possible competing resolver or traffic filter.

## A catch-all needs your resolver and recovery policy

Empty `MatchDomains` requests catch-all routing. Supply a resolver that answers
every name, often a forwarder you run. dnsconfig neither forwards queries nor
reports the host's base nameservers. A forwarder needs its own upstream source
and a way to update it when the network changes. Forwarding through the system
resolver while it points back at your listener can create a loop.

Appending nameservers does not combine namespaces: a negative answer can end
resolution before another server is tried. Use `MatchDomains` for split DNS,
leaving unrelated names with the host's DNS. A catch-all can prevent
captive-portal sign-in if its resolver is reachable only after the tunnel or
network is ready; dnsconfig does not detect portals or suspend settings.

On Windows, the Network Connectivity Status Indicator (NCSI) treats a failed
probe lookup as no internet, so an unreachable catch-all resolver can prevent
the sign-in prompt from opening. Every Windows catch-all therefore publishes
an NRPT exemption with no servers for the default probe hosts. Each name
matches an exact host, not a suffix. Custom probe hosts stay under the
catch-all because they may resolve only internally. The interfaces' DNS
servers see the exempt lookups; a portal's own hostname remains under the
catch-all. See [captive portals](captive-portals.md) for the host list and
sign-in limitations, and the [FAQ][portal-faq] for caller recovery choices.

[portal-faq]: faq.md#why-cant-i-log-into-hotel-or-airport-wi-fi-while-connected

Each attempt writes the exemption before the catch-all in each store. Clear
and replacement Set remove the catch-all before its exemption and stop at the
first failed deletion, so a surviving catch-all keeps its exemption. While
dnsconfig uses the Group Policy store, it puts the exemption there too: a
local-only exemption has no effect while that store is active. Split
configurations publish no exemption.

## Clear removes only what it can attribute

Identity is cleanup authority: reusing it deliberately permits removing a
predecessor's settings. `Clear` succeeds when it finds no artifacts
attributable to that identity and no side effects remain owed. This makes
startup recovery work on a clean host without granting permission to erase
unexplained settings; a value whose ownership evidence was lost stays in place.

Windows recovery records retain the controlled adapter's GUID until both IP
stacks finish cleanup. A successor can clear that adapter without knowing its
friendly name; it does not infer ownership from ordinary DNS values. An owned
rule with missing adapter metadata can be removed without authorizing adapter
cleanup. An unrelated empty Group Policy container is preserved too. These
boundaries protect other applications, even when broader cleanup might make
DNS work again. See
[adapter recovery](../internal/backend/windows/interface.go).

Close joins the worker before final cleanup, so the two cannot write
concurrently. If it must acquire the identity lock itself, it tries without
waiting: another live holder's configuration is meant to stay. Locks remain
held until cleanup returns, even when a synchronous Windows API call exceeds
`ShutdownTimeout`, so an unfinished call cannot race a successor.

Unlike ordinary retries, Close's final cleanup has no later attempt. It
requests owed side effects despite earlier failures while its context is
live. Windows completes three operations even after cancellation:

- A started reload trigger's set/delete pair.
- The empty-container check after deleting Group Policy rules, since an empty
  container would suppress local rules.
- Any owed policy notification in final cleanup, since no recovery record may
  remain for a successor to discover it.

See the [recovery example](../example_test.go) for recovery after a failed
Close.

## macOS owns separate keys and resolver files

macOS uses identity-scoped synthetic SCDynamicStore State keys for catch-all
and search settings, and owned `/etc/resolver/<domain>` files for split routing.
It never writes the primary service, so it has nothing to restore when this
identity leaves. It publishes every requested search suffix, including one the
primary service already supplies, so the keys hold the same suffixes on every
network and carry exactly the claims the conflict check makes. A suffix
published only when the network lacked it would be claimed but invisible to
other identities while the network supplied it, and would stay published after
the network gained it.

configd compiles requested search suffixes ahead of the primary service's
list, so they take precedence for short names. One identity's suffixes all go
in one State key because configd preserves order within a key but not between
keys; a list that does not fit one key is refused rather than split. The
relative order of different identities' suffixes is not specified. See
[Config.SearchDomains](../config.go) for duplicate handling and the
[macOS smoke runner](../internal/cmd/smoketest/runner_macos.go) for layout
assertions.

Each split search domain sits under a match domain, so its key routes the
domain to the same servers as the match file or catch-all. As an exact domain
it can outrank a foreign resolver more specific than either.

Resolver files are staged, synced, and renamed into place so neither an
interrupted write nor a power loss leaves a file without its ownership
header. Removals are followed by a directory sync, so a power loss after a
final Clear does not bring back a file routing its domain to a stopped
resolver. Renames are not, because a lost rename leaves the previous file or
none, and the next Set rewrites it. Clear discovers both published artifacts
and staging files.

scutil exits 0 even when configd does not answer, so its output must prove that
it read the store. Key lists and reads must contain recognized responses, and
compiled DNS output must contain a table under its header. The
no-configuration line is not accepted because scutil also prints it when
configd is unreachable. Otherwise an outage could pass for an empty store,
letting Clear release its lock or a conflict check admit unseen claims. See the
[macOS backend](../internal/backend/darwin/converge.go).

## Windows reloads adapter DNS through the local NRPT key

The DNS Client caches an adapter's `NameServer` and `SearchList` registry values
without watching them. Registry readback, including `Get-DnsClient`, can show
new values while queries still use the old ones. The backend triggers a reload
by setting and deleting a value on the local NRPT container key,
`Dnscache\Parameters\DnsPolicyConfig`, then requests a cache flush.

The trigger belongs on the container rather than a rule so it works even when
no local rule remains. It creates the key if absent; an empty local container
is harmless, unlike an empty Group Policy container. Group Policy writes do
not trigger this reload. A trigger value left by a crash routes nothing, and
the next reload overwrites and removes it. Deleting a local rule also triggers
a reload, so Clear needs no extra trigger after removing its rules.

The alternatives add constraints without establishing an activation barrier:
`ipconfig /registerdns` delays the reload and re-registers host addresses;
service control needs additional access; `SetInterfaceDnsSettings` is absent
on Server 2016 and did not make suffix changes immediately effective in
Server 2019 tests. Consumers still need to disable the adapter's own dynamic
registration, as described in [Options.InterfaceName](../options.go).

Every adapter write owes a reload, tracked in memory until a trigger succeeds.
The first attempt with an adapter after acquiring the identity owes one even
when values match, because a predecessor may have exited between its write and
reload. A converged Clear releases the identity, so a later Set owes one again.
One extra trigger per acquisition is cheap and avoids a separate durable record.

Clear reloads before deleting rules because their recovery records let a
successor find the adapter if the process exits first. A failed reload remains
pending but does not retain rules that route to a resolver the caller is
stopping. If the process then exits after deleting those records, a successor's
Clear cannot discover the owed reload; the change waits for Windows to reload
on its own. A failed reload does not hold back the flush, and every successful
reload owes another flush.

Reload and flush are asynchronous with respect to each other. A query can
still use old adapter values after the trigger, and an answer cached after the
flush but before the reload can survive until its TTL expires. Backend Set and
Clear attempts wait for their writes and side-effect requests to finish, not
for the DNS Client to apply them. Public `Set` and `Clear` only record the goal.

## Windows chooses the NRPT store from foreign policy

Windows has local and Group Policy NRPT stores. Any policy container, even an
empty one, makes the DNS Client ignore the local store. With foreign rules or
container values present, dnsconfig writes each rule to both stores: the policy
copy routes, and the local copy is ready for when the policy store goes away.
Without foreign policy, rules belong in the local store; a policy container
held by dnsconfig would suppress other applications' local rules. Other
dnsconfig identities do not count as foreign policy.

Removing a GPO deletes only what it wrote, so dnsconfig's policy copies keep
the container in effect after foreign policy leaves. Removing one identity's
policy copy alone would strand it on suppressed local rules. Local copies let
dnsconfig release the container in one step; they route once the DNS Client
re-reads policy after its removal. Policy processing triggers that read when
it removes a GPO's container outright.

See [Windows convergence](../internal/backend/windows/converge.go).

### Retiring the policy container

Once foreign policy leaves and every peer's policy rule has an identical local
copy, the next Set or Clear renames the container to
`DnsPolicyConfig-dnsconfig-retired` and deletes it. The rename takes every
policy copy out of effect in one step, including stopped identities' copies.
A crash cannot leave a partial policy table or an unattributed empty container
between those operations. Any identity can clean up a leftover retired key.
Until every peer is ready, for example while one is mid-write or lacks local
copies, an identity keeps its rules in both stores.

Foreign policy can arrive during retirement. If the retired key holds foreign
rules or values and no new container exists, dnsconfig restores it and fails
the attempt. If a new container exists, the retired key routes nothing and
cannot be restored. It is deleted with a warning naming the foreign rules and
values, because leaving it would block later retirements. The next attempt
places rules for the policy it finds.

### Empty policy containers

dnsconfig removes a container its own Clear empties. It preserves any other
empty container because nothing attributes it to dnsconfig. A crash or failed
delete can strand one if foreign policy leaves during Clear: the window is
between the last rule deletion and removal of the container it emptied.

With an empty container and a live policy watcher, Set installs the local
copies but reports `ErrGroupPolicyContainerEmpty` on every attempt so the goal
cannot stay Converged while the DNS Client ignores those copies. Repeat
attempts write nothing, so a change signal can end their backoff. Without a
live policy watcher, Set refuses before mutation: an unmonitored Group Policy
store could suppress the local copies without a repair ever noticing.

The adapter values stay installed and are reloaded despite the error. The
cache flush waits for the container to go, so it drops answers cached while
local rules were ignored. Keeping adapter values adds no exposure: Windows
sends a connection-specific suffix candidate only to that connection's servers.
A search suffix on an adapter without DNS servers therefore produces no query
while the local table is ignored. For a catch-all, the adapter's nameserver
keeps its queries on the configured resolver instead of only the physical
network's.

### Policy changes require notification

dnsconfig requests policy notification only for its own policy-store changes.
A manual deletion of an empty container is not dnsconfig's change, so it
triggers no notification from the library. The DNS Client's cached policy
table can still suppress the local copies until it is notified or restarted;
the error text asks for a reboot. Policy processing notifies when it removes
a container itself.

### Direct policy notification requires LocalSystem

LocalSystem is the supported Windows execution model because
`GenerateGPNotification` can notify the DNS Client directly after Group Policy
NRPT changes, without a domain controller. Elevated Administrator callers fall
back to `RefreshPolicyEx`, which requests all machine policy and reaches the
DNS Client only through a reachable domain controller. Join state is only a
proxy for delivery: a joined host with an unreachable controller gets no
delivery warning in the log.

An accepted notification is not proof of activation. Removed rules can remain
cached, and once their registry artifacts are gone, a fresh Manager's Clear
finds nothing to remove and requests no notification. This is why consumer
privileges matter even when registry writes succeed.

## Installed settings stay when selection is uncertain

Installed settings stay in place even when an application bypasses them or
another configuration takes precedence. Removing a valid contribution just
because it is not selected would also remove the possibility of using it when
the competing configuration leaves.

Successful artifact checks do not establish that queries use these settings.
Diagnose queries in the application that needs them.
