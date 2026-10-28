// Package dnsconfig configures the operating system's DNS resolver on macOS
// and Windows. It does not resolve, forward, or cache DNS queries.
//
// # Configuration model
//
// [New] selects the native backend unless [Options] specifies ForceBackend.
// macOS uses synthetic SCDynamicStore keys and owned /etc/resolver files;
// Windows uses NRPT rules and a caller-controlled adapter's DNS settings.
// Applying and removing configuration requires root on macOS. Windows consumers
// are expected to run as LocalSystem so Group Policy changes can be notified
// directly; elevated Administrator operation falls back to a full policy
// refresh; see "Convergence and repair".
// On macOS, New declines DNS management for a process that is not root: it
// logs one Info line through Options.Logger, Set returns
// [ErrConfigurationDeclined], and Clear converges without touching the host.
// New logs a warning when the Windows process is not LocalSystem or its
// identity cannot be checked; construction still succeeds.
// The OS tools the backends invoke are resolved by absolute path and never
// through PATH. Unsupported platforms select [BackendNoop], which refuses
// [Manager.Set] unless explicitly forced.
//
// [Config] describes a replacement configuration. In split DNS, MatchDomains
// selects routed suffixes. Each SearchDomains entry must equal or be a
// subdomain of a MatchDomains entry.
// Empty MatchDomains selects catch-all routing and requires a nameserver that
// can answer every name, often a caller-run forwarder. Appending the host's
// nameservers does not compose namespaces: a negative answer can end resolution
// before another server is tried.
//
// On Windows, every catch-all also publishes an NRPT exemption with no servers
// for the default Network Connectivity Status Indicator (NCSI) probe hosts.
// Their exact names use the interfaces' DNS instead of the catch-all. NCSI
// cannot detect a captive portal if its probe lookup fails, so an unreachable
// catch-all resolver would otherwise hide the portal. The exemption is always
// on, and the interfaces' resolvers see those lookups. A portal served from
// its own hostname still needs the catch-all removed or a forwarder that can
// reach the local network's DNS.
//
// # Ownership and lifecycle
//
// [Options] requires an Identity that is stable across restarts and distinct
// for independent application instances. It scopes native artifacts and
// recovery. The caller owns the resolver, its network path, and, on Windows,
// the adapter's DNS settings. Keep them available until cleanup completes,
// including any resolver a replaced Config named, since a failed attempt can
// leave it configured. The library does not create interfaces or manage
// addresses, routes, or metrics.
//
// [New] neither applies nor reverts DNS; it starts one worker goroutine per
// Manager. [Manager.Set] records a Config as the goal and [Manager.Clear]
// records removal of this identity's configuration, including a crashed
// predecessor's artifacts. Both return at once. The worker applies the
// latest goal, retries failures with backoff, and repairs drift while a Set
// goal is live.
// [Manager.Status] reports the goal and the worker's progress toward it.
// There is no completion barrier and no callback; poll Status.
//
// Set returns only failures that retrying cannot fix: validation and
// platform-limit errors, [ErrClosed], [ErrConfigurationDeclined], and
// [ErrInterfaceRequired]. The host's answers, including [ErrConflict] and
// [ErrManagerAlreadyRunning], appear in Status.LastError and are retried. A
// failed attempt does not roll back, so between attempts the host can hold
// parts of the previous and new configurations.
//
// [Manager.Close] is the shutdown cleanup. It cancels an in-flight attempt,
// stops the worker, and, if a goal was recorded and no Clear converged since,
// attempts removal with a cancellation deadline of ShutdownTimeout, or
// [DefaultShutdownTimeout] when that is zero, before releasing resources.
// Synchronous Windows API calls can exceed that deadline; Close keeps the
// locks until cleanup returns. It is one-shot; a failed cleanup needs a fresh
// Manager's Clear. Recovery needs the same identity but no saved snapshot or
// Windows adapter name.
//
// Methods are safe for concurrent use and none waits for a converge, except
// that Close waits for an in-flight attempt to return. The worker takes an
// OS-released identity lock before its first attempt and keeps it until a
// Clear converges or Close finishes; when a goal is still owed and the worker
// does not hold the lock, Close tries for it once without waiting. While
// another live Manager holds that identity, attempts report
// [ErrManagerAlreadyRunning] and Close leaves its configuration in place
// without returning an error for it. Each attempt runs under a host lock
// shared by every dnsconfig process, which serializes conflict checks with
// the writes they admit. New and Status take neither lock. The no-op backend
// takes no host locks.
//
// Independent identities have equal standing. Claiming an exact routing domain
// or catch-all already published by another identity is refused with
// [ErrConflict] before mutation and retried, so ownership of a contended
// namespace goes to whichever identity publishes it first, with one macOS
// exception below: a later match domain takes routing for an exact domain
// that another identity only searches.
//
// macOS also publishes every search domain as an exact routing domain.
// A match domain's resolver file answers that exact domain ahead of any search
// entry, so a search domain does not conflict with another identity's match
// domain. Two identities may both search a domain only when one of those two
// has it as a match domain; a third identity's match domain does not count.
//
// Windows claims MatchDomains and the InterfaceName adapter. Parent/child
// suffixes are allowed; the DNS Client routes each name by its longest
// matching suffix.
//
// Each identity normally removes only its own artifacts. On Windows, a Group
// Policy NRPT container holding only dnsconfig rules is retired by rename and
// removed whole when every peer's rule is unstaged and has an identical local
// copy. A peer's staged rule blocks retirement even if it has a local copy.
// The retiring identity's own rules, staged or not, never block retirement:
// they are its own to remove. If foreign rules or values arrive during
// retirement, a Set attempt fails and the next one places rules for that
// policy, while a Clear goes on removing its own rules. The retired key is
// restored unless a new container exists; then it is deleted with those
// foreign rules and values, with a Warn naming them.
//
// # Convergence and repair
//
// Each attempt reads the host, writes only artifacts that differ from the
// goal, removes obsolete owned artifacts, and verifies installation. Matching
// artifacts with no owed side effects cause no writes, cache flushes, or policy
// notifications. On Windows, the first attempt with an adapter after taking
// the identity owes a reload and a subsequent cache flush even if values match:
// a predecessor may have exited between its adapter write and its reload.
//
// Repair is another attempt at the current goal. While a Set goal is live,
// backend change signals trigger repair after a short debounce, and a periodic
// check covers losses the signals miss. While the worker is backing off after
// a failure, signals wait and the periodic check is skipped until the retry
// runs, with one exception: a signal can end backoff after a failed Set
// attempt that wrote no artifact. This includes conflicts and Windows
// attempts that find local rules in place behind an empty Group Policy NRPT
// container. No artifact write of ours can have raised that signal. A
// completed side effect can raise one, but is not repeated, so it can end
// backoff at most once.
// When repeat attempts keep rewriting the host, the worker paces signal-driven
// attempts and logs each rewrite.
//
// Failed attempts retain owed cache flushes, adapter reloads, and policy
// notifications for retry. A failed adapter reload does not stop a Windows
// Clear from removing its rules, and once they are gone only a retry in the
// same process can finish the reload.
//
// macOS signals come from a scutil notification child watching configd's DNS
// keys. Windows signals come from machine-policy notifications and registry
// change notifications on both NRPT stores and the controlled adapter.
//
// Windows notifies Group Policy subscribers after an attempt changes Group
// Policy NRPT rules. LocalSystem uses GenerateGPNotification directly. Elevated
// Administrator callers fall back to RefreshPolicyEx, which requests a refresh
// of all machine policy. That request can succeed without delivering the change
// on a workgroup host or when a domain controller is unreachable. Removed rules
// can remain effective after Clear converges or Close returns nil, leaving DNS
// broken if the caller stops their resolver. A failed request is retried on
// backoff; an accepted one is not repeated. The worker's pacing is the only
// bound on how often repeat attempts request one.
//
// Installed settings affect only queries that use the OS resolver;
// applications with private resolvers or encrypted-DNS policy can bypass
// them. [Status] reports the worker's bookkeeping, not live query results or
// effective-policy readback. macOS retains intact settings when another
// resolver takes precedence.
//
// Change-signal source failures and Windows policy-delivery warnings are
// logged at Warn through Options.Logger. Converged and a nil Close confirm the
// library's artifact checks and accepted notification requests. Neither shows
// that the DNS Client has finished activating or removing the rules, even under
// LocalSystem. No fixed grace period makes the resolver safe to stop. Valid
// rules remain installed while activation is uncertain.
//
// Global and policy search lists remain unchanged and may shadow adapter
// suffixes. Short-name resolution may also depend on caller-managed adapter
// preference.
package dnsconfig
