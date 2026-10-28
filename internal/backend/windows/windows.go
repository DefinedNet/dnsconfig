// Package windows implements the dnsconfig backend for Windows.
//
// It configures the system resolver through the Name Resolution Policy
// Table (NRPT): a set of registry rules the Windows DNS Client consults
// before its normal resolution path. Each rule names one or more DNS
// suffixes and the servers that should answer for them. The backend
// uses NRPT for both modes of operation:
//
//   - Catch-all (backend.Config.MatchDomains empty): the "." namespace routes
//     every query to the configured servers.
//   - Split DNS (non-empty backend.Config.MatchDomains): one rule per batch of
//     match domains routes those suffixes to the servers.
//
// A catch-all also publishes an exemption with no servers for the fixed
// Network Connectivity Status Indicator (NCSI) probe hosts, so portal
// detection can use the interfaces' DNS.
//
// Search domains and catch-all DNS servers are written only on the caller's
// controlled adapter. NRPT rules retain its GUID until adapter cleanup
// succeeds, so recovery does not depend on a snapshot store.
// Machine-global and policy suffix lists are left unchanged.
//
// There are two NRPT stores, and Windows does not merge them: while the
// Group Policy container exists, even empty, the machine-local table is
// ignored wholesale. Set and Clear are one-shot converges: each reads live state,
// writes only what differs, removes obsolete owned rules in either store,
// and returns. Placement follows foreign policy on every attempt. While
// foreign policy uses the GP store, each rule is written to both stores, so
// the local copy is ready when that store goes away; policy processing never
// removes our GP copies, so that happens only by retirement. Otherwise rules
// live only in the local store. Once foreign policy leaves, a container
// held only by dnsconfig rules, each with an identical local copy, is retired
// whole by one rename, since any rule left would keep the GP store in effect;
// until then an identity keeps its copy in both stores. Changes reports machine-policy
// notifications and registry changes that may call for another converge.
//
// Adapter value changes are applied by a value write on the local NRPT
// container key, which makes the DNS Client rebuild its adapter view, before
// the cache flush.
//
// GP mutations request a policy reload. LocalSystem sends a direct
// notification; an elevated administrator requests a full policy refresh.
// Notification delivery and monitoring failures are logged at Warn.
//
// Registry separates the backend logic from native Windows calls for testing.
package windows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner"
)

// Registry is the subset of the Windows registry this backend needs.
// Every keyPath is relative to HKEY_LOCAL_MACHINE and uses backslash separators.
type Registry interface {
	// GetString returns a REG_SZ value. It returns ErrValueNotFound when
	// either the key or the value is absent.
	GetString(keyPath, name string) (string, error)

	// SetString writes a REG_SZ value, creating keyPath if necessary.
	SetString(keyPath, name, data string) error

	// SetExistingString writes a REG_SZ value only when keyPath exists.
	// It returns ErrValueNotFound if the key disappeared.
	SetExistingString(keyPath, name, data string) error

	// KeyExists reports whether keyPath exists without creating it.
	KeyExists(keyPath string) (bool, error)

	// GetMultiString returns a REG_MULTI_SZ value. It returns
	// ErrValueNotFound when either the key or the value is absent.
	GetMultiString(keyPath, name string) ([]string, error)

	// GetDWord returns a REG_DWORD value, or ErrValueNotFound when absent.
	GetDWord(keyPath, name string) (uint32, error)

	// SetMultiString writes a REG_MULTI_SZ value, creating keyPath if
	// necessary.
	SetMultiString(keyPath, name string, data []string) error

	// SetDWord writes a REG_DWORD value, creating keyPath if necessary.
	SetDWord(keyPath, name string, data uint32) error

	// DeleteValue removes a value. Removing an absent value is not an
	// error.
	DeleteValue(keyPath, name string) error

	// CreateKey ensures keyPath exists.
	CreateKey(keyPath string) error

	// RenameKey publishes a populated key under a new sibling name.
	RenameKey(keyPath, newName string) error

	// DeleteKey removes keyPath and its values. The key is expected to
	// have no subkeys. Removing an absent key is not an error.
	DeleteKey(keyPath string) error

	// SubKeyNames returns the immediate child key names of keyPath. It
	// returns an empty slice and a nil error when keyPath is absent.
	SubKeyNames(keyPath string) ([]string, error)

	// ValueNames returns the value names directly under keyPath. It returns
	// an empty slice and a nil error when keyPath is absent.
	ValueNames(keyPath string) ([]string, error)
}

// PolicyNotifier requests that the Windows DNS Client reload Group Policy NRPT.
type PolicyNotifier interface {
	// NotifyPolicyChange asks Windows to re-read machine Group Policy. The
	// returned Delivery reports the request mechanism, not rule activation.
	// The error is nil only for DeliveryNotified.
	NotifyPolicyChange() (Delivery, error)
}

// Delivery reports the mechanism used to request a Group Policy reload.
type Delivery int

const (
	// DeliveryNone means no reload was requested successfully. Rules may take
	// effect on a later policy refresh or reboot.
	DeliveryNone Delivery = iota

	// DeliveryRefresh means RefreshPolicyEx accepted a full refresh request.
	// Delivery requires a reachable domain controller; workgroup hosts report
	// success without delivering the change. Domain membership is only a
	// heuristic for delivery; see machineIsDomainJoined.
	DeliveryRefresh

	// DeliveryNotified means GenerateGPNotification succeeded under
	// LocalSystem.
	DeliveryNotified
)

// String returns a stable identifier for the delivery tier, suitable for
// logging.
func (d Delivery) String() string {
	switch d {
	case DeliveryRefresh:
		return "policy-refresh"
	case DeliveryNotified:
		return "notified"
	case DeliveryNone:
		return "none"
	}
	// No default: the exhaustive linter fails the build when a tier is added
	// without a name here.
	return "none"
}

// ErrValueNotFound indicates a missing registry key or value.
var ErrValueNotFound = errors.New("windows: registry value not found")

const (
	// ipconfigExe is spelled with its extension so the target never depends
	// on PATHEXT.
	ipconfigExe = "ipconfig.exe"

	// nrptBase is the registry path of the local NRPT, relative to
	// HKEY_LOCAL_MACHINE.
	nrptBase = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`

	// Even an empty gpoNrptBase container suppresses nrptBase machine-wide.
	// dnsconfig removes it only by retiring a container its rules hold, or
	// when its own Clear empties it, and never touches the parent DNSClient
	// key, which can hold unrelated policy settings.
	gpoNrptBase = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	// retiredGPName is the sibling a collapsing identity renames the GP
	// container to. The DNS Client does not read it, and its name marks any
	// leftover as dnsconfig's to delete.
	retiredGPName = "DnsPolicyConfig-dnsconfig-retired"
	// gpoNrptName is gpoNrptBase's last element, for restoring a retired
	// container.
	gpoNrptName   = "DnsPolicyConfig"
	retiredGPBase = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\` + retiredGPName

	searchListValue = "SearchList"
	nameServerValue = "NameServer"

	// Rule names are libraryRulePrefix + identity + "-" + index. Staging
	// appends pendingRuleSuffix so the active key sorts first and identities
	// containing "pending" remain unambiguous.
	libraryRulePrefix = "dnsconfig-"
	pendingRuleSuffix = "-pending"

	// maxDomainsPerRule caps the DNS suffixes in a single NRPT rule, and
	// larger match-domain sets are split across rules. Microsoft documents
	// no per-rule limit; 50 is a conservative cap that has not been measured
	// against the DNS Client.
	maxDomainsPerRule = 50

	// nrptUseGenericServers is the ConfigOptions bit telling the DNS
	// Client to resolve matching names via GenericDNSServers.
	nrptUseGenericServers = 0x8

	// nrptVersion is the NRPT rule schema version.
	nrptVersion = 1
)

// Options configures New.
type Options struct {
	// WatchPolicy registers machine-policy notifications. Nil uses
	// RegisterGPNotification on Windows and reports monitoring as
	// unavailable elsewhere.
	WatchPolicy func() (Watcher, error)

	// WatchRegistry registers change notifications on the given keys. Nil
	// uses RegNotifyChangeKeyValue on Windows and reports monitoring as
	// unavailable elsewhere.
	WatchRegistry func([]RegistryWatchKey) (Watcher, error)

	// Identity names the application instance. It is required and scopes
	// NRPT rule names, recovery records, discovery, and cleanup.
	Identity string

	// Logger receives structured diagnostics. It is required.
	Logger *slog.Logger

	// IsLocalSystem checks the execution identity for the startup diagnostic.
	// Nil uses the process token on Windows and skips the check elsewhere.
	IsLocalSystem func() (bool, error)

	// Registry is the registry access layer. It is required.
	Registry Registry

	// Notifier delivers the Group Policy change notification. A nil
	// Notifier means the platform default: the real userenv.dll calls on
	// Windows, an inert notifier elsewhere.
	Notifier PolicyNotifier

	// DomainJoined supplies the delivery heuristic for DeliveryRefresh.
	// Nil uses NetGetJoinInformation on Windows and reports false elsewhere.
	DomainJoined func() (bool, error)

	// Runner runs ipconfig /flushdns to clear the DNS cache after a change.
	// A nil Runner means a real process runner.
	Runner runner.Runner

	// InterfaceName identifies the adapter whose DNS settings the caller controls
	// through cleanup. Set requires it. Clear does not: before this instance
	// has applied, recovery records identify the adapter to clear, so a caller
	// whose own configuration is lost can still clean the host.
	InterfaceName string

	// ResolveInterface maps a friendly adapter name to its GUID. Nil uses the
	// Windows adapter table. Tests inject a resolver without accessing the host.
	ResolveInterface func(string) (string, error)
}

// Backend is the Windows implementation of backend.Backend. Set, Clear, and
// Close must not overlap; ValidateConfig and Changes may be called at any
// time.
type Backend struct {
	watchFactory     func() (Watcher, error)
	regWatchFactory  func([]RegistryWatchKey) (Watcher, error)
	identity         string
	logger           *slog.Logger
	reg              Registry
	runner           runner.Runner
	interfaceName    string
	resolveInterface func(string) (string, error)
	notifier         PolicyNotifier
	// domainJoined supplies the notification-warning heuristic.
	domainJoined func() (bool, error)

	// changes carries coalesced change signals to the caller.
	changes chan struct{}

	// The fields from here to mu are touched only by Set and Clear, which
	// the Manager never runs concurrently.

	// adapterTarget is the adapter whose NameServer and SearchList this
	// instance still owes cleanup: one it wrote to, or a recorded
	// predecessor's adapter whose clear failed. It survives external record
	// deletion.
	adapterTarget *adapterTarget
	// flushOwed, registerOwed, and gpDirty are side effects owed by earlier
	// writes, or for registerOwed by a predecessor; they persist across
	// failed attempts until the flush or adapter reload succeeds or a policy
	// notification request is accepted.
	flushOwed    bool
	registerOwed bool
	gpDirty      bool
	// reloaded reports that a reload has succeeded since this instance took
	// the identity, which settles any reload a predecessor left owed. A
	// converged Clear resets it with the identity.
	reloaded bool

	// mu guards the lifecycle and signal sources.
	mu        sync.Mutex
	closed    bool
	policySrc *source
	regSrc    *source
}

// New constructs a Windows Backend. It starts no notification source; Set
// does.
func New(_ context.Context, opts Options) (*Backend, error) {
	if opts.Registry == nil {
		return nil, errors.New("windows.New: Options.Registry is required")
	}
	if err := backend.ValidateIdentity(opts.Identity); err != nil {
		return nil, fmt.Errorf("windows: Options.Identity: %w", err)
	}
	if opts.Logger == nil {
		return nil, errors.New("windows.New: Options.Logger is required")
	}
	logger := opts.Logger
	checkIdentity := opts.IsLocalSystem
	if checkIdentity == nil {
		checkIdentity = newDefaultLocalSystemCheck()
	}
	if checkIdentity != nil {
		system, err := checkIdentity()
		switch {
		case err != nil:
			logger.Warn("windows: could not verify execution identity; DNS configuration expects LocalSystem", "error", err)
		case !system:
			logger.Warn("windows: DNS configuration expects LocalSystem; running without it is best effort, and Group Policy DNS rules may remain effective after cleanup")
		}
	}
	r := opts.Runner
	if r == nil {
		r = runner.ExecRunner{}
	}
	notifier := opts.Notifier
	if notifier == nil {
		notifier = newDefaultNotifier()
	}
	domainJoined := opts.DomainJoined
	if domainJoined == nil {
		domainJoined = newDefaultDomainJoin()
	}
	resolve := opts.ResolveInterface
	if resolve == nil {
		resolve = resolveSystemInterface
	}
	policyWatch := opts.WatchPolicy
	if policyWatch == nil {
		policyWatch = newDefaultPolicyWatcher
	}
	regWatch := opts.WatchRegistry
	if regWatch == nil {
		regWatch = newDefaultRegistryWatcher
	}
	return &Backend{
		watchFactory:     policyWatch,
		regWatchFactory:  regWatch,
		identity:         opts.Identity,
		logger:           logger,
		reg:              opts.Registry,
		runner:           r,
		interfaceName:    opts.InterfaceName,
		resolveInterface: resolve,
		notifier:         notifier,
		domainJoined:     domainJoined,
		changes:          make(chan struct{}, 1),
	}, nil
}

// Changes returns the coalesced change signal. It is closed by Close.
func (b *Backend) Changes() <-chan struct{} { return b.changes }

// Close stops and joins every notification source and closes the Changes
// channel without changing registry state. The public Manager runs Clear
// first when this instance may have installed configuration.
func (b *Backend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	sources := []*source{b.policySrc, b.regSrc}
	b.policySrc, b.regSrc = nil, nil
	b.mu.Unlock()
	var errs []error
	for _, s := range sources {
		if s != nil {
			errs = append(errs, s.stop())
		}
	}
	// Every forwarder has exited, so nothing can send on the channel now.
	close(b.changes)
	return errors.Join(errs...)
}

// ownedRuleNames lists this identity's active and staged rule names
// under base.
func (b *Backend) ownedRuleNames(base string) ([]string, error) {
	names, err := b.reg.SubKeyNames(base)
	if err != nil {
		return nil, fmt.Errorf("windows: list NRPT rules under %s: %w", base, err)
	}
	var out []string
	for _, name := range names {
		if identity, _, _, ok := parseRuleName(name); ok && identity == b.identity {
			out = append(out, name)
		}
	}
	return out, nil
}

// writeStagedRule writes recovery metadata before the rule body so a
// usable staged rule identifies its adapter. Recovery ignores incomplete
// staged metadata because no adapter writes can have followed it.
func (b *Backend) writeStagedRule(base string, idx int, rule nrptRule, target adapterTarget) error {
	key := b.ruleKey(base, idx, true)
	if err := b.reg.CreateKey(key); err != nil {
		return fmt.Errorf("windows: create NRPT rule key: %w", err)
	}
	return b.populateRule(key, rule, target)
}

// populateRule writes a rule's values under key.
func (b *Backend) populateRule(key string, rule nrptRule, target adapterTarget) error {
	if err := b.writeTarget(key, target); err != nil {
		return err
	}
	if err := b.reg.SetDWord(key, "Version", nrptVersion); err != nil {
		return fmt.Errorf("windows: write NRPT Version: %w", err)
	}
	if err := b.reg.SetMultiString(key, "Name", rule.domains); err != nil {
		return fmt.Errorf("windows: write NRPT Name: %w", err)
	}
	if err := b.reg.SetString(key, "GenericDNSServers", rule.servers); err != nil {
		return fmt.Errorf("windows: write NRPT GenericDNSServers: %w", err)
	}
	if err := b.reg.SetDWord(key, "ConfigOptions", nrptUseGenericServers); err != nil {
		return fmt.Errorf("windows: write NRPT ConfigOptions: %w", err)
	}
	return nil
}

// reload makes the DNS Client apply pending adapter values. The DNS Client
// does not watch the adapter interface keys, but a value write on the local
// NRPT container key makes it re-read them, with or without rules under the
// key and under a Group Policy container; writes under the Group Policy key
// do not. The trigger goes on the container key rather than a rule so it
// works when this identity has no rule left. The key is created when absent:
// an empty local container has no effect, since only the Group Policy
// container suppresses the local table. The reload lands on the DNS Client's
// own schedule; see refreshDNS.
func (b *Backend) reload(ctx context.Context, mut *mutation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.reg.SetString(nrptBase, reloadTriggerValue, "1"); err != nil {
		return fmt.Errorf("windows: trigger adapter reload: %w", err)
	}
	if err := b.reg.DeleteValue(nrptBase, reloadTriggerValue); err != nil {
		// The value left on the key is a write of ours that the registry
		// watcher reports, so the attempt must not count as refused, or
		// that signal would end its backoff every time.
		mut.started = true
		return fmt.Errorf("windows: trigger adapter reload: %w", err)
	}
	b.registerOwed = false
	b.reloaded = true
	b.flushOwed = true
	return nil
}

// refreshDNS flushes the DNS cache after changing resolver settings. The DNS
// Client applies a reload asynchronously, so an immediate flush can precede it
// under load and leave answers cached until their normal expiry; waiting for
// the reload would delay every converge. A failure carries both output
// streams, since ipconfig does not reliably put its error text on stderr.
func (b *Backend) refreshDNS(ctx context.Context) error {
	// Fail rather than fall back to a bare name: a silent downgrade to the
	// $PATH lookup is the wrong move exactly when the environment is already
	// behaving unexpectedly.
	exe, err := systemPath()
	if err != nil {
		return fmt.Errorf("windows: resolve system directory: %w", err)
	}
	stdout, stderr, err := b.runner.Run(ctx, exe, []string{"/flushdns"}, nil)
	if err != nil {
		out := strings.TrimSpace(strings.TrimSpace(string(stdout)) + " " + strings.TrimSpace(string(stderr)))
		return fmt.Errorf("windows: DNS cache flush failed: %w (%s)", err, out)
	}
	return nil
}

// nrptRule is one NRPT rule's routing values.
type nrptRule struct {
	domains []string
	// servers is the GenericDNSServers list; empty exempts the domains from
	// every other rule, leaving them on the interfaces' DNS.
	servers string
}

// desiredRules returns cfg's rules in index order. The catch-all is rule 0
// and the NCSI exemption rule 1, so the exemption shares the staging,
// removal, verification, and recovery paths of every owned rule.
func desiredRules(cfg backend.Config) []nrptRule {
	servers := joinAddrs(cfg.Nameservers)
	var rules []nrptRule
	for _, domains := range nrptDomainBatches(cfg.MatchDomains) {
		rules = append(rules, nrptRule{domains: domains, servers: servers})
	}
	if len(cfg.MatchDomains) == 0 {
		rules = append(rules, nrptRule{domains: ncsiExemptHosts})
	}
	return rules
}

// nrptDomainBatches converts match domains into NRPT namespace strings
// and splits them into rule-sized batches. An empty match list yields a
// single catch-all batch containing only ".".
func nrptDomainBatches(match []string) [][]string {
	if len(match) == 0 {
		return [][]string{{"."}}
	}
	domains := make([]string, 0, len(match))
	for _, d := range match {
		domains = append(domains, nrptDomain(d))
	}
	sort.Strings(domains)

	var batches [][]string
	for len(domains) > 0 {
		n := min(len(domains), maxDomainsPerRule)
		batches = append(batches, domains[:n])
		domains = domains[n:]
	}
	return batches
}

// ruleName builds this identity's idx-th rule key name, staged or active.
func (b *Backend) ruleName(idx int, pending bool) string {
	name := libraryRulePrefix + b.identity + "-" + strconv.Itoa(idx)
	if pending {
		name += pendingRuleSuffix
	}
	return name
}

// ruleKey is the registry path of this identity's idx-th rule under base.
func (b *Backend) ruleKey(base string, idx int, pending bool) string {
	return base + `\` + b.ruleName(idx, pending)
}

// sortRuleNames orders owned rule names by index, each active rule before
// its staged copy. Registry enumeration order is not guaranteed, and a
// lexical sort would put index 10 before 2.
func sortRuleNames(names []string) {
	sort.SliceStable(names, func(i, j int) bool {
		_, a, ap, _ := parseRuleName(names[i])
		_, b, bp, _ := parseRuleName(names[j])
		if a != b {
			return a < b
		}
		return !ap && bp
	})
}

// parseRuleName splits a library rule key name into identity, index, and
// whether it is staged. Names outside the shape report false.
func parseRuleName(name string) (identity string, idx int, pending bool, ok bool) {
	if !strings.HasPrefix(name, libraryRulePrefix) {
		return "", 0, false, false
	}
	rest := strings.TrimPrefix(name, libraryRulePrefix)
	if strings.HasSuffix(rest, pendingRuleSuffix) {
		rest = strings.TrimSuffix(rest, pendingRuleSuffix)
		pending = true
	}
	cut := strings.LastIndexByte(rest, '-')
	if cut <= 0 {
		return "", 0, false, false
	}
	// Only the form ruleName renders is ours; accepting "+5" or "007" would
	// let another writer's key pass as an owned rule.
	idx, err := strconv.Atoi(rest[cut+1:])
	if err != nil || idx < 0 || strconv.Itoa(idx) != rest[cut+1:] {
		return "", 0, false, false
	}
	return rest[:cut], idx, pending, true
}

// checkConflicts refuses exact namespace matches with another identity, and
// an adapter another identity's rule records: adapter values carry no owner,
// so two identities on one adapter would overwrite each other's values and
// either one's Clear would delete the survivor's. Staged rules count because
// they can already route queries, and they record the adapter before their
// Name. Overlapping suffixes remain subject to the DNS Client's ordering.
func (b *Backend) checkConflicts(cfg backend.Config, target adapterTarget) error {
	holders := map[string]string{}
	adapterHolder := ""
	for _, base := range []string{nrptBase, gpoNrptBase} {
		names, err := b.reg.SubKeyNames(base)
		if err != nil {
			return fmt.Errorf("windows: list NRPT rules under %s: %w", base, err)
		}
		for _, name := range names {
			identity, _, _, ok := parseRuleName(name)
			if !ok || identity == b.identity {
				continue
			}
			key := base + `\` + name
			guid, err := b.reg.GetString(key, interfaceGUIDValue)
			switch {
			case errors.Is(err, ErrValueNotFound):
			case err != nil:
				return fmt.Errorf("windows: read adapter recorded by %s: %w", name, err)
			case adapterHolder == "" && strings.EqualFold(guid, target.guid):
				adapterHolder = identity
			}
			namespaces, err := b.reg.GetMultiString(key, "Name")
			// A rule without Name routes nothing: its owner crashed mid-write
			// or deleted it after the listing. Refusing on it would stall every
			// identity until the owner runs again.
			if errors.Is(err, ErrValueNotFound) {
				continue
			}
			if err != nil {
				return fmt.Errorf("windows: read namespaces of %s: %w", name, err)
			}
			for _, ns := range namespaces {
				ns = strings.ToLower(ns)
				if _, taken := holders[ns]; !taken {
					holders[ns] = identity
				}
			}
		}
	}
	for _, batch := range nrptDomainBatches(cfg.MatchDomains) {
		for _, ns := range batch {
			if holder, ok := holders[strings.ToLower(ns)]; ok {
				domain := "."
				if ns != "." {
					domain = strings.TrimPrefix(ns, ".")
				}
				return backend.NewConflictError(domain, holder)
			}
		}
	}
	if adapterHolder != "" {
		return &adapterConflictError{name: b.interfaceName, guid: target.guid, holder: adapterHolder}
	}
	return nil
}

// adapterConflictError reports an adapter another identity's rule records.
// It is not a ConflictError, whose Domain is a DNS name.
type adapterConflictError struct {
	name, guid string
	holder     string
}

func (e *adapterConflictError) Error() string {
	return fmt.Sprintf("adapter %q (%s) held by identity %q", e.name, e.guid, e.holder)
}

// Is matches ErrConflict, so callers and the Manager treat the refusal like a
// domain conflict.
func (e *adapterConflictError) Is(target error) bool { return target == backend.ErrConflict }

// nrptDomain converts a domain to the NRPT namespace form. A leading dot
// marks a suffix match (the suffix and all of its subdomains).
func nrptDomain(domain string) string {
	return "." + domain
}

// joinAddrs renders addresses as the semicolon-separated list NRPT's
// GenericDNSServers value expects.
func joinAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ";")
}
