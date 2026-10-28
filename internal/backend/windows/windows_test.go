package windows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner/runnertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testGUID      = "{00000000-0000-0000-0000-000000000001}"
	testIdentity  = "test-app"
	otherIdentity = "other-app"
	testInterface = "test-adapter"
	tcpipKey      = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
)

func newTestBackend(ctx context.Context, opts Options) (*Backend, error) {
	opts.Identity = testIdentity
	opts.InterfaceName = testInterface
	opts.ResolveInterface = func(string) (string, error) { return testGUID, nil }
	if opts.Logger == nil {
		opts.Logger = discardLogger()
	}
	if opts.Runner == nil {
		opts.Runner = &runnertest.FakeRunner{}
	}
	if opts.DomainJoined == nil {
		opts.DomainJoined = func() (bool, error) { return false, nil }
	}
	if opts.Notifier == nil {
		opts.Notifier = &fakeNotifier{delivery: DeliveryNotified}
	}
	if opts.WatchPolicy == nil {
		opts.WatchPolicy = func() (Watcher, error) { return newFakeWatcher(), nil }
	}
	if opts.WatchRegistry == nil {
		opts.WatchRegistry = func([]RegistryWatchKey) (Watcher, error) { return newFakeWatcher(), nil }
	}
	return New(ctx, opts)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// TestExecutionIdentityWarningAtFirstWrite checks that the LocalSystem
// diagnostic waits for the first write, so a process that only constructs a
// backend or clears an empty host logs nothing, and that it is logged once.
func TestExecutionIdentityWarningAtFirstWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		system bool
		err    error
		want   string
	}{
		{name: "LocalSystem", system: true},
		{name: "other identity", want: "running without it is best effort"},
		{name: "token read fails", err: errors.New("token unavailable"), want: "could not verify execution identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			reg := newFakeRegistry()
			calls := 0
			ctx := context.Background()
			b, err := newTestBackend(ctx, Options{
				Registry: reg,
				Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
				IsLocalSystem: func() (bool, error) {
					calls++
					return tc.system, tc.err
				},
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = b.Close() })
			require.NoError(t, b.clearGoal(ctx))
			assert.Empty(t, reg.writes, "an empty host gives Clear nothing to write")
			assert.Zero(t, calls, "nothing written, nothing checked")
			assert.NotContains(t, logs.String(), "LocalSystem")

			require.NoError(t, b.setGoal(ctx, catchAll(t)))
			require.NoError(t, b.clearGoal(ctx))
			require.NoError(t, b.setGoal(ctx, catchAll(t)))
			require.NoError(t, b.Close())
			assert.Equal(t, 1, calls)
			if tc.want == "" {
				assert.NotContains(t, logs.String(), "level=WARN")
				return
			}
			assert.Equal(t, 1, strings.Count(logs.String(), "level=WARN"), logs.String())
			assert.Contains(t, logs.String(), tc.want)
			if tc.err != nil {
				assert.Contains(t, logs.String(), tc.err.Error())
			}
		})
	}
}

func TestNewRequiresLogger(t *testing.T) {
	_, err := New(context.Background(), Options{Identity: testIdentity, Registry: newFakeRegistry()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Options.Logger is required")
}

// fakeRegistry is an in-memory Registry. Keys are flat backslash paths;
// a key exists once any value is written to it or CreateKey names it.
// Creating a key materializes its ancestors, as the real registry does, so
// tests can observe whether a container key survives its last subkey.
// writes logs every mutating call, including ones that change nothing.
// reloads counts adapter reload triggers; failReload fails them before the
// trigger is written and failReloadDelete after, leaving the value behind.
type fakeRegistry struct {
	keys             map[string]map[string]any // keyPath -> valueName -> string|[]string|uint32
	writes           []string
	reloads          int
	failReload       error
	failReloadDelete error
	// fail, when set, runs at the start of every Registry method with the
	// method's name, key path, and value name; a non-nil result fails the
	// call without touching the fake. Assertion helpers such as hasKey and
	// ourRuleNames bypass it, but a test's own Registry calls do not, so
	// a hook should match only the call it fails.
	fail func(op, keyPath, name string) error
}

func (r *fakeRegistry) check(op, keyPath, name string) error {
	if r.fail == nil {
		return nil
	}
	return r.fail(op, keyPath, name)
}

// fake returns the registry itself, so a wrapper that embeds it hands the
// underlying fake to a harness.
func (r *fakeRegistry) fake() *fakeRegistry { return r }

// fakeHolder is satisfied by every registry wrapper that embeds fakeRegistry.
type fakeHolder interface {
	fake() *fakeRegistry
}

func newFakeRegistry() *fakeRegistry {
	r := &fakeRegistry{keys: map[string]map[string]any{}}
	for _, path := range adapterPaths(testGUID) {
		r.ensure(path)
	}
	return r
}

func (r *fakeRegistry) logWrite(op, keyPath, name string) {
	r.writes = append(r.writes, op+" "+keyPath+" "+name)
}

func (r *fakeRegistry) ensure(keyPath string) map[string]any {
	if v, ok := r.keys[keyPath]; ok {
		return v
	}
	if i := strings.LastIndexByte(keyPath, '\\'); i > 0 {
		r.ensure(keyPath[:i])
	}
	v := map[string]any{}
	r.keys[keyPath] = v
	return v
}

// hasKey reports whether keyPath exists, for assertions about container keys.
func (r *fakeRegistry) hasKey(keyPath string) bool {
	_, ok := r.keys[keyPath]
	return ok
}

func (r *fakeRegistry) snapshot() map[string]map[string]any {
	out := make(map[string]map[string]any, len(r.keys))
	for key, values := range r.keys {
		cloned := make(map[string]any, len(values))
		for name, value := range values {
			if strings, ok := value.([]string); ok {
				value = append([]string(nil), strings...)
			}
			cloned[name] = value
		}
		out[key] = cloned
	}
	return out
}

func (r *fakeRegistry) GetString(keyPath, name string) (string, error) {
	if err := r.check("GetString", keyPath, name); err != nil {
		return "", err
	}
	v, ok := r.keys[keyPath]
	if !ok {
		return "", ErrValueNotFound
	}
	raw, ok := v[name]
	if !ok {
		return "", ErrValueNotFound
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("windows test: %s\\%s is not a string", keyPath, name)
	}
	return s, nil
}

func (r *fakeRegistry) SetString(keyPath, name, data string) error {
	if err := r.check("SetString", keyPath, name); err != nil {
		return err
	}
	return r.setString(keyPath, name, data)
}

func (r *fakeRegistry) setString(keyPath, name, data string) error {
	if name == reloadTriggerValue && keyPath == nrptBase {
		if r.failReload != nil {
			return r.failReload
		}
		r.reloads++
	}
	r.logWrite("SetString", keyPath, name)
	r.ensure(keyPath)[name] = data
	return nil
}

func (r *fakeRegistry) SetExistingString(path, name, data string) error {
	if err := r.check("SetExistingString", path, name); err != nil {
		return err
	}
	if !r.hasKey(path) {
		return ErrValueNotFound
	}
	return r.setString(path, name, data)
}

func (r *fakeRegistry) KeyExists(path string) (bool, error) {
	if err := r.check("KeyExists", path, ""); err != nil {
		return false, err
	}
	return r.hasKey(path), nil
}

func (r *fakeRegistry) GetMultiString(keyPath, name string) ([]string, error) {
	if err := r.check("GetMultiString", keyPath, name); err != nil {
		return nil, err
	}
	v, ok := r.keys[keyPath]
	if !ok {
		return nil, ErrValueNotFound
	}
	raw, ok := v[name]
	if !ok {
		return nil, ErrValueNotFound
	}
	s, ok := raw.([]string)
	if !ok {
		return nil, fmt.Errorf("windows test: %s\\%s is not a multi-string", keyPath, name)
	}
	return append([]string(nil), s...), nil
}

func (r *fakeRegistry) SetMultiString(keyPath, name string, data []string) error {
	if err := r.check("SetMultiString", keyPath, name); err != nil {
		return err
	}
	r.logWrite("SetMultiString", keyPath, name)
	r.ensure(keyPath)[name] = append([]string(nil), data...)
	return nil
}

func (r *fakeRegistry) SetDWord(keyPath, name string, data uint32) error {
	if err := r.check("SetDWord", keyPath, name); err != nil {
		return err
	}
	r.logWrite("SetDWord", keyPath, name)
	r.ensure(keyPath)[name] = data
	return nil
}

func (r *fakeRegistry) GetDWord(keyPath, name string) (uint32, error) {
	if err := r.check("GetDWord", keyPath, name); err != nil {
		return 0, err
	}
	value, ok := r.keys[keyPath][name]
	if !ok {
		return 0, ErrValueNotFound
	}
	n, ok := value.(uint32)
	if !ok {
		return 0, fmt.Errorf("windows test: %s\\%s is not a DWORD", keyPath, name)
	}
	return n, nil
}

func (r *fakeRegistry) DeleteValue(keyPath, name string) error {
	if err := r.check("DeleteValue", keyPath, name); err != nil {
		return err
	}
	if name == reloadTriggerValue && keyPath == nrptBase && r.failReloadDelete != nil {
		return r.failReloadDelete
	}
	r.logWrite("DeleteValue", keyPath, name)
	if v, ok := r.keys[keyPath]; ok {
		delete(v, name)
	}
	return nil
}

func (r *fakeRegistry) CreateKey(keyPath string) error {
	if err := r.check("CreateKey", keyPath, ""); err != nil {
		return err
	}
	r.logWrite("CreateKey", keyPath, "")
	r.ensure(keyPath)
	return nil
}

// DeleteKey rejects populated containers, matching the registry API.
func (r *fakeRegistry) DeleteKey(keyPath string) error {
	if err := r.check("DeleteKey", keyPath, ""); err != nil {
		return err
	}
	r.logWrite("DeleteKey", keyPath, "")
	subs := r.subKeyNames(keyPath)
	if len(subs) > 0 {
		return fmt.Errorf("windows test: %s has subkeys", keyPath)
	}
	delete(r.keys, keyPath)
	return nil
}

func (r *fakeRegistry) ValueNames(keyPath string) ([]string, error) {
	if err := r.check("ValueNames", keyPath, ""); err != nil {
		return nil, err
	}
	v, ok := r.keys[keyPath]
	if !ok {
		return nil, nil
	}
	out := make([]string, 0, len(v))
	for name := range v {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func (r *fakeRegistry) SubKeyNames(keyPath string) ([]string, error) {
	if err := r.check("SubKeyNames", keyPath, ""); err != nil {
		return nil, err
	}
	return r.subKeyNames(keyPath), nil
}

func (r *fakeRegistry) subKeyNames(keyPath string) []string {
	prefix := keyPath + `\`
	seen := map[string]bool{}
	var out []string
	for k := range r.keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		child := k[len(prefix):]
		if i := strings.IndexByte(child, '\\'); i >= 0 {
			child = child[:i]
		}
		if child != "" && !seen[child] {
			seen[child] = true
			out = append(out, child)
		}
	}
	sort.Strings(out)
	return out
}

// ruleKey returns the registry path of the idx-th NRPT rule in the local
// store; gpRuleKey is its Group Policy counterpart.
func ruleKey(idx int) string {
	return nrptBase + `\` + ruleName(testIdentity, idx)
}

func gpRuleKey(idx int) string {
	return gpoNrptBase + `\` + ruleName(testIdentity, idx)
}

// ruleName is the active rule key name identity writes for idx.
func ruleName(identity string, idx int) string {
	return libraryRulePrefix + identity + "-" + strconv.Itoa(idx)
}

// rulePrefix is this test identity's rule name prefix, for expected lists.
const rulePrefix = libraryRulePrefix + testIdentity + "-"

// catchAllRules are the rules a catch-all goal publishes: the catch-all and
// the NCSI exemption.
var catchAllRules = []string{rulePrefix + "0", rulePrefix + "1"}

// dropOwnRules deletes every rule this test identity owns under base,
// standing in for lost recovery records.
func dropOwnRules(t *testing.T, reg *fakeRegistry, base string) {
	t.Helper()
	for _, name := range reg.ourRuleNamesIn(base) {
		require.NoError(t, reg.DeleteKey(base+`\`+name))
	}
}

// ourRuleNames returns the sorted NRPT rule key names this backend owns in
// the local store; gpRuleNames does the same for the Group Policy store.
func (r *fakeRegistry) ourRuleNames() []string { return r.ourRuleNamesIn(nrptBase) }

func (r *fakeRegistry) gpRuleNames() []string { return r.ourRuleNamesIn(gpoNrptBase) }

func (r *fakeRegistry) ourRuleNamesIn(base string) []string {
	var out []string
	for _, s := range r.subKeyNames(base) {
		if identity, _, _, ok := parseRuleName(s); ok && identity == testIdentity {
			out = append(out, s)
		}
	}
	return out
}

// fakeNotifier records notification attempts and replies with a fixed tier,
// standing in for the privilege the test is simulating.
type fakeNotifier struct {
	delivery Delivery
	err      error
	calls    int
}

func (f *fakeNotifier) NotifyPolicyChange() (Delivery, error) {
	f.calls++
	return f.delivery, f.err
}

type harness struct {
	*Backend
	reg    *fakeRegistry
	fr     *runnertest.FakeRunner
	notify *fakeNotifier
}

// captureLogs routes the backend's log output to the returned buffer.
func (h *harness) captureLogs() *bytes.Buffer {
	var buf bytes.Buffer
	h.logger = slog.New(slog.NewTextHandler(&buf, nil))
	return &buf
}

// setGoal makes the first converge toward cfg, as a new Set goal would.
func (b *Backend) setGoal(ctx context.Context, cfg backend.Config) error {
	_, err := b.Set(ctx, cfg, backend.Attempt{NewGoal: true})
	return err
}

// clearGoal makes the first Clear attempt, as a new Clear goal would.
func (b *Backend) clearGoal(ctx context.Context) error {
	_, err := b.Clear(ctx, backend.Attempt{NewGoal: true})
	return err
}

// ownedState reports whether either NRPT store holds this identity's rules
// or this instance still owes adapter cleanup. It only inspects.
func (b *Backend) ownedState() (bool, error) {
	for _, base := range []string{nrptBase, gpoNrptBase} {
		names, err := b.ownedRuleNames(base)
		if err != nil {
			return false, err
		}
		if len(names) > 0 {
			return true, nil
		}
	}
	return b.adapterTarget != nil, nil
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWith(t, &fakeNotifier{delivery: DeliveryNotified})
}

func newHarnessWith(t *testing.T, n *fakeNotifier) *harness {
	t.Helper()
	reg := newFakeRegistry()
	fr := &runnertest.FakeRunner{}
	b, err := newTestBackend(context.Background(), Options{
		Registry: reg,
		Runner:   fr,
		Notifier: n,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return &harness{Backend: b, reg: reg, fr: fr, notify: n}
}

// seedForeignGPRule installs an unprefixed rule in the Group Policy store,
// standing in for a real GPO or another DNS manager.
func seedForeignGPRule(t *testing.T, reg *fakeRegistry, name string) {
	t.Helper()
	key := gpoNrptBase + `\` + name
	require.NoError(t, reg.CreateKey(key))
	require.NoError(t, reg.SetDWord(key, "Version", nrptVersion))
	require.NoError(t, reg.SetMultiString(key, "Name", []string{".foreign.example"}))
	require.NoError(t, reg.SetString(key, "GenericDNSServers", "203.0.113.53"))
	require.NoError(t, reg.SetDWord(key, "ConfigOptions", nrptUseGenericServers))
}

func mustAddrs(t *testing.T, ss ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		a, err := netip.ParseAddr(s)
		require.NoError(t, err)
		out[i] = a
	}
	return out
}

func TestNewRequiresRegistry(t *testing.T) {
	_, err := newTestBackend(context.Background(), Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Options.Registry is required")
}

func TestSetCatchAll(t *testing.T) {
	h := newHarness(t)
	err := h.setGoal(context.Background(), backend.Config{
		Nameservers: mustAddrs(t, "1.1.1.1", "8.8.8.8"),
	})
	require.NoError(t, err)

	require.Equal(t, catchAllRules, h.reg.ourRuleNames(),
		"catch-all should produce the catch-all and its exemption")

	rule := h.reg.keys[ruleKey(0)]
	require.NotNil(t, rule)
	assert.Equal(t, []string{"."}, rule["Name"], "catch-all namespace must be \".\"")
	assert.Equal(t, "1.1.1.1;8.8.8.8", rule["GenericDNSServers"])
	assert.Equal(t, uint32(nrptUseGenericServers), rule["ConfigOptions"])
	assert.Equal(t, uint32(nrptVersion), rule["Version"])
}

func TestSetSplit(t *testing.T) {
	h := newHarness(t)
	err := h.setGoal(context.Background(), backend.Config{
		Nameservers:  mustAddrs(t, "10.0.0.53"),
		MatchDomains: []string{"example.com", "corp.internal"},
	})
	require.NoError(t, err)

	require.Equal(t, []string{rulePrefix + "0"}, h.reg.ourRuleNames())
	rule := h.reg.keys[ruleKey(0)]
	require.NotNil(t, rule)
	// Match domains are normalised to NRPT suffix form and sorted.
	assert.Equal(t, []string{".corp.internal", ".example.com"}, rule["Name"])
	assert.Equal(t, "10.0.0.53", rule["GenericDNSServers"])
}

func TestSetBatchesLargeMatchSets(t *testing.T) {
	h := newHarness(t)
	var domains []string
	for i := range 120 {
		domains = append(domains, fmt.Sprintf("d%03d.example.com", i))
	}
	err := h.setGoal(context.Background(), backend.Config{
		Nameservers:  mustAddrs(t, "10.0.0.53"),
		MatchDomains: domains,
	})
	require.NoError(t, err)

	// 120 domains -> rules of 50, 50, 20.
	require.Equal(t, []string{rulePrefix + "0", rulePrefix + "1", rulePrefix + "2"},
		h.reg.ourRuleNames())
	assert.Len(t, h.reg.keys[ruleKey(0)]["Name"], maxDomainsPerRule)
	assert.Len(t, h.reg.keys[ruleKey(1)]["Name"], maxDomainsPerRule)
	assert.Len(t, h.reg.keys[ruleKey(2)]["Name"], 120-2*maxDomainsPerRule)
}

func TestSetReapplyReplacesRules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	require.NoError(t, h.setGoal(ctx, backend.Config{
		Nameservers:  mustAddrs(t, "10.0.0.53"),
		MatchDomains: []string{"a.example", "b.example", "c.example"},
	}))
	// Re-apply as catch-all: the prior split rules must be gone.
	require.NoError(t, h.setGoal(ctx, backend.Config{
		Nameservers: mustAddrs(t, "9.9.9.9"),
	}))

	require.Equal(t, catchAllRules, h.reg.ourRuleNames())
	assert.Equal(t, []string{"."}, h.reg.keys[ruleKey(0)]["Name"])
	assert.Equal(t, "9.9.9.9", h.reg.keys[ruleKey(0)]["GenericDNSServers"])
}

func TestValidateConfigRejectsZone(t *testing.T) {
	h := newHarness(t)
	err := h.ValidateConfig(backend.Config{
		Nameservers: []netip.Addr{netip.MustParseAddr("fe80::1%Ethernet")},
	})
	assert.ErrorContains(t, err, "zone-scoped")
}

func TestGlobalSearchListPreserved(t *testing.T) {
	for _, prior := range []string{"", "corp.example"} {
		t.Run(prior, func(t *testing.T) {
			h := newHarness(t)
			require.NoError(t, h.reg.SetString(tcpipKey, searchListValue, prior))
			require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
			got, err := h.reg.GetString(tcpipKey, searchListValue)
			require.NoError(t, err)
			assert.Equal(t, prior, got)
			require.NoError(t, h.reg.SetString(tcpipKey, searchListValue, "administrator.example"))
			require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
			require.NoError(t, h.clearGoal(context.Background()))
			got, err = h.reg.GetString(tcpipKey, searchListValue)
			require.NoError(t, err)
			assert.Equal(t, "administrator.example", got)
		})
	}
}

// flushObserver runs check before each ipconfig /flushdns.
type flushObserver struct {
	*runnertest.FakeRunner
	check func()
}

func (r *flushObserver) Run(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, []byte, error) {
	if slices.Equal(args, []string{"/flushdns"}) {
		r.check()
	}
	return r.FakeRunner.Run(ctx, name, args, stdin)
}

// TestReloadPrecedesFlushOnSetAndClear checks that Set and Clear each trigger
// the adapter reload before the cache flush, and that the flush is the only
// command run.
func TestReloadPrecedesFlushOnSetAndClear(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var reloadsAtFlush []int
	h.runner = &flushObserver{FakeRunner: h.fr, check: func() {
		reloadsAtFlush = append(reloadsAtFlush, h.reg.reloads)
	}}
	require.NoError(t, h.setGoal(ctx, backend.Config{
		Nameservers: mustAddrs(t, "1.1.1.1"),
	}))
	require.NoError(t, h.clearGoal(ctx))

	var args [][]string
	for _, c := range h.fr.CallsFor(ipconfigExe) {
		args = append(args, c.Args)
	}
	assert.Equal(t, [][]string{{"/flushdns"}, {"/flushdns"}}, args, "the flush is the only command")
	assert.Equal(t, []int{1, 2}, reloadsAtFlush, "apply and reset each reload adapter settings before flushing the cache")
}

func TestRefreshDNSFailureCarriesOutput(t *testing.T) {
	h := newHarness(t)
	h.fr.OnCall(ipconfigExe, runnertest.Response{
		Stdout: []byte("\r\nWindows IP Configuration\r\n\r\nCould not flush the DNS Resolver Cache: Function failed during execution.\r\n"),
		Stderr: []byte("stderr text\n"),
		Err:    errors.New("exit status 1"),
	})
	err := h.refreshDNS(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Function failed during execution.")
	assert.Contains(t, err.Error(), "stderr text")
}

// catchAll is the minimal config the Group Policy tests apply.
func catchAll(t *testing.T) backend.Config {
	t.Helper()
	return backend.Config{Nameservers: mustAddrs(t, "1.1.1.1")}
}

// TestPlacementLocalWithoutForeignGPRules checks that local rules need no policy notification.
func TestPlacementLocalWithoutForeignGPRules(t *testing.T) {
	h := newHarness(t)
	logs := h.captureLogs()
	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))

	assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
	assert.Empty(t, h.reg.gpRuleNames(), "nothing may be written to the Group Policy store")
	assert.False(t, h.reg.hasKey(gpoNrptBase),
		"an empty Group Policy container suppresses the local NRPT; it must not be created")
	assert.Zero(t, h.notify.calls, "a local-only write needs no policy notification")
	assert.Contains(t, logs.String(), "store="+nrptBase)
}

// TestPlacementGroupPolicyWhenForeignRulesExist routes through the GP store,
// which suppresses the local table, and keeps an identical local copy ready
// for when that store goes away.
func TestPlacementGroupPolicyWhenForeignRulesExist(t *testing.T) {
	h := newHarness(t)
	logs := h.captureLogs()
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")

	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))

	assert.Equal(t, catchAllRules, h.reg.gpRuleNames())
	assert.Equal(t, catchAllRules, h.reg.ourRuleNames())
	assert.Equal(t, []string{"."}, h.reg.keys[gpRuleKey(0)]["Name"])
	assert.Equal(t, h.reg.keys[gpRuleKey(0)], h.reg.keys[ruleKey(0)], "the local copy matches the GP rule")
	assert.Equal(t, 1, h.notify.calls, "a Group Policy write must be notified")

	assert.NotContains(t, logs.String(), "notification delivery is unconfirmed")
	assert.Contains(t, logs.String(), fmt.Sprintf("store=%q", gpoNrptBase))
	assert.Contains(t, logs.String(), "delivery=notified")
}

// TestPlacementValueOnGPContainerCounts treats container values as foreign use.
func TestPlacementValueOnGPContainerCounts(t *testing.T) {
	h := newHarness(t)
	require.NoError(t, h.reg.SetDWord(gpoNrptBase, "SomeVendorFlag", 1))

	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))
	assert.Equal(t, catchAllRules, h.reg.gpRuleNames())
}

// TestSweepClearsBothStores cleans up records regardless of previous placement.
func TestSweepClearsBothStores(t *testing.T) {
	h := newHarness(t)
	// Stale rules in both stores, as a crashed run of either mode would leave.
	require.NoError(t, h.reg.CreateKey(ruleKey(7)))
	require.NoError(t, h.reg.CreateKey(gpRuleKey(7)))
	require.NoError(t, h.writeTarget(ruleKey(7), adapterTarget{testGUID}))
	require.NoError(t, h.writeTarget(gpRuleKey(7), adapterTarget{testGUID}))
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")

	require.NoError(t, h.setGoal(context.Background(), catchAll(t)))

	assert.Equal(t, catchAllRules, h.reg.ourRuleNames(),
		"the stale local rule must be swept and replaced by exactly this apply's copy")
	assert.Equal(t, catchAllRules, h.reg.gpRuleNames(),
		"the stale Group Policy rule must be swept and replaced by exactly this apply's rule")
}

// TestClearKeepsGPContainerWithForeignRules preserves other policy users.
func TestClearKeepsGPContainerWithForeignRules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
	before := h.reg.keys[gpoNrptBase+`\{FOREIGN-RULE}`]
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.clearGoal(ctx))

	assert.Empty(t, h.reg.gpRuleNames(), "our rules must go")
	assert.Empty(t, h.reg.ourRuleNames(), "our local copies must go too")
	assert.True(t, h.reg.hasKey(gpoNrptBase), "a container still holding foreign rules must survive")
	assert.Equal(t, before, h.reg.keys[gpoNrptBase+`\{FOREIGN-RULE}`],
		"the foreign rule must survive verbatim")
}

// TestNeverTouchesDNSClientParentKey protects unrelated DNS policy settings.
func TestNeverTouchesDNSClientParentKey(t *testing.T) {
	parent := `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	h := newHarness(t)
	ctx := context.Background()
	require.NoError(t, h.reg.SetDWord(parent, "EnableMulticast", 0))
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")
	require.NoError(t, h.setGoal(ctx, catchAll(t)))
	require.NoError(t, h.reg.DeleteKey(gpoNrptBase+`\{FOREIGN-RULE}`))
	require.NoError(t, h.clearGoal(ctx))

	require.False(t, h.reg.hasKey(gpoNrptBase), "precondition: the container was deleted")
	assert.True(t, h.reg.hasKey(parent), "the parent DNSClient key must never be deleted")
	got, err := h.reg.ValueNames(parent)
	require.NoError(t, err)
	assert.Equal(t, []string{"EnableMulticast"}, got, "the parent's values must be untouched")
}

// TestGroupPolicyInertWhenNotNotified checks the delivery warning.
func TestGroupPolicyInertWhenNotNotified(t *testing.T) {
	tiers := []struct {
		name     string
		delivery Delivery
		err      error
	}{
		{"unprivileged", DeliveryNone, errors.New("neither LocalSystem nor elevated")},
		{"elevated fallback", DeliveryRefresh, errors.New("policy refresh requested")},
	}
	for _, tc := range tiers {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			reg := newFakeRegistry()
			seedForeignGPRule(t, reg, "{FOREIGN-RULE}")
			b, err := newTestBackend(context.Background(), Options{
				Logger:   slog.New(slog.NewTextHandler(&buf, nil)),
				Registry: reg,
				Notifier: &fakeNotifier{delivery: tc.delivery, err: tc.err},
			})
			require.NoError(t, err)

			res, err := b.Set(context.Background(), catchAll(t), backend.Attempt{NewGoal: true})
			if tc.delivery == DeliveryNone {
				require.Error(t, err, "a failed request fails the converge")
				assert.True(t, res.Changed)
				assert.True(t, res.Pending, "a failed request stays owed")
			} else {
				require.NoError(t, err, "an accepted request completes the side effect")
				assert.False(t, res.Pending)
			}
			assert.Equal(t, catchAllRules, reg.gpRuleNames(),
				"an unconfirmed notification must retain valid rules for possible later activation")
			assert.Contains(t, buf.String(), "notification delivery is unconfirmed")
			assert.Contains(t, buf.String(), "delivery="+tc.delivery.String())
		})
	}
}

// TestDomainJoinedRefreshDelivers checks the domain-membership warning heuristic.
func TestDomainJoinedRefreshDelivers(t *testing.T) {
	var buf bytes.Buffer
	reg := newFakeRegistry()
	seedForeignGPRule(t, reg, "{FOREIGN-RULE}")
	b, err := newTestBackend(context.Background(), Options{
		Logger:       slog.New(slog.NewTextHandler(&buf, nil)),
		Registry:     reg,
		Notifier:     &fakeNotifier{delivery: DeliveryRefresh, err: errors.New("policy refresh forced")},
		DomainJoined: func() (bool, error) { return true, nil },
	})
	require.NoError(t, err)

	require.NoError(t, b.setGoal(context.Background(), catchAll(t)))
	assert.NotContains(t, buf.String(), "notification delivery is unconfirmed",
		"a forced refresh on a domain-joined host is expected to deliver")
	assert.Contains(t, buf.String(), "domain-joined")
	assert.Contains(t, buf.String(), "delivery=policy-refresh")
	assert.Contains(t, buf.String(), fmt.Sprintf("store=%q", gpoNrptBase))
}

// TestWorkgroupRefreshStaysInert keeps the delivery warning without
// requesting again: an accepted refresh completes the side effect.
func TestWorkgroupRefreshStaysInert(t *testing.T) {
	var buf bytes.Buffer
	n := &fakeNotifier{delivery: DeliveryRefresh, err: errors.New("policy refresh forced")}
	reg := newFakeRegistry()
	seedForeignGPRule(t, reg, "{FOREIGN-RULE}")
	b, err := newTestBackend(context.Background(), Options{
		Logger:       slog.New(slog.NewTextHandler(&buf, nil)),
		Registry:     reg,
		Notifier:     n,
		DomainJoined: func() (bool, error) { return false, nil },
	})
	require.NoError(t, err)

	require.NoError(t, b.setGoal(context.Background(), catchAll(t)))
	require.Equal(t, 1, n.calls)
	assert.Contains(t, buf.String(), "notification delivery is unconfirmed",
		"a workgroup host has no DC to process the refresh")

	res, err := b.Set(context.Background(), catchAll(t), backend.Attempt{})
	require.NoError(t, err)
	assert.False(t, res.Pending)
	assert.Equal(t, 1, n.calls, "uncertain delivery alone does not cause another request")
}

// TestDomainJoinLookupErrorStaysInert keeps delivery unconfirmed after a failed lookup.
func TestDomainJoinLookupErrorStaysInert(t *testing.T) {
	var buf bytes.Buffer
	reg := newFakeRegistry()
	seedForeignGPRule(t, reg, "{FOREIGN-RULE}")
	b, err := newTestBackend(context.Background(), Options{
		Logger:       slog.New(slog.NewTextHandler(&buf, nil)),
		Registry:     reg,
		Notifier:     &fakeNotifier{delivery: DeliveryRefresh, err: errors.New("policy refresh forced")},
		DomainJoined: func() (bool, error) { return false, errors.New("lookup failed") },
	})
	require.NoError(t, err)

	require.NoError(t, b.setGoal(context.Background(), catchAll(t)))
	assert.Contains(t, buf.String(), "notification delivery is unconfirmed",
		"an undetermined domain-join state must not be treated as delivered")
}

// TestDomainJoinIrrelevantToTier1 checks that direct delivery skips membership.
func TestDomainJoinIrrelevantToTier1(t *testing.T) {
	joinCalls := 0
	reg := newFakeRegistry()
	seedForeignGPRule(t, reg, "{FOREIGN-RULE}")
	b, err := newTestBackend(context.Background(), Options{
		Registry:     reg,
		Notifier:     &fakeNotifier{delivery: DeliveryNotified},
		DomainJoined: func() (bool, error) { joinCalls++; return false, nil },
	})
	require.NoError(t, err)

	require.NoError(t, b.setGoal(context.Background(), catchAll(t)))
	assert.Zero(t, joinCalls, "tier-1 delivery must not consult domain-join state")
}

// TestNotifyFiresOnceAfterAllWrites checks one notification per settled
// operation, using enough match domains for two Group Policy rules.
func TestNotifyFiresOnceAfterAllWrites(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")

	require.NoError(t, h.setGoal(ctx, splitConfig(t, maxDomainsPerRule+1)))
	require.Equal(t, []string{rulePrefix + "0", rulePrefix + "1"}, h.reg.gpRuleNames())
	assert.Equal(t, 1, h.notify.calls, "one notification per apply, however many rules it wrote")

	require.NoError(t, h.clearGoal(ctx))
	assert.Equal(t, 2, h.notify.calls, "removing Group Policy rules needs notifying too")
}

// TestNotifyRetriedWhileUndelivered keeps a failed request owed and requests
// it again on each later attempt until one is accepted, after which a
// converged host requests nothing.
func TestNotifyRetriedWhileUndelivered(t *testing.T) {
	n := &fakeNotifier{delivery: DeliveryNone, err: errors.New("no privilege")}
	h := newHarnessWith(t, n)
	ctx := context.Background()
	seedForeignGPRule(t, h.reg, "{FOREIGN-RULE}")

	res, err := h.Set(ctx, catchAll(t), backend.Attempt{NewGoal: true})
	require.Error(t, err)
	assert.True(t, res.Pending)
	require.Equal(t, 1, n.calls)

	h.reg.writes = nil
	res, err = h.Set(ctx, catchAll(t), backend.Attempt{})
	require.Error(t, err, "a failed request fails the converge")
	assert.Equal(t, backend.Result{Pending: true}, res)
	assert.Equal(t, 2, n.calls, "a failed request is made again on the next attempt")
	assert.Empty(t, h.reg.writes)

	// The process gains the privilege (or the API starts answering).
	n.delivery, n.err = DeliveryNotified, nil
	res, err = h.Set(ctx, catchAll(t), backend.Attempt{})
	require.NoError(t, err)
	assert.Equal(t, backend.Result{}, res)
	assert.Equal(t, 3, n.calls)
	assert.Empty(t, h.reg.writes)

	assertNoOp(t, h, catchAll(t), backend.Attempt{Converged: true})
}

// TestClearDiscoversOwnedRules checks that Clear finds this identity's rules
// in either store without a prior Set, and leaves foreign rules alone.
func TestClearDiscoversOwnedRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     string
		changed bool
	}{
		{"Group Policy rule", gpRuleKey(0), true},
		{"local rule", nrptBase + `\` + rulePrefix + `0`, true},
		{"foreign local rule", nrptBase + `\{someone-elses-rule}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := newFakeRegistry()
			require.NoError(t, reg.CreateKey(tc.key))
			b, err := newTestBackend(context.Background(), Options{Registry: reg})
			require.NoError(t, err)
			t.Cleanup(func() { _ = b.Close() })
			if tc.changed {
				require.NoError(t, b.writeTarget(tc.key, adapterTarget{testGUID}))
			}
			res, err := b.Clear(context.Background(), backend.Attempt{NewGoal: true})
			require.NoError(t, err)
			assert.Equal(t, tc.changed, res.Changed)
			assert.Equal(t, !tc.changed, reg.hasKey(tc.key))
		})
	}
}

func (r *fakeRegistry) RenameKey(path, name string) error {
	if err := r.check("RenameKey", path, name); err != nil {
		return err
	}
	r.logWrite("RenameKey", path, name)
	i := strings.LastIndexByte(path, '\\')
	target := path[:i+1] + name
	if r.hasKey(target) {
		return errors.New("rename target exists")
	}
	if !r.hasKey(path) {
		return ErrValueNotFound
	}
	// Like RegRenameKey, the whole subtree moves.
	for k, v := range r.keys {
		if k == path || strings.HasPrefix(k, path+`\`) {
			r.keys[target+k[len(path):]] = v
			delete(r.keys, k)
		}
	}
	return nil
}

// TestNewRejectsUnsafeIdentity checks that the backend does not rely on the
// facade's validation before interpolating the identity into registry paths.
func TestNewRejectsUnsafeIdentity(t *testing.T) {
	for _, identity := range []string{"", `a\b`, "A"} {
		b, err := New(context.Background(), Options{
			Logger:   discardLogger(),
			Identity: identity,
			Registry: newFakeRegistry(),
			Runner:   &runnertest.FakeRunner{},
		})
		assert.Error(t, err, "%q", identity)
		assert.Nil(t, b, "%q", identity)
	}
}
