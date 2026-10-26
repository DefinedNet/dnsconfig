package windows

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// mutation tracks what one Set or Clear attempt has written. begin runs
// before each write, because a write that fails can still change the host.
// The counters and the adapter and container flags count only completed
// writes and are used for logging.
type mutation struct {
	b *Backend
	// started reports that the attempt has begun writing to the host.
	started bool
	// store is the NRPT store whose rules take effect.
	store        string
	rulesWritten int
	rulesRemoved int
	adapter      bool
	container    bool
	// reloadErr preserves an earlier reload failure without retrying it in
	// this attempt. finish reports it with the other operation failures.
	reloadErr error
	// gpWarned limits the GP store write warning to once per attempt.
	gpWarned bool
}

// begin marks the host as changed and owes a DNS cache flush, plus a policy
// notification for a write to the GP store.

func (x *mutation) begin(base string) {
	x.started = true
	x.b.flushOwed = true
	if base == gpoNrptBase {
		x.b.gpDirty = true
	}
}

// beginAdapter prepares an adapter value write. The DNS Client applies
// adapter values only after a reload, so one is owed.
func (x *mutation) beginAdapter() {
	x.begin("")
	x.adapter = true
	x.b.registerOwed = true
}

// owePredecessorReload owes a reload on the first attempt with an adapter
// target after this instance takes the identity, even when every adapter
// value matches: a predecessor may have exited, or failed its trigger,
// between its adapter write and its reload. The trigger is one value set and
// delete on the local container key, so one extra per acquisition is cheap.
func (b *Backend) owePredecessorReload() {
	if !b.reloaded {
		b.registerOwed = true
	}
}

// Set converges the host toward cfg: NRPT rules in the selected stores,
// their recovery records, and the controlled adapter's values on both IP
// stacks. A failure leaves the writes in place for the next attempt.
func (b *Backend) Set(ctx context.Context, cfg backend.Config, attempt backend.Attempt) (backend.Result, error) {
	mut := &mutation{b: b}
	err := b.setArtifacts(ctx, cfg, mut)
	return b.finish(ctx, "set", mut, attempt, err)
}

// Clear converges the host toward having no configuration for this
// identity, including what a crashed predecessor left, and completes owed
// side effects. Once nothing remains and nothing is owed, it stops the
// change sources; the next Set restarts them.
func (b *Backend) Clear(ctx context.Context, attempt backend.Attempt) (backend.Result, error) {
	mut := &mutation{b: b}
	err := b.clearArtifacts(ctx, mut)
	res, err := b.finish(ctx, "clear", mut, attempt, err)
	// The final attempt skips this: Close runs next and reports teardown
	// failures itself.
	// A converged Clear releases the identity, so a later Set may follow a
	// predecessor again.
	if err == nil && !res.Pending && !attempt.Final {
		b.releaseSources()
		b.reloaded = false
	}
	return res, err
}

// finish completes owed side effects and logs the attempt.
//
// After a failure, side effects wait for the retry, which would owe them
// again, so each is requested once per successful converge. The final
// cleanup has no retry, so it requests them despite earlier failures while
// its context is still live, and requests an owed policy notification even
// after cancellation: its last recovery record may already be gone.
//
// ErrGroupPolicyContainerEmpty defers them too, even though repeat attempts
// write nothing. While the container suppresses the local rules, lookups
// cache answers from the interfaces' DNS servers, and only a flush after the
// container is gone drops them. The reload is the exception: the adapter
// values carry queries to the configured resolver only once loaded.
func (b *Backend) finish(ctx context.Context, op string, mut *mutation, attempt backend.Attempt, err error) (backend.Result, error) {
	var notifyErr, reloadErr, flushErr error
	reloadReady := ctx.Err() == nil && b.registerOwed && mut.reloadErr == nil
	if err == nil || attempt.Final {
		if b.gpDirty && (attempt.Final || ctx.Err() == nil) {
			notifyErr = b.notifyPolicy()
		}
		if reloadReady {
			reloadErr = b.reload(ctx, mut)
		}
		if ctx.Err() == nil && b.flushOwed {
			flushErr = b.refreshDNS(ctx)
			if flushErr == nil {
				b.flushOwed = false
			}
		}
	} else if reloadReady && errors.Is(err, backend.ErrGroupPolicyContainerEmpty) {
		reloadErr = b.reload(ctx, mut)
	}
	err = errors.Join(err, mut.reloadErr, notifyErr, reloadErr, flushErr)
	if cancelErr := ctx.Err(); cancelErr != nil && !errors.Is(err, cancelErr) {
		err = errors.Join(err, cancelErr)
	}
	res := backend.Result{Changed: mut.started, Pending: b.flushOwed || b.registerOwed || b.gpDirty}
	switch {
	case err != nil:
		// The Manager warns for its current goal. A superseded attempt's
		// failure reaches only Status, since the newer goal rewrites the same
		// artifacts.
		b.logger.Debug("windows DNS "+op+" failed", "err", err, "changed", res.Changed, "pending", res.Pending)
	case res.Changed && op == "set":
		b.logger.Info("windows DNS converged", "store", mut.store,
			"rules_written", mut.rulesWritten, "rules_removed", mut.rulesRemoved,
			"adapter_changed", mut.adapter, "gp_container_removed", mut.container, "pending", res.Pending)
	case res.Changed:
		b.logger.Info("windows DNS cleared",
			"rules_removed", mut.rulesRemoved, "adapter_changed", mut.adapter,
			"gp_container_removed", mut.container, "pending", res.Pending)
	}
	return res, err
}

// setArtifacts writes cfg's rules and adapter values for Set.
func (b *Backend) setArtifacts(ctx context.Context, cfg backend.Config, mut *mutation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Resolve the adapter on every attempt, so a replaced device is picked
	// up by the next converge rather than the next goal.
	target, err := b.resolveApplyTarget()
	if err != nil {
		return err
	}
	b.ensureRegistryWatch(target)
	prior, err := b.recoveryTarget(ctx)
	if err != nil {
		return err
	}
	if err := b.checkConflicts(cfg, target); err != nil {
		return err
	}
	place, err := b.choosePlacement(ctx, mut)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.owePredecessorReload()
	mut.store = place.store
	if err := b.convergeRules(ctx, place.stores, place.vacate, cfg, target, prior, mut); err != nil {
		return err
	}
	if place.collapse {
		retired, err := b.retireGPContainer(ctx, mut)
		if err != nil {
			return err
		}
		if !retired {
			// Another writer changed the container during this attempt. The
			// next attempt places rules with that change in view.
			return errors.New("windows: Group Policy NRPT container changed during converge")
		}
	}
	if err := b.convergeAdapter(ctx, target, cfg, mut); err != nil {
		return err
	}
	if place.unattributed {
		// Nothing attributes this container to dnsconfig, so it is not ours
		// to delete. Deleting it by hand is not enough on its own: the DNS
		// Client keeps its cached policy table until notified or restarted,
		// and dnsconfig notifies only for its own changes. Hence the advice
		// to reboot.
		return fmt.Errorf(`windows: HKLM\%s: %w; if no Group Policy defines the key, delete it and reboot: the DNS Client keeps its cached policy table until notified or restarted`, gpoNrptBase, backend.ErrGroupPolicyContainerEmpty)
	}
	return nil
}

// placement says where one Set attempt keeps this identity's rules.
type placement struct {
	// store is the store whose rules take effect, for logging.
	store string
	// stores must end up holding the config's rules; vacate must end up
	// holding none of this identity's rules.
	stores, vacate []string
	// collapse retires the GP container after the rules converge.
	collapse bool
	// unattributed reports a GP container holding neither foreign policy
	// nor dnsconfig rules. It still suppresses the local rules.
	unattributed bool
}

// choosePlacement selects the NRPT stores for this attempt. Along the way it
// deletes any retired container a crash left behind.
//
// While the GP container exists, Windows ignores the local store. With
// foreign policy present, this identity's rules go in both stores. Without
// it, the container exists only because dnsconfig rules hold it. Removing
// just this identity's GP copy would leave it on suppressed local rules, so
// it keeps a copy in both stores until every peer's GP rule also has a local
// copy. Then the whole container is retired in one rename.
func (b *Backend) choosePlacement(ctx context.Context, mut *mutation) (placement, error) {
	if err := ctx.Err(); err != nil {
		return placement{}, err
	}
	// Start the policy watcher before reading the GP store, so the reads
	// below see policy that arrives meanwhile, and a GP write is refused up
	// front if monitoring is unavailable.
	watchErr := b.ensurePolicyWatch()
	foreign, err := b.foreignPolicy()
	if err != nil {
		return placement{}, err
	}
	gpExists, err := b.reg.KeyExists(gpoNrptBase)
	if err != nil {
		return placement{}, fmt.Errorf("windows: inspect Group Policy NRPT container: %w", err)
	}
	if watchErr != nil && (foreign || gpExists) {
		// Any GP container suppresses local rules, even an empty one or one
		// holding only our leftovers, so every GP-store change needs
		// monitoring.
		return placement{}, fmt.Errorf("windows: Group Policy NRPT requires a policy watcher: %w", watchErr)
	}
	if err := b.removeRetiredContainer(ctx, mut); err != nil {
		return placement{}, err
	}
	held, collapse := false, false
	if !foreign && gpExists {
		held, collapse, err = b.gpDnsconfigHeld(ctx)
		if err != nil {
			return placement{}, err
		}
	}
	place := placement{
		store:        nrptBase,
		stores:       []string{nrptBase},
		vacate:       []string{gpoNrptBase},
		collapse:     collapse,
		unattributed: gpExists && !foreign && !held,
	}
	if foreign {
		place.store = gpoNrptBase
	}
	if foreign || held {
		// The local copy does nothing while the GP store is in effect.
		// Policy processing never removes our GP copies; the store goes away
		// only when a retirement, by us or a peer, finds every identity's
		// local copy ready. A container about to be retired is converged
		// too, so both copies name the same adapter if the retirement fails.
		place.stores, place.vacate = []string{nrptBase, gpoNrptBase}, nil
	}
	return place, nil
}

// convergeRules makes each store in stores hold exactly cfg's rules and
// removes this identity's rules from each store in vacate.
//
// Replacements are written under -pending names before the rules they
// replace are deleted, so a complete rule set routes at every step. If the
// adapter changed, the old one is cleared first, while its records still
// name it, and records naming the new adapter are published only after
// every record naming the old one is gone.
func (b *Backend) convergeRules(ctx context.Context, stores, vacate []string, cfg backend.Config, target adapterTarget, prior *adapterTarget, mut *mutation) error {
	// A staged record may be the only record of the old adapter. Clear that
	// adapter before staging overwrites the record.
	if prior != nil && prior.guid != target.guid {
		if err := b.clearAdapter(ctx, *prior, mut); err != nil {
			return err
		}
	}
	rules := desiredRules(cfg)
	staged, err := b.stageRules(ctx, stores, rules, target, mut)
	if err != nil {
		return err
	}
	if err := b.pruneRules(ctx, stores, vacate, len(rules), staged, mut); err != nil {
		return err
	}
	if err := b.publishRules(ctx, stores, staged, rules, target, mut); err != nil {
		return err
	}
	return b.verifyRuleSet(stores, vacate, len(rules))
}

// stageRules writes a -pending copy of each rule whose active copy in a
// store differs from cfg, and returns the staged indices per store. Windows
// reads -pending rules like any other, so a staged rule already routes.
// Indices run in descending order so the NCSI exemption is installed before
// the catch-all, both here and in publishRules.
func (b *Backend) stageRules(ctx context.Context, stores []string, rules []nrptRule, target adapterTarget, mut *mutation) (map[string][]int, error) {
	staged := map[string][]int{}
	for _, base := range stores {
		for i := len(rules) - 1; i >= 0; i-- {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			ok, err := b.stageRule(base, i, rules[i], target, mut)
			if err != nil {
				return nil, err
			}
			if ok {
				staged[base] = append(staged[base], i)
			}
		}
	}
	return staged, nil
}

// stageRule makes sure a -pending copy of rule i exists under base, unless
// the active copy already matches, and reports whether one does. A matching
// -pending copy left by an interrupted attempt is reused.
func (b *Backend) stageRule(base string, i int, rule nrptRule, target adapterTarget, mut *mutation) (staged bool, err error) {
	current, err := b.ruleMatches(b.ruleKey(base, i, false), rule, target)
	if err != nil || current {
		return false, err
	}
	reusable, err := b.ruleMatches(b.ruleKey(base, i, true), rule, target)
	if err != nil {
		return false, err
	}
	if !reusable {
		if base == gpoNrptBase && !mut.gpWarned {
			mut.gpWarned = true
			b.logger.Warn("writing NRPT rules to the Group Policy store; overlapping namespaces may change routing", "gpo_path", gpoNrptBase)
		}
		mut.begin(base)
		if err := b.writeStagedRule(base, i, rule, target); err != nil {
			return false, err
		}
	}
	return true, nil
}

// pruneRules deletes rules that must not survive publication. In each store
// in stores, matching active rules and this attempt's staged copies stay;
// active rules a staged copy will replace, rules at index n or above, and
// stale staged copies go. Each store in vacate loses all of this identity's
// rules.
func (b *Backend) pruneRules(ctx context.Context, stores, vacate []string, n int, staged map[string][]int, mut *mutation) error {
	for _, base := range stores {
		if err := ctx.Err(); err != nil {
			return err
		}
		stay := map[string]bool{}
		for i := range n {
			stay[b.ruleName(i, false)] = true
		}
		for _, i := range staged[base] {
			stay[b.ruleName(i, false)] = false
			stay[b.ruleName(i, true)] = true
		}
		names, err := b.ownedRuleNames(base)
		if err != nil {
			return err
		}
		names = slices.DeleteFunc(names, func(name string) bool { return stay[name] })
		if err := b.deleteRules(ctx, base, names, mut); err != nil {
			return err
		}
	}
	for _, base := range vacate {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, err := b.ownedRuleNames(base)
		if err != nil {
			return err
		}
		if err := b.deleteRules(ctx, base, names, mut); err != nil {
			return err
		}
	}
	return nil
}

// publishRules renames each staged copy to its active name and reads the
// result back.
func (b *Backend) publishRules(ctx context.Context, stores []string, staged map[string][]int, rules []nrptRule, target adapterTarget, mut *mutation) error {
	for _, base := range stores {
		for _, i := range staged[base] {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := b.ruleName(i, false)
			mut.begin(base)
			if err := b.reg.RenameKey(b.ruleKey(base, i, true), name); err != nil {
				return fmt.Errorf("windows: publish NRPT rule: %w", err)
			}
			mut.rulesWritten++
			match, err := b.ruleMatches(b.ruleKey(base, i, false), rules[i], target)
			if err != nil {
				return err
			}
			if !match {
				return fmt.Errorf("windows: NRPT rule %s changed during readback", name)
			}
		}
	}
	return nil
}

// deleteRules deletes the named rules under base in index order, so the
// catch-all goes before its NCSI exemption. It stops at the first failure,
// so a catch-all is never left without its exemption.
func (b *Backend) deleteRules(ctx context.Context, base string, names []string, mut *mutation) error {
	sortRuleNames(names)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		mut.begin(base)
		if err := b.reg.DeleteKey(base + `\` + name); err != nil {
			return fmt.Errorf("windows: delete NRPT rule %q: %w", name, err)
		}
		mut.rulesRemoved++
	}
	return nil
}

// verifyRuleSet checks that each store in stores holds exactly this
// identity's first n rules and each store in vacate holds none of them,
// catching another writer that raced this attempt.
func (b *Backend) verifyRuleSet(stores, vacate []string, n int) error {
	want := make([]string, 0, n)
	for i := range n {
		want = append(want, b.ruleName(i, false))
	}
	slices.Sort(want)
	for _, base := range stores {
		names, err := b.ownedRuleNames(base)
		if err != nil {
			return err
		}
		slices.Sort(names)
		if !slices.Equal(names, want) {
			return fmt.Errorf("windows: NRPT rules under %s are %v after converge, want %v", base, names, want)
		}
	}
	for _, base := range vacate {
		names, err := b.ownedRuleNames(base)
		if err != nil {
			return err
		}
		if len(names) > 0 {
			return fmt.Errorf("windows: NRPT rules %v remain under %s after converge", names, base)
		}
	}
	return nil
}

// clearArtifacts removes this identity's configuration in dependency order.
// Adapter values go first, while the rules that record the adapter still
// exist; if any value fails to clear, every rule stays so a retry can find
// the adapter. GP rules go before their local copies.
func (b *Backend) clearArtifacts(ctx context.Context, mut *mutation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := b.recoveryTarget(ctx)
	if err != nil {
		return err
	}
	if target != nil {
		b.owePredecessorReload()
		if err := b.clearAdapter(ctx, *target, mut); err != nil {
			return err
		}
	}
	// Run the owed reload before the rules go: their recovery records lead a
	// successor to the reload if this process exits first. A failed reload
	// stays owed in memory, but the rules are deleted anyway, since keeping
	// them would route queries to a resolver the caller is about to stop. If
	// this process then exits before a later reload succeeds, a successor's
	// Clear finds no target, and Windows is left to apply the change on its
	// own. A failed reload does not hold back the flush.
	if b.registerOwed {
		mut.reloadErr = b.reload(ctx, mut)
	}
	// finish reports the saved reload failure and cancellation.
	if ctx.Err() != nil {
		return nil
	}
	if err := b.removeRetiredContainer(ctx, mut); err != nil {
		return err
	}
	// If only dnsconfig rules hold the container and every owner has local
	// copies, retire the whole container, our rules included, before any
	// local copy goes. A GP rule of ours left without its local twin would
	// stop peers from ever retiring the container.
	_, collapse, err := b.gpDnsconfigHeld(ctx)
	if err != nil {
		return err
	}
	bases := []string{gpoNrptBase, nrptBase}
	if collapse {
		retired, err := b.retireGPContainer(ctx, mut)
		if err != nil {
			return err
		}
		if retired {
			bases = bases[1:]
		}
	}
	return b.clearRules(ctx, bases, mut)
}

// HasArtifacts implements backend.Backend by listing this identity's rules,
// active or staged, in both NRPT stores, as clearRules does. Every adapter
// value Set writes follows a rule naming that adapter, so the rules are the
// evidence Clear needs.
func (b *Backend) HasArtifacts(ctx context.Context) (bool, error) {
	for _, base := range []string{gpoNrptBase, nrptBase} {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		names, err := b.ownedRuleNames(base)
		if err != nil || len(names) > 0 {
			return len(names) > 0, err
		}
	}
	return false, nil
}

// clearRules deletes this identity's rules from bases, GP store first when
// it is listed. If any GP rule survives, the local copies stay too, for the
// reason clearArtifacts retires the container first.
func (b *Backend) clearRules(ctx context.Context, bases []string, mut *mutation) error {
	var errs []error
	gpRulesLeft := false
	for _, base := range bases {
		if ctx.Err() != nil {
			return errors.Join(errs...)
		}
		if base == nrptBase && gpRulesLeft {
			break
		}
		names, err := b.ownedRuleNames(base)
		if err == nil {
			err = b.deleteRules(ctx, base, names, mut)
		}
		if err != nil {
			errs = append(errs, err)
			if base == gpoNrptBase {
				gpRulesLeft = true
			}
		}
		if base == gpoNrptBase && len(names) > 0 {
			// The container's other holders may have left since this Clear
			// began. If our deletions emptied it, delete it now; later,
			// nothing will show it was ours. Finish this check even after
			// cancellation so an empty container cannot suppress local rules.
			if err := b.deleteContainerIfEmpty(mut); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// notifyPolicy asks Windows to reload policy after GP-store changes. It runs
// on every attempt that owes a notification; the worker's pacing limits how
// often. An accepted request completes the side effect even if delivery or
// activation is unconfirmed; that uncertainty is logged and does not
// trigger another request. A failed request fails the attempt
// and stays owed, so the worker retries it with backoff.
func (b *Backend) notifyPolicy() error {
	d, err := b.notifier.NotifyPolicyChange()
	unconfirmed := false
	switch d {
	case DeliveryNotified:
		b.logger.Info("Group Policy NRPT change notified", "delivery", d.String())
	case DeliveryRefresh:
		// Domain membership is a delivery heuristic, not an activation check.
		joined, jerr := b.domainJoined()
		if jerr != nil {
			b.logger.Warn("could not determine domain-join state; policy notification delivery is unconfirmed", "err", jerr)
		}
		if joined {
			b.logger.Info("Group Policy refresh requested on a domain-joined host; activation is unverified", "delivery", d.String())
		} else {
			unconfirmed = true
		}
	case DeliveryNone:
		if err == nil {
			err = errors.New("no notification mechanism accepted the request")
		}
		unconfirmed = true
	}
	if unconfirmed {
		b.logger.Warn("Group Policy notification delivery is unconfirmed; retaining rules for possible activation on a later refresh",
			"delivery", d.String(), "err", err)
	}
	if d == DeliveryNone {
		return fmt.Errorf("windows: Group Policy notification request failed: %w", err)
	}
	b.gpDirty = false
	return nil
}

// foreignPolicy reports whether the GP container holds rules or values no
// dnsconfig identity owns. Only those put this identity's rules in the GP
// store. Peers' rules do not, or two identities would hold each other there
// after foreign policy left.
func (b *Backend) foreignPolicy() (bool, error) {
	names, values, err := b.readContainer(gpoNrptBase)
	if err != nil {
		return false, err
	}
	return len(foreignRuleNames(names)) > 0 || len(values) > 0, nil
}

// readContainer lists the rule subkeys and the values of an NRPT container.
func (b *Backend) readContainer(base string) (names, values []string, err error) {
	names, err = b.reg.SubKeyNames(base)
	if err != nil {
		return nil, nil, fmt.Errorf("windows: inspect rules under %s: %w", base, err)
	}
	values, err = b.reg.ValueNames(base)
	if err != nil {
		return nil, nil, fmt.Errorf("windows: inspect values of %s: %w", base, err)
	}
	return names, values, nil
}

// foreignRuleNames returns the rule names no dnsconfig identity owns.
func foreignRuleNames(names []string) []string {
	var foreign []string
	for _, name := range names {
		if _, _, _, owned := parseRuleName(name); !owned {
			foreign = append(foreign, name)
		}
	}
	return foreign
}

// ruleMatches reports whether key holds the wanted rule values; other values
// on the key are ignored.
// A missing key or value is a mismatch, not an error.
func (b *Backend) ruleMatches(key string, rule nrptRule, target adapterTarget) (bool, error) {
	for _, value := range []struct{ name, want string }{
		{"GenericDNSServers", rule.servers}, {interfaceGUIDValue, target.guid},
	} {
		got, err := b.reg.GetString(key, value.name)
		if errors.Is(err, ErrValueNotFound) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("windows: inspect %s %s: %w", key, value.name, err)
		}
		if got != value.want {
			return false, nil
		}
	}
	gotDomains, err := b.reg.GetMultiString(key, "Name")
	if errors.Is(err, ErrValueNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("windows: inspect rule namespaces: %w", err)
	}
	if !slices.Equal(gotDomains, rule.domains) {
		return false, nil
	}
	for _, value := range []struct {
		name string
		want uint32
	}{{"Version", nrptVersion}, {"ConfigOptions", nrptUseGenericServers}} {
		got, err := b.reg.GetDWord(key, value.name)
		if errors.Is(err, ErrValueNotFound) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("windows: inspect rule %s: %w", value.name, err)
		}
		if got != value.want {
			return false, nil
		}
	}
	return true, nil
}

// gpDnsconfigHeld reports whether the GP container holds only dnsconfig
// rules, and at least one (held), and whether every other identity's rule
// there also has an identical local copy (collapsible). Retiring a
// collapsible container loses no routes: our rules are ours to remove, and
// each peer's local copy takes over. A peer rule that is staged or missing
// values is not ready, so the container stays. An empty container is not
// held, because nothing shows it belongs to dnsconfig.
func (b *Backend) gpDnsconfigHeld(ctx context.Context) (held, collapsible bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	names, values, err := b.readContainer(gpoNrptBase)
	if err != nil {
		return false, false, err
	}
	if len(values) != 0 || len(names) == 0 {
		return false, false, nil
	}
	collapsible = true
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return false, false, err
		}
		identity, _, pending, owned := parseRuleName(name)
		switch {
		case !owned:
			return false, false, nil
		case identity == b.identity || !collapsible:
		case pending:
			collapsible = false
		default:
			collapsible = b.hasLocalTwin(ctx, name)
		}
	}
	return true, collapsible, ctx.Err()
}

// hasLocalTwin reports whether a peer's GP rule has an identical local copy.
// An unreadable rule, in either store, counts as not ready rather than as an
// error: its owner keeps the container, and other identities' attempts do not
// fail over it.
func (b *Backend) hasLocalTwin(ctx context.Context, name string) bool {
	if ctx.Err() != nil {
		return false
	}
	key := gpoNrptBase + `\` + name
	domains, err := b.reg.GetMultiString(key, "Name")
	if err != nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	servers, err := b.reg.GetString(key, "GenericDNSServers")
	if err != nil {
		return false
	}
	target, err := b.readRecordTarget(ctx, key)
	if err != nil {
		return false
	}
	ready, err := b.ruleMatches(nrptBase+`\`+name, nrptRule{domains: domains, servers: servers}, target)
	return err == nil && ready
}

// retireGPContainer renames a collapsible GP container to retiredGPName,
// then deletes it. The rename removes the container and every rule in one
// step, so a crash cannot leave a partial GP table or an empty container of
// unknown origin. A retired key left by a crash is clearly dnsconfig's, and
// the next attempt deletes it. Collapsibility is checked again because
// another writer, such as the policy engine, may have changed the container
// since placement was chosen; retired is false if it did.
func (b *Backend) retireGPContainer(ctx context.Context, mut *mutation) (retired bool, err error) {
	_, ok, err := b.gpDnsconfigHeld(ctx)
	if err != nil || !ok {
		return false, err
	}
	if err := b.removeRetiredContainer(ctx, mut); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	names, err := b.reg.SubKeyNames(gpoNrptBase)
	if err != nil {
		return false, fmt.Errorf("windows: inspect policy rules: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	mut.begin(gpoNrptBase)
	if err := b.reg.RenameKey(gpoNrptBase, retiredGPName); err != nil {
		return false, fmt.Errorf("windows: retire Group Policy NRPT container: %w", err)
	}
	mut.rulesRemoved += len(names)
	mut.container = true
	if err := b.removeRetiredContainer(ctx, mut); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// A container that reappeared after the rename belongs to policy this
	// attempt's placement did not see.
	recreated, err := b.reg.KeyExists(gpoNrptBase)
	return err == nil && !recreated, err
}

// removeRetiredContainer deletes a retired container and its rules. The DNS
// Client never reads it, so a partial delete changes no routing, but its
// presence means GP rules were removed, so a policy notification is owed.
//
// The policy engine can write to the container between the collapsibility
// check and the rename. If the retired key holds foreign rules or values and
// no new container exists, the key is restored and the attempt fails, so the
// next attempt places rules for that policy. If a new container exists, the
// retired key cannot be restored and routes nothing either way, so it is
// deleted; left in place, it would block every later retirement by
// occupying retiredGPName.
func (b *Backend) removeRetiredContainer(ctx context.Context, mut *mutation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	exists, err := b.reg.KeyExists(retiredGPBase)
	if err != nil || !exists {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	mut.begin(gpoNrptBase)
	names, values, err := b.readContainer(retiredGPBase)
	if err != nil {
		return err
	}
	foreignRules := foreignRuleNames(names)
	if len(values) > 0 || len(foreignRules) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		active, err := b.reg.KeyExists(gpoNrptBase)
		if err != nil {
			return err
		}
		if !active {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := b.reg.RenameKey(retiredGPBase, gpoNrptName); err != nil {
				return fmt.Errorf("windows: restore policy container holding foreign rules: %w", err)
			}
			return errors.New("windows: foreign policy arrived while retiring the Group Policy NRPT container; restored it")
		}
		b.logger.Warn("deleting retired Group Policy NRPT container that holds foreign policy; a new container exists",
			"retired_path", retiredGPBase, "foreign_rules", foreignRules, "foreign_values", values)
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := b.reg.DeleteKey(retiredGPBase + `\` + name); err != nil {
			return fmt.Errorf("windows: delete retired NRPT rule %q: %w", name, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.reg.DeleteKey(retiredGPBase); err != nil {
		return fmt.Errorf("windows: delete retired policy container: %w", err)
	}
	return ctx.Err()
}

// deleteContainerIfEmpty removes the GP container when it holds no rules and
// no values.
func (b *Backend) deleteContainerIfEmpty(mut *mutation) error {
	names, values, err := b.readContainer(gpoNrptBase)
	if err != nil {
		return err
	}
	if len(names) > 0 || len(values) > 0 {
		return nil
	}
	exists, err := b.reg.KeyExists(gpoNrptBase)
	if err != nil || !exists {
		return err
	}
	mut.begin(gpoNrptBase)
	if err := b.reg.DeleteKey(gpoNrptBase); err != nil {
		return fmt.Errorf("windows: delete emptied Group Policy NRPT container: %w", err)
	}
	mut.container = true
	return nil
}

// ValidateConfig implements backend.Backend.
func (b *Backend) ValidateConfig(cfg backend.Config) error {
	for _, ns := range cfg.Nameservers {
		if ns.Zone() != "" {
			return fmt.Errorf("windows: zone-scoped nameserver %s is not supported by NRPT", ns)
		}
	}
	return nil
}
