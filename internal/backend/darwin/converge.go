//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// convergePlan is what one Set attempt must change, computed from cfg and a
// read of every owned artifact before anything is written.
type convergePlan struct {
	keys []stateKeyConfig
	// keyWrites lists desired key indices whose live key is missing or
	// differs; keyMissing marks the missing ones.
	keyWrites  []int
	keyMissing map[int]bool
	// obsoleteKeys names owned keys beyond the desired count.
	obsoleteKeys []string
	// compiled is the resolver table read with the store snapshot. It
	// verifies an attempt that writes nothing.
	compiled []dnsResolver

	body  []byte
	files map[string]bool
	// fileWrites lists desired resolver files that are missing or differ.
	fileWrites []string
	// obsoleteFiles lists owned resolver-directory entries that cfg does not
	// want, including staging files an interrupted write left behind.
	obsoleteFiles []string
}

// convergeChanges records what an attempt changed, for Result and logging.
type convergeChanges struct {
	keysCreated  []string
	keysUpdated  []string
	keysRemoved  []string
	filesWritten []string
	filesRemoved []string
}

func (c *convergeChanges) any() bool {
	return len(c.keysCreated)+len(c.keysUpdated)+len(c.keysRemoved)+len(c.filesWritten)+len(c.filesRemoved) > 0
}

// Set implements backend.Backend. Every attempt reads each owned
// State key and resolver file, writes only the differences, and verifies the
// compiled resolver table even when nothing was written, so a repeat of a
// converged goal changes nothing and flushes nothing. A failure leaves what
// was written for the next attempt.
func (b *Backend) Set(ctx context.Context, cfg backend.Config, attempt backend.Attempt) (backend.Result, error) {
	// Started before planning so a refused attempt still wakes the worker
	// when the host changes, for example when a conflicting claim goes away.
	b.ensureEventSource()

	plan, err := b.buildPlan(ctx, cfg)
	if err != nil {
		return backend.Result{Pending: b.flushOwed}, err
	}
	var changed convergeChanges
	// wrote counts a write that failed partway, such as a key configd
	// accepted but reshaped, so the worker records a possible change.
	wrote, err := b.apply(ctx, plan, &changed)
	if err == nil && b.flushOwed {
		err = b.flushResolverCache(ctx)
	}
	result := backend.Result{Changed: wrote, Pending: b.flushOwed}
	if changed.any() {
		b.logChanges(attempt, &changed, err)
	}
	return result, err
}

// ValidateConfig implements backend.Backend. It sizes the State keys a
// converge publishes; every configured search domain goes in one key.
func (b *Backend) ValidateConfig(cfg backend.Config) error {
	if cfg.IsSplit() && len(cfg.Nameservers) > maxResolverFileNameservers {
		return fmt.Errorf("darwin: split DNS supports at most %d nameservers, got %d", maxResolverFileNameservers, len(cfg.Nameservers))
	}
	for _, domain := range cfg.MatchDomains {
		if !isValidResolverFileName(domain) {
			return fmt.Errorf("darwin: refusing to write resolver file for unsafe domain %q", domain)
		}
	}
	_, err := buildStateKeys(cfg)
	return err
}

// buildPlan runs the conflict check and reads every owned artifact. It
// writes nothing, so any error it returns is a refusal.
func (b *Backend) buildPlan(ctx context.Context, cfg backend.Config) (*convergePlan, error) {
	plan := &convergePlan{files: map[string]bool{}, keyMissing: map[int]bool{}}
	for _, domain := range cfg.MatchDomains {
		plan.files[domain] = true
	}

	// The compiled table verifies a catch-all or search key; a split config
	// without search domains publishes neither.
	snap, err := b.takeSnapshot(ctx, !cfg.IsSplit() || len(cfg.SearchDomains) > 0)
	if err != nil {
		return nil, err
	}
	plan.compiled = snap.compiled

	keys, err := buildStateKeys(cfg)
	if err != nil {
		return nil, err
	}
	plan.keys = keys

	entries, err := b.scanResolverDir()
	if err != nil {
		return nil, err
	}
	otherFiles := b.otherIdentityFiles(entries)

	// Checked on every attempt: a configd restart drops every identity's
	// keys, and another identity may republish a contended namespace first.
	if err := b.checkConflicts(cfg, snap, otherFiles); err != nil {
		return nil, err
	}

	for i, want := range keys {
		got, found, err := snap.key(b.stateKey(i))
		if err != nil {
			return nil, err
		}
		if found && stateKeyEqual(got, want) {
			continue
		}
		plan.keyWrites = append(plan.keyWrites, i)
		plan.keyMissing[i] = !found
	}
	for idx, name := range snap.owned(b.identity) {
		if idx >= len(keys) {
			plan.obsoleteKeys = append(plan.obsoleteKeys, name)
		}
	}
	slices.Sort(plan.obsoleteKeys)

	if cfg.IsSplit() {
		plan.body = renderResolverFile(b.identity, cfg.Nameservers)
	}
	for name := range plan.files {
		path := filepath.Join(b.resolverDir, name)
		current, exists, owner, err := b.inspectResolverFile(path)
		if err != nil {
			return nil, fmt.Errorf("darwin: inspect %s: %w", path, err)
		}
		if exists && owner != b.identity {
			if owner != "" {
				return nil, backend.NewConflictError(name, owner)
			}
			return nil, fmt.Errorf("darwin: refusing to overwrite foreign resolver file %s", path)
		}
		if !bytes.Equal(current, plan.body) {
			plan.fileWrites = append(plan.fileWrites, name)
		}
	}
	slices.Sort(plan.fileWrites)

	for _, name := range b.ownedNames(entries) {
		if !plan.files[name] {
			plan.obsoleteFiles = append(plan.obsoleteFiles, name)
		}
	}
	return plan, nil
}

// apply carries out plan. Resolver files are written before State keys
// and obsolete artifacts are removed only after the compiled table verifies,
// so a suffix moving between mechanisms never falls back to the uplink in
// between. Obsolete key removal is attempted before file removal to avoid
// leaving competing search keys without their covering file. File cleanup
// continues after a key-removal failure because obsolete files can route
// queries to a resolver the caller may stop.
// touched reports whether anything was written or removed.
func (b *Backend) apply(ctx context.Context, plan *convergePlan, changed *convergeChanges) (touched bool, err error) {
	touch := func() {
		touched = true
		b.flushOwed = true
	}

	if len(plan.fileWrites) > 0 {
		if err := b.fs.MkdirAll(b.resolverDir, 0o755); err != nil {
			return touched, fmt.Errorf("darwin: mkdir %s: %w", b.resolverDir, err)
		}
	}
	for _, name := range plan.fileWrites {
		touch()
		if err := b.publishResolverFile(name, plan.body); err != nil {
			return touched, err
		}
		changed.filesWritten = append(changed.filesWritten, name)
	}

	for _, idx := range plan.keyWrites {
		touch()
		if err := b.writeStateKey(ctx, idx, plan.keys[idx]); err != nil {
			return touched, err
		}
		if plan.keyMissing[idx] {
			changed.keysCreated = append(changed.keysCreated, b.stateKey(idx))
		} else {
			changed.keysUpdated = append(changed.keysUpdated, b.stateKey(idx))
		}
	}

	if len(plan.keys) > 0 {
		// A write changes what configd compiles; without one, the table read
		// with the plan is current.
		resolvers := plan.compiled
		if touched {
			if resolvers, err = b.readCompiledDNS(ctx); err != nil {
				return touched, err
			}
		}
		if err := verifyCompiledDNS(plan.keys, resolvers); err != nil {
			return touched, err
		}
	}

	var errs []error
	if len(plan.obsoleteKeys) > 0 {
		touch()
		removed, _, err := b.removeStateKeys(ctx, plan.obsoleteKeys)
		if err != nil {
			errs = append(errs, err)
		}
		changed.keysRemoved = append(changed.keysRemoved, removed...)
	}
	for _, name := range plan.obsoleteFiles {
		touch()
		if err := b.removeOwnedResolverEntry(name); err != nil {
			errs = append(errs, err)
			continue
		}
		changed.filesRemoved = append(changed.filesRemoved, name)
	}
	if err := b.syncResolverDir(); err != nil {
		errs = append(errs, err)
	}
	return touched, errors.Join(errs...)
}

// logChanges reports a converge that changed the host. Creating keys after
// the goal had converged gets its own message: the smoke harness reads it to
// prove a configd restart was repaired, not survived. A retry that finishes
// a partial first install does not qualify.
func (b *Backend) logChanges(attempt backend.Attempt, c *convergeChanges, err error) {
	msg := "darwin: converge changed host DNS"
	if attempt.Converged && len(c.keysCreated) > 0 {
		msg = "darwin: converge recreated dynamic-store keys"
	}
	attrs := []any{"new_goal", attempt.NewGoal, "converged", attempt.Converged}
	add := func(key string, values []string) {
		if len(values) > 0 {
			attrs = append(attrs, key, values)
		}
	}
	add("keys_created", c.keysCreated)
	add("keys_updated", c.keysUpdated)
	add("keys_removed", c.keysRemoved)
	add("files_written", c.filesWritten)
	add("files_removed", c.filesRemoved)
	level := slog.LevelInfo
	if err != nil {
		level = slog.LevelWarn
		attrs = append(attrs, "err", err)
	}
	b.logger.Log(context.Background(), level, msg, attrs...)
}

// Clear implements backend.Backend. It removes every State key and
// resolver file discovery attributes to this identity, including a crashed
// predecessor's, then completes an owed cache flush. A failed attempt defers
// the flush to its retry, except the final cleanup, which has none. Once
// nothing remains and nothing is owed it stops the notification source,
// which has nothing left to watch.
func (b *Backend) Clear(ctx context.Context, attempt backend.Attempt) (backend.Result, error) {
	changed, err := b.clearArtifacts(ctx, attempt.Final)
	if b.flushOwed && (err == nil || attempt.Final) {
		err = errors.Join(err, b.flushResolverCache(ctx))
	}
	result := backend.Result{Changed: changed, Pending: b.flushOwed}
	if err == nil {
		b.releaseEventSource()
	}
	return result, err
}

// clearArtifacts removes this identity's artifacts and reports whether it
// removed any.
func (b *Backend) clearArtifacts(ctx context.Context, final bool) (bool, error) {
	// Inspect everything before removing anything, so an unreadable entry
	// leaves the host as it was.
	entries, err := b.scanResolverDir()
	if err != nil {
		return false, err
	}
	files := b.ownedNames(entries)
	var errs []error
	keys, err := b.listStateKeyNames(ctx)
	if err != nil {
		// The final Clear has no retry, and a resolver file outlives the
		// configd restarts and reboots that drop State keys, so it still
		// removes the files it attributed. Keys are never removed unlisted.
		if !final {
			return false, err
		}
		errs = append(errs, err)
	}

	var removed []string
	var unverified bool
	// Keys go first: another identity's key beside ours for a domain is
	// admitted only while our file for it exists, so a Clear cut short after
	// removing the file would leave the two keys competing and refuse that
	// identity. A failed key removal does not hold the files back, because a
	// file left behind keeps routing the domain to a resolver that is likely
	// gone; the peer is then refused until this identity's next Clear, a
	// configd restart, or a reboot removes the key.
	if len(keys) > 0 {
		b.flushOwed = true
		gone, unchecked, err := b.removeStateKeys(ctx, keys)
		if err != nil {
			errs = append(errs, err)
		}
		removed = append(removed, gone...)
		unverified = unchecked
	}
	for _, name := range files {
		b.flushOwed = true
		if err := b.removeOwnedResolverEntry(name); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, filepath.Join(b.resolverDir, name))
	}
	if err := b.syncResolverDir(); err != nil {
		errs = append(errs, err)
	}
	if len(removed) > 0 {
		b.logger.Info("darwin: clear removed owned DNS artifacts", "removed", removed)
	}
	return len(removed) > 0 || unverified, errors.Join(errs...)
}

// resolverTempName is the staging name for domain's resolver file.
func resolverTempName(identity, domain string) string {
	// A full domain plus the identity can exceed the filesystem name limit.
	return fmt.Sprintf("%s%s%s%x", resolverTempPrefix, identity, resolverTempSep, sha256.Sum256([]byte(domain)))
}

// removeOwnedResolverEntry removes name from the resolver directory. Remove
// acts on a link itself, never its target. Already gone counts as removed.
func (b *Backend) removeOwnedResolverEntry(name string) error {
	path := filepath.Join(b.resolverDir, name)
	if err := b.fs.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("darwin: remove %s: %w", path, err)
	}
	b.dirSyncOwed = true
	return nil
}

// syncResolverDir makes owed removals durable. Without it a power loss after
// a final Clear can bring a removed file back at boot, routing its domain to
// a resolver that is gone with nothing left to remove it. A failure fails the
// attempt, so a non-final Clear or Set retries the sync before converging.
func (b *Backend) syncResolverDir() error {
	if !b.dirSyncOwed {
		return nil
	}
	// A missing directory holds nothing to resurrect: rmdir needed it empty.
	if err := b.fs.SyncDir(b.resolverDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("darwin: sync %s: %w", b.resolverDir, err)
	}
	b.dirSyncOwed = false
	return nil
}

// publishResolverFile writes body to a staging file and renames it over the
// domain's resolver file, so an interrupted write leaves either the previous
// file or the complete new one, never a truncated header that would make
// this identity's file look foreign. Rename replaces rather than follows a
// link at the destination. The host lock excludes other identities between
// planning and rename; an unrelated privileged writer in /etc/resolver takes
// no part in it, so the ownership re-check narrows but cannot close that race.
func (b *Backend) publishResolverFile(name string, body []byte) error {
	path := filepath.Join(b.resolverDir, name)
	tmp := filepath.Join(b.resolverDir, resolverTempName(b.identity, name))
	// A leftover staging entry is removed first so that WriteFile creates a
	// fresh file instead of writing through a link placed there.
	if err := b.fs.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("darwin: remove stale %s: %w", tmp, err)
	}
	fail := func(err error) error {
		if rmErr := b.fs.Remove(tmp); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			// Discovery attributes the staging name, so a later converge or
			// Clear removes it.
			b.logger.Warn("darwin: could not remove resolver staging file", "path", tmp, "err", rmErr)
		}
		return err
	}
	if err := b.fs.WriteFile(tmp, body, 0o644); err != nil {
		return fail(fmt.Errorf("darwin: write %s: %w", tmp, err))
	}
	// WriteFile's mode is subject to the umask; resolver files must be
	// world-readable for mDNSResponder.
	if err := b.fs.Chmod(tmp, 0o644); err != nil {
		return fail(fmt.Errorf("darwin: chmod %s: %w", tmp, err))
	}
	// Rename does not order the file's data and mode before it, so a power
	// loss after an unsynced rename can leave a header-less file at path that
	// Set then refuses as foreign and Clear skips.
	if err := b.fs.Sync(tmp); err != nil {
		return fail(fmt.Errorf("darwin: sync %s: %w", tmp, err))
	}
	_, exists, owner, err := b.inspectResolverFile(path)
	if err != nil {
		return fail(fmt.Errorf("darwin: inspect %s before rename: %w", path, err))
	}
	if exists && owner != b.identity {
		return fail(fmt.Errorf("darwin: refusing to replace resolver file %s owned elsewhere", path))
	}
	if err := b.fs.Rename(tmp, path); err != nil {
		return fail(fmt.Errorf("darwin: rename %s: %w", path, err))
	}
	return nil
}

// flushResolverCache flushes the directory-services and mDNSResponder caches
// and clears the owed flush only when both succeed.
func (b *Backend) flushResolverCache(ctx context.Context) error {
	var errs []error
	if _, stderr, err := b.runner.Run(ctx, dscacheutilBinary, []string{"-flushcache"}, nil); err != nil {
		errs = append(errs, fmt.Errorf("darwin: dscacheutil -flushcache: %w: %s", err, bytes.TrimSpace(stderr)))
	}
	if _, stderr, err := b.runner.Run(ctx, killallBinary, []string{"-HUP", mDNSResponderProcess}, nil); err != nil {
		errs = append(errs, fmt.Errorf("darwin: killall -HUP mDNSResponder: %w: %s", err, bytes.TrimSpace(stderr)))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	b.flushOwed = false
	return nil
}
