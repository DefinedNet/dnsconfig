//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// hostLog is the combined mutation log of both fakes at one moment.
type hostLog struct {
	fs     []fsMutation
	scutil []string
}

func observeHost(fs *testFS, fake *scutilFake) hostLog {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return hostLog{fs: fs.mutations(), scutil: slices.Clone(fake.mutating)}
}

// assertQuiet fails unless log holds no mutation.
func assertQuiet(t *testing.T, log hostLog, msg string) {
	t.Helper()
	assert.Empty(t, log.fs, msg)
	assert.Empty(t, log.scutil, msg)
}

// since returns what was logged after before.
func (h hostLog) since(before hostLog) hostLog {
	return hostLog{fs: h.fs[len(before.fs):], scutil: h.scutil[len(before.scutil):]}
}

func splitNoSearchConfig() backend.Config {
	cfg := splitConfig()
	cfg.SearchDomains = nil
	return cfg
}

func TestResolverFileWithMaximumLengthDomain(t *testing.T) {
	fs := newTestFS(t)
	b := newTestBackend(t, fs, newScutilFake())
	b.identity = strings.Repeat("a", 63)
	domain := strings.Repeat(strings.Repeat("b", 63)+".", 3) + strings.Repeat("c", 61)
	cfg := splitNoSearchConfig()
	cfg.MatchDomains = []string{domain}

	res, err := b.Set(context.Background(), cfg, newGoal)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	body, err := os.ReadFile(fs.path(domain))
	require.NoError(t, err)
	assert.Equal(t, renderResolverFile(b.identity, cfg.Nameservers), body)
	_, err = b.Clear(context.Background(), newGoal)
	require.NoError(t, err)
	entries, err := os.ReadDir(fs.dir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// TestConvergedSetWritesNothing is the no-op invariant: our own writes raise
// the notifications that wake the worker, so any side effect on a converged
// host would sustain its own loop.
func TestConvergedSetWritesNothing(t *testing.T) {
	overlapping := catchAllConfig()
	overlapping.SearchDomains = []string{"lan.example", "corp.example"}
	for _, tc := range []struct {
		name string
		cfg  backend.Config
	}{
		{"catch-all", catchAllConfig()},
		{"split with search", splitConfig()},
		{"split without search", splitNoSearchConfig()},
		{"search overlapping the base list", overlapping},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			b := newTestBackend(t, fs, fake)
			res, err := b.Set(context.Background(), tc.cfg, newGoal)
			require.NoError(t, err)
			require.Equal(t, backend.Result{Changed: true}, res)

			for _, attempt := range []backend.Attempt{repeat, repeat, newGoal} {
				before := observeHost(fs, fake)
				res, err := b.Set(context.Background(), tc.cfg, attempt)
				require.NoError(t, err)
				assert.Equal(t, backend.Result{}, res)
				assertQuiet(t, observeHost(fs, fake).since(before), "a converged host sees no key, file, or cache-flush command")
			}
		})
	}
}

// TestSearchDomainsIgnoreTheBaseList: every search domain is published,
// including one the primary service already supplies, so the keys do not
// depend on the network and a change to the base list rewrites nothing.
func TestSearchDomainsIgnoreTheBaseList(t *testing.T) {
	search := []string{"lan.example", "corp.example"}
	ns := []netip.Addr{netip.MustParseAddr("127.0.0.99")}
	for _, tc := range []struct {
		name string
		cfg  backend.Config
		key  int
	}{
		{"catch-all", backend.Config{Nameservers: ns, SearchDomains: search}, 1},
		{"split", backend.Config{Nameservers: ns, MatchDomains: []string{"example"}, SearchDomains: search}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			b := newTestBackend(t, fs, fake)
			cfg := tc.cfg
			require.Contains(t, fake.baseSearch, "lan.example")
			require.NoError(t, trySet(b, cfg))
			key, found := fake.key(tc.key)
			require.True(t, found)
			assert.Equal(t, search, key.Domains)
			assert.False(t, key.NoSearch)

			for _, base := range [][]string{nil, {"corp.example", "other.example"}, {"lan.example"}} {
				fake.mu.Lock()
				fake.baseSearch = base
				fake.mu.Unlock()
				before := observeHost(fs, fake)
				res, err := b.Set(context.Background(), cfg, repeat)
				require.NoError(t, err)
				assert.Equal(t, backend.Result{}, res)
				assertQuiet(t, observeHost(fs, fake).since(before), "the base list does not feed the keys")
			}
		})
	}
}

// TestSearchClaimsMatchPublishedKeys: a search domain the primary service
// already supplies is still published, so another identity sees the claim
// this identity's conflict check makes. Hiding it would admit the peer and
// then refuse this identity on every repair.
func TestSearchClaimsMatchPublishedKeys(t *testing.T) {
	ns := []netip.Addr{netip.MustParseAddr("127.0.0.99")}
	searcher := backend.Config{Nameservers: ns, MatchDomains: []string{"example"}, SearchDomains: []string{"lan.example"}}
	catchAll := backend.Config{Nameservers: ns, SearchDomains: []string{"lan.example"}}
	for _, tc := range []struct {
		name          string
		first, second backend.Config
	}{
		{"split searcher first", searcher, catchAll},
		{"catch-all searcher first", catchAll, searcher},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			require.Contains(t, fake.baseSearch, "lan.example")
			first := newTestBackend(t, fs, fake)
			second, err := New(context.Background(), Options{Identity: otherIdentity, FS: fs, Runner: fake, Logger: discardLogger()})
			require.NoError(t, err)
			useFS(second, fs)
			t.Cleanup(func() { _ = second.Close() })

			require.NoError(t, trySet(first, tc.first))
			before := observeHost(fs, fake)
			err = trySet(second, tc.second)
			var conflict *backend.ConflictError
			require.ErrorAs(t, err, &conflict)
			assert.Equal(t, "lan.example.", conflict.Domain)
			assert.Equal(t, testIdentity, conflict.Holder)
			assertQuiet(t, observeHost(fs, fake).since(before), "a refused Set writes nothing")

			res, err := first.Set(context.Background(), tc.first, repeat)
			require.NoError(t, err, "the first identity's repair is not refused")
			assert.Equal(t, backend.Result{}, res)
		})
	}
}

// TestCompiledTableReadFailsClosed: the snapshot reads scutil --dns before
// writing and the attempt re-reads it after. An empty table fails
// verification and unrecognized output fails as unanswered, never passing.
// After a write that is a touched failure the worker retries; before one it
// is a refusal that writes nothing.
func TestCompiledTableReadFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		out    string
		wantIs error
		want   string
	}{
		{"empty table", "DNS configuration\n", nil, "compiled resolver table"},
		{"no configuration", "No DNS configuration available\n", errScutilUnanswered, ""},
		{"silent", "", errScutilUnanswered, ""},
		{"server gone", "  Configuration daemon not (no longer) available\n", errScutilUnanswered, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			fake.compiledOutput = []byte(tc.out)
			fake.compiledOutputFrom = 1
			b := newTestBackend(t, fs, fake)

			check := func(err error) {
				t.Helper()
				if tc.wantIs != nil {
					assert.ErrorIs(t, err, tc.wantIs)
				} else {
					assert.ErrorContains(t, err, tc.want)
				}
			}
			res, err := b.Set(context.Background(), catchAllConfig(), newGoal)
			check(err)
			assert.Equal(t, backend.Result{Changed: true, Pending: true}, res)
			assert.Zero(t, fake.flushCount())

			before := observeHost(fs, fake)
			res, err = b.Set(context.Background(), catchAllConfig(), repeat)
			check(err)
			assert.False(t, res.Changed)
			assertQuiet(t, observeHost(fs, fake).since(before), "a quiet attempt touches nothing")

			res, err = b.Set(context.Background(), splitNoSearchConfig(), repeat)
			require.NoError(t, err, "a goal without keys never reads the table")
			assert.True(t, res.Changed)

			fake.mu.Lock()
			fake.compiledOutput = nil
			fake.mu.Unlock()
			require.NoError(t, trySet(b, catchAllConfig()))
		})
	}
}

// TestOwedFlushCompletesOnceAfterFailedAttempt: a failed attempt that wrote
// something owes a flush; the next successful attempt performs it exactly
// once, whether or not it writes anything itself.
func TestOwedFlushCompletesOnceAfterFailedAttempt(t *testing.T) {
	t.Run("write failure", func(t *testing.T) {
		fs := newTestFS(t)
		fake := newScutilFake()
		b := newTestBackend(t, fs, fake)
		// The search key write fails after the catch-all key landed.
		fake.armMutationFailure(1)
		res, err := b.Set(context.Background(), catchAllConfig(), newGoal)
		require.ErrorIs(t, err, errInjectedScutil)
		assert.Equal(t, backend.Result{Changed: true, Pending: true}, res, "the attempt had started writing")
		assert.Zero(t, fake.flushCount(), "a partial converge does not flush")

		fake.armMutationFailure(-1)
		res, err = b.Set(context.Background(), catchAllConfig(), repeat)
		require.NoError(t, err)
		assert.Equal(t, backend.Result{Changed: true}, res)
		assert.Equal(t, 1, fake.flushCount())

		_, err = b.Set(context.Background(), catchAllConfig(), repeat)
		require.NoError(t, err)
		assert.Equal(t, 1, fake.flushCount(), "the owed flush completed once")
	})

	t.Run("verification failure after writes", func(t *testing.T) {
		fs := newTestFS(t)
		fake := newScutilFake()
		b := newTestBackend(t, fs, fake)
		fake.mu.Lock()
		fake.omitCompiled = true
		fake.mu.Unlock()
		res, err := b.Set(context.Background(), catchAllConfig(), newGoal)
		require.ErrorContains(t, err, "compiled resolver table")
		assert.Equal(t, backend.Result{Changed: true, Pending: true}, res)
		assert.Equal(t, 2, fake.keyCount(), "a failed converge leaves what it wrote")
		assert.Zero(t, fake.flushCount())

		fake.mu.Lock()
		fake.omitCompiled = false
		fake.mu.Unlock()
		before := observeHost(fs, fake)
		res, err = b.Set(context.Background(), catchAllConfig(), repeat)
		require.NoError(t, err)
		assert.Equal(t, backend.Result{}, res, "nothing left to write, and the flush completed")
		assert.Equal(t, []string{"dscacheutil", "killall"}, observeHost(fs, fake).since(before).scutil)
	})

	t.Run("flush failure", func(t *testing.T) {
		fs := newTestFS(t)
		fake := newScutilFake()
		b := newTestBackend(t, fs, fake)
		flushErr := errors.New("dscacheutil failed")
		fake.mu.Lock()
		fake.flushErr = flushErr
		fake.mu.Unlock()
		res, err := b.Set(context.Background(), catchAllConfig(), newGoal)
		require.ErrorIs(t, err, flushErr)
		assert.Equal(t, backend.Result{Changed: true, Pending: true}, res)

		// The repeat finds every artifact in place, so it writes nothing;
		// the flush stays owed.
		res, err = b.Set(context.Background(), catchAllConfig(), repeat)
		require.ErrorIs(t, err, flushErr)
		assert.Equal(t, backend.Result{Pending: true}, res)

		fake.mu.Lock()
		fake.flushErr = nil
		fake.mu.Unlock()
		res, err = b.Set(context.Background(), catchAllConfig(), repeat)
		require.NoError(t, err)
		assert.Equal(t, backend.Result{}, res)
		assert.Equal(t, 3, fake.flushCount())
	})

	t.Run("clear with nothing left", func(t *testing.T) {
		fs := newTestFS(t)
		fake := newScutilFake()
		b := newTestBackend(t, fs, fake)
		require.NoError(t, trySet(b, catchAllConfig()))
		flushErr := errors.New("dscacheutil failed")
		fake.mu.Lock()
		fake.flushErr = flushErr
		fake.mu.Unlock()
		res, err := b.Clear(context.Background(), newGoal)
		require.ErrorIs(t, err, flushErr)
		assert.Equal(t, backend.Result{Changed: true, Pending: true}, res)
		assert.Zero(t, fake.keyCount())

		fake.mu.Lock()
		fake.flushErr = nil
		fake.mu.Unlock()
		flushes := fake.flushCount()
		res, err = b.Clear(context.Background(), repeat)
		require.NoError(t, err)
		assert.Equal(t, backend.Result{}, res, "only the owed flush remained")
		assert.Equal(t, flushes+1, fake.flushCount())

		res, err = b.Clear(context.Background(), repeat)
		require.NoError(t, err)
		assert.Equal(t, backend.Result{}, res)
		assert.Equal(t, flushes+1, fake.flushCount())
	})
}

// TestConvergeRepairsDrift: each kind of drift is corrected by one converge,
// and the converge after it is quiet.
func TestConvergeRepairsDrift(t *testing.T) {
	const file, stale = "corp.example", "stale.example"
	staging := resolverTempName(testIdentity, file)
	for _, tc := range []struct {
		name  string
		drift func(t *testing.T, fs *testFS, fake *scutilFake)
		check func(t *testing.T, fs *testFS, fake *scutilFake)
	}{
		{
			name:  "missing key",
			drift: func(_ *testing.T, _ *testFS, fake *scutilFake) { fake.deleteKey(0) },
			check: func(t *testing.T, _ *testFS, fake *scutilFake) {
				_, found := fake.key(0)
				assert.True(t, found)
			},
		},
		{
			name: "modified key",
			drift: func(_ *testing.T, _ *testFS, fake *scutilFake) {
				fake.mu.Lock()
				fake.keys[0] = stateKeyConfig{Servers: []string{"192.0.2.9"}, Domains: []string{"corp.example"}}
				fake.mu.Unlock()
			},
			check: func(t *testing.T, _ *testFS, fake *scutilFake) {
				key, found := fake.key(0)
				require.True(t, found)
				assert.Equal(t, []string{"127.0.0.99"}, key.Servers)
			},
		},
		{
			name:  "missing file",
			drift: func(t *testing.T, fs *testFS, _ *scutilFake) { require.NoError(t, os.Remove(fs.path(file))) },
		},
		{
			name: "modified file",
			drift: func(t *testing.T, fs *testFS, _ *scutilFake) {
				fs.seed(t, file, renderResolverFile(testIdentity, []netip.Addr{netip.MustParseAddr("192.0.2.9")}), 0o644)
			},
		},
		{
			name: "stale predecessor key",
			drift: func(_ *testing.T, _ *testFS, fake *scutilFake) {
				fake.mu.Lock()
				fake.keys[3] = stateKeyConfig{Servers: []string{"127.0.0.99"}, Domains: []string{""}, NoSearch: true}
				fake.mu.Unlock()
			},
			check: func(t *testing.T, _ *testFS, fake *scutilFake) {
				_, found := fake.key(3)
				assert.False(t, found)
			},
		},
		{
			name: "stale predecessor file",
			drift: func(t *testing.T, fs *testFS, _ *scutilFake) {
				fs.seed(t, stale, renderResolverFile(testIdentity, []netip.Addr{netip.MustParseAddr("127.0.0.99")}), 0o644)
			},
			check: func(t *testing.T, fs *testFS, _ *scutilFake) {
				_, err := os.Lstat(fs.path(stale))
				assert.ErrorIs(t, err, os.ErrNotExist)
			},
		},
		{
			name: "staging file with a truncated header",
			drift: func(t *testing.T, fs *testFS, _ *scutilFake) {
				fs.seed(t, staging, []byte("# Managed"), 0o644)
			},
			check: func(t *testing.T, fs *testFS, _ *scutilFake) {
				_, err := os.Lstat(fs.path(staging))
				assert.ErrorIs(t, err, os.ErrNotExist)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fake := newScutilFake()
			b := newTestBackend(t, fs, fake)
			cfg := splitConfig()
			require.NoError(t, trySet(b, cfg))
			tc.drift(t, fs, fake)

			res, err := b.Set(context.Background(), cfg, repeat)
			require.NoError(t, err)
			assert.Equal(t, backend.Result{Changed: true}, res)
			body, err := os.ReadFile(fs.path(file))
			require.NoError(t, err)
			assert.Equal(t, renderResolverFile(testIdentity, cfg.Nameservers), body)
			assert.Equal(t, os.FileMode(0o644), fileMode(t, fs.path(file)))
			if tc.check != nil {
				tc.check(t, fs, fake)
			}

			before := observeHost(fs, fake)
			res, err = b.Set(context.Background(), cfg, repeat)
			require.NoError(t, err)
			assert.Equal(t, backend.Result{}, res)
			assertQuiet(t, observeHost(fs, fake).since(before), "the repaired host is converged")
		})
	}
}

// TestVerificationMismatchRetriesWithoutLatching: configd rejecting what was
// written fails the attempt, and the next attempt tries again.
func TestVerificationMismatchRetriesWithoutLatching(t *testing.T) {
	t.Run("read-back", func(t *testing.T) {
		fake := newScutilFake()
		b := newTestBackend(t, newTestFS(t), fake)
		fake.mu.Lock()
		fake.corruptNextSet = true
		fake.mu.Unlock()
		res, err := b.Set(context.Background(), catchAllConfig(), newGoal)
		require.ErrorContains(t, err, "read-back mismatch")
		assert.True(t, res.Changed, "configd accepted the write before reshaping it")

		_, err = b.Set(context.Background(), catchAllConfig(), repeat)
		require.NoError(t, err)
		key, found := fake.key(0)
		require.True(t, found)
		assert.Equal(t, []string{""}, key.Domains)
		assert.True(t, key.NoSearch)
	})

	t.Run("compiled table on a quiet attempt", func(t *testing.T) {
		fs := newTestFS(t)
		fake := newScutilFake()
		b := newTestBackend(t, fs, fake)
		require.NoError(t, trySet(b, catchAllConfig()))
		fake.mu.Lock()
		fake.omitCompiled = true
		fake.mu.Unlock()
		before := observeHost(fs, fake)
		for range 2 {
			res, err := b.Set(context.Background(), catchAllConfig(), repeat)
			require.ErrorContains(t, err, "compiled resolver table", "verification runs even when nothing is written")
			assert.False(t, res.Changed, "nothing was touched")
		}
		assert.Empty(t, observeHost(fs, fake).since(before).scutil)

		fake.mu.Lock()
		fake.omitCompiled = false
		fake.mu.Unlock()
		_, err := b.Set(context.Background(), catchAllConfig(), repeat)
		require.NoError(t, err)
	})
}

// TestRepeatRefusesNamespaceTakenWhileKeysWereMissing models a configd
// restart: every identity's keys vanish, another identity republishes the
// contended catch-all first, and this identity's next converge is refused
// before writing, until the holder lets go.
func TestRepeatRefusesNamespaceTakenWhileKeysWereMissing(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)
	require.NoError(t, trySet(b, catchAllConfig()))

	fake.mu.Lock()
	clear(fake.keys)
	holder := stateKeyName(otherIdentity, 0)
	fake.otherKeys[holder] = stateKeyConfig{Servers: []string{"127.0.0.77"}, Domains: []string{""}, NoSearch: true}
	fake.mu.Unlock()

	before := observeHost(fs, fake)
	res, err := b.Set(context.Background(), catchAllConfig(), repeat)
	require.Error(t, err)
	var conflict *backend.ConflictError
	require.ErrorAs(t, err, &conflict)
	assert.Equal(t, ".", conflict.Domain)
	assert.Equal(t, otherIdentity, conflict.Holder)
	assert.Equal(t, backend.Result{}, res, "a refused converge reports no write")
	assert.Empty(t, observeHost(fs, fake).since(before).scutil, "a refused converge writes nothing")

	fake.mu.Lock()
	delete(fake.otherKeys, holder)
	fake.mu.Unlock()
	res, err = b.Set(context.Background(), catchAllConfig(), repeat)
	require.NoError(t, err)
	assert.Equal(t, backend.Result{Changed: true}, res)
	assert.Equal(t, 2, fake.keyCount())
}

// partialWriteFS writes a prefix of the body and fails, as an interrupted
// write would, and can also fail the cleanup of the file it left.
type partialWriteFS struct {
	*testFS
	failWrites  int
	failRemoves bool
}

func (f *partialWriteFS) WriteFile(path string, body []byte, perm os.FileMode) error {
	if f.failWrites > 0 {
		f.failWrites--
		if err := f.testFS.WriteFile(path, body[:10], perm); err != nil {
			return err
		}
		return errors.New("injected short write")
	}
	return f.testFS.WriteFile(path, body, perm)
}

func (f *partialWriteFS) Remove(path string) error {
	if _, err := os.Lstat(path); err == nil && f.failRemoves {
		return errors.New("injected remove failure")
	}
	return f.testFS.Remove(path)
}

// TestInterruptedResolverWriteLeavesNoUnownedFile: a write cut short lands in
// the staging file, never at the domain's path, and a staging file that
// cannot be removed is still attributed to this identity by name.
func TestInterruptedResolverWriteLeavesNoUnownedFile(t *testing.T) {
	for _, stuck := range []bool{false, true} {
		t.Run(map[bool]string{false: "staging removed", true: "staging stuck"}[stuck], func(t *testing.T) {
			fs := &partialWriteFS{testFS: newTestFS(t), failWrites: 1, failRemoves: stuck}
			path := fs.path("corp.example")
			staging := fs.path(resolverTempName(testIdentity, "corp.example"))
			fake := newScutilFake()
			b := newTestBackend(t, fs, fake)
			cfg := splitNoSearchConfig()

			_, err := b.Set(context.Background(), cfg, newGoal)
			require.ErrorContains(t, err, "injected short write")
			_, err = os.Lstat(path)
			assert.ErrorIs(t, err, os.ErrNotExist, "the domain's path never holds a partial file")
			_, err = os.Lstat(staging)
			if stuck {
				require.NoError(t, err)
				assert.True(t, hasOwned(t, b), "a stuck staging file is recovery evidence")
			} else {
				assert.ErrorIs(t, err, os.ErrNotExist)
			}

			fs.failRemoves = false
			_, err = b.Set(context.Background(), cfg, repeat)
			require.NoError(t, err, "the retry does not mistake our partial write for a foreign file")
			body, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, renderResolverFile(testIdentity, cfg.Nameservers), body)
			_, err = os.Lstat(staging)
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}

	t.Run("clear removes a stuck staging file", func(t *testing.T) {
		fs := &partialWriteFS{testFS: newTestFS(t), failWrites: 1, failRemoves: true}
		b := newTestBackend(t, fs, newScutilFake())
		_, err := b.Set(context.Background(), splitNoSearchConfig(), newGoal)
		require.Error(t, err)
		fs.failRemoves = false

		res, err := b.Clear(context.Background(), newGoal)
		require.NoError(t, err)
		assert.True(t, res.Changed)
		assert.False(t, hasOwned(t, b))
	})
}

// TestResolverFileSyncedBeforeRename: the staged file is durable before it
// takes the domain's name, and a failed sync never renames.
func TestResolverFileSyncedBeforeRename(t *testing.T) {
	const name = "corp.example"
	staging := resolverTempName(testIdentity, name)
	syncErr := errors.New("injected sync failure")
	for _, tc := range []struct {
		name    string
		syncErr error
		want    []fsMutation
	}{
		{
			name: "synced",
			want: []fsMutation{
				{Op: "Remove", Path: staging},
				{Op: "WriteFile", Path: staging},
				{Op: "Chmod", Path: staging},
				{Op: "Sync", Path: staging},
				{Op: "Rename", Path: name},
			},
		},
		{
			name:    "sync fails",
			syncErr: syncErr,
			want: []fsMutation{
				{Op: "Remove", Path: staging},
				{Op: "WriteFile", Path: staging},
				{Op: "Chmod", Path: staging},
				{Op: "Sync", Path: staging},
				{Op: "Remove", Path: staging},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			fs.fail(opSync, fs.path(staging), tc.syncErr)
			b := newTestBackend(t, fs, newScutilFake())

			_, err := b.Set(context.Background(), splitNoSearchConfig(), newGoal)
			var got []fsMutation
			for _, m := range fs.mutations() {
				if m.Path == fs.path(staging) || m.Path == fs.path(name) {
					got = append(got, fsMutation{Op: m.Op, Path: filepath.Base(m.Path)})
				}
			}
			assert.Equal(t, tc.want, got)
			_, stagingErr := os.Lstat(fs.path(staging))
			assert.ErrorIs(t, stagingErr, os.ErrNotExist, "no staging file remains")
			_, pathErr := os.Lstat(fs.path(name))
			if tc.syncErr != nil {
				require.ErrorIs(t, err, tc.syncErr)
				assert.ErrorIs(t, pathErr, os.ErrNotExist, "an unsynced file never takes the domain's name")
				return
			}
			require.NoError(t, err)
			assert.NoError(t, pathErr)
		})
	}
}

// TestResolverRemovalSyncsDirectory: an attempt that removes resolver files
// syncs the directory once, after the last removal, and one that removes
// nothing does not. A failed sync fails the attempt and the retry syncs
// although it has nothing left to remove.
func TestResolverRemovalSyncsDirectory(t *testing.T) {
	// ops returns the Remove and SyncDir calls logged since mark.
	ops := func(fs *testFS, mark int) []fsMutation {
		var got []fsMutation
		for _, m := range fs.mutations()[mark:] {
			if m.Op == string(opRemove) || m.Op == string(opSyncDir) {
				got = append(got, fsMutation{Op: m.Op, Path: filepath.Base(m.Path)})
			}
		}
		return got
	}
	syncs := func(fs *testFS, mark int) int {
		n := 0
		for _, m := range ops(fs, mark) {
			if m.Op == string(opSyncDir) {
				n++
			}
		}
		return n
	}
	dir := func(fs *testFS) string { return filepath.Base(fs.dir) }
	split := backend.Config{Nameservers: ns("127.0.0.99"), MatchDomains: []string{"a.example", "b.example"}}

	t.Run("clear", func(t *testing.T) {
		fs := newTestFS(t)
		b := newTestBackend(t, fs, newScutilFake())
		require.NoError(t, trySet(b, split))
		require.NoError(t, trySet(b, split))
		assert.Zero(t, syncs(fs, 0), "writing files and a converged repeat remove nothing")

		mark := len(fs.mutations())
		require.NoError(t, tryClear(b))
		assert.Equal(t, []fsMutation{
			{Op: "Remove", Path: "a.example"},
			{Op: "Remove", Path: "b.example"},
			{Op: "SyncDir", Path: dir(fs)},
		}, ops(fs, mark))

		mark = len(fs.mutations())
		require.NoError(t, tryClear(b))
		assert.Zero(t, syncs(fs, mark), "a Clear that removes nothing does not sync")
	})
	t.Run("obsolete", func(t *testing.T) {
		fs := newTestFS(t)
		b := newTestBackend(t, fs, newScutilFake())
		require.NoError(t, trySet(b, split))
		mark := len(fs.mutations())
		require.NoError(t, trySet(b, catchAllConfig()))
		assert.Equal(t, []fsMutation{
			{Op: "Remove", Path: "a.example"},
			{Op: "Remove", Path: "b.example"},
			{Op: "SyncDir", Path: dir(fs)},
		}, ops(fs, mark))
	})
	t.Run("sync fails", func(t *testing.T) {
		fs := newTestFS(t)
		b := newTestBackend(t, fs, newScutilFake())
		require.NoError(t, trySet(b, split))
		syncErr := errors.New("injected directory sync failure")
		fs.fail(opSyncDir, fs.dir, syncErr)
		res, err := b.Clear(context.Background(), newGoal)
		require.ErrorIs(t, err, syncErr)
		assert.True(t, res.Pending, "the flush waits for a durable removal")

		fs.fail(opSyncDir, fs.dir, nil)
		mark := len(fs.mutations())
		require.NoError(t, tryClear(b))
		assert.Equal(t, []fsMutation{{Op: "SyncDir", Path: dir(fs)}}, ops(fs, mark))
	})
	t.Run("directory gone", func(t *testing.T) {
		fs := newTestFS(t)
		b := newTestBackend(t, fs, newScutilFake())
		require.NoError(t, trySet(b, split))
		fs.fail(opSyncDir, fs.dir, os.ErrNotExist)
		require.NoError(t, tryClear(b), "a vanished directory cannot bring removed files back")

		fs.fail(opSyncDir, fs.dir, nil)
		mark := len(fs.mutations())
		require.NoError(t, tryClear(b))
		assert.Zero(t, syncs(fs, mark), "nothing is left owed")
	})
}

// linkPlantingFS replaces the destination with a link to an unrelated file
// the moment the staging file is written, as a concurrent privileged writer
// outside the host lock could.
type linkPlantingFS struct {
	*testFS
	dest, target string
	planted      bool
}

func (f *linkPlantingFS) WriteFile(path string, body []byte, perm os.FileMode) error {
	if err := f.testFS.WriteFile(path, body, perm); err != nil {
		return err
	}
	if !f.planted {
		f.planted = true
		_ = os.Remove(f.dest)
		return os.Symlink(f.target, f.dest)
	}
	return nil
}

// TestResolverWriteNeverFollowsLinks covers a link at the staging path and a
// link swapped in at the destination after planning.
func TestResolverWriteNeverFollowsLinks(t *testing.T) {
	const name = "corp.example"
	staging := resolverTempName(testIdentity, name)
	targetBody := []byte("unrelated\n")
	foreignFile := func(t *testing.T) string {
		t.Helper()
		target := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(target, targetBody, 0o600))
		return target
	}

	t.Run("link at the staging path", func(t *testing.T) {
		fs := newTestFS(t)
		target := foreignFile(t)
		require.NoError(t, os.MkdirAll(fs.dir, 0o755))
		require.NoError(t, os.Symlink(target, fs.path(staging)))
		b := newTestBackend(t, fs, newScutilFake())

		require.NoError(t, trySet(b, splitNoSearchConfig()))
		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, targetBody, got)
		assert.Equal(t, os.FileMode(0o600), fileMode(t, target))
		assert.False(t, isSymlink(t, fs.path(name)))
	})

	t.Run("link swapped in at the destination", func(t *testing.T) {
		inner := newTestFS(t)
		target := foreignFile(t)
		fs := &linkPlantingFS{testFS: inner, dest: inner.path(name), target: target}
		b := newTestBackend(t, fs, newScutilFake())

		_, err := b.Set(context.Background(), splitNoSearchConfig(), newGoal)
		require.ErrorContains(t, err, "owned elsewhere")
		got, err := os.ReadFile(target)
		require.NoError(t, err)
		assert.Equal(t, targetBody, got)
		assert.True(t, isSymlink(t, fs.path(name)), "the foreign link stays")
		_, err = os.Lstat(fs.path(staging))
		assert.ErrorIs(t, err, os.ErrNotExist, "the staging file is cleaned up")
	})
}

// TestConvergeLogsWhatChanged pins the Info line the macOS smoke row reads
// after a configd restart, keeps quiet converges silent, and withholds the
// repair line from a retry that finishes a partial first install.
func TestConvergeLogsWhatChanged(t *testing.T) {
	var buf bytes.Buffer
	fake := newScutilFake()
	fs := newTestFS(t)
	b, err := New(context.Background(), Options{
		Identity: testIdentity,
		FS:       fs,
		Runner:   fake,
		Logger:   slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})),
		IsRoot:   asRoot,
	})
	require.NoError(t, err)
	useFS(b, fs)
	t.Cleanup(func() { _ = b.Close() })

	_, err = b.Set(context.Background(), catchAllConfig(), newGoal)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "darwin: converge changed host DNS")
	assert.NotContains(t, buf.String(), "recreated")

	buf.Reset()
	_, err = b.Set(context.Background(), catchAllConfig(), repeat)
	require.NoError(t, err)
	assert.NotContains(t, buf.String(), "level=INFO", "a quiet converge logs nothing at Info")

	fake.deleteKey(0)
	_, err = b.Set(context.Background(), catchAllConfig(), repeat)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "darwin: converge changed host DNS")
	assert.NotContains(t, buf.String(), "recreated", "the goal had not converged before this attempt")

	buf.Reset()
	fake.deleteKey(0)
	_, err = b.Set(context.Background(), catchAllConfig(), converged)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "darwin: converge recreated dynamic-store keys")
	assert.Contains(t, buf.String(), stateKeyName(testIdentity, 0))
}

// TestConvergeScutilProcessCount bounds the scutil processes one converge
// starts. The worker repeats a converged goal on every periodic check, so
// each read it repeats is a process spawned for the life of the goal.
func TestConvergeScutilProcessCount(t *testing.T) {
	cfg := catchAllConfig()
	cfg.SearchDomains = []string{"corp.example", "dev.example"}
	peer := func(fake *scutilFake) {
		fake.otherKeys[stateKeyName(otherIdentity, 0)] = stateKeyConfig{Servers: []string{"127.0.0.77"}, Domains: []string{"other.example"}}
	}
	for _, tc := range []struct {
		name  string
		seed  func(*scutilFake)
		first int
		quiet int
	}{
		// A first converge lists, reads the table, sets and reads back
		// each of its two keys, and re-reads the table; a peer's key adds
		// one show session. A steady-state converge lists, shows every
		// attributable key in one session, and reads the table once.
		{"alone", func(*scutilFake) {}, 7, 3},
		{"with another identity", peer, 8, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newScutilFake()
			tc.seed(fake)
			b := newTestBackend(t, newTestFS(t), fake)

			res, err := b.Set(context.Background(), cfg, newGoal)
			require.NoError(t, err)
			require.True(t, res.Changed)
			require.Equal(t, 2, fake.keyCount())
			first := fake.runCount()
			assert.Equal(t, tc.first, first)

			res, err = b.Set(context.Background(), cfg, repeat)
			require.NoError(t, err)
			require.False(t, res.Changed)
			quiet := fake.runCount() - first
			assert.Equal(t, tc.quiet, quiet)
		})
	}
}

// assertInOrder fails unless every entry of want appears in ops, each after
// the one before it.
func assertInOrder(t *testing.T, ops []string, want ...string) {
	t.Helper()
	next := 0
	for _, op := range ops {
		if next < len(want) && op == want[next] {
			next++
		}
	}
	assert.Equal(t, len(want), next, "want %q in this order within %q", want, ops)
}

// TestFirstInstallWritesFileBeforeKey: a search domain that the resolver
// file also matches is never published as a key before the file routes it,
// and the table is verified after the key is written.
func TestFirstInstallWritesFileBeforeKey(t *testing.T) {
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)
	order := recordOrder(fs, fake)

	require.NoError(t, trySet(b, splitConfig()))
	assertInOrder(t, order.snapshot(),
		"fs Rename corp.example",
		"scutil set "+stateKeyName(testIdentity, 0),
		opCompiledRead,
	)
}

// replacementFixture converges a split config for corp.example, then leaves
// a predecessor's key at index 1. A split config publishes one key, so the
// obsolete key a replacement removes comes from a predecessor's larger plan.
func replacementFixture(t *testing.T) (*testFS, *scutilFake, *Backend) {
	t.Helper()
	fs := newTestFS(t)
	fake := newScutilFake()
	b := newTestBackend(t, fs, fake)
	require.NoError(t, trySet(b, splitConfig()))
	fake.mu.Lock()
	fake.keys[1] = stateKeyConfig{Servers: []string{"127.0.0.99"}, Domains: []string{"old.example"}}
	fake.mu.Unlock()
	return fs, fake, b
}

func labConfig() backend.Config {
	cfg := splitConfig()
	cfg.SearchDomains = []string{"lab.example"}
	cfg.MatchDomains = []string{"lab.example"}
	return cfg
}

// TestReplacementAppliesBeforeRemoving: the new file and key are in place
// and verified before anything obsolete goes, and the obsolete key goes
// before the obsolete file.
func TestReplacementAppliesBeforeRemoving(t *testing.T) {
	fs, fake, b := replacementFixture(t)
	order := recordOrder(fs, fake)

	res, err := b.Set(context.Background(), labConfig(), newGoal)
	require.NoError(t, err)
	assert.True(t, res.Changed)
	assertInOrder(t, order.snapshot(),
		"fs Rename lab.example",
		"scutil set "+stateKeyName(testIdentity, 0),
		opCompiledRead,
		"scutil remove "+stateKeyName(testIdentity, 1),
		"fs Remove corp.example",
	)
	assert.Equal(t, 1, fake.keyCount())
	_, err = os.Lstat(fs.path("corp.example"))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

// TestFailedKeyRemovalStillRemovesObsoleteFiles: an obsolete file would keep
// routing its domain to servers the caller may stop, so a failed key removal
// does not keep it.
func TestFailedKeyRemovalStillRemovesObsoleteFiles(t *testing.T) {
	fs, fake, b := replacementFixture(t)
	// The attempt's mutations are the key 0 set, then the key 1 remove.
	fake.armMutationFailure(1)

	res, err := b.Set(context.Background(), labConfig(), newGoal)
	require.ErrorIs(t, err, errInjectedScutil)
	assert.True(t, res.Changed)
	_, err = os.Lstat(fs.path("corp.example"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the obsolete file is removed")
	_, found := fake.key(1)
	assert.True(t, found, "the failed removal left the key")
}
