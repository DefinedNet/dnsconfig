//go:build darwin

// Package darwin implements the dnsconfig backend for macOS.
//
// Runtime DNS facts are published through synthetic SCDynamicStore State
// keys. Split DNS additionally uses /etc/resolver files because those files
// outrank supplemental State entries for the same suffix.
package darwin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/DefinedNet/dnsconfig/internal/backend"
	"github.com/DefinedNet/dnsconfig/internal/runner"
)

const (
	// defaultResolverDir is the directory macOS scans for per-suffix resolver
	// files.
	defaultResolverDir = "/etc/resolver"

	// configd's resolver-file parser stops at MAXNS from resolv.h.
	maxResolverFileNameservers = 3

	// Absolute paths keep a writable $PATH entry from substituting a binary for
	// a root-privileged caller: exec.LookPath returns the first match without
	// complaint, and Go's ErrDot guard covers only non-absolute results. These
	// locations are SIP-protected, so the target cannot be replaced by root.
	scutilBinary = "/usr/sbin/scutil"

	maxScutilOutput = 1 << 20

	dscacheutilBinary    = "/usr/bin/dscacheutil"
	killallBinary        = "/usr/bin/killall"
	mDNSResponderProcess = "mDNSResponder"

	// resolverTempPrefix names the staging file a resolver file is written
	// to before rename. The identity follows it, then '+' and a domain hash;
	// an identity cannot contain '+', so the owner parses
	// unambiguously even when a partial write left no header. The name holds
	// characters no DNS label uses, so it routes no real suffix.
	resolverTempPrefix = ".dnsconfig-"
	resolverTempSep    = "+"
)

// Options configures a new Backend.
type Options struct {
	// Identity names the application instance. It is required and scopes
	// State-key names, resolver-file headers, discovery, and cleanup.
	Identity string
	// FS is the filesystem used for /etc/resolver. nil uses the disk.
	FS backend.FS
	// Runner executes scutil and cache-flush commands. nil uses ExecRunner.
	Runner runner.Runner
	// Logger receives non-fatal warnings. It is required.
	Logger *slog.Logger
	// IsRoot reports whether the process runs as root, for the startup
	// diagnostic. Nil checks the effective user ID.
	IsRoot func() bool
}

type stateKeyConfig struct {
	Servers  []string
	Domains  []string
	NoSearch bool
}

// Backend is the macOS implementation of backend.Backend.
type Backend struct {
	identity string
	fs       backend.FS
	runner   runner.Runner
	logger   *slog.Logger
	// resolverDir is defaultResolverDir except in tests, which point it at a
	// temporary directory.
	resolverDir string

	// flushOwed records that artifacts changed since the last successful
	// resolver-cache flush. It survives failed attempts so the flush happens
	// once the host converges, and only then. Only Set and Clear touch it.
	flushOwed bool

	// dirSyncOwed records a resolver-file removal not yet synced to disk. It
	// survives a failed sync so the retry syncs although it removes nothing.
	dirSyncOwed bool

	// changes carries coalesced notifications to the worker. It is created
	// in New and closed by Close after the notification child is joined, so
	// no send can follow the close.
	changes chan struct{}

	// mu guards the lifecycle and notification source below. It is never
	// held across a subprocess call except the notification child's start.
	mu     sync.Mutex
	closed bool
	// source is the running child, if any; sourceErr is why the last start
	// failed. Both are nil while no Set goal needs the child.
	source    *eventSource
	sourceErr error

	closeOnce sync.Once
}

// New constructs a Backend without reading or changing system DNS state.
func New(_ context.Context, opts Options) (*Backend, error) {
	if err := backend.ValidateIdentity(opts.Identity); err != nil {
		return nil, fmt.Errorf("darwin: Options.Identity: %w", err)
	}
	if opts.Logger == nil {
		return nil, errors.New("darwin.New: Options.Logger is required")
	}
	fs := opts.FS
	if fs == nil {
		fs = backend.DiskFS{}
	}
	isRoot := opts.IsRoot
	if isRoot == nil {
		isRoot = func() bool { return os.Geteuid() == 0 }
	}
	if !isRoot() {
		opts.Logger.Warn("darwin: DNS configuration requires root for the dynamic store, /etc/resolver, and the lock directory; without it every Set and Clear attempt is refused before writing")
	}
	r := opts.Runner
	if r == nil {
		r = runner.ExecRunner{}
	}
	return &Backend{
		identity:    opts.Identity,
		fs:          fs,
		runner:      r,
		logger:      opts.Logger,
		resolverDir: defaultResolverDir,
		changes:     make(chan struct{}, 1),
	}, nil
}

// resolverEntry is one non-directory entry in the resolver directory.
type resolverEntry struct {
	name string
	// owner is the identity in the file's header, or "" for a file the
	// library did not write. A staging file is attributed by its name
	// instead, because an interrupted write can leave one without a
	// complete header.
	owner   string
	staging bool
}

// scanResolverDir attributes every entry in the resolver directory. It reads
// before anything is removed, so an unreadable entry fails the attempt while
// the host is unchanged.
func (b *Backend) scanResolverDir() ([]resolverEntry, error) {
	entries, err := b.fs.ReadDir(b.resolverDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("darwin: read %s: %w", b.resolverDir, err)
	}
	var scanned []resolverEntry
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		if rest, ok := strings.CutPrefix(name, resolverTempPrefix); ok {
			identity, _, ok := strings.Cut(rest, resolverTempSep)
			if !ok {
				identity = ""
			}
			scanned = append(scanned, resolverEntry{name: name, owner: identity, staging: true})
			continue
		}
		owner, err := b.resolverFileOwner(filepath.Join(b.resolverDir, name))
		if err != nil {
			return nil, fmt.Errorf("darwin: inspect %s: %w", name, err)
		}
		scanned = append(scanned, resolverEntry{name: name, owner: owner})
	}
	return scanned, nil
}

// ownedNames lists the entries attributed to this identity, staging files
// included.
func (b *Backend) ownedNames(entries []resolverEntry) []string {
	var owned []string
	for _, e := range entries {
		if e.owner == b.identity {
			owned = append(owned, e.name)
		}
	}
	return owned
}

// otherIdentityFiles maps each resolver file another identity wrote, by
// lowercase name, to that identity. Staging files route nothing.
func (b *Backend) otherIdentityFiles(entries []resolverEntry) map[string]string {
	files := map[string]string{}
	for _, e := range entries {
		if !e.staging && e.owner != "" && e.owner != b.identity {
			files[strings.ToLower(e.name)] = e.owner
		}
	}
	return files
}

// conflictClaim is one domain cfg publishes and the other identity, if any,
// whose artifact for it would compete.
type conflictClaim struct {
	domain, holder string
}

// checkConflicts refuses cfg when it repeats another identity's catch-all or
// resolver file, or shares a State-key domain with another identity when
// neither of the two owns the resolver file for that exact domain.
// Overlapping suffixes remain subject to configd's ordering.
//
// A resolver file answers every query for its exact domain and its
// subdomains ahead of any State key for that domain, whatever the write order
// or key order, so a key beside the file only adds the suffix to the search
// list, where configd folds duplicates into one entry. Only a file owned by
// one of the two key holders makes their keys compatible: a third identity's
// file can leave while both keys stay, and they would then compete. A file
// this attempt plans counts, because apply writes files before keys and
// removes keys before files.
func (b *Backend) checkConflicts(cfg backend.Config, snap *storeSnapshot, fileHolders map[string]string) error {
	keyHolders, err := b.otherIdentityKeyClaims(snap)
	if err != nil {
		return err
	}

	var claims []conflictClaim
	if !cfg.IsSplit() && len(keyHolders["."]) > 0 {
		claims = append(claims, conflictClaim{".", keyHolders["."][0]})
	}
	for _, domain := range cfg.MatchDomains {
		if holder := fileHolders[domain]; holder != "" {
			claims = append(claims, conflictClaim{domain, holder})
		}
	}
	for _, domain := range cfg.SearchDomains {
		if slices.Contains(cfg.MatchDomains, domain) {
			continue
		}
		for _, holder := range keyHolders[domain] {
			if fileHolders[domain] != holder {
				claims = append(claims, conflictClaim{domain, holder})
				break
			}
		}
	}
	slices.SortFunc(claims, func(x, y conflictClaim) int { return strings.Compare(x.domain, y.domain) })
	if len(claims) > 0 {
		return backend.NewConflictError(claims[0].domain, claims[0].holder)
	}
	return nil
}

// otherIdentityKeyClaims maps each domain other identities' State keys
// publish to those identities, sorted. A key's empty domain is its
// catch-all, ".".
func (b *Backend) otherIdentityKeyClaims(snap *storeSnapshot) (map[string][]string, error) {
	holders := map[string][]string{}
	for _, name := range snap.names {
		identity, _, ok := parseStateKeyName(name)
		if !ok || identity == b.identity {
			continue
		}
		key, found, err := snap.key(name)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		for _, domain := range key.Domains {
			claim := "."
			if domain != "" {
				claim = strings.ToLower(strings.TrimSuffix(domain, "."))
			}
			if !slices.Contains(holders[claim], identity) {
				holders[claim] = append(holders[claim], identity)
			}
		}
	}
	for _, list := range holders {
		slices.Sort(list)
	}
	return holders, nil
}
