//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

const (
	stateKeyPrefix      = "State:/Network/Service/dnsconfig-"
	stateKeySuffix      = "/DNS"
	stateKeyListPattern = stateKeyPrefix + ".*"

	maxScutilValues    = 99
	maxScutilLineBytes = 2047

	// scutil exits 0 whether or not configd answered: a failed request prints
	// an SCErrorString line in place of a result. Only these forms are read
	// as results; anything else, including empty output, is an error.
	scutilNoKeys     = "no keys."
	scutilSubKey     = "subKey ["
	scutilNoSuchKey  = "No such key"
	scutilDictionary = "<dictionary> {"
)

// buildStateKeys publishes every search domain, including any the primary
// service already supplies, so the keys do not depend on the current network
// and carry exactly the claims checkConflicts makes. configd compiles
// supplemental search domains ahead of the primary service's list, so
// requested suffixes win for short names. All of them go in one key because
// configd keeps a key's domains in order but has compiled a later key ahead of
// an earlier one; a list that does not fit one scutil line is refused. Config
// requires each split search domain to sit under a match domain, so the key
// routes each domain to the same servers as the match file or catch-all; as an
// exact domain it can still outrank a foreign resolver more specific than
// either.
func buildStateKeys(cfg backend.Config) ([]stateKeyConfig, error) {
	servers := addrsToStrings(cfg.Nameservers)
	if err := validateScutilValues("ServerAddresses", servers); err != nil {
		return nil, err
	}
	var keys []stateKeyConfig
	if !cfg.IsSplit() {
		keys = append(keys, stateKeyConfig{Servers: servers, Domains: []string{""}, NoSearch: true})
	}
	if search := cfg.SearchDomains; len(search) > 0 {
		if err := checkScutilChars("SupplementalMatchDomains", search); err != nil {
			return nil, err
		}
		if len(search) > maxScutilValues {
			return nil, fmt.Errorf("darwin: %d search domains configured; macOS accepts at most %d", len(search), maxScutilValues)
		}
		if n := len(scutilAddLine("SupplementalMatchDomains", search)); n > maxScutilLineBytes {
			return nil, fmt.Errorf("darwin: search domains need a %d-byte scutil line; macOS accepts at most %d bytes", n, maxScutilLineBytes)
		}
		keys = append(keys, stateKeyConfig{Servers: slices.Clone(servers), Domains: slices.Clone(search)})
	}
	return keys, nil
}

// checkScutilChars rejects a value that could not survive scutil's line-oriented
// command language intact. Domains and addresses are already validated before
// they reach here, so this keeps a future path that skips that validation from
// silently appending commands to the script instead of setting a key.
func checkScutilChars(property string, values []string) error {
	for _, value := range values {
		for i := 0; i < len(value); i++ {
			switch c := value[i]; {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			// ':' and '%' carry IPv6 addresses and their zones.
			case c == '.', c == '-', c == '_', c == ':', c == '%':
			default:
				return fmt.Errorf("darwin: %s value %q contains unsupported byte %q", property, value, c)
			}
		}
	}
	return nil
}

func validateScutilValues(property string, values []string) error {
	if err := checkScutilChars(property, values); err != nil {
		return err
	}
	if len(values) > maxScutilValues {
		return fmt.Errorf("darwin: %s has %d values; scutil accepts at most %d", property, len(values), maxScutilValues)
	}
	if len(scutilAddLine(property, values)) > maxScutilLineBytes {
		return fmt.Errorf("darwin: %s command exceeds scutil's %d-byte line limit", property, maxScutilLineBytes)
	}
	return nil
}

func scutilAddLine(property string, values []string) string {
	var b strings.Builder
	b.WriteString("d.add ")
	b.WriteString(property)
	b.WriteString(" *")
	for _, value := range values {
		b.WriteByte(' ')
		if value == "" {
			b.WriteString(`""`)
		} else {
			b.WriteString(value)
		}
	}
	return b.String()
}

// stateKeyName includes the identity so prefix discovery can find all instances
// while cleanup filters to one.
func stateKeyName(identity string, index int) string {
	return stateKeyPrefix + identity + "-" + strconv.Itoa(index) + stateKeySuffix
}

// parseStateKeyName separates the index after the last '-' because identities
// can contain '-'. Prefix matches with an unexpected key shape are not owned.
func parseStateKeyName(name string) (identity string, index int, ok bool) {
	if !strings.HasPrefix(name, stateKeyPrefix) || !strings.HasSuffix(name, stateKeySuffix) {
		return "", 0, false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(name, stateKeyPrefix), stateKeySuffix)
	cut := strings.LastIndexByte(middle, '-')
	if cut <= 0 {
		return "", 0, false
	}
	// Only the form stateKeyName renders is ours; accepting "+1" or "01"
	// would let another writer's key pass as an owned one.
	suffix := middle[cut+1:]
	index, err := strconv.Atoi(suffix)
	if err != nil || index < 0 || strconv.Itoa(index) != suffix {
		return "", 0, false
	}
	return middle[:cut], index, true
}

func (b *Backend) stateKey(index int) string { return stateKeyName(b.identity, index) }

func (b *Backend) writeStateKey(ctx context.Context, index int, cfg stateKeyConfig) error {
	var script strings.Builder
	script.WriteString("d.init\n")
	script.WriteString(scutilAddLine("ServerAddresses", cfg.Servers))
	script.WriteByte('\n')
	script.WriteString(scutilAddLine("SupplementalMatchDomains", cfg.Domains))
	script.WriteByte('\n')
	script.WriteString("d.add SupplementalMatchDomainsNoSearch # ")
	if cfg.NoSearch {
		script.WriteByte('1')
	} else {
		script.WriteByte('0')
	}
	script.WriteString("\nset ")
	script.WriteString(b.stateKey(index))
	script.WriteString("\nquit\n")

	_, stderr, err := b.runner.Run(ctx, scutilBinary, nil, strings.NewReader(script.String()))
	if err != nil {
		return fmt.Errorf("darwin: set %s: %w: %s", b.stateKey(index), err, bytes.TrimSpace(stderr))
	}
	got, found, err := b.readStateKey(ctx, index)
	if err != nil {
		return err
	}
	if !found || !stateKeyEqual(got, cfg) {
		return fmt.Errorf("darwin: read-back mismatch for %s: got %+v, want %+v", b.stateKey(index), got, cfg)
	}
	return nil
}

func (b *Backend) readStateKey(ctx context.Context, index int) (stateKeyConfig, bool, error) {
	name := b.stateKey(index)
	shown, invalid, err := b.showStateKeys(ctx, []string{name})
	if err != nil {
		return stateKeyConfig{}, false, err
	}
	if err := invalid[name]; err != nil {
		return stateKeyConfig{}, false, err
	}
	cfg, found := shown[name]
	return cfg, found, nil
}

// showStateKeys reads names in one scutil session and returns the
// dictionary of each one present, or in invalid why it is not a DNS
// dictionary. Each show prints exactly one result, either the "No such key"
// line or a dictionary closed by an unindented brace, so the output splits
// by position; a missing, extra, or other result fails the whole read.
func (b *Backend) showStateKeys(ctx context.Context, names []string) (shown map[string]stateKeyConfig, invalid map[string]error, err error) {
	shown, invalid = map[string]stateKeyConfig{}, map[string]error{}
	if len(names) == 0 {
		return shown, invalid, nil
	}
	var script strings.Builder
	for _, name := range names {
		script.WriteString("show " + name + "\n")
	}
	script.WriteString("quit\n")
	command := "show " + names[0]
	if len(names) > 1 {
		command = fmt.Sprintf("show (%d keys)", len(names))
	}
	stdout, stderr, err := b.runner.Run(ctx, scutilBinary, nil, strings.NewReader(script.String()))
	if err != nil {
		return nil, nil, fmt.Errorf("darwin: scutil %s: %w: %s", command, err, bytes.TrimSpace(stderr))
	}
	if len(stdout) > maxScutilOutput {
		return nil, nil, fmt.Errorf("darwin: scutil %s exceeded %d bytes", command, maxScutilOutput)
	}
	results, err := splitShowOutput(command, stdout)
	if err != nil {
		return nil, nil, err
	}
	if len(results) != len(names) {
		return nil, nil, unansweredError(command, fmt.Sprintf("%d results for %d keys", len(results), len(names)))
	}
	for i, body := range results {
		if body == nil {
			continue
		}
		cfg, err := parseStateKey(body)
		if err != nil {
			invalid[names[i]] = fmt.Errorf("darwin: parse %s: %w", names[i], err)
			continue
		}
		shown[names[i]] = cfg
	}
	return shown, invalid, nil
}

// splitShowOutput returns one entry per show result: nil for an absent key,
// or the dictionary's lines.
func splitShowOutput(command string, stdout []byte) ([][]byte, error) {
	lines := strings.Split(string(stdout), "\n")
	var results [][]byte
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		switch {
		case line == "":
		case line == scutilNoSuchKey:
			results = append(results, nil)
		case strings.HasPrefix(line, scutilDictionary):
			end := i + 1
			for end < len(lines) && strings.TrimRight(lines[end], " \t\r") != "}" {
				end++
			}
			if end == len(lines) {
				return nil, unansweredError(command, "unterminated dictionary")
			}
			results = append(results, []byte(strings.Join(lines[i:end+1], "\n")))
			i = end
		default:
			return nil, unansweredError(command, line)
		}
	}
	return results, nil
}

// errScutilUnanswered marks scutil output that is not a completed request's
// result, so absence of a key cannot be told from configd not answering. A
// present key holding a non-dictionary value lands here too and fails closed.
var errScutilUnanswered = errors.New("unrecognized scutil output; configd may not have answered")

// unansweredError quotes the line that failed to parse.
func unansweredError(command, line string) error {
	if line == "" {
		line = "(empty)"
	}
	const maxQuoted = 200
	if len(line) > maxQuoted {
		line = line[:maxQuoted] + "..."
	}
	return fmt.Errorf("darwin: scutil %s: %w: %q", command, errScutilUnanswered, line)
}

// parseKeyList accepts scutil's two forms for a completed list: "no keys."
// alone, or one subKey line per key.
func parseKeyList(command string, stdout []byte) ([]string, error) {
	text := strings.TrimSpace(string(stdout))
	if text == scutilNoKeys {
		return nil, nil
	}
	var keys []string
	for raw := range strings.SplitSeq(text, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(raw), scutilSubKey)
		var key string
		if ok {
			_, key, ok = strings.Cut(rest, "] = ")
		}
		if !ok || key == "" {
			return nil, unansweredError(command, strings.TrimSpace(raw))
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func parseStateKey(body []byte) (stateKeyConfig, error) {
	var cfg stateKeyConfig
	var array *[]string
	foundNoSearch := false
	for raw := range strings.SplitSeq(string(body), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "ServerAddresses : <array>"):
			array = &cfg.Servers
		case strings.HasPrefix(line, "SupplementalMatchDomains : <array>"):
			array = &cfg.Domains
		case strings.HasPrefix(line, "SupplementalMatchDomainsNoSearch :"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "SupplementalMatchDomainsNoSearch :"))
			if value != "0" && value != "1" {
				return stateKeyConfig{}, fmt.Errorf("invalid SupplementalMatchDomainsNoSearch %q", value)
			}
			cfg.NoSearch = value == "1"
			foundNoSearch = true
			array = nil
		case line == "}":
			array = nil
		case array != nil:
			_, value, ok := strings.Cut(line, ":")
			if ok {
				*array = append(*array, strings.TrimSpace(value))
			}
		}
	}
	if len(cfg.Servers) == 0 || len(cfg.Domains) == 0 || !foundNoSearch {
		return stateKeyConfig{}, errors.New("incomplete DNS dictionary")
	}
	return cfg, nil
}

func stateKeyEqual(a, b stateKeyConfig) bool {
	return a.NoSearch == b.NoSearch && slices.Equal(a.Servers, b.Servers) && slices.Equal(a.Domains, b.Domains)
}

// storeSnapshot is one read of the library's dynamic-store keys and the
// compiled resolver table. A Set attempt plans from it and, when it writes
// nothing, verifies against it, so a converged goal costs one list, one
// show session, and one table read.
type storeSnapshot struct {
	// names lists every key under the library prefix, whichever identity
	// wrote it.
	names []string
	// keys holds the dictionary of each listed key with a well-formed name
	// that was still present when shown; invalid holds why a shown value
	// is not a DNS dictionary. That fails only a reader of the key, so an
	// obsolete owned key can still be removed.
	keys    map[string]stateKeyConfig
	invalid map[string]error
	// compiled is the scutil --dns table, or nil when the snapshot was taken
	// without it.
	compiled []dnsResolver
}

// takeSnapshot reads the store. Keys whose names do not parse are listed
// but never shown: no identity owns them, and their values need not be DNS
// dictionaries.
func (b *Backend) takeSnapshot(ctx context.Context, withCompiled bool) (*storeSnapshot, error) {
	names, err := b.listLibraryKeyNames(ctx)
	if err != nil {
		return nil, err
	}
	var shown []string
	for _, name := range names {
		if _, _, ok := parseStateKeyName(name); ok {
			shown = append(shown, name)
		}
	}
	keys, invalid, err := b.showStateKeys(ctx, shown)
	if err != nil {
		return nil, err
	}
	snap := &storeSnapshot{names: names, keys: keys, invalid: invalid}
	if withCompiled {
		if snap.compiled, err = b.readCompiledDNS(ctx); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

// key returns name's dictionary as shown, and whether it was present.
func (s *storeSnapshot) key(name string) (stateKeyConfig, bool, error) {
	if err := s.invalid[name]; err != nil {
		return stateKeyConfig{}, false, err
	}
	cfg, found := s.keys[name]
	return cfg, found, nil
}

// owned maps identity's key indices to their names.
func (s *storeSnapshot) owned(identity string) map[int]string {
	keys := map[int]string{}
	for _, name := range s.names {
		if owner, idx, ok := parseStateKeyName(name); ok && owner == identity {
			keys[idx] = name
		}
	}
	return keys
}

// listStateKeyNames returns this identity's dynamic-store keys. Another
// identity's keys are never removed or rewritten by this instance.
func (b *Backend) listStateKeyNames(ctx context.Context) ([]string, error) {
	all, err := b.listLibraryKeyNames(ctx)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, name := range all {
		if identity, _, ok := parseStateKeyName(name); ok && identity == b.identity {
			keys = append(keys, name)
		}
	}
	return keys, nil
}

// listLibraryKeyNames returns every key under the library prefix, whichever
// identity wrote it. Conflict checks read them; cleanup does not. An
// unanswered list is an error, never an empty store: Clear would otherwise
// converge and release the identity lock with keys installed, and the
// conflict check would admit claims it could not see.
func (b *Backend) listLibraryKeyNames(ctx context.Context) ([]string, error) {
	script := "list " + stateKeyListPattern + "\nquit\n"
	stdout, stderr, err := b.runner.Run(ctx, scutilBinary, nil, strings.NewReader(script))
	if err != nil {
		return nil, fmt.Errorf("darwin: list dynamic-store keys: %w: %s", err, bytes.TrimSpace(stderr))
	}
	if len(stdout) > maxScutilOutput {
		return nil, fmt.Errorf("darwin: dynamic-store key list exceeded %d bytes", maxScutilOutput)
	}
	listed, err := parseKeyList("list "+stateKeyListPattern, stdout)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, key := range listed {
		if strings.HasPrefix(key, stateKeyPrefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// removeStateKeys removes each named key and returns the ones confirmed gone.
// scutil exits 0 when a remove is refused, so success is judged by listing
// the keys again rather than by exit status. unverified reports removes whose
// effect is unknown because every remove call failed or the follow-up list
// did; a kill or cancel can land after configd processed the remove, so that
// counts as a change. A key the list still shows is a confirmed non-removal.
func (b *Backend) removeStateKeys(ctx context.Context, names []string) (removed []string, unverified bool, err error) {
	var attempted []string
	var errs []error
	for _, name := range names {
		if err := b.removeStateKeyName(ctx, name); err != nil {
			errs = append(errs, err)
			continue
		}
		attempted = append(attempted, name)
	}
	if len(attempted) == 0 {
		return nil, true, errors.Join(errs...)
	}
	remaining, err := b.listStateKeyNames(ctx)
	if err != nil {
		return nil, true, errors.Join(append(errs, err)...)
	}
	for _, name := range attempted {
		if slices.Contains(remaining, name) {
			errs = append(errs, fmt.Errorf("darwin: remove %s: key still present after scutil remove", name))
			continue
		}
		removed = append(removed, name)
	}
	return removed, false, errors.Join(errs...)
}

func (b *Backend) removeStateKeyName(ctx context.Context, key string) error {
	script := "remove " + key + "\nquit\n"
	_, stderr, err := b.runner.Run(ctx, scutilBinary, nil, strings.NewReader(script))
	if err != nil {
		return fmt.Errorf("darwin: remove %s: %w: %s", key, err, bytes.TrimSpace(stderr))
	}
	return nil
}
