package windows

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// ErrInterfaceNotFound means the requested adapter is absent, rather than
// unreadable. Recovery can still use its recorded GUID.
var ErrInterfaceNotFound = errors.New("windows: interface not found")

const (
	interfaceGUIDValue = "DnsconfigInterface"
	// reloadTriggerValue is set and deleted on the local NRPT container key
	// to make the DNS Client rebuild its adapter view. A process that exits
	// between the set and the delete leaves it on the key, where it routes
	// nothing and changes nothing, even across a reboot; the next reload
	// overwrites and removes it.
	reloadTriggerValue = "DnsconfigReload"
)

type adapterTarget struct {
	guid string
}

func adapterPaths(guid string) []string {
	return []string{
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + guid,
		`SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\` + guid,
	}
}

// canonicalGUID prevents malformed recovery data from becoming a registry path.
func canonicalGUID(s string) (string, error) {
	if len(s) != 38 || s[0] != '{' || s[37] != '}' {
		return "", errors.New("invalid adapter GUID")
	}
	for i := 1; i < 37; i++ {
		if i == 9 || i == 14 || i == 19 || i == 24 {
			if s[i] != '-' {
				return "", errors.New("invalid adapter GUID")
			}
			continue
		}
		c := s[i]
		if !strings.ContainsRune("0123456789abcdefABCDEF", rune(c)) {
			return "", errors.New("invalid adapter GUID")
		}
	}
	return strings.ToUpper(s), nil
}

func (b *Backend) resolveApplyTarget() (adapterTarget, error) {
	guid, err := b.resolveInterface(b.interfaceName)
	if err != nil {
		return adapterTarget{}, fmt.Errorf("windows: resolve interface %q: %w", b.interfaceName, err)
	}
	guid, err = canonicalGUID(guid)
	if err != nil {
		return adapterTarget{}, fmt.Errorf("windows: resolve interface %q: %w", b.interfaceName, err)
	}
	for _, path := range adapterPaths(guid) {
		exists, err := b.reg.KeyExists(path)
		if err != nil {
			return adapterTarget{}, fmt.Errorf("windows: inspect adapter key %s: %w", path, err)
		}
		if !exists {
			return adapterTarget{}, fmt.Errorf("%w: adapter key %s is absent", ErrInterfaceNotFound, path)
		}
	}
	return adapterTarget{guid: guid}, nil
}

// recoveryTarget requires active records to agree on one adapter. Without
// active records, complete staged metadata covers a crash during the rule swap;
// incomplete staged metadata cannot authorize cleanup. An active rule missing
// its recorded GUID names no adapter, so it is skipped rather than refusing
// the attempt: refusing would leave the damage in place forever, while Set
// rewrites the rule with fresh values and Clear sweeps it like any owned rule.
//
// Recorded GUIDs that are present must be valid and agree. Cleanup is
// authorized by the recorded GUID, never by InterfaceName: a predecessor's
// adapter is cleared under whatever name, or no name, the successor was
// given, and clearAdapter adopts that adapter as the pending cleanup target,
// so requiring it to match InterfaceName would strand the predecessor's
// configuration after one failed clear.
func (b *Backend) recoveryTarget(ctx context.Context) (*adapterTarget, error) {
	var target, staged *adapterTarget
	for _, base := range []string{nrptBase, gpoNrptBase} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names, err := b.reg.SubKeyNames(base)
		if err != nil {
			return nil, fmt.Errorf("windows: list recovery records: %w", err)
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			identity, _, pending, ok := parseRuleName(name)
			if !ok || identity != b.identity {
				continue
			}
			key := base + `\` + name
			current, err := b.readRecordTarget(ctx, key)
			if pending {
				if err == nil && staged == nil {
					staged = &current
				}
				continue
			}
			if errors.Is(err, ErrValueNotFound) {
				b.logger.Warn("owned NRPT rule lacks its adapter recovery values; converge will replace or remove it", "key", key)
				continue
			}
			if err != nil {
				return nil, err
			}
			if target != nil && target.guid != current.guid {
				return nil, errors.New("windows: conflicting adapter recovery targets")
			}
			target = &current
		}
	}
	if target == nil {
		target = staged
	}
	if b.adapterTarget != nil {
		if target != nil && target.guid != b.adapterTarget.guid {
			return nil, errors.New("windows: recorded adapter conflicts with this instance's pending cleanup")
		}
		if target == nil {
			target = b.adapterTarget
		}
	}
	return target, ctx.Err()
}

// readRecordTarget reads and validates the adapter target a rule
// records.
func (b *Backend) readRecordTarget(ctx context.Context, key string) (adapterTarget, error) {
	if err := ctx.Err(); err != nil {
		return adapterTarget{}, err
	}
	guid, err := b.reg.GetString(key, interfaceGUIDValue)
	if err != nil {
		return adapterTarget{}, fmt.Errorf("windows: read recovery target in %s: %w", key, err)
	}
	guid, err = canonicalGUID(guid)
	if err != nil {
		return adapterTarget{}, fmt.Errorf("windows: read recovery target in %s: %w", key, err)
	}
	return adapterTarget{guid: guid}, ctx.Err()
}

func (b *Backend) writeTarget(key string, target adapterTarget) error {
	if err := b.reg.SetString(key, interfaceGUIDValue, target.guid); err != nil {
		return fmt.Errorf("windows: record adapter GUID: %w", err)
	}
	return nil
}

// desiredAdapterValues returns NameServer and SearchList for each IP stack in
// adapterPaths order. An empty string means the value must be absent.
func desiredAdapterValues(cfg backend.Config) [2]map[string]string {
	var servers [2][]string
	if len(cfg.MatchDomains) == 0 {
		for _, addr := range cfg.Nameservers {
			if addr.Is4() {
				servers[0] = append(servers[0], addr.String())
			} else {
				servers[1] = append(servers[1], addr.String())
			}
		}
	}
	var out [2]map[string]string
	for i := range out {
		out[i] = map[string]string{
			nameServerValue: strings.Join(servers[i], ","),
			searchListValue: strings.Join(cfg.SearchDomains, ","),
		}
	}
	return out
}

// convergeAdapter writes only the adapter values that differ from cfg
// and reads each written value back.
func (b *Backend) convergeAdapter(ctx context.Context, target adapterTarget, cfg backend.Config, mut *mutation) error {
	b.adapterTarget = &target
	want := desiredAdapterValues(cfg)
	for i, path := range adapterPaths(target.guid) {
		for _, name := range []string{nameServerValue, searchListValue} {
			if err := ctx.Err(); err != nil {
				return err
			}
			data := want[i][name]
			match, err := b.adapterValueMatches(path, name, data)
			if err != nil {
				return err
			}
			if match {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			mut.beginAdapter()
			if data == "" {
				err = b.reg.DeleteValue(path, name)
			} else {
				err = b.reg.SetExistingString(path, name, data)
			}
			if err != nil {
				return fmt.Errorf("windows: write adapter %s %s: %w", target.guid, name, err)
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if match, err := b.adapterValueMatches(path, name, data); err != nil {
				return err
			} else if !match {
				return fmt.Errorf("windows: adapter %s %s changed during readback", target.guid, name)
			}
		}
	}
	return nil
}

// adapterValueMatches compares one adapter value with data. An empty data
// is satisfied by an absent or empty value: Windows creates interface keys
// with an empty NameServer, which the DNS Client already treats as unset,
// so deleting it would only cost a reload.
func (b *Backend) adapterValueMatches(path, name, data string) (bool, error) {
	got, err := b.reg.GetString(path, name)
	if errors.Is(err, ErrValueNotFound) {
		got = ""
	} else if err != nil {
		return false, fmt.Errorf("windows: read adapter %s %s: %w", path, name, err)
	}
	return got == data, nil
}

// clearAdapter deletes whichever NameServer and SearchList values are
// set on the caller-controlled target, without checking who wrote them.
// An empty value is Windows's own unset form and is left alone. A device
// Windows removed took its interface keys with it, so nothing is found and
// the target is released.
func (b *Backend) clearAdapter(ctx context.Context, target adapterTarget, mut *mutation) error {
	b.adapterTarget = &target
	var errs []error
	for _, path := range adapterPaths(target.guid) {
		for _, name := range []string{searchListValue, nameServerValue} {
			if err := ctx.Err(); err != nil {
				return errors.Join(append(errs, err)...)
			}
			got, err := b.reg.GetString(path, name)
			if errors.Is(err, ErrValueNotFound) || err == nil && got == "" {
				continue
			} else if err != nil {
				errs = append(errs, fmt.Errorf("windows: read adapter %s %s: %w", target.guid, name, err))
				continue
			}
			if err := ctx.Err(); err != nil {
				return errors.Join(append(errs, err)...)
			}
			mut.beginAdapter()
			if err := b.reg.DeleteValue(path, name); err != nil {
				errs = append(errs, fmt.Errorf("windows: clear adapter %s %s: %w", target.guid, name, err))
			}
		}
	}
	err := errors.Join(append(errs, ctx.Err())...)
	if err == nil {
		b.adapterTarget = nil
	}
	return err
}
