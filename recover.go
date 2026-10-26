package dnsconfig

import (
	"context"
	"errors"

	"github.com/DefinedNet/dnsconfig/internal/backend"
)

// Recover removes DNS configuration that a previous instance of o.Identity
// left behind, for a caller starting up after an unclean exit. Call it before
// [New] for that identity; a process that keeps running needs no Recover,
// since [Manager.Clear] and [Manager.Close] remove the same artifacts.
//
// Recover validates o and selects a backend as New does, then reads the host
// without taking locks. When nothing of this identity's is found it returns
// false and nil, having written nothing, started no change-signal source,
// and taken no lock. Otherwise it removes the artifacts the way
// [Manager.Close] does for a goal its worker never reached: it takes the
// identity lock without waiting, makes one final Clear under the host lock,
// and releases both. changed reports whether that Clear changed the host.
//
// ctx bounds construction and the read. The removal is bounded like Close's
// cleanup, by o.ShutdownTimeout or [DefaultShutdownTimeout] when it is zero,
// including the host-lock wait, and observes neither ctx nor its deadline.
//
// Errors are wrapped in [Error] with Op "Recover", except invalid Options,
// which are returned as-is. Unlike Close, Recover returns
// [ErrManagerAlreadyRunning] when another live Manager holds the identity:
// the caller asked for removal and nothing was removed. A failed cleanup is
// an error. A later Recover or a Manager's Clear finds the artifacts that
// remain, but not a reload or Group Policy notification still owed once the
// last rule is gone. The no-op backend finds nothing.
//
// Recover looks for the artifacts Clear attributes to the identity, so the
// limits are the same: a setting whose ownership evidence is gone stays. On
// Windows that includes a side effect a predecessor still owed after deleting
// its rules. Recover reports false; a removed Group Policy rule stays in
// effect until the DNS Client is notified or restarted, and a removed adapter
// value is applied on the DNS Client's own schedule.
func Recover(ctx context.Context, o Options) (changed bool, err error) {
	m, err := build(ctx, "Recover", o)
	if err != nil {
		return false, err
	}
	return m.recoverHost(ctx)
}

// recoverHost runs Recover over m's backend and locker. m must be unstarted.
func (m *Manager) recoverHost(ctx context.Context) (bool, error) {
	var res backend.Result
	found, err := m.backend.HasArtifacts(ctx)
	if err == nil && found {
		err = m.acquireLifetime()
		if err == nil {
			res, err = m.finalClear()
		}
	}
	// The backend stops before the identity is released, as in Close.
	err = errors.Join(err, m.backend.Close(), m.releaseLifetime())
	if err != nil {
		return res.Changed, &Error{Op: "Recover", Backend: m.kind, Err: err}
	}
	return res.Changed, nil
}
