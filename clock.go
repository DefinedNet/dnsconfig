package dnsconfig

import "time"

// clock is the worker's time source. Tests substitute a manual clock so
// debounce, backoff, pacing, and periodic checks run without sleeping.
type clock interface {
	Now() time.Time
	NewTimer(d time.Duration) clockTimer
}

// clockTimer is the subset of *time.Timer the worker uses.
type clockTimer interface {
	C() <-chan time.Time
	Stop() bool
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) NewTimer(d time.Duration) clockTimer { return realTimer{time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time { return r.t.C }

func (r realTimer) Stop() bool { return r.t.Stop() }
