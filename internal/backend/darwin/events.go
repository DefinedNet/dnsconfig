//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/DefinedNet/dnsconfig/internal/runner"
)

// The State pattern catches VPN and other runtime supplemental resolvers. The
// Setup pattern catches persistent DNS changes before configd compiles them.
const scutilWatchCommands = "n.add State:/Network/Service/[^/]+/DNS pattern\n" +
	"n.add Setup:/Network/Service/[^/]+/DNS pattern\n" +
	"n.add State:/Network/Global/DNS\n" +
	"n.watch\n"

var errNoStarter = errors.New("darwin: runner cannot start the scutil notification child")

// eventSource is a running `scutil` n.watch child whose stdout feeds
// Backend.changes.
type eventSource struct {
	// done closes when the stdout scanner exits; err, written before that,
	// is why.
	done <-chan struct{}
	err  error
	stop func()
}

// Changes implements backend.Backend.
func (b *Backend) Changes() <-chan struct{} { return b.changes }

// ensureEventSource starts the notification child unless one is live. A dead
// child is replaced, so each Set, including the worker's periodic ones,
// retries a source that exited or failed to start.
func (b *Backend) ensureEventSource() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	var dead *eventSource
	if b.source != nil {
		select {
		case <-b.source.done:
			dead = b.source
			b.source = nil
		default:
			b.mu.Unlock()
			return
		}
	}
	// Started under mu so Close cannot miss a child started concurrently.
	src, err := b.startEventSource()
	wasHealthy := b.sourceErr == nil && dead == nil
	if err != nil {
		b.sourceErr = err
		if wasHealthy {
			b.logger.Warn("darwin: scutil notification source unavailable; drift is found only by periodic converges", "err", err)
		}
	} else {
		b.source = src
		b.sourceErr = nil
	}
	b.mu.Unlock()
	if dead != nil {
		b.logger.Warn("darwin: scutil notification child exited; restarted it", "err", dead.err, "restarted", err == nil)
		dead.stop()
	}
}

// releaseEventSource stops the notification child once nothing is left to
// watch. The next Set starts a new one.
func (b *Backend) releaseEventSource() {
	b.mu.Lock()
	src := b.source
	b.source = nil
	b.sourceErr = nil
	b.mu.Unlock()
	if src != nil {
		src.stop()
	}
}

// startEventSource launches the notification child. Its stop terminates the
// child and joins the stdout scanner, after which the scanner sends nothing.
func (b *Backend) startEventSource() (*eventSource, error) {
	starter, ok := b.runner.(runner.Starter)
	if !ok {
		return nil, errNoStarter
	}
	childCtx, cancelChild := context.WithCancel(context.Background())
	proc, err := starter.Start(childCtx, scutilBinary, nil)
	if err != nil {
		cancelChild()
		return nil, fmt.Errorf("darwin: start scutil notification child: %w", err)
	}
	if _, err := io.WriteString(proc.Stdin(), scutilWatchCommands); err != nil {
		cancelChild()
		_ = proc.Kill()
		return nil, fmt.Errorf("darwin: drive scutil notification child: %w", err)
	}

	done := make(chan struct{})
	src := &eventSource{done: done}
	go func() {
		defer close(done)
		// scutil's notification output is undocumented. Any non-empty line is
		// enough because a converge re-reads every owned artifact.
		scanner := bufio.NewScanner(proc.Stdout())
		for scanner.Scan() {
			if len(scanner.Bytes()) == 0 {
				continue
			}
			select {
			case b.changes <- struct{}{}:
			default:
			}
		}
		src.err = scanner.Err()
		if src.err == nil {
			src.err = errors.New("darwin: scutil notification child exited")
		}
	}()
	src.stop = func() {
		// Cancellation starts ExecRunner's pipe-shutdown timer before Kill waits
		// to reap, so the stdout scanner cannot hold the join indefinitely.
		cancelChild()
		_ = proc.Kill()
		<-done
	}
	return src, nil
}

// Close implements backend.Backend. It stops and joins the
// notification child and closes the Changes channel without changing DNS.
func (b *Backend) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		src := b.source
		b.source = nil
		b.mu.Unlock()
		if src != nil {
			src.stop()
		}
		close(b.changes)
	})
	return nil
}
