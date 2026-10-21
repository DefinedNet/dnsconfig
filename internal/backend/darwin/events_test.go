//go:build darwin

package darwin

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DefinedNet/dnsconfig/internal/runner"
)

type blockingEventRunner struct {
	*scutilFake

	proc      *blockingEventProcess
	startOnce sync.Once
	started   chan struct{}
}

func newBlockingEventRunner() *blockingEventRunner {
	reader, writer := io.Pipe()
	gatedStdout := &gatedEOFReader{
		reader:      reader,
		eofObserved: make(chan struct{}),
		eofRelease:  make(chan struct{}),
	}
	return &blockingEventRunner{
		scutilFake: newScutilFake(),
		proc: &blockingEventProcess{
			stdout:       gatedStdout,
			stdoutWriter: writer,
			cancelSeen:   make(chan struct{}),
			killStarted:  make(chan struct{}),
			killRelease:  make(chan struct{}),
			killDone:     make(chan struct{}),
		},
		started: make(chan struct{}),
	}
}

func (r *blockingEventRunner) Start(ctx context.Context, _ string, _ []string) (runner.Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.startOnce.Do(func() {
		r.proc.ctx = ctx
		go func() {
			<-ctx.Done()
			_ = r.proc.stdoutWriter.Close()
		}()
		close(r.started)
	})
	return r.proc, nil
}

type blockingEventProcess struct {
	stdin        bytes.Buffer
	stdout       *gatedEOFReader
	stdoutWriter *io.PipeWriter
	ctx          context.Context

	cancelSeen  chan struct{}
	killStarted chan struct{}
	killRelease chan struct{}
	killDone    chan struct{}
	killOnce    sync.Once
	releaseOnce sync.Once
}

func (p *blockingEventProcess) Stdin() io.Writer  { return &p.stdin }
func (p *blockingEventProcess) Stdout() io.Reader { return p.stdout }

func (p *blockingEventProcess) Kill() error {
	p.killOnce.Do(func() {
		if p.ctx.Err() != nil {
			close(p.cancelSeen)
		}
		close(p.killStarted)
		<-p.killRelease
		close(p.killDone)
	})
	return nil
}

func (p *blockingEventProcess) releaseKill() {
	p.releaseOnce.Do(func() { close(p.killRelease) })
}

type gatedEOFReader struct {
	reader io.Reader

	eofObserved chan struct{}
	eofRelease  chan struct{}
	observeOnce sync.Once
	releaseOnce sync.Once
}

func (r *gatedEOFReader) Read(buf []byte) (int, error) {
	n, err := r.reader.Read(buf)
	if err == io.EOF {
		r.observeOnce.Do(func() { close(r.eofObserved) })
		<-r.eofRelease
	}
	return n, err
}

func (r *gatedEOFReader) releaseEOF() {
	r.releaseOnce.Do(func() { close(r.eofRelease) })
}

// TestSourceStopJoinsChildTeardown: Close and a completed Clear both return
// only after the child is reaped and its stdout scanner has exited, so no
// send can reach a closed Changes channel.
func TestSourceStopJoinsChildTeardown(t *testing.T) {
	for _, tt := range []struct {
		name string
		stop func(*Backend) error
	}{
		{name: "clear", stop: tryClear},
		{name: "close", stop: func(b *Backend) error { return b.Close() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			eventRunner := newBlockingEventRunner()
			b := newTestBackend(t, newTestFS(t), eventRunner)
			t.Cleanup(eventRunner.proc.releaseKill)
			t.Cleanup(eventRunner.proc.stdout.releaseEOF)

			require.NoError(t, trySet(b, catchAllConfig()))
			select {
			case <-eventRunner.started:
			case <-time.After(time.Second):
				t.Fatal("Set did not start the scutil child")
			}

			stopDone := make(chan error, 1)
			go func() { stopDone <- tt.stop(b) }()
			select {
			case <-eventRunner.proc.killStarted:
			case <-time.After(time.Second):
				t.Fatal("stop did not begin child teardown")
			}
			select {
			case <-eventRunner.proc.cancelSeen:
			case <-time.After(time.Second):
				t.Fatal("stop did not cancel the child context before Kill")
			}

			select {
			case err := <-stopDone:
				t.Fatalf("stop returned before child teardown completed: %v", err)
			case <-time.After(50 * time.Millisecond):
			}

			eventRunner.proc.releaseKill()
			select {
			case <-eventRunner.proc.killDone:
			case <-time.After(time.Second):
				t.Fatal("scutil child teardown did not finish")
			}
			select {
			case <-eventRunner.proc.stdout.eofObserved:
			case <-time.After(time.Second):
				t.Fatal("stdout scanner did not observe child teardown")
			}
			select {
			case err := <-stopDone:
				t.Fatalf("stop returned before the stdout scanner exited: %v", err)
			case <-time.After(50 * time.Millisecond):
			}

			eventRunner.proc.stdout.releaseEOF()
			select {
			case err := <-stopDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("stop did not return after child teardown completed")
			}
		})
	}
}

func TestEventSourceStopJoinsKillAfterScannerExit(t *testing.T) {
	eventRunner := newBlockingEventRunner()
	eventRunner.proc.stdout.releaseEOF()
	t.Cleanup(eventRunner.proc.releaseKill)

	b := newTestBackend(t, newTestFS(t), eventRunner)
	src, err := b.startEventSource()
	require.NoError(t, err)

	stopDone := make(chan struct{})
	go func() {
		src.stop()
		close(stopDone)
	}()
	select {
	case <-eventRunner.proc.killStarted:
	case <-time.After(time.Second):
		t.Fatal("event-source stop did not call Kill")
	}
	select {
	case <-eventRunner.proc.cancelSeen:
	case <-time.After(time.Second):
		t.Fatal("event-source stop did not cancel the child context")
	}
	select {
	case <-src.done:
	case <-time.After(time.Second):
		t.Fatal("stdout scanner did not exit after child cancellation")
	}
	select {
	case <-stopDone:
		t.Fatal("event-source stop returned before Kill completed")
	case <-time.After(50 * time.Millisecond):
	}

	eventRunner.proc.releaseKill()
	select {
	case <-stopDone:
	case <-time.After(time.Second):
		t.Fatal("event-source stop did not return after Kill completed")
	}
}

// pipeEventRunner starts children whose stdout the test writes and closes.
type pipeEventRunner struct {
	*scutilFake

	mu    sync.Mutex
	procs []*pipeProcess
}

func newPipeEventRunner() *pipeEventRunner {
	return &pipeEventRunner{scutilFake: newScutilFake()}
}

func (r *pipeEventRunner) Start(ctx context.Context, _ string, _ []string) (runner.Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	p := &pipeProcess{stdout: reader, writer: writer}
	r.mu.Lock()
	r.procs = append(r.procs, p)
	r.mu.Unlock()
	return p, nil
}

func (r *pipeEventRunner) starts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.procs)
}

func (r *pipeEventRunner) last() *pipeProcess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[len(r.procs)-1]
}

type pipeProcess struct {
	stdin  bytes.Buffer
	stdout *io.PipeReader
	writer *io.PipeWriter
}

func (p *pipeProcess) Stdin() io.Writer  { return &p.stdin }
func (p *pipeProcess) Stdout() io.Reader { return p.stdout }
func (p *pipeProcess) Kill() error       { return p.writer.Close() }

// emit writes one notification line as scutil would.
func (p *pipeProcess) emit(t *testing.T) {
	t.Helper()
	_, err := io.WriteString(p.writer, "notification callback (store address = 0x0).\n")
	require.NoError(t, err)
}

func TestChangesCoalescesNotificationsAndClosesOnClose(t *testing.T) {
	eventRunner := newPipeEventRunner()
	b := newTestBackend(t, newTestFS(t), eventRunner)
	changes := b.Changes()
	require.NotNil(t, changes)
	assert.Equal(t, 1, cap(changes))

	require.NoError(t, trySet(b, catchAllConfig()))
	require.Equal(t, 1, eventRunner.starts())
	proc := eventRunner.last()
	assert.Equal(t, scutilWatchCommands, proc.stdin.String())
	require.NoError(t, trySet(b, catchAllConfig()))
	assert.Equal(t, 1, eventRunner.starts(), "a live source is not restarted")

	// The pipe hands each line to the scanner synchronously, but the send
	// for the last line can still be in flight when emit returns. Ending
	// the stream and joining the scanner makes every line's send complete
	// before the channel is inspected, so the count is exact.
	for range 3 {
		proc.emit(t)
	}
	require.NoError(t, proc.writer.Close())
	b.mu.Lock()
	src := b.source
	b.mu.Unlock()
	require.NotNil(t, src)
	select {
	case <-src.done:
	case <-time.After(time.Second):
		t.Fatal("scanner did not finish after the stream ended")
	}
	select {
	case _, ok := <-changes:
		require.True(t, ok)
	default:
		t.Fatal("a notification did not reach Changes")
	}
	select {
	case <-changes:
		t.Fatal("notifications must coalesce into one pending signal")
	default:
	}

	require.NoError(t, b.Close())
	require.NoError(t, b.Close(), "Close is idempotent")
	select {
	case _, ok := <-changes:
		assert.False(t, ok, "Close closes Changes")
	case <-time.After(time.Second):
		t.Fatal("Close did not close Changes")
	}
}

// TestDeadSourceRestartedBySet: a child that exits is replaced by the next
// Set, and a completed Clear stops the source.
func TestDeadSourceRestartedBySet(t *testing.T) {
	eventRunner := newPipeEventRunner()
	b := newTestBackend(t, newTestFS(t), eventRunner)

	require.NoError(t, trySet(b, catchAllConfig()))
	require.NoError(t, eventRunner.last().writer.Close())
	require.Eventually(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		select {
		case <-b.source.done:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	_, err := b.Set(context.Background(), catchAllConfig(), repeat)
	require.NoError(t, err)
	assert.Equal(t, 2, eventRunner.starts(), "a dead source is restarted by the next Set")

	require.NoError(t, tryClear(b))
	b.mu.Lock()
	stopped := b.source == nil
	b.mu.Unlock()
	assert.True(t, stopped, "a completed Clear stops the source")
}

func TestSourceStartFailsWithoutStarter(t *testing.T) {
	b := newTestBackend(t, newTestFS(t), newScutilFake())
	require.NoError(t, trySet(b, catchAllConfig()), "missing monitoring leaves periodic checks, not a refusal")
	b.mu.Lock()
	defer b.mu.Unlock()
	assert.ErrorIs(t, b.sourceErr, errNoStarter)
}
