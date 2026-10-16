package kubernetes //nolint:testpackage // Exercises the unexported execution at the Kubernetes stream boundary.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.containerssh.io/containerssh/config"
	"go.containerssh.io/containerssh/internal/metrics"
	"go.containerssh.io/containerssh/log"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/exec"
)

// Follow channelHandler's ordering: run must receive the agent PID before the
// initial resize. The stream emits no application output to rescue PID framing.
func TestSettingsPIDFramingAndResize(t *testing.T) {
	for _, tc := range []struct {
		mode config.KubernetesExecutionMode
		tty  bool
	}{
		{config.KubernetesExecutionModeConnection, true},
		{config.KubernetesExecutionModePersistent, true},
		{config.KubernetesExecutionModeSession, true},
		{config.KubernetesExecutionModeConnection, false},
		{config.KubernetesExecutionModeSession, false},
	} {
		t.Run(fmt.Sprintf("%s/tty=%t", tc.mode, tc.tty), func(t *testing.T) {
			waitEcho := tc.mode == config.KubernetesExecutionModeSession && tc.tty
			stream := &settingsPIDStream{pidWritten: make(chan struct{}), echo: make(chan bool),
				size: make(chan remotecommand.TerminalSize, 1), finish: make(chan struct{}), waitEcho: waitEcho}
			collector := metrics.New(nil)
			pod := &kubernetesPodImpl{config: config.KubernetesConfig{}, tty: &tc.tty, wg: &sync.WaitGroup{}}
			pod.config.Pod.Mode = tc.mode
			if tc.mode == config.KubernetesExecutionModeConnection {
				pod.wg.Add(1)
			}
			execution := &kubernetesExecutionImpl{pod: pod, exec: stream, tty: tc.tty,
				terminalSizeQueue: &pushSizeQueueImpl{resizeChan: make(chan remotecommand.TerminalSize)},
				logger:            log.NewTestLogger(t), doneChan: make(chan struct{}), lock: &sync.Mutex{},
				backendRequestsMetric: collector.MustCreateCounter("requests", "", "test"),
				backendFailuresMetric: collector.MustCreateCounter("failures", "", "test")}
			var stdout bytes.Buffer
			runReturned, exited := make(chan struct{}), make(chan int, 1)
			resizeResult := make(chan error, 1)
			go func() {
				execution.run(bytes.NewReader(nil), &stdout, io.Discard, func() error { return nil }, func(code int) { exited <- code })
				close(runReturned)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				resizeResult <- execution.resize(ctx, 24, 80)
			}()
			select {
			case <-stream.pidWritten:
			case <-time.After(time.Second):
				t.Fatal("stream did not write PID")
			}
			stalled := false
			if waitEcho {
				select {
				case <-runReturned:
					t.Error("session PTY must retain its six-byte PID/wait-echo framing")
				case <-time.After(50 * time.Millisecond):
				}
			} else {
				select {
				case <-runReturned:
				case <-time.After(500 * time.Millisecond):
					t.Error("four-byte PID must unblock run and initial resize without application output")
					stalled = true
				}
			}
			// On red, supply the two missing bytes only to drain stock's blocked
			// goroutines; they are never part of the successful exec-mode fixture.
			stream.echo <- waitEcho || stalled
			select {
			case size := <-stream.size:
				require.Equal(t, remotecommand.TerminalSize{Width: 80, Height: 24}, size)
			case <-time.After(2 * time.Second):
				t.Fatal("initial resize never reached the stream")
			}
			require.NoError(t, <-resizeResult)
			close(stream.finish)
			require.Equal(t, 9, <-exited)
			require.Equal(t, 0x1234, execution.pid)
			if !stalled {
				if waitEcho {
					require.Equal(t, "\r\n", stdout.String())
				} else {
					require.Empty(t, stdout.String())
				}
			}
		})
	}
}

// The remotecommand.Executor boundary supplies agent bytes, then requires a
// terminal size before producing anything else, as a terminal-dependent app does.
type settingsPIDStream struct {
	pidWritten chan struct{}
	echo       chan bool
	size       chan remotecommand.TerminalSize
	finish     chan struct{}
	waitEcho   bool
}

func (s *settingsPIDStream) Stream(options remotecommand.StreamOptions) error {
	return s.StreamWithContext(context.Background(), options)
}

func (s *settingsPIDStream) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	if s.waitEcho {
		var start [1]byte
		if _, err := io.ReadFull(options.Stdin, start[:]); err != nil {
			return err
		}
		if start[0] != '\n' {
			return fmt.Errorf("missing session --wait start newline")
		}
	}
	// Fragment the four-byte little-endian PID at the transport boundary.
	if _, err := options.Stdout.Write([]byte{0x34}); err != nil {
		return err
	}
	if _, err := options.Stdout.Write([]byte{0x12, 0, 0}); err != nil {
		return err
	}
	close(s.pidWritten)
	if <-s.echo {
		if _, err := options.Stdout.Write([]byte("\r\n")); err != nil {
			return err
		}
	}
	size := options.TerminalSizeQueue.Next()
	if size == nil {
		return fmt.Errorf("size queue closed before initial resize")
	}
	s.size <- *size
	<-s.finish
	return exec.CodeExitError{Err: fmt.Errorf("fixture exit"), Code: 9}
}
