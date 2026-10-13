package kubernetes

import (
	"context"
	"errors"
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

func TestResizeQueueShutdown(t *testing.T) {
	for _, mode := range []config.KubernetesExecutionMode{
		config.KubernetesExecutionModeConnection,
		config.KubernetesExecutionModePersistent,
		config.KubernetesExecutionModeSession,
	} {
		t.Run(string(mode), func(t *testing.T) {
			tty := true
			pod := &kubernetesPodImpl{
				config: config.KubernetesConfig{},
				tty:    &tty,
				wg:     &sync.WaitGroup{},
			}
			pod.config.Pod.Mode = mode
			// PID framing is independent of resize shutdown. Bypass the agent so
			// this regression also runs against versions with different framing.
			pod.config.Pod.DisableAgent = true
			pod.config.Timeouts.PodStop = time.Second
			if mode == config.KubernetesExecutionModeConnection {
				pod.wg.Add(1)
			}

			collector := metrics.New(nil)
			stream := &resizeExecutor{
				entered:  make(chan struct{}),
				received: make(chan remotecommand.TerminalSize, 1),
				finish:   make(chan struct{}),
			}
			execution := &kubernetesExecutionImpl{
				pod:               pod,
				exec:              stream,
				terminalSizeQueue: &pushSizeQueueImpl{resizeChan: make(chan remotecommand.TerminalSize)},
				logger:            log.NewTestLogger(t),
				doneChan:          make(chan struct{}),
				backendRequestsMetric: collector.MustCreateCounter(
					"resize-shutdown-requests", "", "test"),
				backendFailuresMetric: collector.MustCreateCounter(
					"resize-shutdown-failures", "", "test"),
			}
			network := &networkHandler{
				mutex:  &sync.Mutex{},
				config: config.KubernetesConfig{},
				logger: log.NewTestLogger(t),
			}
			network.config.Timeouts.Window = 2 * time.Second
			handler := &channelHandler{networkHandler: network, exec: execution}

			exitStatus := make(chan int, 1)
			streamDone := make(chan struct{})
			go func() {
				execution.handleStream(nil, io.Discard, io.Discard, func() error { return nil }, func(code int) {
					exitStatus <- code
				})
				close(streamDone)
			}()
			select {
			case <-stream.entered:
			case <-time.After(time.Second):
				t.Fatal("remotecommand executor did not enter StreamWithContext")
			}

			// A live window request must reach the real execution's stream queue.
			active := captureWindow(handler, 80, 24)
			if active.panicValue != nil {
				t.Fatalf("active OnWindow panicked: %v", active.panicValue)
			}
			require.NoError(t, active.err)
			select {
			case size := <-stream.received:
				require.Equal(t, remotecommand.TerminalSize{Width: 80, Height: 24}, size)
			case <-time.After(time.Second):
				t.Fatal("active resize was not delivered to the remotecommand executor")
			}

			// The executor stops reading sizes. Leave an OnWindow push pending
			// while actual stream completion stops its queue.
			const concurrentResizes = 4
			results := make(chan resizeCall, concurrentResizes)
			started := make(chan struct{}, concurrentResizes)
			for i := 0; i < concurrentResizes; i++ {
				go func() {
					started <- struct{}{}
					results <- captureWindow(handler, 100, 40)
				}()
			}
			for i := 0; i < concurrentResizes; i++ {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("concurrent resize caller did not start")
				}
			}
			select {
			case result := <-results:
				t.Fatalf("resize completed before the stream stopped: %+v", result)
			case <-time.After(25 * time.Millisecond):
			}

			close(stream.finish)
			select {
			case <-streamDone:
			case <-time.After(time.Second):
				t.Fatal("execution did not finish after the remote stream returned")
			}
			require.Equal(t, 7, <-exitStatus)

			var failures []string
			for i := 0; i < concurrentResizes; i++ {
				select {
				case result := <-results:
					if result.panicValue != nil {
						failures = append(failures, fmt.Sprintf("concurrent OnWindow panicked: %v", result.panicValue))
					} else if result.err == nil {
						failures = append(failures, "concurrent resize succeeded after stream shutdown")
					}
				case <-time.After(time.Second):
					failures = append(failures, "concurrent OnWindow remained blocked after stream shutdown")
				}
			}

			// A delayed window notification must return an error, never panic.
			delayed := captureWindow(handler, 120, 50)
			if delayed.panicValue != nil {
				failures = append(failures, fmt.Sprintf("post-exit OnWindow panicked: %v", delayed.panicValue))
			} else if delayed.err == nil {
				failures = append(failures, "post-exit OnWindow unexpectedly succeeded")
			}
			require.Empty(t, failures, "%s execution resize shutdown failures", mode)
		})
	}

	t.Run("queue shutdown contract", func(t *testing.T) {
		const prompt = 250 * time.Millisecond

		readerQueue := &pushSizeQueueImpl{resizeChan: make(chan remotecommand.TerminalSize)}
		readResult := make(chan *remotecommand.TerminalSize, 1)
		go func() { readResult <- readerQueue.Next() }()
		select {
		case size := <-readResult:
			t.Fatalf("Next returned before shutdown: %v", size)
		case <-time.After(25 * time.Millisecond):
		}
		readerQueue.Stop()
		readerQueue.Stop()
		select {
		case size := <-readResult:
			require.Nil(t, size, "Next must return nil after shutdown")
		case <-time.After(prompt):
			t.Fatal("Stop did not release a blocked Next")
		}

		writerQueue := &pushSizeQueueImpl{resizeChan: make(chan remotecommand.TerminalSize)}
		writeResult := make(chan resizePushResult, 1)
		go func() {
			err, panicValue := captureResizePush(writerQueue, context.Background())
			writeResult <- resizePushResult{err: err, panicValue: panicValue}
		}()
		select {
		case result := <-writeResult:
			t.Fatalf("Push returned before shutdown: %+v", result)
		case <-time.After(25 * time.Millisecond):
		}
		writerQueue.Stop()
		writerQueue.Stop()
		select {
		case result := <-writeResult:
			require.Nil(t, result.panicValue, "Stop must not panic a blocked Push")
			require.Error(t, result.err, "shutdown must release a pending Push with an error")
		case <-time.After(prompt):
			t.Fatal("Stop did not release a blocked Push")
		}

		futureErr, futurePanic := captureResizePush(writerQueue, context.Background())
		require.Nil(t, futurePanic, "Push after Stop must not panic")
		require.Error(t, futureErr, "Push after Stop must return an error")

		cancelledQueue := &pushSizeQueueImpl{resizeChan: make(chan remotecommand.TerminalSize)}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cancelledErr, cancelledPanic := captureResizePush(cancelledQueue, ctx)
		require.Nil(t, cancelledPanic)
		require.ErrorIs(t, cancelledErr, context.Canceled, "caller cancellation must be preserved")
		cancelledQueue.Stop()
	})
}

type resizeCall struct {
	err        error
	panicValue interface{}
}

func captureWindow(handler *channelHandler, columns, rows uint32) (result resizeCall) {
	defer func() { result.panicValue = recover() }()
	result.err = handler.OnWindow(1, columns, rows, 0, 0)
	return result
}

type resizePushResult struct {
	err        error
	panicValue interface{}
}

func captureResizePush(queue pushSizeQueue, ctx context.Context) (err error, panicValue interface{}) {
	defer func() { panicValue = recover() }()
	err = queue.Push(ctx, remotecommand.TerminalSize{Width: 80, Height: 24})
	return err, panicValue
}

type resizeExecutor struct {
	entered  chan struct{}
	received chan remotecommand.TerminalSize
	finish   chan struct{}
}

func (s *resizeExecutor) Stream(options remotecommand.StreamOptions) error {
	return s.StreamWithContext(context.Background(), options)
}

func (s *resizeExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	close(s.entered)
	size := options.TerminalSizeQueue.Next()
	if size == nil {
		return fmt.Errorf("terminal size queue stopped before active resize")
	}
	s.received <- *size
	<-s.finish
	return exec.CodeExitError{Err: errors.New("resize fixture exit"), Code: 7}
}
