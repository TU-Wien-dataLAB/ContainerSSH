package kubernetes

import (
	"context"
	"errors"
	"sync"

	"k8s.io/client-go/tools/remotecommand"
)

type pushSizeQueueImpl struct {
	resizeChan chan remotecommand.TerminalSize
	lock       sync.Mutex
	stopped    bool
	stopChan   chan struct{}
}

func (s *pushSizeQueueImpl) Push(ctx context.Context, size remotecommand.TerminalSize) error {
	s.lock.Lock()
	stopChan := s.getStopChanLocked()
	stopped := s.stopped
	s.lock.Unlock()
	if stopped {
		return errors.New("terminal size queue is stopped")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-stopChan:
		return errors.New("terminal size queue is stopped")
	case s.resizeChan <- size:
		return nil
	}
}

func (s *pushSizeQueueImpl) Next() *remotecommand.TerminalSize {
	s.lock.Lock()
	stopChan := s.getStopChanLocked()
	stopped := s.stopped
	s.lock.Unlock()
	if stopped {
		return nil
	}

	select {
	case <-stopChan:
		return nil
	case size := <-s.resizeChan:
		return &size
	}
}

func (s *pushSizeQueueImpl) Stop() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	// Window requests may still be sending when execution finishes. Signal
	// shutdown without closing their data channel or blocking behind a send.
	close(s.getStopChanLocked())
}

func (s *pushSizeQueueImpl) getStopChanLocked() chan struct{} {
	if s.stopChan == nil {
		s.stopChan = make(chan struct{})
	}
	return s.stopChan
}
