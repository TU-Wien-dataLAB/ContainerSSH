// Package sshserver implements SSH transport and dispatches requests to backend handlers.
package sshserver

import (
	"fmt"
	"sync"
)

// startOnceSessionChannelHandler permits one successful program start over the
// channel's lifetime. Failed starts remain retryable, as in the stock server.
// The lock is separate from channelWrapper's IO lock: a backend start may send
// exit status or close the channel synchronously.
type startOnceSessionChannelHandler struct {
	SessionChannelHandler
	startLock sync.Mutex
	started   bool
}

func (s *startOnceSessionChannelHandler) start(start func() error) error {
	s.startLock.Lock()
	defer s.startLock.Unlock()
	if s.started {
		return fmt.Errorf("a program has already been started on this channel")
	}
	if err := start(); err != nil {
		return err
	}
	s.started = true
	return nil
}

func (s *startOnceSessionChannelHandler) OnShell(requestID uint64) error {
	return s.start(func() error { return s.SessionChannelHandler.OnShell(requestID) })
}

func (s *startOnceSessionChannelHandler) OnExecRequest(requestID uint64, command string) error {
	return s.start(func() error { return s.SessionChannelHandler.OnExecRequest(requestID, command) })
}

func (s *startOnceSessionChannelHandler) OnSubsystem(requestID uint64, subsystem string) error {
	return s.start(func() error { return s.SessionChannelHandler.OnSubsystem(requestID, subsystem) })
}
