package sshserver_test

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.containerssh.io/containerssh/internal/sshserver"
	"go.containerssh.io/containerssh/log"
	"go.containerssh.io/containerssh/metadata"
	"golang.org/x/crypto/ssh"
)

// Exercise the real request/reply loop, not a backend that already refuses restarts.
func TestSettingsSingleAcceptedStart(t *testing.T) {
	logger := log.NewTestLogger(t)
	user := sshserver.NewTestUser("settings")
	user.SetPassword("test")
	handler := &settingsStartHandler{}
	srv := sshserver.NewTestServer(t, sshserver.NewTestAuthenticationHandler(handler, user), logger, nil)
	srv.Start()
	defer srv.Stop(5 * time.Second)
	conn, err := net.DialTimeout("tcp", srv.GetListen(), 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
	hostKey, err := ssh.ParsePrivateKey([]byte(srv.GetHostKey()))
	require.NoError(t, err)
	sshConn, channels, requests, err := ssh.NewClientConn(conn, srv.GetListen(), &ssh.ClientConfig{
		User: "settings", Auth: []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
	})
	require.NoError(t, err)
	client := ssh.NewClient(sshConn, channels, requests)
	defer func() { _ = client.Close() }()
	starts := []struct {
		name    string
		payload []byte
	}{
		{"shell", nil},
		{"exec", ssh.Marshal(struct{ Command string }{"/app"})},
		{"subsystem", ssh.Marshal(struct{ Name string }{"sftp"})},
	}
	for _, first := range starts {
		t.Run(first.name, func(t *testing.T) {
			channel, replies, err := client.OpenChannel("session", nil)
			require.NoError(t, err)
			defer func() { _ = channel.Close() }()
			go ssh.DiscardRequests(replies)
			before := handler.attempts.Load()
			// A backend-rejected start must not consume the channel's opportunity.
			ok, err := channel.SendRequest(first.name, true, first.payload)
			require.NoError(t, err)
			require.False(t, ok)
			ok, err = channel.SendRequest(first.name, true, first.payload)
			require.NoError(t, err)
			require.True(t, ok)
			for _, next := range starts {
				ok, err = channel.SendRequest(next.name, true, next.payload)
				require.NoError(t, err)
				require.False(t, ok, "second %s after %s must be rejected", next.name, first.name)
			}
			// Exit status doesn't make the same channel reusable; non-start requests still work.
			ok, err = channel.SendRequest("env", true, ssh.Marshal(struct{ Name, Value string }{"exit", "0"}))
			require.NoError(t, err)
			require.True(t, ok)
			ok, err = channel.SendRequest("shell", true, nil)
			require.NoError(t, err)
			require.False(t, ok)
			require.Equal(t, before+2, handler.attempts.Load(), "only failed start and first accepted start reach backend")
		})
	}
}

type settingsStartHandler struct {
	sshserver.AbstractHandler
	attempts atomic.Int32
}

func (h *settingsStartHandler) OnNetworkConnection(meta metadata.ConnectionMetadata) (sshserver.NetworkConnectionHandler, metadata.ConnectionMetadata, error) {
	return &settingsStartNetwork{handler: h}, meta, nil
}

type settingsStartNetwork struct {
	sshserver.AbstractNetworkConnectionHandler
	handler *settingsStartHandler
}

func (n *settingsStartNetwork) OnHandshakeSuccess(meta metadata.ConnectionAuthenticatedMetadata) (sshserver.SSHConnectionHandler, metadata.ConnectionAuthenticatedMetadata, error) {
	return &settingsStartConnection{handler: n.handler}, meta, nil
}

type settingsStartConnection struct {
	fullSSHConnectionHandler
	handler *settingsStartHandler
}

func (c *settingsStartConnection) OnSessionChannel(_ metadata.ChannelMetadata, _ []byte, channel sshserver.SessionChannel) (sshserver.SessionChannelHandler, sshserver.ChannelRejection) {
	return &settingsStartSession{handler: c.handler, channel: channel, rejectFirst: true}, nil
}

type settingsStartSession struct {
	sshserver.AbstractSessionChannelHandler
	handler     *settingsStartHandler
	channel     sshserver.SessionChannel
	rejectFirst bool
}

func (s *settingsStartSession) start() error {
	s.handler.attempts.Add(1)
	if s.rejectFirst {
		s.rejectFirst = false
		return fmt.Errorf("start failed")
	}
	return nil
}
func (s *settingsStartSession) OnShell(_ uint64) error                 { return s.start() }
func (s *settingsStartSession) OnSubsystem(_ uint64, _ string) error   { return s.start() }
func (s *settingsStartSession) OnExecRequest(_ uint64, _ string) error { return s.start() }
func (s *settingsStartSession) OnEnvRequest(_ uint64, _, _ string) error {
	s.channel.ExitStatus(0)
	return nil
}
