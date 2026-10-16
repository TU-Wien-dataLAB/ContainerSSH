package authintegration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"go.containerssh.io/containerssh/config"
	"go.containerssh.io/containerssh/internal/authintegration"
	"go.containerssh.io/containerssh/internal/geoip/dummy"
	"go.containerssh.io/containerssh/internal/metrics"
	"go.containerssh.io/containerssh/internal/sshserver"
	"go.containerssh.io/containerssh/internal/structutils"
	"go.containerssh.io/containerssh/internal/test"
	"go.containerssh.io/containerssh/log"
	"go.containerssh.io/containerssh/service"
)

// authWebhookFixture is a controlled authentication webhook fixture. It answers
// requests to /password, /pubkey, and /authz with the configured JSON response
// bodies.
type authWebhookFixture struct {
	t          *testing.T
	mutex      *sync.Mutex
	responses  map[string]string
	failPaths  map[string]int
	httpServer *httptest.Server
}

func startAuthWebhookFixture(t *testing.T) *authWebhookFixture {
	fixture := &authWebhookFixture{
		t:         t,
		mutex:     &sync.Mutex{},
		responses: map[string]string{},
		failPaths: map[string]int{},
	}
	fixture.httpServer = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		parts := strings.Split(request.URL.Path, "/")
		path := parts[len(parts)-1]
		fixture.mutex.Lock()
		defer fixture.mutex.Unlock()
		status, ok := fixture.failPaths[path]
		if !ok {
			status = http.StatusOK
		}
		response, ok := fixture.responses[path]
		if !ok {
			response = `{"success":false}`
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, err := writer.Write([]byte(response))
		assert.NoError(fixture.t, err)
	}))
	t.Cleanup(fixture.httpServer.Close)
	return fixture
}

// setResponse sets the JSON response body for a request path (password, pubkey,
// or authz).
func (f *authWebhookFixture) setResponse(path string, response string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.responses[path] = response
}

// setFailure sets a failing HTTP status code for a request path to simulate a
// webhook outage.
func (f *authWebhookFixture) setFailure(path string, status int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.failPaths[path] = status
}

func (f *authWebhookFixture) URL() string {
	return f.httpServer.URL
}

// startFixtureSSHServer starts an SSH server wired against the fixture webhook
// with public key authentication and authorization enabled. It returns the SSH
// configuration and the backend so tests can assert on backend interactions.
func startFixtureSSHServer(t *testing.T, fixture *authWebhookFixture) (config.SSHConfig, *testBackend) {
	backend := &testBackend{}
	webhookConfig := config.AuthWebhookClientConfig{
		HTTPClientConfiguration: config.HTTPClientConfiguration{
			URL:     fixture.URL(),
			Timeout: 2 * time.Second,
		},
		AuthTimeout: 2 * time.Second,
	}
	handler, _, err := authintegration.New(
		config.AuthConfig{
			PublicKeyAuth: config.PublicKeyAuthConfig{
				Method:  config.PubKeyAuthMethodWebhook,
				Webhook: webhookConfig,
			},
			Authz: config.AuthzConfig{
				Method:  config.AuthzMethodWebhook,
				Webhook: webhookConfig,
			},
		},
		backend,
		log.NewTestLogger(t),
		metrics.New(dummy.New()),
		authintegration.BehaviorNoPassthrough,
	)
	assert.NoError(t, err)

	sshServerConfig := config.SSHConfig{}
	structutils.Defaults(&sshServerConfig)
	assert.NoError(t, sshServerConfig.GenerateHostKey())
	port := test.GetNextPort(t, "SSH")
	sshServerConfig.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	srv, err := sshserver.New(sshServerConfig, handler, log.NewTestLogger(t))
	assert.NoError(t, err)

	lifecycle := service.NewLifecycle(srv)
	ready := make(chan struct{})
	lifecycle.OnRunning(
		func(s service.Service, l service.Lifecycle) {
			ready <- struct{}{}
		},
	)
	go func() {
		assert.NoError(t, lifecycle.Run())
	}()
	<-ready
	t.Cleanup(func() {
		lifecycle.Stop(context.Background())
	})
	return sshServerConfig, backend
}

// sshConnectionResult captures the observable result of a real SSH connection
// attempt: the dial error and all user authentication banners received.
type sshConnectionResult struct {
	dialError error
	banners   []string
}

// connectWithPublicKey performs a real SSH connection attempt using public key
// authentication with the provided username and collects any user authentication
// banners the server sends.
func connectWithPublicKey(t *testing.T, cfg config.SSHConfig, username string) sshConnectionResult {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(privateKey)
	assert.NoError(t, err)

	result := sshConnectionResult{}
	clientConfig := ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         10 * time.Second,
		BannerCallback: func(message string) error {
			result.banners = append(result.banners, message)
			return nil
		},
	}
	client, err := ssh.Dial("tcp", cfg.Listen, &clientConfig)
	result.dialError = err
	if client != nil {
		assert.NoError(t, client.Close())
	}
	return result
}

// TestPubKeyDenialWithMessageReachesClientAsBanner is the tracer bullet for
// readable denials: a webhook that answers HTTP 200 with success=false and a
// user-facing message causes the connecting SSH client to see exactly that text
// as an SSH user authentication banner immediately before the authentication
// failure.
func TestPubKeyDenialWithMessageReachesClientAsBanner(t *testing.T) {
	denialMessage := "unknown pod template 'unknown' — use a configured template username"
	fixture := startAuthWebhookFixture(t)
	fixture.setResponse(
		"pubkey",
		fmt.Sprintf(`{"success":false,"message":%q}`, denialMessage),
	)
	fixture.setResponse("authz", `{"success":true}`)

	start := time.Now()
	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	result := connectWithPublicKey(t, sshServerConfig, "unknown")
	elapsed := time.Since(start)

	assert.Error(
		t,
		result.dialError,
		"a message-bearing denial must still fail authentication",
	)
	assert.Equal(
		t,
		[]string{denialMessage},
		result.banners,
		"the client must see the exact webhook message as a pre-failure banner",
	)
	assert.Less(
		t,
		elapsed,
		5*time.Second,
		"a healthy permanent denial must complete promptly",
	)
	assert.Equal(
		t,
		int32(0),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"a denial must not initialize a backend session",
	)
}

// TestAuthzDenialWithMessageReachesClientAsBanner is the motivating scenario
// for readable denials: the user authenticates successfully by public key, the
// authorization check denies with an explicit message, and the SSH client sees
// exactly that text as a banner immediately before the connection fails.
func TestAuthzDenialWithMessageReachesClientAsBanner(t *testing.T) {
	denialMessage := "unknown pod template 'unknown' — use a configured template username"
	fixture := startAuthWebhookFixture(t)
	fixture.setResponse("pubkey", `{"success":true}`)
	fixture.setResponse(
		"authz",
		fmt.Sprintf(`{"success":false,"message":%q}`, denialMessage),
	)

	start := time.Now()
	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	result := connectWithPublicKey(t, sshServerConfig, "unknown")
	elapsed := time.Since(start)

	assert.Error(
		t,
		result.dialError,
		"a message-bearing authorization denial must still fail authentication",
	)
	assert.Equal(
		t,
		[]string{denialMessage},
		result.banners,
		"the client must see the exact authorization denial message as a pre-failure banner",
	)
	assert.Less(
		t,
		elapsed,
		5*time.Second,
		"a healthy permanent authorization denial must complete promptly",
	)
	assert.Equal(
		t,
		int32(0),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"an authorization denial must not initialize a backend session",
	)
}

// TestAuthzDenialWithoutMessageHasNoBanner verifies that message-less
// authorization denials behave exactly as before: authentication fails without
// a banner.
func TestAuthzDenialWithoutMessageHasNoBanner(t *testing.T) {
	fixture := startAuthWebhookFixture(t)
	fixture.setResponse("pubkey", `{"success":true}`)
	fixture.setResponse("authz", `{"success":false}`)

	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	result := connectWithPublicKey(t, sshServerConfig, "foo")

	assert.Error(t, result.dialError)
	assert.Empty(
		t,
		result.banners,
		"a message-less authorization denial must not acquire a banner",
	)
	assert.Equal(
		t,
		int32(0),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"an authorization denial must not initialize a backend session",
	)
}

// TestPubKeyDenialWithoutMessageHasNoBanner verifies that message-less denials
// behave exactly as before: authentication fails without a banner.
func TestPubKeyDenialWithoutMessageHasNoBanner(t *testing.T) {
	fixture := startAuthWebhookFixture(t)
	fixture.setResponse("pubkey", `{"success":false}`)

	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	result := connectWithPublicKey(t, sshServerConfig, "foo")

	assert.Error(t, result.dialError)
	assert.Empty(
		t,
		result.banners,
		"a message-less denial must not acquire a banner",
	)
	assert.Equal(
		t,
		int32(0),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"a denial must not initialize a backend session",
	)
}

// TestPubKeySuccessWithMessageAuthenticates verifies that a message on a
// successful webhook response does not become a denial banner and authentication
// still succeeds.
func TestPubKeySuccessWithMessageAuthenticates(t *testing.T) {
	fixture := startAuthWebhookFixture(t)
	fixture.setResponse("pubkey", `{"success":true,"message":"welcome"}`)
	fixture.setResponse("authz", `{"success":true}`)

	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	result := connectWithPublicKey(t, sshServerConfig, "foo")

	assert.NoError(
		t,
		result.dialError,
		"a message on a successful response must not deny authentication",
	)
	assert.Empty(
		t,
		result.banners,
		"a successful authentication must not produce a denial banner",
	)
	assert.Equal(
		t,
		int32(1),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"a successful authentication must initialize the backend",
	)
}

// TestWebhookOutageDoesNotProduceBanner verifies that a webhook outage keeps
// its fail-closed behavior and never surfaces an internal error as a banner.
func TestWebhookOutageDoesNotProduceBanner(t *testing.T) {
	fixture := startAuthWebhookFixture(t)
	fixture.setFailure("pubkey", http.StatusInternalServerError)

	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	result := connectWithPublicKey(t, sshServerConfig, "foo")

	assert.Error(
		t,
		result.dialError,
		"a webhook outage must fail closed",
	)
	assert.Empty(
		t,
		result.banners,
		"an infrastructure failure must never appear as a banner",
	)
	assert.Equal(
		t,
		int32(0),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"a webhook outage must not initialize a backend session",
	)
}

// generateOpenSSHTestKey generates a fresh ed25519 key for the OpenSSH client
// tests and returns its path. The test is skipped when no OpenSSH client
// tooling is available.
func generateOpenSSHTestKey(t *testing.T) string {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH client not available, skipping OpenSSH banner verification")
	}
	sshKeyGen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not available, skipping OpenSSH banner verification")
	}

	tempDir := t.TempDir()
	keyFile := tempDir + "/testkey"
	if out, err := exec.Command(sshKeyGen, "-q", "-t", "ed25519", "-N", "", "-f", keyFile).CombinedOutput(); err != nil {
		assert.FailNow(t, "failed to generate test key", string(out))
		return ""
	}
	return keyFile
}

// runOpenSSHClient connects with the actual OpenSSH client in noninteractive
// use and returns the captured stderr and the command error.
func runOpenSSHClient(
	t *testing.T,
	sshServerConfig config.SSHConfig,
	username string,
	keyFile string,
) (string, error) {
	listens := strings.Split(sshServerConfig.Listen, ":")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-i", keyFile,
		"-p", listens[len(listens)-1],
		username+"@127.0.0.1", "true",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	return stderr.String(), runErr
}

// TestOpenSSHClientSeesDenialBanner verifies, with the actual OpenSSH client in
// noninteractive use, that a message-bearing denial is printed as the banner and
// authentication still fails. The test is skipped when no OpenSSH client is
// available.
func TestOpenSSHClientSeesDenialBanner(t *testing.T) {
	keyFile := generateOpenSSHTestKey(t)

	denialMessage := "unknown pod template 'unknown' — use a configured template username"
	fixture := startAuthWebhookFixture(t)
	fixture.setResponse(
		"pubkey",
		fmt.Sprintf(`{"success":false,"message":%q}`, denialMessage),
	)
	fixture.setResponse("authz", `{"success":true}`)

	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	stderr, runErr := runOpenSSHClient(t, sshServerConfig, "unknown", keyFile)

	assert.Error(
		t,
		runErr,
		"the OpenSSH client must still fail authentication on a denial",
	)
	assert.Contains(
		t,
		stderr,
		denialMessage,
		"the OpenSSH client must print the denial message as the banner",
	)
	assert.Equal(
		t,
		int32(0),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"a denial must not initialize a backend session",
	)
}

// TestOpenSSHClientSeesAuthzDenialBanner verifies, with the actual OpenSSH
// client in noninteractive use, the motivating scenario for readable denials:
// the public-key authentication succeeds, the authorization check denies with
// an explicit message, and the OpenSSH client prints exactly that text as the
// banner while the connection fails. The test is skipped when no OpenSSH
// client is available.
func TestOpenSSHClientSeesAuthzDenialBanner(t *testing.T) {
	keyFile := generateOpenSSHTestKey(t)

	denialMessage := "unknown pod template 'unknown' — use a configured template username"
	fixture := startAuthWebhookFixture(t)
	fixture.setResponse("pubkey", `{"success":true}`)
	fixture.setResponse(
		"authz",
		fmt.Sprintf(`{"success":false,"message":%q}`, denialMessage),
	)

	start := time.Now()
	sshServerConfig, backend := startFixtureSSHServer(t, fixture)
	stderr, runErr := runOpenSSHClient(t, sshServerConfig, "unknown", keyFile)
	elapsed := time.Since(start)

	assert.Error(
		t,
		runErr,
		"the OpenSSH client must still fail the connection on an authorization denial",
	)
	assert.Contains(
		t,
		stderr,
		denialMessage,
		"the OpenSSH client must print the authorization denial message as the banner",
	)
	assert.Less(
		t,
		elapsed,
		15*time.Second,
		"a healthy permanent authorization denial must complete promptly and must not enter retry handling",
	)
	assert.Equal(
		t,
		int32(0),
		atomic.LoadInt32(&backend.handshakeSuccesses),
		"an authorization denial must not initialize a backend session",
	)
}
