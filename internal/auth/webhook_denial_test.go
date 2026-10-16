package auth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	auth2 "go.containerssh.io/containerssh/auth"
	"go.containerssh.io/containerssh/config"
	"go.containerssh.io/containerssh/internal/auth"
	"go.containerssh.io/containerssh/internal/geoip/dummy"
	"go.containerssh.io/containerssh/internal/metrics"
	"go.containerssh.io/containerssh/internal/test"
	"go.containerssh.io/containerssh/log"
	"go.containerssh.io/containerssh/metadata"
)

// startAuthFixture starts a webhook HTTP server that answers every authentication
// and authorization request with the provided JSON response body.
func startAuthFixture(t *testing.T, responseBody string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, err := writer.Write([]byte(responseBody))
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	return server
}

// newFixtureWebhookClient creates a webhook client for the fixture server at url.
func newFixtureWebhookClient(t *testing.T, url string) auth.WebhookClient {
	t.Helper()
	client, err := auth.NewWebhookClient(
		auth.AuthenticationTypeAll,
		config.AuthWebhookClientConfig{
			HTTPClientConfiguration: config.HTTPClientConfiguration{
				URL:     url,
				Timeout: 2 * time.Second,
			},
			AuthTimeout: 30 * time.Second,
		},
		log.NewTestLogger(t),
		metrics.New(dummy.New()),
	)
	assert.NoError(t, err)
	return client
}

// TestPubKeyDenialWithMessageIsTerminalAndCarriesMessage verifies that an HTTP 200
// response with success=false and a user-facing message results in a terminal
// authentication failure carrying that message. The message must not cause
// retries and must complete promptly.
func TestPubKeyDenialWithMessageIsTerminalAndCarriesMessage(t *testing.T) {
	denialMessage := "unknown pod template 'unknown' — use a configured template username"
	server := startAuthFixture(
		t,
		fmt.Sprintf(`{"success":false,"message":%q}`, denialMessage),
	)
	client := newFixtureWebhookClient(t, server.URL)

	start := time.Now()
	authContext := client.PubKey(
		metadata.NewTestAuthenticatingMetadata("unknown"),
		auth2.PublicKey{PublicKey: "ssh-rsa asdf"},
	)
	elapsed := time.Since(start)

	assert.False(t, authContext.Success(), "a denial must not authenticate")
	assert.Less(
		t,
		elapsed,
		5*time.Second,
		"a policy denial must complete promptly and must not enter retry handling",
	)

	var denial *auth2.UserFacingDenial
	if assert.ErrorAs(
		t,
		authContext.Error(),
		&denial,
		"a message-bearing denial must carry the user-facing message",
	) {
		assert.Equal(t, denialMessage, denial.Message)
	}
}

// TestPubKeyDenialWithoutMessageKeepsExistingBehavior verifies that message-less
// denials behave exactly as before: a plain failure without an error.
func TestPubKeyDenialWithoutMessageKeepsExistingBehavior(t *testing.T) {
	server := startAuthFixture(t, `{"success":false}`)
	client := newFixtureWebhookClient(t, server.URL)

	authContext := client.PubKey(
		metadata.NewTestAuthenticatingMetadata("foo"),
		auth2.PublicKey{PublicKey: "ssh-rsa asdf"},
	)

	assert.False(t, authContext.Success())
	assert.NoError(
		t,
		authContext.Error(),
		"a message-less denial must not acquire an error",
	)
	assert.False(
		t,
		auth2.IsUserFacingDenial(authContext.Error()),
		"a message-less denial must not carry a user-facing message",
	)
}

// TestPubKeySuccessWithMessageSucceeds verifies that a message on a successful
// response does not become a denial.
func TestPubKeySuccessWithMessageSucceeds(t *testing.T) {
	server := startAuthFixture(t, `{"success":true,"message":"welcome"}`)
	client := newFixtureWebhookClient(t, server.URL)

	authContext := client.PubKey(
		metadata.NewTestAuthenticatingMetadata("foo"),
		auth2.PublicKey{PublicKey: "ssh-rsa asdf"},
	)

	assert.True(t, authContext.Success())
	assert.NoError(t, authContext.Error())
}

// TestAuthzDenialWithMessageIsTerminalAndCarriesMessage verifies that a message-bearing
// authorization denial is a terminal failure carrying the user-facing message.
func TestAuthzDenialWithMessageIsTerminalAndCarriesMessage(t *testing.T) {
	denialMessage := "pod limit (3) reached — delete a box"
	server := startAuthFixture(
		t,
		fmt.Sprintf(`{"success":false,"message":%q}`, denialMessage),
	)
	client := newFixtureWebhookClient(t, server.URL)

	start := time.Now()
	authzContext := client.Authorize(
		metadata.NewTestAuthenticatingMetadata("foo").Authenticated("foo"),
	)
	elapsed := time.Since(start)

	assert.False(t, authzContext.Success())
	assert.Less(
		t,
		elapsed,
		5*time.Second,
		"a policy denial must complete promptly and must not enter retry handling",
	)

	var denial *auth2.UserFacingDenial
	if assert.ErrorAs(
		t,
		authzContext.Error(),
		&denial,
		"a message-bearing denial must carry the user-facing message",
	) {
		assert.Equal(t, denialMessage, denial.Message)
	}
}

// TestAuthzDenialWithoutMessageKeepsExistingBehavior verifies that message-less
// authorization denials behave exactly as before: a plain failure without an
// error.
func TestAuthzDenialWithoutMessageKeepsExistingBehavior(t *testing.T) {
	server := startAuthFixture(t, `{"success":false}`)
	client := newFixtureWebhookClient(t, server.URL)

	authzContext := client.Authorize(
		metadata.NewTestAuthenticatingMetadata("foo").Authenticated("foo"),
	)

	assert.False(t, authzContext.Success())
	assert.NoError(
		t,
		authzContext.Error(),
		"a message-less denial must not acquire an error",
	)
	assert.False(
		t,
		auth2.IsUserFacingDenial(authzContext.Error()),
		"a message-less denial must not carry a user-facing message",
	)
}

// TestAuthzSuccessWithMessageSucceeds verifies that a message on a successful
// authorization response does not become a denial.
func TestAuthzSuccessWithMessageSucceeds(t *testing.T) {
	server := startAuthFixture(t, `{"success":true,"message":"welcome"}`)
	client := newFixtureWebhookClient(t, server.URL)

	authzContext := client.Authorize(
		metadata.NewTestAuthenticatingMetadata("foo").Authenticated("foo"),
	)

	assert.True(t, authzContext.Success())
	assert.NoError(t, authzContext.Error())
}

// TestWebhookNon200DoesNotBecomeUserFacingDenial verifies that infrastructure
// failures (non-200 responses) keep their fail-closed behavior and never turn
// into user-facing denial messages.
func TestWebhookNon200DoesNotBecomeUserFacingDenial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(500)
	}))
	t.Cleanup(server.Close)

	client, err := auth.NewWebhookClient(
		auth.AuthenticationTypeAll,
		config.AuthWebhookClientConfig{
			HTTPClientConfiguration: config.HTTPClientConfiguration{
				URL:     server.URL,
				Timeout: 2 * time.Second,
			},
			AuthTimeout: 1 * time.Second,
		},
		log.NewTestLogger(t),
		metrics.New(dummy.New()),
	)
	assert.NoError(t, err)

	authContext := client.PubKey(
		metadata.NewTestAuthenticatingMetadata("foo"),
		auth2.PublicKey{PublicKey: "ssh-rsa asdf"},
	)

	assert.False(t, authContext.Success())
	assert.Error(
		t,
		authContext.Error(),
		"a non-200 response must remain a fail-closed backend error",
	)
	assert.False(
		t,
		auth2.IsUserFacingDenial(authContext.Error()),
		"an infrastructure failure must not become a user-facing denial",
	)
}

// TestWebhookTransportErrorDoesNotBecomeUserFacingDenial verifies that a
// webhook outage (connection refused) keeps its fail-closed retry/timeout
// behavior and never turns into a user-facing denial message.
func TestWebhookTransportErrorDoesNotBecomeUserFacingDenial(t *testing.T) {
	// Point the client at a closed port so the connection is refused.
	closedPort := test.GetNextPort(t, "closed auth server")

	client, err := auth.NewWebhookClient(
		auth.AuthenticationTypeAll,
		config.AuthWebhookClientConfig{
			HTTPClientConfiguration: config.HTTPClientConfiguration{
				URL:     fmt.Sprintf("http://127.0.0.1:%d", closedPort),
				Timeout: 2 * time.Second,
			},
			AuthTimeout: 1 * time.Second,
		},
		log.NewTestLogger(t),
		metrics.New(dummy.New()),
	)
	assert.NoError(t, err)

	authContext := client.PubKey(
		metadata.NewTestAuthenticatingMetadata("foo"),
		auth2.PublicKey{PublicKey: "ssh-rsa asdf"},
	)

	assert.False(t, authContext.Success())
	assert.Error(
		t,
		authContext.Error(),
		"a webhook outage must remain a fail-closed backend error",
	)
	assert.False(
		t,
		auth2.IsUserFacingDenial(authContext.Error()),
		"a webhook outage must not become a user-facing denial",
	)
}
