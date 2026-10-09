package auth

import (
    "go.containerssh.io/containerssh/metadata"
)

// PasswordAuthRequest is an authentication request for password authentication.
//
// swagger:model PasswordAuthRequest
type PasswordAuthRequest struct {
	metadata.ConnectionAuthPendingMetadata `json:",inline"`

	// Password the user provided for authentication.
	//
	// required: true
	// swagger:strfmt Base64
	Password string `json:"passwordBase64"`
}

// PublicKeyAuthRequest is an authentication request for public key authentication.
//
// swagger:model PublicKeyAuthRequest
type PublicKeyAuthRequest struct {
	metadata.ConnectionAuthPendingMetadata `json:",inline"`

	PublicKey `json:",inline"`
}

// AuthorizationRequest is the authorization request used after some
// authentication methods (e.g. kerberos) to determine whether users are
// allowed to access the service
//
// swagger:model AuthorizationRequest
type AuthorizationRequest struct {
	metadata.ConnectionAuthenticatedMetadata `json:",inline"`
}

// ResponseBody is a response to authentication requests.
//
// swagger:model AuthResponseBody
type ResponseBody struct {
	metadata.ConnectionAuthenticatedMetadata `json:",inline"`

	// Success indicates if the authentication was successful.
	//
	// required: true
	// in: body
	Success bool `json:"success"`

	// Message is an optional user-facing message describing a negative
	// decision (success = false). It is delivered to the connecting client
	// during authentication (e.g. as an SSH user authentication banner as
	// described in RFC 4252, section 5.4) and must therefore be safe to be
	// displayed to an unauthenticated user. A message on a successful response
	// is not a denial and is not delivered as a banner. Messages on
	// infrastructure failures (non-200 responses) are never delivered.
	Message string `json:"message,omitempty"`
}

// Response is the full HTTP authentication response.
//
// swagger:response AuthResponse
type Response struct {
	// The response body
	//
	// in: body
	ResponseBody
}
