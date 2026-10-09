package auth

import "errors"

// UserFacingDenial is an error carrying a user-facing message that an
// authentication or authorization webhook supplied along with a negative
// decision (HTTP 200 with success = false and a non-empty message field).
//
// The message is supplied by the webhook and is safe to be displayed to the
// connecting user during authentication, e.g. as an SSH user authentication
// banner as described in RFC 4252, section 5.4. Errors that do not carry a
// UserFacingDenial (e.g. infrastructure or internal errors) must never be
// displayed to the user.
type UserFacingDenial struct {
	// Message is the user-facing denial message supplied by the webhook.
	Message string
}

// Error implements the error interface and returns the user-facing message.
func (e *UserFacingDenial) Error() string {
	return e.Message
}

// IsUserFacingDenial reports whether err carries a user-facing denial message
// supplied by an authentication or authorization webhook.
func IsUserFacingDenial(err error) bool {
	var denial *UserFacingDenial
	return errors.As(err, &denial)
}
