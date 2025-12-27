package oauth

import "errors"

var (
// ErrProviderNotFound signals missing provider configuration for org.
	ErrProviderNotFound = errors.New("oauth: provider not found")
	// ErrInvalidRequest indicates caller input validation errors.
	ErrInvalidRequest = errors.New("oauth: invalid request")
	// ErrInvalidState indicates the OAuth state/nonce pair is invalid or missing.
	ErrInvalidState = errors.New("oauth: invalid state")
	// ErrTokenInvalid indicates malformed or unverifiable tokens.
	ErrTokenInvalid = errors.New("oauth: token invalid")
	// ErrUserNotFound signals that the authenticated identity is not linked.
	ErrUserNotFound = errors.New("oauth: user not found")
)
