package domain

import "time"

// OAuthToken persists refresh tokens.
type OAuthToken struct {
	ID           int64
	OrgID        int64
	ClientID     string
	UserID       int64
	AccessToken  string
	RefreshToken string
	Scopes       []string
	ExpiresAt    time.Time
	Revoked      bool
	CreatedAt    time.Time
}

// OAuthCode models short-lived authorization codes.
type OAuthCode struct {
	ID                  int64
	OrgID               int64
	ClientID            string
	UserID              int64
	Code                string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Revoked             bool
	CreatedAt           time.Time
}

// OAuthKey stores per-org signing keys.
type OAuthKey struct {
	ID        int64
	OrgID     int64
	KID       string
	Secret    []byte
	Algorithm string
	IsActive  bool
	CreatedAt time.Time
	RotatedAt *time.Time
}
