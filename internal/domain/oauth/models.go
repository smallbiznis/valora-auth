package oauth

import "time"

// OAuthProvider represents an enabled OAuth/OIDC provider that orgs expose.
type OAuthProvider struct {
	Name        string
	DisplayName string
	IconURL     string
	AuthURL     string
	OrgID       int64
}

// OAuthProviderConfig stores the persisted configuration for an external IdP.
type OAuthProviderConfig struct {
	OrgID        int64
	ProviderName string
	DisplayName  string
	IconURL      string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	Extra        map[string]any
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// OAuthState captures the state/nonce/pkce tuple persisted during authorization.
type OAuthState struct {
	State        string
	Nonce        string
	CodeVerifier string
	Provider     string
	RedirectURI  string
	OrgID        int64
	CreatedAt    time.Time
}

// OAuthTokenResponse models the response from an external IdP token endpoint.
type OAuthTokenResponse struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
	IDToken      string
	Scope        string
	Raw          map[string]any
}

// OAuthUserInfo represents the normalized profile data returned by IdPs.
type OAuthUserInfo struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Name     string `json:"name,omitempty"`
	Picture  string `json:"picture,omitempty"`
	OrgID    int64  `json:"org_id,omitempty"`
	TenantID int64  `json:"tenant_id,omitempty"`
	Provider string `json:"provider,omitempty"`
}
