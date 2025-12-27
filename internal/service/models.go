package service

// AuthTokensWithUser bundles OAuth tokens with user profile metadata.
type AuthTokensWithUser struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token,omitempty"`
	IDToken      string        `json:"id_token,omitempty"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    int64         `json:"expires_in"`
	User         UserViewModel `json:"user"`
}

// UserViewModel represents lightweight user profile data returned to clients.
type UserViewModel struct {
	ID        int64  `json:"id"`
	OrgID     int64  `json:"org_id,omitempty"`
	TenantID  int64  `json:"tenant_id,omitempty"`
	Email     string `json:"email,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Name      string `json:"name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}
