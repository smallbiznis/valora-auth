package repository

import (
	"context"

	"github.com/smallbiznis/valora-auth/internal/domain"
)

// OrgRepository exposes org-level queries.
type OrgRepository interface {
	GetDomainByHost(ctx context.Context, host string) (domain.Domain, error)
	GetOrg(ctx context.Context, orgID int64) (domain.Org, error)
	GetOrgBySlug(ctx context.Context, slug string) (domain.Org, error)
	GetPrimaryDomain(ctx context.Context, orgID int64) (domain.Domain, error)
	GetBranding(ctx context.Context, orgID int64) (domain.Branding, error)
	ListAuthProviders(ctx context.Context, orgID int64) ([]domain.AuthProvider, error)
	GetPasswordConfig(ctx context.Context, orgID int64) (domain.PasswordConfig, error)
	GetOTPConfig(ctx context.Context, orgID int64) (domain.OTPConfig, error)
	ListOAuthIDPConfigs(ctx context.Context, orgID int64) ([]domain.OAuthIDPConfig, error)
}

// UserRepository exposes persistence for platform users.
type UserRepository interface {
	GetByEmail(ctx context.Context, orgID int64, email string) (domain.User, error)
	GetByID(ctx context.Context, orgID, userID int64) (domain.User, error)
	Create(ctx context.Context, user domain.User) (domain.User, error)
}

// TokenRepository handles refresh token persistence.
type TokenRepository interface {
	CreateToken(ctx context.Context, token domain.OAuthToken) (domain.OAuthToken, error)
	GetByRefreshToken(ctx context.Context, orgID int64, token string) (domain.OAuthToken, error)
	GetByRefreshTokenValue(ctx context.Context, token string) (domain.OAuthToken, error)
	GetByAccessToken(ctx context.Context, token string) (domain.OAuthToken, error)
	RotateRefreshToken(ctx context.Context, tokenID int64, refreshToken string, expiresAt int64) error
	RevokeToken(ctx context.Context, tokenID int64) error
}

// OAuthClientRepository exposes client metadata.
type OAuthClientRepository interface {
	GetClientByID(ctx context.Context, orgID int64, clientID string) (domain.OAuthClient, error)
}

// CodeRepository manages authorization codes.
type CodeRepository interface {
	CreateCode(ctx context.Context, code domain.OAuthCode) error
	GetCode(ctx context.Context, orgID int64, code string) (domain.OAuthCode, error)
	MarkCodeUsed(ctx context.Context, code string) error
}

// KeyRepository stores signing keys per org.
type KeyRepository interface {
	GetActiveKey(ctx context.Context, orgID int64) (domain.OAuthKey, error)
	CreateKey(ctx context.Context, key domain.OAuthKey) (domain.OAuthKey, error)
}
