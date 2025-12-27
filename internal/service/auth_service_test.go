package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/bwmarrin/snowflake"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smallbiznis/valora-auth/internal/config"
	"github.com/smallbiznis/valora-auth/internal/domain"
	"github.com/smallbiznis/valora-auth/internal/jwt"
	"github.com/smallbiznis/valora-auth/internal/org"
	"github.com/smallbiznis/valora-auth/internal/password"
	"github.com/smallbiznis/valora-auth/internal/service"
)

func TestPasswordGrantAndRefreshFlow(t *testing.T) {
	ctx := context.Background()
	user := domain.User{ID: 10, OrgID: 1, Email: "user@tenant", Name: "Test User"}
	hash, _ := password.Hash("password")
	user.PasswordHash = hash

	userRepo := &memoryUserRepo{user: user}
	tokenRepo := &memoryTokenRepo{}
	codeRepo := &memoryCodeRepo{}
	keyRepo := &memoryKeyRepo{}
	clientRepo := &memoryClientRepo{}

	cfg := config.Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, RefreshTokenBytes: 32}
	keyManager := jwt.NewKeyManager(keyRepo)
	generator := jwt.NewGenerator(keyManager, cfg.AccessTokenTTL)
	logger := zap.NewNop()
	node, _ := snowflake.NewNode(1)
	authService := service.NewAuthService(userRepo, tokenRepo, codeRepo, clientRepo, node, generator, keyManager, cfg, logger)

	orgCtx := &org.Context{
		Org: domain.Org{ID: 1, Name: "Tenant A", Code: "client"},
		// ClientID:       "client",
		PasswordConfig: domain.PasswordConfig{OrgID: 1, MinLength: 8, LockoutAttempts: 5, LockoutDurationSeconds: 300},
		AuthProviders:  []domain.AuthProvider{{ProviderType: "password", IsActive: true}},
		OTPConfig:      domain.OTPConfig{OrgID: 1, Channel: "sms", ExpirySeconds: 300},
	}

	tokenResp, err := authService.PasswordGrant(ctx, orgCtx, user.Email, "password", "openid", "https://tenant")
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)
	require.NotEmpty(t, tokenResp.RefreshToken)

	refreshResp, err := authService.RefreshGrant(ctx, orgCtx, tokenRepo.lastToken.RefreshToken, "", "https://tenant")
	require.NoError(t, err)
	require.NotEmpty(t, refreshResp.AccessToken)
	require.NotEqual(t, tokenResp.RefreshToken, refreshResp.RefreshToken)

	claims, custom, err := authService.ValidateToken(ctx, orgCtx.Org.ID, tokenResp.AccessToken, "https://tenant")
	require.NoError(t, err)
	require.Equal(t, "10", claims.Subject)
	require.Equal(t, user.Email, custom.Email)
}

type memoryUserRepo struct {
	user domain.User
}

type memoryTokenRepo struct {
	lastToken domain.OAuthToken
}

type memoryCodeRepo struct{}

type memoryKeyRepo struct {
	key domain.OAuthKey
}

type memoryClientRepo struct{}

func (m *memoryUserRepo) GetByEmail(ctx context.Context, orgID int64, email string) (domain.User, error) {
	return m.user, nil
}

func (m *memoryUserRepo) GetByID(ctx context.Context, orgID, userID int64) (domain.User, error) {
	return m.user, nil
}

func (m *memoryUserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	if user.ID == 0 {
		user.ID = m.user.ID
		if user.ID == 0 {
			user.ID = 1
		}
	}
	m.user = user
	return m.user, nil
}

func (m *memoryTokenRepo) CreateToken(ctx context.Context, token domain.OAuthToken) (domain.OAuthToken, error) {
	token.ID = 1
	m.lastToken = token
	return token, nil
}

func (m *memoryTokenRepo) GetByRefreshToken(ctx context.Context, orgID int64, token string) (domain.OAuthToken, error) {
	return m.lastToken, nil
}

func (m *memoryTokenRepo) GetByRefreshTokenValue(ctx context.Context, token string) (domain.OAuthToken, error) {
	return m.lastToken, nil
}

func (m *memoryTokenRepo) GetByAccessToken(ctx context.Context, token string) (domain.OAuthToken, error) {
	return m.lastToken, nil
}

func (m *memoryTokenRepo) RotateRefreshToken(ctx context.Context, tokenID int64, refreshToken string, expiresAt int64) error {
	m.lastToken.RefreshToken = refreshToken
	m.lastToken.ExpiresAt = time.Unix(expiresAt, 0)
	return nil
}

func (m *memoryTokenRepo) RevokeToken(ctx context.Context, tokenID int64) error { return nil }

func (m *memoryCodeRepo) CreateCode(ctx context.Context, code domain.OAuthCode) error { return nil }

func (m *memoryCodeRepo) GetCode(ctx context.Context, orgID int64, code string) (domain.OAuthCode, error) {
	return domain.OAuthCode{}, pgx.ErrNoRows
}

func (m *memoryCodeRepo) MarkCodeUsed(ctx context.Context, code string) error { return nil }

func (m *memoryKeyRepo) GetActiveKey(ctx context.Context, orgID int64) (domain.OAuthKey, error) {
	if m.key.ID == 0 {
		return domain.OAuthKey{}, pgx.ErrNoRows
	}
	return m.key, nil
}

func (m *memoryKeyRepo) CreateKey(ctx context.Context, key domain.OAuthKey) (domain.OAuthKey, error) {
	key.ID = 1
	m.key = key
	return key, nil
}

func (m *memoryClientRepo) GetClientByID(ctx context.Context, orgID int64, clientID string) (domain.OAuthClient, error) {
	return domain.OAuthClient{
		OrgID:        orgID,
		ClientID:     clientID,
		RedirectURIs: []string{"https://tenant/callback"},
	}, nil
}
