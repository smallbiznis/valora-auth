package handler_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bwmarrin/snowflake"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smallbiznis/valora-auth/internal/config"
	"github.com/smallbiznis/valora-auth/internal/domain"
	httpHandler "github.com/smallbiznis/valora-auth/internal/http/handler"
	"github.com/smallbiznis/valora-auth/internal/jwt"
	"github.com/smallbiznis/valora-auth/internal/org"
	"github.com/smallbiznis/valora-auth/internal/repository"
	"github.com/smallbiznis/valora-auth/internal/service"
)

func TestJWKSHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orgCtx := testOrgCtx()
	authSvc := newTestAuthService()
	handler := httpHandler.NewAuthHandler(authSvc, nil, &service.DiscoveryService{})

	req := httptest.NewRequest(http.MethodGet, "https://tenant.smallbiznis/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("orgContext", orgCtx)
	c.Set("tenantContext", orgCtx)

	handler.JWKS(c)

	res := w.Result()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Logf("jwks response: %s", string(body))
	require.Contains(t, string(body), "keys")
}

func TestOpenIDConfigurationResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orgCtx := testOrgCtx()
	handler := httpHandler.NewAuthHandler(newTestAuthService(), nil, &service.DiscoveryService{})

	req := httptest.NewRequest(http.MethodGet, "https://tenant.smallbiznis/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("orgContext", orgCtx)
	c.Set("tenantContext", orgCtx)

	handler.OpenIDConfig(c)

	res := w.Result()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, string(body), "authorization_endpoint")
	require.Contains(t, string(body), "jwks_uri")
}

func testOrgCtx() *org.Context {
	return &org.Context{
		Domain: domain.Domain{Host: "tenant.smallbiznis"},
		Org:    domain.Org{ID: 1, Name: "SmallBiznis", Code: "client", Timezone: "Asia/Singapore"},
		// ClientID:       "client",
		Branding:       domain.Branding{OrgID: 1, LogoURL: strPtr("https://cdn/logo.png")},
		AuthProviders:  []domain.AuthProvider{{OrgID: 1, ProviderType: "password", IsActive: true}},
		PasswordConfig: domain.PasswordConfig{OrgID: 1, MinLength: 8, LockoutAttempts: 5, LockoutDurationSeconds: 300},
		OTPConfig:      domain.OTPConfig{OrgID: 1, Channel: "sms", ExpirySeconds: 300},
	}
}

func newTestAuthService() *service.AuthService {
	keyRepo := &inMemoryKeyRepo{}
	keyManager := jwt.NewKeyManager(keyRepo)
	generator := jwt.NewGenerator(keyManager, time.Minute)
	cfg := config.Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, RefreshTokenBytes: 32}
	logger := zap.NewNop()
	node, _ := snowflake.NewNode(1)
	return service.NewAuthService(&noopUserRepo{}, &noopTokenRepo{}, &noopCodeRepo{}, &noopClientRepo{}, node, generator, keyManager, cfg, logger)
}

type noopUserRepo struct{}

type noopTokenRepo struct{}

type noopCodeRepo struct{}

type inMemoryKeyRepo struct{ key domain.OAuthKey }

type noopClientRepo struct{}

var _ repository.UserRepository = (*noopUserRepo)(nil)
var _ repository.TokenRepository = (*noopTokenRepo)(nil)
var _ repository.CodeRepository = (*noopCodeRepo)(nil)
var _ repository.KeyRepository = (*inMemoryKeyRepo)(nil)
var _ repository.OAuthClientRepository = (*noopClientRepo)(nil)

func (n *noopUserRepo) GetByEmail(ctx context.Context, orgID int64, email string) (domain.User, error) {
	return domain.User{}, fmt.Errorf("not implemented")
}

func (n *noopUserRepo) GetByID(ctx context.Context, orgID, userID int64) (domain.User, error) {
	return domain.User{}, fmt.Errorf("not implemented")
}

func (n *noopUserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	return user, fmt.Errorf("not implemented")
}

func (n *noopTokenRepo) CreateToken(ctx context.Context, token domain.OAuthToken) (domain.OAuthToken, error) {
	return token, nil
}

func (n *noopTokenRepo) GetByRefreshToken(ctx context.Context, orgID int64, token string) (domain.OAuthToken, error) {
	return domain.OAuthToken{}, fmt.Errorf("not implemented")
}

func (n *noopTokenRepo) GetByRefreshTokenValue(ctx context.Context, token string) (domain.OAuthToken, error) {
	return domain.OAuthToken{}, fmt.Errorf("not implemented")
}

func (n *noopTokenRepo) GetByAccessToken(ctx context.Context, token string) (domain.OAuthToken, error) {
	return domain.OAuthToken{}, fmt.Errorf("not implemented")
}

func (n *noopTokenRepo) RotateRefreshToken(ctx context.Context, tokenID int64, refreshToken string, expiresAt int64) error {
	return nil
}

func (n *noopTokenRepo) RevokeToken(ctx context.Context, tokenID int64) error { return nil }

func (n *noopCodeRepo) CreateCode(ctx context.Context, code domain.OAuthCode) error { return nil }

func (n *noopCodeRepo) GetCode(ctx context.Context, orgID int64, code string) (domain.OAuthCode, error) {
	return domain.OAuthCode{}, fmt.Errorf("not implemented")
}

func (n *noopCodeRepo) MarkCodeUsed(ctx context.Context, code string) error { return nil }

func (i *inMemoryKeyRepo) GetActiveKey(ctx context.Context, orgID int64) (domain.OAuthKey, error) {
	if i.key.ID == 0 {
		return domain.OAuthKey{}, pgx.ErrNoRows
	}
	return i.key, nil
}

func (i *inMemoryKeyRepo) CreateKey(ctx context.Context, key domain.OAuthKey) (domain.OAuthKey, error) {
	key.ID = 1
	i.key = key
	return key, nil
}

func (n *noopClientRepo) GetClientByID(ctx context.Context, orgID int64, clientID string) (domain.OAuthClient, error) {
	return domain.OAuthClient{
		OrgID:        orgID,
		ClientID:     clientID,
		RedirectURIs: []string{"https://tenant/callback"},
	}, nil
}

func strPtr(s string) *string {
	return &s
}
