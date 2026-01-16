package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smallbiznis/railzway-auth/internal/config"
	domain "github.com/smallbiznis/railzway-auth/internal/domain"
	domainoauth "github.com/smallbiznis/railzway-auth/internal/domain/oauth"
	"github.com/smallbiznis/railzway-auth/internal/jwt"
)

func TestOAuthService_StartAuthorization(t *testing.T) {
	h := newOAuthTestHarness()
	ctx := context.Background()
	out, err := h.service.StartAuthorization(ctx, 1, StartAuthorizationInput{
		Provider:    "google",
		RedirectURI: "https://app.smallbiznis.dev/oauth/callback",
	})
	require.NoError(t, err)
	require.NotEmpty(t, out.AuthorizationURL)
	require.NotEmpty(t, out.State)

	state, err := h.stateStore.GetState(ctx, buildStateKey(out.State))
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, "google", state.Provider)
}

func TestOAuthService_HandleCallback(t *testing.T) {
	h := newOAuthTestHarness()
	ctx := context.Background()
	state := domainoauth.OAuthState{
		State:        "state123",
		Provider:     "google",
		CodeVerifier: "code-verifier",
		RedirectURI:  "https://app.smallbiznis.dev/oauth/callback",
		OrgID:        1,
	}
	require.NoError(t, h.stateStore.SaveState(ctx, buildStateKey(state.State), state, time.Minute))
	h.providerClient.token = &domainoauth.OAuthTokenResponse{
		AccessToken: "external-access",
		TokenType:   "Bearer",
	}
	h.providerClient.userinfo = &domainoauth.OAuthUserInfo{
		Subject: "sub-123",
		Email:   "oauth@example.com",
		Name:    "OAuth User",
		Picture: "https://img",
	}

	session, err := h.service.HandleCallback(
		WithIssuer(ctx, "https://tenant.smallbiznis.dev"),
		1,
		OAuthCallbackInput{
			Provider:    "google",
			Code:        "auth-code",
			State:       state.State,
			RedirectURI: state.RedirectURI,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.Equal(t, "oauth@example.com", session.Email)
	require.NotEmpty(t, session.AccessToken)
	require.NotEmpty(t, session.RefreshToken)
}

func TestOAuthService_IntrospectToken(t *testing.T) {
	h := newOAuthTestHarness()
	ctx := context.Background()
	out, err := h.service.StartAuthorization(ctx, 1, StartAuthorizationInput{
		Provider:    "google",
		RedirectURI: "https://app/callback",
	})
	require.NoError(t, err)
	stateKey := buildStateKey(out.State)
	state, err := h.stateStore.GetState(ctx, stateKey)
	require.NoError(t, err)
	require.NotNil(t, state)
	h.providerClient.token = &domainoauth.OAuthTokenResponse{AccessToken: "ext", TokenType: "Bearer"}
	h.providerClient.userinfo = &domainoauth.OAuthUserInfo{Email: "introspect@example.com", Subject: "sub", Name: "Intro"}
	session, err := h.service.HandleCallback(
		WithIssuer(ctx, "https://tenant.smallbiznis.dev"),
		1,
		OAuthCallbackInput{
			Provider:    "google",
			Code:        "code",
			State:       state.State,
			RedirectURI: state.RedirectURI,
		},
	)
	require.NoError(t, err)

	introspect, err := h.service.IntrospectToken(ctx, session.AccessToken)
	require.NoError(t, err)
	require.True(t, introspect.Active)
	require.Equal(t, fmt.Sprintf("%d", session.UserID), introspect.Subject)
	require.Equal(t, int64(1), introspect.OrgID)
}

// ---- Test harness and fakes ----

type oauthTestHarness struct {
	service        OAuthService
	stateStore     *memoryStateStore
	providerClient *fakeProviderClient
	userRepo       *fakeUserRepo
}

func newOAuthTestHarness() *oauthTestHarness {
	providerRepo := &fakeProviderRepo{
		configs: map[int64][]domainoauth.OAuthProviderConfig{
			1: {{
				OrgID:        1,
				ProviderName: "google",
				DisplayName:  "Google",
				IconURL:      "",
				ClientID:     "client",
				ClientSecret: "secret",
				AuthURL:      "https://example.com/oauth/authorize",
				TokenURL:     "https://example.com/oauth/token",
				UserInfoURL:  "https://example.com/oauth/userinfo",
				Scopes:       []string{"openid", "email"},
			}},
		},
	}
	stateStore := newMemoryStateStore()
	providerClient := &fakeProviderClient{}
	orgRepo := &fakeOrgRepo{org: domain.Org{ID: 1, Name: "Tenant"}}
	userRepo := newFakeUserRepo()
	tokenRepo := newFakeTokenRepo()
	keyRepo := &memoryKeyRepo{}
	keyManager := jwt.NewKeyManager(keyRepo)
	generator := jwt.NewGenerator(keyManager, time.Minute)
	cfg := config.Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, RefreshTokenBytes: 32}
	svc := NewOAuthService(providerRepo, stateStore, providerClient, orgRepo, userRepo, tokenRepo, generator, cfg, zap.NewNop())
	return &oauthTestHarness{
		service:        svc,
		stateStore:     stateStore,
		providerClient: providerClient,
		userRepo:       userRepo,
	}
}

type fakeProviderRepo struct {
	configs map[int64][]domainoauth.OAuthProviderConfig
}

func (f *fakeProviderRepo) GetProvidersByOrg(ctx context.Context, orgID int64) ([]domainoauth.OAuthProviderConfig, error) {
	if cfgs, ok := f.configs[orgID]; ok {
		return cfgs, nil
	}
	return nil, domainoauth.ErrProviderNotFound
}

func (f *fakeProviderRepo) GetProviderByName(ctx context.Context, orgID int64, name string) (*domainoauth.OAuthProviderConfig, error) {
	if cfgs, ok := f.configs[orgID]; ok {
		for _, cfg := range cfgs {
			if strings.EqualFold(cfg.ProviderName, name) {
				copyCfg := cfg
				return &copyCfg, nil
			}
		}
	}
	return nil, domainoauth.ErrProviderNotFound
}

type memoryStateStore struct {
	mu   sync.RWMutex
	data map[string]domainoauth.OAuthState
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{data: map[string]domainoauth.OAuthState{}}
}

func (m *memoryStateStore) SaveState(_ context.Context, key string, data domainoauth.OAuthState, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = data
	return nil
}

func (m *memoryStateStore) GetState(_ context.Context, key string) (*domainoauth.OAuthState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if state, ok := m.data[key]; ok {
		copy := state
		return &copy, nil
	}
	return nil, nil
}

func (m *memoryStateStore) DeleteState(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

type fakeProviderClient struct {
	token    *domainoauth.OAuthTokenResponse
	userinfo *domainoauth.OAuthUserInfo
}

func (f *fakeProviderClient) ExchangeCode(context.Context, domainoauth.OAuthProviderConfig, string, string, string) (*domainoauth.OAuthTokenResponse, error) {
	if f.token == nil {
		return nil, fmt.Errorf("token not configured")
	}
	return f.token, nil
}

func (f *fakeProviderClient) FetchUserInfo(context.Context, domainoauth.OAuthProviderConfig, string) (*domainoauth.OAuthUserInfo, error) {
	if f.userinfo == nil {
		return nil, fmt.Errorf("userinfo not configured")
	}
	return f.userinfo, nil
}

type fakeOrgRepo struct {
	org domain.Org
}

func (f *fakeOrgRepo) GetDomainByHost(context.Context, string) (domain.Domain, error) {
	return domain.Domain{}, nil
}
func (f *fakeOrgRepo) GetOrg(ctx context.Context, orgID int64) (domain.Org, error) {
	return f.org, nil
}
func (f *fakeOrgRepo) GetOrgBySlug(context.Context, string) (domain.Org, error) {
	return f.org, nil
}
func (f *fakeOrgRepo) GetPrimaryDomain(context.Context, int64) (domain.Domain, error) {
	return domain.Domain{}, nil
}
func (f *fakeOrgRepo) GetBranding(context.Context, int64) (domain.Branding, error) {
	return domain.Branding{}, nil
}
func (f *fakeOrgRepo) ListAuthProviders(context.Context, int64) ([]domain.AuthProvider, error) {
	return nil, nil
}
func (f *fakeOrgRepo) GetPasswordConfig(context.Context, int64) (domain.PasswordConfig, error) {
	return domain.PasswordConfig{}, nil
}
func (f *fakeOrgRepo) GetOTPConfig(context.Context, int64) (domain.OTPConfig, error) {
	return domain.OTPConfig{}, nil
}
func (f *fakeOrgRepo) ListOAuthIDPConfigs(context.Context, int64) ([]domain.OAuthIDPConfig, error) {
	return nil, nil
}

type fakeUserRepo struct {
	mu    sync.Mutex
	users map[string]domain.User
	id    int64
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: map[string]domain.User{}, id: 1}
}

func (f *fakeUserRepo) GetByEmail(ctx context.Context, orgID int64, email string) (domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if user, ok := f.users[email]; ok {
		return user, nil
	}
	return domain.User{}, fmt.Errorf("get user: %w", pgx.ErrNoRows)
}

func (f *fakeUserRepo) GetByID(ctx context.Context, orgID, userID int64) (domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.ID == userID {
			return u, nil
		}
	}
	return domain.User{}, fmt.Errorf("get user: %w", pgx.ErrNoRows)
}

func (f *fakeUserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	user.ID = f.id
	f.id++
	f.users[user.Email] = user
	return user, nil
}

type fakeTokenRepo struct {
	mu     sync.Mutex
	nextID int64
	tokens []domain.OAuthToken
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{nextID: 1}
}

func (f *fakeTokenRepo) CreateToken(ctx context.Context, token domain.OAuthToken) (domain.OAuthToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	token.ID = f.nextID
	f.nextID++
	f.tokens = append(f.tokens, token)
	return token, nil
}

func (f *fakeTokenRepo) GetByRefreshToken(ctx context.Context, orgID int64, token string) (domain.OAuthToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.OrgID == orgID && t.RefreshToken == token {
			return t, nil
		}
	}
	return domain.OAuthToken{}, fmt.Errorf("get refresh token: %w", pgx.ErrNoRows)
}

func (f *fakeTokenRepo) GetByRefreshTokenValue(ctx context.Context, token string) (domain.OAuthToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.RefreshToken == token {
			return t, nil
		}
	}
	return domain.OAuthToken{}, fmt.Errorf("get refresh token: %w", pgx.ErrNoRows)
}

func (f *fakeTokenRepo) GetByAccessToken(ctx context.Context, token string) (domain.OAuthToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.AccessToken == token {
			return t, nil
		}
	}
	return domain.OAuthToken{}, fmt.Errorf("get access token: %w", pgx.ErrNoRows)
}

func (f *fakeTokenRepo) RotateRefreshToken(ctx context.Context, tokenID int64, refreshToken string, expiresAt int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for idx, t := range f.tokens {
		if t.ID == tokenID {
			f.tokens[idx].RefreshToken = refreshToken
			return nil
		}
	}
	return nil
}

func (f *fakeTokenRepo) RevokeToken(ctx context.Context, tokenID int64) error {
	return nil
}

type memoryKeyRepo struct {
	mu  sync.Mutex
	key domain.OAuthKey
}

func (m *memoryKeyRepo) GetActiveKey(ctx context.Context, orgID int64) (domain.OAuthKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key.ID == 0 {
		return domain.OAuthKey{}, pgx.ErrNoRows
	}
	return m.key, nil
}

func (m *memoryKeyRepo) CreateKey(ctx context.Context, key domain.OAuthKey) (domain.OAuthKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key.ID = 1
	m.key = key
	return key, nil
}
