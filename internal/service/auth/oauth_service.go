package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	oauthadapter "github.com/smallbiznis/railzway-auth/internal/adapter/oauth"
	"github.com/smallbiznis/railzway-auth/internal/config"
	domain "github.com/smallbiznis/railzway-auth/internal/domain"
	domainoauth "github.com/smallbiznis/railzway-auth/internal/domain/oauth"
	"github.com/smallbiznis/railzway-auth/internal/jwt"
	"github.com/smallbiznis/railzway-auth/internal/repository"
)

// OAuthService defines OAuth/OIDC orchestration behaviors.
type OAuthService interface {
	ListProviders(ctx context.Context, orgID int64) ([]domainoauth.OAuthProvider, error)
	StartAuthorization(ctx context.Context, orgID int64, in StartAuthorizationInput) (*StartAuthorizationOutput, error)
	HandleCallback(ctx context.Context, orgID int64, in OAuthCallbackInput) (*OAuthSession, error)
	IntrospectToken(ctx context.Context, token string) (*TokenIntrospection, error)
	RevokeToken(ctx context.Context, token string) error
	UserInfo(ctx context.Context, token string) (*domainoauth.OAuthUserInfo, error)
}

// StartAuthorizationInput contains parameters for constructing authorization URLs.
type StartAuthorizationInput struct {
	Provider    string
	RedirectURI string
	Scopes      []string
}

// StartAuthorizationOutput returns the prepared authorization URL and PKCE metadata.
type StartAuthorizationOutput struct {
	AuthorizationURL string
	State            string
	Nonce            string
}

// OAuthCallbackInput captures callback query parameters.
type OAuthCallbackInput struct {
	Provider    string
	Code        string
	State       string
	RedirectURI string
}

// OAuthSession represents the authenticated SmallBiznis session.
type OAuthSession struct {
	UserID       int64
	Email        string
	Name         string
	Picture      string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	TokenType    string
}

// TokenIntrospection expresses RFC 7662 compliant response.
type TokenIntrospection struct {
	Active    bool
	Subject   string
	Scope     string
	ExpiresAt int64
	IssuedAt  int64
	ClientID  string
	OrgID     int64
}

type oauthService struct {
	providerRepo   repository.OAuthProviderConfigRepo
	stateStore     repository.OAuthStateStore
	providerClient oauthadapter.ProviderClient
	orgRepo        repository.OrgRepository
	userRepo       repository.UserRepository
	tokenRepo      repository.TokenRepository
	jwt            *jwt.Generator
	cfg            config.Config
	logger         *zap.Logger
}

// NewOAuthService wires the OAuth service implementation.
func NewOAuthService(
	providerRepo repository.OAuthProviderConfigRepo,
	stateStore repository.OAuthStateStore,
	providerClient oauthadapter.ProviderClient,
	orgRepo repository.OrgRepository,
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	jwtGenerator *jwt.Generator,
	cfg config.Config,
	logger *zap.Logger,
) OAuthService {
	return &oauthService{
		providerRepo:   providerRepo,
		stateStore:     stateStore,
		providerClient: providerClient,
		orgRepo:        orgRepo,
		userRepo:       userRepo,
		tokenRepo:      tokenRepo,
		jwt:            jwtGenerator,
		cfg:            cfg,
		logger:         logger,
	}
}

const (
	statePrefix = "oauth:state:"
	stateTTL    = 5 * time.Minute
)

type ctxKey string

const issuerContextKey ctxKey = "oauth:issuer"

// WithIssuer stores the issuer URL inside context for downstream calls.
func WithIssuer(ctx context.Context, issuer string) context.Context {
	trimmed := strings.TrimSpace(issuer)
	if trimmed == "" {
		return ctx
	}
	return context.WithValue(ctx, issuerContextKey, trimmed)
}

func issuerFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(issuerContextKey).(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}

func (s *oauthService) ListProviders(ctx context.Context, orgID int64) ([]domainoauth.OAuthProvider, error) {
	configs, err := s.providerRepo.GetProvidersByOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list providers: %w", err)
	}
	if len(configs) == 0 {
		return nil, domainoauth.ErrProviderNotFound
	}
	providers := make([]domainoauth.OAuthProvider, 0, len(configs))
	for _, cfg := range configs {
		providers = append(providers, domainoauth.OAuthProvider{
			Name:        cfg.ProviderName,
			DisplayName: cfg.DisplayName,
			IconURL:     cfg.IconURL,
			AuthURL:     cfg.AuthURL,
			OrgID:       cfg.OrgID,
		})
	}
	return providers, nil
}

func (s *oauthService) StartAuthorization(ctx context.Context, orgID int64, in StartAuthorizationInput) (*StartAuthorizationOutput, error) {
	provider := strings.TrimSpace(in.Provider)
	redirect := strings.TrimSpace(in.RedirectURI)
	if provider == "" || redirect == "" {
		return nil, domainoauth.ErrInvalidRequest
	}

	cfg, err := s.providerRepo.GetProviderByName(ctx, orgID, provider)
	if err != nil {
		if errors.Is(err, domainoauth.ErrProviderNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("load provider: %w", err)
	}

	state, err := secureRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}
	nonce, err := secureRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	codeVerifier, err := secureRandomString(64)
	if err != nil {
		return nil, fmt.Errorf("generate pkce verifier: %w", err)
	}
	codeChallenge := pkceChallenge(codeVerifier)

	authURL, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return nil, fmt.Errorf("parse auth url: %w", err)
	}

	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = cfg.Scopes
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	params := authURL.Query()
	params.Set("client_id", cfg.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirect)
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	for k, v := range cfg.Extra {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		if str := fmt.Sprint(v); strings.TrimSpace(str) != "" {
			params.Set(key, str)
		}
	}
	authURL.RawQuery = params.Encode()

	stateKey := buildStateKey(state)
	payload := domainoauth.OAuthState{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		Provider:     cfg.ProviderName,
		RedirectURI:  redirect,
		OrgID:        orgID,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.stateStore.SaveState(ctx, stateKey, payload, stateTTL); err != nil {
		return nil, fmt.Errorf("persist state: %w", err)
	}

	return &StartAuthorizationOutput{
		AuthorizationURL: authURL.String(),
		State:            state,
		Nonce:            nonce,
	}, nil
}

func (s *oauthService) HandleCallback(ctx context.Context, orgID int64, in OAuthCallbackInput) (*OAuthSession, error) {
	if err := validateCallbackInput(in); err != nil {
		return nil, err
	}

	state, cleanup, err := s.loadCallbackState(ctx, orgID, in)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, err
	}

	cfg, err := s.loadProviderConfig(ctx, orgID, state.Provider)
	if err != nil {
		return nil, err
	}

	expectedRedirect := strings.TrimSpace(state.RedirectURI)
	tokenResp, err := s.exchangeCodeForToken(ctx, cfg, in.Code, state.CodeVerifier, expectedRedirect)
	if err != nil {
		return nil, err
	}

	userInfo, err := s.fetchProviderUserInfo(ctx, cfg, tokenResp.AccessToken)
	if err != nil {
		return nil, err
	}

	user, err := s.ensureUser(ctx, orgID, userInfo)
	if err != nil {
		return nil, err
	}

	session, err := s.buildOAuthSession(ctx, orgID, cfg, user)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func validateCallbackInput(in OAuthCallbackInput) error {
	if strings.TrimSpace(in.State) == "" || strings.TrimSpace(in.Code) == "" {
		return domainoauth.ErrInvalidRequest
	}
	return nil
}

func (s *oauthService) loadCallbackState(ctx context.Context, orgID int64, in OAuthCallbackInput) (*domainoauth.OAuthState, func(), error) {
	stateKey := buildStateKey(in.State)
	state, err := s.stateStore.GetState(ctx, stateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("load state: %w", err)
	}
	if state == nil {
		return nil, nil, domainoauth.ErrInvalidState
	}
	cleanup := func() {
		s.deleteOAuthState(ctx, stateKey)
	}
	if err := validateCallbackState(state, orgID, in); err != nil {
		return nil, cleanup, err
	}
	return state, cleanup, nil
}

func validateCallbackState(state *domainoauth.OAuthState, orgID int64, in OAuthCallbackInput) error {
	if state.OrgID != orgID || !strings.EqualFold(state.Provider, in.Provider) {
		return domainoauth.ErrInvalidState
	}
	expectedRedirect := strings.TrimSpace(state.RedirectURI)
	actualRedirect := strings.TrimSpace(in.RedirectURI)
	if expectedRedirect != "" && actualRedirect != "" && expectedRedirect != actualRedirect {
		return domainoauth.ErrInvalidState
	}
	return nil
}

func (s *oauthService) deleteOAuthState(ctx context.Context, stateKey string) {
	if err := s.stateStore.DeleteState(ctx, stateKey); err != nil {
		s.log().Warn("failed to delete oauth state", zap.Error(err))
	}
}

func (s *oauthService) loadProviderConfig(ctx context.Context, orgID int64, provider string) (*domainoauth.OAuthProviderConfig, error) {
	cfg, err := s.providerRepo.GetProviderByName(ctx, orgID, provider)
	if err != nil {
		if errors.Is(err, domainoauth.ErrProviderNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("load provider: %w", err)
	}
	return cfg, nil
}

func (s *oauthService) exchangeCodeForToken(ctx context.Context, cfg *domainoauth.OAuthProviderConfig, code, verifier, redirectURI string) (*domainoauth.OAuthTokenResponse, error) {
	tokenResp, err := s.providerClient.ExchangeCode(ctx, *cfg, code, verifier, redirectURI)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	if strings.TrimSpace(tokenResp.AccessToken) == "" {
		return nil, domainoauth.ErrTokenInvalid
	}
	return tokenResp, nil
}

func (s *oauthService) fetchProviderUserInfo(ctx context.Context, cfg *domainoauth.OAuthProviderConfig, accessToken string) (*domainoauth.OAuthUserInfo, error) {
	userInfo, err := s.providerClient.FetchUserInfo(ctx, *cfg, accessToken)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	if strings.TrimSpace(userInfo.Email) == "" {
		return nil, domainoauth.ErrTokenInvalid
	}
	return userInfo, nil
}

func (s *oauthService) buildOAuthSession(ctx context.Context, orgID int64, cfg *domainoauth.OAuthProviderConfig, user domain.User) (*OAuthSession, error) {
	orgRow, err := s.orgRepo.GetOrg(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("org lookup: %w", err)
	}

	issuer, ok := issuerFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("missing issuer context")
	}

	scope := append([]string{}, cfg.Scopes...)
	if len(scope) == 0 {
		scope = []string{"openid", "profile", "email"}
	}
	scopeString := strings.Join(scope, " ")

	accessToken, err := s.jwt.GenerateAccessToken(ctx, orgRow, user, scopeString, issuer, []string{cfg.ProviderName})
	if err != nil {
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err := secureRandomString(s.cfg.RefreshTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	if _, err := s.tokenRepo.CreateToken(ctx, domain.OAuthToken{
		OrgID:        orgID,
		ClientID:     cfg.ProviderName,
		UserID:       user.ID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Scopes:       scope,
		ExpiresAt:    time.Now().Add(s.cfg.RefreshTokenTTL),
		CreatedAt:    time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	return &OAuthSession{
		UserID:       user.ID,
		Email:        user.Email,
		Name:         user.Name,
		Picture:      user.AvatarURL,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.cfg.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

func (s *oauthService) IntrospectToken(ctx context.Context, token string) (*TokenIntrospection, error) {
	if strings.TrimSpace(token) == "" {
		return nil, domainoauth.ErrInvalidRequest
	}
	claimsJSON, err := decodeJWTSection(token, 1)
	if err != nil {
		return &TokenIntrospection{Active: false}, nil
	}
	var payload struct {
		Issuer   string `json:"iss"`
		OrgID    int64  `json:"org_id"`
		TenantID int64  `json:"tenant_id"`
	}
	if err := json.Unmarshal(claimsJSON, &payload); err != nil {
		return &TokenIntrospection{Active: false}, nil
	}
	orgID := payload.OrgID
	if orgID == 0 {
		orgID = payload.TenantID
	}
	std, custom, err := s.jwt.ValidateAccessToken(ctx, orgID, token, payload.Issuer)
	if err != nil {
		return &TokenIntrospection{Active: false}, nil
	}
	ti := &TokenIntrospection{
		Active:   true,
		Subject:  std.Subject,
		Scope:    custom.Scope,
		OrgID:    custom.OrgID,
		ClientID: firstAudience(std.Audience),
	}
	if std.Expiry != nil {
		ti.ExpiresAt = std.Expiry.Time().Unix()
	}
	if std.IssuedAt != nil {
		ti.IssuedAt = std.IssuedAt.Time().Unix()
	}
	return ti, nil
}

func (s *oauthService) RevokeToken(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return domainoauth.ErrInvalidRequest
	}

	if stored, err := s.tokenRepo.GetByRefreshTokenValue(ctx, token); err == nil {
		return s.tokenRepo.RevokeToken(ctx, stored.ID)
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lookup refresh token: %w", err)
	}

	if stored, err := s.tokenRepo.GetByAccessToken(ctx, token); err == nil {
		return s.tokenRepo.RevokeToken(ctx, stored.ID)
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lookup access token: %w", err)
	}

	return domainoauth.ErrTokenInvalid
}

func (s *oauthService) UserInfo(ctx context.Context, token string) (*domainoauth.OAuthUserInfo, error) {
	if strings.TrimSpace(token) == "" {
		return nil, domainoauth.ErrInvalidRequest
	}
	claimsJSON, err := decodeJWTSection(token, 1)
	if err != nil {
		return nil, domainoauth.ErrTokenInvalid
	}
	var payload struct {
		Issuer   string `json:"iss"`
		OrgID    int64  `json:"org_id"`
		TenantID int64  `json:"tenant_id"`
	}
	if err := json.Unmarshal(claimsJSON, &payload); err != nil {
		return nil, domainoauth.ErrTokenInvalid
	}
	orgID := payload.OrgID
	if orgID == 0 {
		orgID = payload.TenantID
	}
	std, custom, err := s.jwt.ValidateAccessToken(ctx, orgID, token, payload.Issuer)
	if err != nil {
		return nil, domainoauth.ErrTokenInvalid
	}
	provider := ""
	if len(custom.Providers) == 1 {
		provider = custom.Providers[0]
	}
	return &domainoauth.OAuthUserInfo{
		Subject:  std.Subject,
		Email:    custom.Email,
		Name:     custom.Name,
		Picture:  custom.Picture,
		OrgID:    custom.OrgID,
		TenantID: custom.OrgID,
		Provider: provider,
	}, nil
}

func (s *oauthService) ensureUser(ctx context.Context, orgID int64, info *domainoauth.OAuthUserInfo) (domain.User, error) {
	email := strings.ToLower(strings.TrimSpace(info.Email))
	user, err := s.userRepo.GetByEmail(ctx, orgID, email)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, fmt.Errorf("get user: %w", err)
	}

	name := strings.TrimSpace(info.Name)
	if name == "" {
		name = email
	}
	newUser := domain.User{
		OrgID:         orgID,
		Email:         email,
		EmailVerified: true,
		Name:          name,
		AvatarURL:     info.Picture,
		Status:        "ACTIVE",
	}
	created, err := s.userRepo.Create(ctx, newUser)
	if err != nil {
		return domain.User{}, fmt.Errorf("create user: %w", err)
	}
	return created, nil
}

func (s *oauthService) log() *zap.Logger {
	if s != nil && s.logger != nil {
		return s.logger
	}
	return zap.L()
}

func buildStateKey(state string) string {
	return statePrefix + strings.TrimSpace(state)
}

func secureRandomString(size int) (string, error) {
	if size <= 0 {
		size = 32
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func decodeJWTSection(token string, index int) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) <= index {
		return nil, fmt.Errorf("jwt parts")
	}
	return base64.RawURLEncoding.DecodeString(parts[index])
}

func firstAudience(aud []string) string {
	if len(aud) > 0 {
		return aud[0]
	}
	return ""
}
