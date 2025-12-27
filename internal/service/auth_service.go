package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/bwmarrin/snowflake"
	gojose "github.com/go-jose/go-jose/v4"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/smallbiznis/valora-auth/internal/config"
	"github.com/smallbiznis/valora-auth/internal/domain"
	"github.com/smallbiznis/valora-auth/internal/jwt"
	"github.com/smallbiznis/valora-auth/internal/org"
	pw "github.com/smallbiznis/valora-auth/internal/password"
	"github.com/smallbiznis/valora-auth/internal/repository"
)

// TokenResponse matches Auth0 OAuth token responses.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// OAuthError standardizes OAuth compliant errors.
type OAuthError struct {
	Code        string
	Description string
	Status      int
}

func (e *OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func newOAuthError(code, desc string, status int) *OAuthError {
	return &OAuthError{Code: code, Description: desc, Status: status}
}

const authorizationCodeTTL = 5 * time.Minute

// AuthService encapsulates authentication flows.
type AuthService struct {
	users     repository.UserRepository
	tokens    repository.TokenRepository
	codes     repository.CodeRepository
	clients   repository.OAuthClientRepository
	snowflake *snowflake.Node
	jwt       *jwt.Generator
	keys      *jwt.KeyManager
	cfg       config.Config
	logger    *zap.Logger
	tracer    trace.Tracer
}

// NewAuthService wires dependencies.
func NewAuthService(users repository.UserRepository, tokens repository.TokenRepository, codes repository.CodeRepository, clients repository.OAuthClientRepository, snowflake *snowflake.Node, generator *jwt.Generator, keys *jwt.KeyManager, cfg config.Config, logger *zap.Logger) *AuthService {
	return &AuthService{
		users:     users,
		tokens:    tokens,
		codes:     codes,
		clients:   clients,
		snowflake: snowflake,
		jwt:       generator,
		keys:      keys,
		cfg:       cfg,
		logger:    logger,
		tracer:    otel.Tracer("github.com/smallbiznis/valora-auth/internal/service"),
	}
}

// PasswordGrant authenticates the user with email/password.
func (s *AuthService) PasswordGrant(ctx context.Context, orgCtx *org.Context, email, password, scope, issuer string) (*TokenResponse, error) {
	ctx, span := s.startSpan(ctx, "AuthService.PasswordGrant")
	defer span.End()

	normalized := strings.ToLower(strings.TrimSpace(email))
	user, err := s.users.GetByEmail(ctx, orgCtx.Org.ID, normalized)
	if err != nil {
		span.RecordError(err)
		return nil, newOAuthError("invalid_grant", "Wrong email or password.", 400)
	}

	valid, err := pw.Verify(password, user.PasswordHash)
	if err != nil || !valid {
		span.RecordError(fmt.Errorf("invalid password"))
		return nil, newOAuthError("invalid_grant", "Wrong email or password.", 400)
	}

	providers := make([]string, 0, len(orgCtx.AuthProviders))
	for _, provider := range orgCtx.AuthProviders {
		if provider.IsActive {
			providers = append(providers, provider.ProviderType)
		}
	}

	resp, err := s.issueTokens(ctx, orgCtx, user, scope, issuer, providers)
	if err == nil {
		s.audit("password.login.success", "org_id", orgCtx.Org.ID, "user_id", user.ID)
	} else {
		span.RecordError(err)
	}
	return resp, err
}

// OTPGrant validates a time-based OTP using org configuration.
func (s *AuthService) OTPGrant(ctx context.Context, orgCtx *org.Context, email, code, scope, issuer string) (*TokenResponse, error) {
	ctx, span := s.startSpan(ctx, "AuthService.OTPGrant")
	defer span.End()

	if !otpEnabled(orgCtx.OTPConfig) {
		return nil, newOAuthError("unsupported_grant_type", "OTP login disabled for org.", 400)
	}
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return nil, newOAuthError("invalid_grant", "OTP code required.", 400)
	}
	if len(trimmed) != otpCodeLength(orgCtx.OTPConfig) {
		return nil, newOAuthError("invalid_grant", "Invalid OTP code.", 400)
	}
	user, err := s.users.GetByEmail(ctx, orgCtx.Org.ID, strings.ToLower(email))
	if err != nil {
		span.RecordError(err)
		return nil, newOAuthError("invalid_grant", "Wrong email or OTP.", 400)
	}
	expected := generateOTP(user.PasswordHash, otpCodeLength(orgCtx.OTPConfig), otpTTL(orgCtx.OTPConfig))
	if subtle.ConstantTimeCompare([]byte(trimmed), []byte(expected)) != 1 {
		return nil, newOAuthError("invalid_grant", "Wrong email or OTP.", 400)
	}

	providers := []string{"otp"}
	resp, err := s.issueTokens(ctx, orgCtx, user, scope, issuer, providers)
	if err == nil {
		s.audit("otp.login.success", "org_id", orgCtx.Org.ID, "user_id", user.ID)
	} else {
		span.RecordError(err)
	}
	return resp, err
}

// RefreshGrant rotates the refresh token and issues a new access token.
func (s *AuthService) RefreshGrant(ctx context.Context, orgCtx *org.Context, refreshToken, scope, issuer string) (*TokenResponse, error) {
	ctx, span := s.startSpan(ctx, "AuthService.RefreshGrant")
	defer span.End()

	if refreshToken == "" {
		return nil, newOAuthError("invalid_grant", "Refresh token missing.", 400)
	}

	token, err := s.tokens.GetByRefreshToken(ctx, orgCtx.Org.ID, refreshToken)
	if err != nil || token.Revoked || time.Now().After(token.ExpiresAt) {
		if err != nil {
			span.RecordError(err)
		}
		return nil, newOAuthError("invalid_grant", "Invalid refresh token.", 400)
	}

	user, err := s.users.GetByID(ctx, orgCtx.Org.ID, token.UserID)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("refresh load user: %w", err)
	}

	refresh, err := s.rotateRefreshToken(ctx, token)
	if err != nil {
		return nil, err
	}

	providers := make([]string, 0, len(orgCtx.AuthProviders))
	for _, provider := range orgCtx.AuthProviders {
		if provider.IsActive {
			providers = append(providers, provider.ProviderType)
		}
	}
	storedScope := strings.Join(token.Scopes, " ")
	effectiveScope := normalizeScope(coalesce(scope, storedScope))
	access, err := s.jwt.GenerateAccessToken(ctx, orgCtx.Org, user, effectiveScope, issuer, providers)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("refresh token generate: %w", err)
	}

	resp := &TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
	}
	s.audit("refresh_token.success", "org_id", orgCtx.Org.ID, "user_id", user.ID)
	return resp, nil
}

// AuthorizationCodeGrant redeems an authorization code.
func (s *AuthService) AuthorizationCodeGrant(ctx context.Context, orgCtx *org.Context, code, redirectURI, scope, issuer string) (*TokenResponse, error) {
	if code == "" {
		return nil, newOAuthError("invalid_grant", "Authorization code missing.", 400)
	}
	if s.codes == nil {
		return nil, newOAuthError("unsupported_grant_type", "Authorization code flow disabled.", 400)
	}
	stored, err := s.codes.GetCode(ctx, orgCtx.Org.ID, code)
	if err != nil || stored.Revoked || time.Now().After(stored.ExpiresAt) {
		return nil, newOAuthError("invalid_grant", "Invalid authorization code.", 400)
	}
	if redirectURI != "" && stored.RedirectURI != redirectURI {
		return nil, newOAuthError("invalid_grant", "Mismatched redirect_uri.", 400)
	}
	user, err := s.users.GetByID(ctx, orgCtx.Org.ID, stored.UserID)
	if err != nil {
		return nil, fmt.Errorf("authorization code load user: %w", err)
	}
	if err := s.codes.MarkCodeUsed(ctx, stored.Code); err != nil {
		return nil, fmt.Errorf("authorization code mark used: %w", err)
	}

	providers := make([]string, 0, len(orgCtx.AuthProviders))
	for _, provider := range orgCtx.AuthProviders {
		if provider.IsActive {
			providers = append(providers, provider.ProviderType)
		}
	}
	return s.issueTokens(ctx, orgCtx, user, coalesce(scope, defaultRESTScope), issuer, providers)
}

// CreateAuthorizationCode persists an authorization code for later redemption.
func (s *AuthService) CreateAuthorizationCode(ctx context.Context, orgCtx *org.Context, userID int64, clientID, redirectURI, codeChallenge, codeChallengeMethod string) (string, error) {
	ctx, span := s.startSpan(ctx, "AuthService.CreateAuthorizationCode")
	defer span.End()

	if orgCtx == nil {
		return "", newOAuthError("invalid_request", "Org context missing.", http.StatusBadRequest)
	}
	if s.codes == nil {
		return "", newOAuthError("unsupported_response_type", "Authorization code flow disabled.", http.StatusBadRequest)
	}

	redirect := strings.TrimSpace(redirectURI)
	if redirect == "" {
		return "", newOAuthError("invalid_request", "redirect_uri is required.", http.StatusBadRequest)
	}

	client := strings.TrimSpace(clientID)
	if client == "" {
		return "", newOAuthError("invalid_request", "client_id is required.", http.StatusBadRequest)
	}

	user, err := s.users.GetByID(ctx, orgCtx.Org.ID, userID)
	if err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("authorize load user: %w", err)
	}

	codeValue := randomString(32)
	record := domain.OAuthCode{
		ID:                  randomID(),
		OrgID:               orgCtx.Org.ID,
		ClientID:            client,
		UserID:              user.ID,
		Code:                codeValue,
		RedirectURI:         redirect,
		CodeChallenge:       strings.TrimSpace(codeChallenge),
		CodeChallengeMethod: strings.TrimSpace(codeChallengeMethod),
		ExpiresAt:           time.Now().Add(authorizationCodeTTL),
		CreatedAt:           time.Now(),
	}

	if err := s.codes.CreateCode(ctx, record); err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("persist authorization code: %w", err)
	}

	s.audit("authorization_code.issued", "org_id", orgCtx.Org.ID, "user_id", user.ID, "client_id", client)
	return codeValue, nil
}

// DeviceCodeGrant is optional and currently unsupported.
func (s *AuthService) DeviceCodeGrant(ctx context.Context) (*TokenResponse, error) {
	return nil, newOAuthError("unsupported_grant_type", "device_code is not enabled.", 400)
}

// ClientCredentialsGrant is optional and returns unsupported for now.
func (s *AuthService) ClientCredentialsGrant(ctx context.Context) (*TokenResponse, error) {
	return nil, newOAuthError("unsupported_grant_type", "client_credentials is not enabled.", 400)
}

func coalesce(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func normalizeScope(scope string) string {
	trimmed := strings.TrimSpace(scope)
	if trimmed == "" {
		return "openid profile email"
	}
	return trimmed
}

func (s *AuthService) rotateRefreshToken(ctx context.Context, token domain.OAuthToken) (string, error) {
	next := randomString(s.cfg.RefreshTokenBytes)
	expires := time.Now().Add(s.cfg.RefreshTokenTTL)
	if err := s.tokens.RotateRefreshToken(ctx, token.ID, next, expires.Unix()); err != nil {
		return "", fmt.Errorf("rotate refresh token: %w", err)
	}
	return next, nil
}

func (s *AuthService) issueTokens(ctx context.Context, orgCtx *org.Context, user domain.User, scope, issuer string, providers []string) (*TokenResponse, error) {
	ctx, span := s.startSpan(ctx, "AuthService.issueTokens")
	defer span.End()

	effectiveScope := normalizeScope(scope)
	access, err := s.jwt.GenerateAccessToken(ctx, orgCtx.Org, user, effectiveScope, issuer, providers)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("generate access token: %w", err)
	}

	refreshToken := randomString(s.cfg.RefreshTokenBytes)
	oauthToken := domain.OAuthToken{
		ID:           s.snowflake.Generate().Int64(),
		OrgID:        orgCtx.Org.ID,
		ClientID:     orgCtx.ClientID,
		UserID:       user.ID,
		AccessToken:  access,
		RefreshToken: refreshToken,
		Scopes:       strings.Fields(effectiveScope),
		ExpiresAt:    time.Now().Add(s.cfg.RefreshTokenTTL),
		CreatedAt:    time.Now(),
	}

	if _, err := s.tokens.CreateToken(ctx, oauthToken); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  access,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
	}, nil
}

func (s *AuthService) startSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if s == nil || s.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return s.tracer.Start(ctx, name)
}

func (s *AuthService) audit(event string, attrs ...any) {
	logger := s.log()
	if logger == nil {
		return
	}
	fields := make([]zap.Field, 0, len(attrs)/2+2)
	fields = append(fields, zap.String("event", event), zap.Time("timestamp", time.Now().UTC()))
	for i := 0; i+1 < len(attrs); i += 2 {
		key, ok := attrs[i].(string)
		if !ok {
			continue
		}
		fields = append(fields, zap.Any(key, attrs[i+1]))
	}
	logger.Info("audit", fields...)
}

func (s *AuthService) log() *zap.Logger {
	if s != nil && s.logger != nil {
		return s.logger
	}
	return zap.L()
}

func randomString(n int) string {
	if n <= 0 {
		n = 64
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func randomID() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[0] &= 0x7f
	return int64(binary.BigEndian.Uint64(b[:]))
}

// ValidateToken proxies to JWT generator to validate tokens.
func (s *AuthService) ValidateToken(ctx context.Context, orgID int64, token, issuer string) (*gojwt.Claims, *jwt.AccessTokenClaims, error) {
	return s.jwt.ValidateAccessToken(ctx, orgID, token, issuer)
}

// JWKS returns org JWKS set.
func (s *AuthService) JWKS(ctx context.Context, orgID int64) (gojose.JSONWebKeySet, error) {
	return s.keys.JWKS(ctx, orgID)
}

// IsValidRedirectURI validates redirect URIs against stored OAuth clients.
func (s *AuthService) IsValidRedirectURI(ctx context.Context, orgID int64, clientID, redirectURI string) bool {
	if s == nil || s.clients == nil {
		return false
	}
	cleanClient := strings.TrimSpace(clientID)
	cleanRedirect := strings.TrimSpace(redirectURI)
	if cleanClient == "" || cleanRedirect == "" {
		return false
	}

	client, err := s.clients.GetClientByID(ctx, orgID, cleanClient)
	if err != nil {
		s.log().Warn("lookup oauth client failed", zap.Int64("org_id", orgID), zap.String("client_id", cleanClient), zap.Error(err))
		return false
	}
	for _, allowed := range client.RedirectURIs {
		if strings.EqualFold(strings.TrimSpace(allowed), cleanRedirect) {
			return true
		}
	}
	return false
}

func otpEnabled(cfg domain.OTPConfig) bool {
	return strings.TrimSpace(cfg.Channel) != ""
}

func otpCodeLength(cfg domain.OTPConfig) int {
	return 6
}

func otpTTL(cfg domain.OTPConfig) time.Duration {
	if cfg.ExpirySeconds <= 0 {
		return 5 * time.Minute
	}
	return time.Duration(cfg.ExpirySeconds) * time.Second
}

func generateOTP(secret string, length int, ttl time.Duration) string {
	if length <= 0 {
		length = 6
	}
	period := int64(ttl.Seconds())
	if period <= 0 {
		period = 30
	}
	counter := time.Now().Unix() / period
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(counter))
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := int(sum[offset]&0x7f)<<24 | int(sum[offset+1]&0xff)<<16 | int(sum[offset+2]&0xff)<<8 | int(sum[offset+3]&0xff)
	divisor := int(math.Pow10(length))
	if divisor <= 0 {
		divisor = 1000000
	}
	otp := binaryCode % divisor
	return fmt.Sprintf("%0*d", length, otp)
}
