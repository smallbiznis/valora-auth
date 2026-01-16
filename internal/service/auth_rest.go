package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/smallbiznis/railzway-auth/internal/domain"
	basemiddleware "github.com/smallbiznis/railzway-auth/internal/middleware"
	"github.com/smallbiznis/railzway-auth/internal/org"
	pw "github.com/smallbiznis/railzway-auth/internal/password"
)

const defaultRESTScope = "openid profile email offline_access"

// LoginWithPassword performs username/password login and returns REST-friendly payload.
func (s *AuthService) LoginWithPassword(ctx context.Context, orgID int64, email, password, clientID, scope string) (AuthTokensWithUser, error) {
	ctx, span := s.startSpan(ctx, "AuthService.LoginWithPassword")
	defer span.End()

	orgCtx, err := s.orgContextFromContext(ctx, orgID, clientID)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	effectiveScope := coalesce(scope, defaultRESTScope)
	issuer := orgIssuer(orgCtx)

	tokenResp, err := s.PasswordGrant(ctx, orgCtx, email, password, effectiveScope, issuer)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	user, err := s.users.GetByEmail(ctx, orgID, normalizeIdentifier(email))
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("load user profile: %w", err)
	}

	s.audit("rest.password_login.success", "org_id", orgID, "user_id", user.ID)
	return newAuthTokensWithUser(user, tokenResp), nil
}

func (s *AuthService) RegisterWithPassword(ctx context.Context, orgID int64, email, password, name, clientId string) (AuthTokensWithUser, error) {
	ctx, span := s.startSpan(ctx, "AuthService.RegisterWithPassword")
	defer span.End()

	orgCtx, err := s.orgContextFromContext(ctx, orgID, clientId)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	normalized := normalizeIdentifier(email)
	if normalized == "" {
		return AuthTokensWithUser{}, newOAuthError("invalid_request", "Email is required.", http.StatusBadRequest)
	}
	if strings.TrimSpace(password) == "" {
		return AuthTokensWithUser{}, newOAuthError("invalid_request", "Password is required.", http.StatusBadRequest)
	}

	if _, err := s.users.GetByEmail(ctx, orgID, normalized); err == nil {
		return AuthTokensWithUser{}, newOAuthError("invalid_request", "Email already registered.", http.StatusBadRequest)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("check existing user: %w", err)
	}

	hashed, err := pw.Hash(password)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("hash password: %w", err)
	}

	model := domain.User{
		ID:            s.snowflake.Generate().Int64(),
		OrgID:         orgID,
		Email:         normalized,
		PasswordHash:  hashed,
		Name:          strings.TrimSpace(name),
		EmailVerified: false,
		Phone:         "",
		PhoneVerified: false,
		AvatarURL:     "",
		Status:        "ACTIVE",
	}

	created, err := s.users.Create(ctx, model)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("create user: %w", err)
	}

	providers := make([]string, 0, len(orgCtx.AuthProviders))
	for _, provider := range orgCtx.AuthProviders {
		if provider.IsActive {
			providers = append(providers, provider.ProviderType)
		}
	}

	tokenResp, err := s.issueTokens(ctx, orgCtx, created, defaultRESTScope, orgIssuer(orgCtx), providers)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	s.audit("rest.password_register.success", "org_id", orgID, "user_id", created.ID)
	return newAuthTokensWithUser(created, tokenResp), nil
}

// ForgotPassword kicks off password reset notifications.
func (s *AuthService) ForgotPassword(ctx context.Context, orgID int64, email string) error {
	ctx, span := s.startSpan(ctx, "AuthService.ForgotPassword")
	defer span.End()

	normalized := normalizeIdentifier(email)
	if normalized == "" {
		return newOAuthError("invalid_request", "Email is required.", http.StatusBadRequest)
	}

	if _, err := s.users.GetByEmail(ctx, orgID, normalized); err != nil {
		span.RecordError(err)
		if logger := s.log(); logger != nil {
			logger.Warn("password reset requested for unknown user",
				zap.Int64("org_id", orgID),
				zap.String("email", normalized),
				zap.Error(err),
			)
		}
	}

	s.audit("rest.password_forgot.request", "org_id", orgID, "email", normalized)
	return nil
}

// RequestOTP generates an OTP code for passwordless login.
func (s *AuthService) RequestOTP(ctx context.Context, orgID int64, phone, channel string) error {
	ctx, span := s.startSpan(ctx, "AuthService.RequestOTP")
	defer span.End()

	orgCtx, err := s.orgContextFromContext(ctx, orgID, "")
	if err != nil {
		span.RecordError(err)
		return err
	}
	if !otpEnabled(orgCtx.OTPConfig) {
		return newOAuthError("unsupported_grant_type", "OTP login disabled for org.", http.StatusBadRequest)
	}

	identifier := normalizeIdentifier(phone)
	if identifier == "" {
		return newOAuthError("invalid_request", "Phone identifier is required.", http.StatusBadRequest)
	}

	user, err := s.users.GetByEmail(ctx, orgID, identifier)
	if err != nil {
		span.RecordError(err)
		return newOAuthError("invalid_request", "Account not eligible for OTP login.", http.StatusBadRequest)
	}

	_ = generateOTP(user.PasswordHash, otpCodeLength(orgCtx.OTPConfig), otpTTL(orgCtx.OTPConfig))
	s.audit("rest.otp_request.accepted", "org_id", orgID, "user_id", user.ID, "channel", channel)

	return nil
}

// VerifyOTP validates OTP and issues OAuth tokens.
func (s *AuthService) VerifyOTP(ctx context.Context, orgID int64, phone, code, clientID, scope string) (AuthTokensWithUser, error) {
	ctx, span := s.startSpan(ctx, "AuthService.VerifyOTP")
	defer span.End()

	orgCtx, err := s.orgContextFromContext(ctx, orgID, clientID)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	effectiveScope := coalesce(scope, defaultRESTScope)
	issuer := orgIssuer(orgCtx)

	tokenResp, err := s.OTPGrant(ctx, orgCtx, phone, code, effectiveScope, issuer)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	user, err := s.users.GetByEmail(ctx, orgID, normalizeIdentifier(phone))
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("load user profile: %w", err)
	}

	s.audit("rest.otp_verify.success", "org_id", orgID, "user_id", user.ID)
	return newAuthTokensWithUser(user, tokenResp), nil
}

func (s *AuthService) GetUserInfo(ctx context.Context, orgID int64, userID int64) (UserViewModel, error) {
	ctx, span := s.startSpan(ctx, "AuthService.GetUserInfo")
	defer span.End()

	user, err := s.users.GetByID(ctx, orgID, userID)
	if err != nil {
		span.RecordError(err)
		return UserViewModel{}, fmt.Errorf("load user: %w", err)
	}

	return UserViewModel{
		ID:        user.ID,
		OrgID:     user.OrgID,
		TenantID:  user.OrgID,
		Email:     user.Email,
		Name:      user.Name,
		AvatarURL: user.AvatarURL,
	}, nil
}

func (s *AuthService) orgContextFromContext(ctx context.Context, orgID int64, clientID string) (*org.Context, error) {
	orgCtx, ok := basemiddleware.OrgContextFromContext(ctx)
	if !ok || orgCtx == nil {
		return nil, newOAuthError("invalid_request", "Org context missing.", http.StatusBadRequest)
	}
	if orgID != 0 && orgCtx.Org.ID != orgID {
		return nil, newOAuthError("invalid_request", "Org mismatch.", http.StatusBadRequest)
	}
	orgCtx.ClientID = clientID
	return orgCtx, nil
}

func orgIssuer(ctx *org.Context) string {
	if ctx.Domain.Host != "" {
		return fmt.Sprintf("https://%s", ctx.Domain.Host)
	}
	return ""
}

func newAuthTokensWithUser(user domain.User, tokenResp *TokenResponse) AuthTokensWithUser {
	return AuthTokensWithUser{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      "",
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    int64(tokenResp.ExpiresIn),
		User: UserViewModel{
			ID:        user.ID,
			OrgID:     user.OrgID,
			TenantID:  user.OrgID,
			Email:     user.Email,
			Name:      user.Name,
			AvatarURL: user.AvatarURL,
		},
	}
}

func normalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
