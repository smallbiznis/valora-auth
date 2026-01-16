package jwt

import (
	"context"
	"fmt"
	"time"

	gojose "github.com/go-jose/go-jose/v4"
	gojwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/smallbiznis/railzway-auth/internal/domain"
)

// Generator is responsible for signing and validating JWTs.
type Generator struct {
	keys      *KeyManager
	accessTTL time.Duration
}

// NewGenerator constructs a JWT generator.
func NewGenerator(manager *KeyManager, accessTTL time.Duration) *Generator {
	return &Generator{keys: manager, accessTTL: accessTTL}
}

// AccessTokenClaims represent the JWT payload for access tokens.
type AccessTokenClaims struct {
	OrgID     int64    `json:"org_id"`
	TenantID  int64    `json:"tenant_id,omitempty"`
	Scope     string   `json:"scope"`
	Email     string   `json:"email"`
	Name      string   `json:"name"`
	Picture   string   `json:"picture"`
	Providers []string `json:"providers"`
}

// GenerateAccessToken produces a signed JWT.
func (g *Generator) GenerateAccessToken(ctx context.Context, org domain.Org, user domain.User, scope, issuer string, providers []string) (string, error) {
	key, err := g.keys.EnsureSigningKey(ctx, org.ID)
	if err != nil {
		return "", fmt.Errorf("ensure signing key: %w", err)
	}

	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.SignatureAlgorithm(key.Algorithm), Key: key.Secret}, (&gojose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.KID))
	if err != nil {
		return "", fmt.Errorf("new signer: %w", err)
	}

	now := time.Now().UTC()
	stdClaims := gojwt.Claims{
		Subject:   fmt.Sprintf("%d", user.ID),
		Audience:  gojwt.Audience{org.Name},
		Issuer:    issuer,
		IssuedAt:  gojwt.NewNumericDate(now),
		Expiry:    gojwt.NewNumericDate(now.Add(g.accessTTL)),
		NotBefore: gojwt.NewNumericDate(now),
	}

	custom := AccessTokenClaims{
		OrgID:     org.ID,
		TenantID:  org.ID,
		Scope:     scope,
		Email:     user.Email,
		Name:      user.Name,
		Picture:   user.AvatarURL,
		Providers: providers,
	}

	token, err := gojwt.Signed(signer).Claims(stdClaims).Claims(custom).Serialize()
	if err != nil {
		return "", fmt.Errorf("serialize jwt: %w", err)
	}

	return token, nil
}

// ValidateAccessToken ensures the token is valid and returns its claims.
func (g *Generator) ValidateAccessToken(ctx context.Context, orgID int64, token, issuer string) (*gojwt.Claims, *AccessTokenClaims, error) {
	key, err := g.keys.ActiveKey(ctx, orgID)
	if err != nil {
		return nil, nil, fmt.Errorf("load key: %w", err)
	}

	var allowedAlgorithms [1]gojose.SignatureAlgorithm
	allowedAlgorithms[0] = gojose.SignatureAlgorithm(key.Algorithm)
	parsed, err := gojwt.ParseSigned(token, allowedAlgorithms[:])
	if err != nil {
		return nil, nil, fmt.Errorf("parse token: %w", err)
	}

	var std gojwt.Claims
	var custom AccessTokenClaims
	if err := parsed.Claims(key.Secret, &std, &custom); err != nil {
		return nil, nil, fmt.Errorf("verify token: %w", err)
	}

	if err := std.Validate(gojwt.Expected{Issuer: issuer}); err != nil {
		return nil, nil, fmt.Errorf("validate claims: %w", err)
	}

	if custom.OrgID == 0 && custom.TenantID != 0 {
		custom.OrgID = custom.TenantID
	}

	return &std, &custom, nil
}
