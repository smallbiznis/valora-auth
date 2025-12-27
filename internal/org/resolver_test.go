package org_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smallbiznis/valora-auth/internal/domain"
	"github.com/smallbiznis/valora-auth/internal/org"
)

func TestResolverResolve(t *testing.T) {
	repo := &mockOrgRepo{}
	resolver := org.NewResolver(repo)

	ctx, err := resolver.Resolve(context.Background(), "tenant.smallbiznis.test")
	require.NoError(t, err)
	require.Equal(t, int64(1), ctx.Org.ID)
	require.Equal(t, "SmallBiznis", ctx.Org.Name)
	// require.Equal(t, "client", ctx.ClientID)
	require.Len(t, ctx.AuthProviders, 1)
	require.Equal(t, 8, ctx.PasswordConfig.MinLength)
}

func TestResolverResolveBySlug(t *testing.T) {
	repo := &mockOrgRepo{}
	resolver := org.NewResolver(repo)

	ctx, err := resolver.ResolveBySlug(context.Background(), "smallbiznis")
	require.NoError(t, err)
	require.Equal(t, int64(1), ctx.Org.ID)
	require.Equal(t, "primary.smallbiznis.test", ctx.Domain.Host)
}

type mockOrgRepo struct{}

func (m *mockOrgRepo) GetDomainByHost(ctx context.Context, host string) (domain.Domain, error) {
	return domain.Domain{ID: 1, Host: host, OrgID: 1}, nil
}

func (m *mockOrgRepo) GetOrg(ctx context.Context, orgID int64) (domain.Org, error) {
	return domain.Org{ID: orgID, Name: "SmallBiznis", Code: "client", Slug: "smallbiznis"}, nil
}

func (m *mockOrgRepo) GetOrgBySlug(ctx context.Context, slug string) (domain.Org, error) {
	return domain.Org{ID: 1, Name: "SmallBiznis", Code: "client", Slug: slug}, nil
}

func (m *mockOrgRepo) GetPrimaryDomain(ctx context.Context, orgID int64) (domain.Domain, error) {
	return domain.Domain{ID: orgID, Host: "primary.smallbiznis.test", OrgID: orgID}, nil
}

func (m *mockOrgRepo) GetBranding(ctx context.Context, orgID int64) (domain.Branding, error) {
	return domain.Branding{OrgID: orgID, LogoURL: strPtr("https://cdn/logo.png")}, nil
}

func (m *mockOrgRepo) ListAuthProviders(ctx context.Context, orgID int64) ([]domain.AuthProvider, error) {
	return []domain.AuthProvider{{OrgID: orgID, ProviderType: "password", IsActive: true}}, nil
}

func (m *mockOrgRepo) GetPasswordConfig(ctx context.Context, orgID int64) (domain.PasswordConfig, error) {
	return domain.PasswordConfig{
		OrgID:                  orgID,
		MinLength:              8,
		RequireUppercase:       false,
		RequireNumber:          true,
		RequireSymbol:          false,
		AllowSignup:            true,
		AllowPasswordReset:     true,
		LockoutAttempts:        5,
		LockoutDurationSeconds: 300,
	}, nil
}

func (m *mockOrgRepo) GetOTPConfig(ctx context.Context, orgID int64) (domain.OTPConfig, error) {
	return domain.OTPConfig{OrgID: orgID, Channel: "sms", ExpirySeconds: 300}, nil
}

func (m *mockOrgRepo) ListOAuthIDPConfigs(ctx context.Context, orgID int64) ([]domain.OAuthIDPConfig, error) {
	return []domain.OAuthIDPConfig{{OrgID: orgID, Provider: "google", ClientID: "id", ClientSecret: "secret", AuthorizationURL: "https://auth", TokenURL: "https://token", UserinfoURL: "https://userinfo", JWKSURL: "https://jwks"}}, nil
}

func strPtr(s string) *string {
	return &s
}
