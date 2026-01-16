package tenant

import (
	"context"
	"fmt"
	"strings"

	"github.com/smallbiznis/railzway-auth/internal/domain"
	"github.com/smallbiznis/railzway-auth/internal/repository"
	"go.uber.org/zap"
)

// Context stores resolved tenant metadata used throughout the request lifecycle.
type Context struct {
	Domain          domain.Domain
	Tenant          domain.Org
	ClientID        string
	Branding        domain.Branding
	AuthProviders   []domain.AuthProvider
	PasswordConfig  domain.PasswordConfig
	OTPConfig       domain.OTPConfig
	SocialProviders []domain.OAuthIDPConfig
}

// Resolver loads tenant metadata from repositories.
type Resolver struct {
	repo repository.OrgRepository
}

// NewResolver creates a tenant resolver.
func NewResolver(repo repository.OrgRepository) *Resolver {
	return &Resolver{repo: repo}
}

// Resolve loads tenant information from host header.
func (r *Resolver) Resolve(ctx context.Context, host string) (*Context, error) {
	cleaned := strings.ToLower(strings.TrimSpace(host))
	if cleaned == "" {
		zap.L().Warn("tenant resolver received empty host")
		return nil, fmt.Errorf("resolve tenant: empty host")
	}

	domainRow, err := r.repo.GetDomainByHost(ctx, cleaned)
	if err != nil {
		zap.L().Error("failed to resolve domain", zap.String("host", cleaned), zap.Error(err))
		return nil, fmt.Errorf("resolve domain: %w", err)
	}

	tenantRow, err := r.repo.GetOrg(ctx, domainRow.OrgID)
	if err != nil {
		zap.L().Error("failed to resolve tenant", zap.String("host", cleaned), zap.Int64("tenant_id", domainRow.OrgID), zap.Error(err))
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}

	return r.buildContext(ctx, domainRow, tenantRow)
}

// ResolveBySlug loads tenant information using tenant slug header.
func (r *Resolver) ResolveBySlug(ctx context.Context, slug string) (*Context, error) {
	cleaned := strings.ToLower(strings.TrimSpace(slug))
	if cleaned == "" {
		zap.L().Warn("tenant resolver received empty slug")
		return nil, fmt.Errorf("resolve tenant: empty slug")
	}

	tenantRow, err := r.repo.GetOrgBySlug(ctx, cleaned)
	if err != nil {
		zap.L().Error("failed to resolve tenant by slug", zap.String("slug", cleaned), zap.Error(err))
		return nil, fmt.Errorf("resolve tenant by slug: %w", err)
	}

	domainRow, err := r.repo.GetPrimaryDomain(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to resolve primary domain", zap.Int64("tenant_id", tenantRow.ID), zap.String("slug", cleaned), zap.Error(err))
		return nil, fmt.Errorf("resolve primary domain: %w", err)
	}

	return r.buildContext(ctx, domainRow, tenantRow)
}

func (r *Resolver) buildContext(ctx context.Context, domainRow domain.Domain, tenantRow domain.Org) (*Context, error) {
	branding, err := r.repo.GetBranding(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to resolve branding", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve branding: %w", err)
	}

	authProviders, err := r.repo.ListAuthProviders(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to list auth providers", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve auth providers: %w", err)
	}

	passwordConfig, err := r.repo.GetPasswordConfig(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to load password config", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve password config: %w", err)
	}

	otpConfig, err := r.repo.GetOTPConfig(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to load otp config", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve otp config: %w", err)
	}

	socialProviders, err := r.repo.ListOAuthIDPConfigs(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to load social providers", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve social providers: %w", err)
	}

	zap.L().Debug("tenant context resolved", zap.String("host", domainRow.Host), zap.Int64("tenant_id", tenantRow.ID))

	return &Context{
		Domain: domainRow,
		Tenant: tenantRow,
		// ClientID:        tenantRow.Code,
		Branding:        branding,
		AuthProviders:   authProviders,
		PasswordConfig:  passwordConfig,
		OTPConfig:       otpConfig,
		SocialProviders: socialProviders,
	}, nil
}
