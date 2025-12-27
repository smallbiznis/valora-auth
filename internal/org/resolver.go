package org

import (
	"context"
	"fmt"
	"strings"

	"github.com/smallbiznis/valora-auth/internal/domain"
	"github.com/smallbiznis/valora-auth/internal/repository"
	"go.uber.org/zap"
)

// Context stores resolved org metadata used throughout the request lifecycle.
type Context struct {
	Domain          domain.Domain
	Org             domain.Org
	ClientID        string
	Branding        domain.Branding
	AuthProviders   []domain.AuthProvider
	PasswordConfig  domain.PasswordConfig
	OTPConfig       domain.OTPConfig
	SocialProviders []domain.OAuthIDPConfig
}

// Resolver loads org metadata from repositories.
type Resolver struct {
	repo repository.OrgRepository
}

// NewResolver creates an org resolver.
func NewResolver(repo repository.OrgRepository) *Resolver {
	return &Resolver{repo: repo}
}

// Resolve loads org information from host header.
func (r *Resolver) Resolve(ctx context.Context, host string) (*Context, error) {
	cleaned := strings.ToLower(strings.TrimSpace(host))
	if cleaned == "" {
		zap.L().Warn("org resolver received empty host")
		return nil, fmt.Errorf("resolve org: empty host")
	}

	domainRow, err := r.repo.GetDomainByHost(ctx, cleaned)
	if err != nil {
		zap.L().Error("failed to resolve domain", zap.String("host", cleaned), zap.Error(err))
		return nil, fmt.Errorf("resolve domain: %w", err)
	}

	orgRow, err := r.repo.GetOrg(ctx, domainRow.OrgID)
	if err != nil {
		zap.L().Error("failed to resolve org", zap.String("host", cleaned), zap.Int64("org_id", domainRow.OrgID), zap.Error(err))
		return nil, fmt.Errorf("resolve org: %w", err)
	}

	return r.buildContext(ctx, domainRow, orgRow)
}

// ResolveBySlug loads org information using org slug header.
func (r *Resolver) ResolveBySlug(ctx context.Context, slug string) (*Context, error) {
	cleaned := strings.ToLower(strings.TrimSpace(slug))
	if cleaned == "" {
		zap.L().Warn("org resolver received empty slug")
		return nil, fmt.Errorf("resolve org: empty slug")
	}

	orgRow, err := r.repo.GetOrgBySlug(ctx, cleaned)
	if err != nil {
		zap.L().Error("failed to resolve org by slug", zap.String("slug", cleaned), zap.Error(err))
		return nil, fmt.Errorf("resolve org by slug: %w", err)
	}

	domainRow, err := r.repo.GetPrimaryDomain(ctx, orgRow.ID)
	if err != nil {
		zap.L().Error("failed to resolve primary domain", zap.Int64("org_id", orgRow.ID), zap.String("slug", cleaned), zap.Error(err))
		return nil, fmt.Errorf("resolve primary domain: %w", err)
	}

	return r.buildContext(ctx, domainRow, orgRow)
}

func (r *Resolver) buildContext(ctx context.Context, domainRow domain.Domain, orgRow domain.Org) (*Context, error) {
	branding, err := r.repo.GetBranding(ctx, orgRow.ID)
	if err != nil {
		zap.L().Error("failed to resolve branding", zap.Int64("org_id", orgRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve branding: %w", err)
	}

	authProviders, err := r.repo.ListAuthProviders(ctx, orgRow.ID)
	if err != nil {
		zap.L().Error("failed to list auth providers", zap.Int64("org_id", orgRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve auth providers: %w", err)
	}

	passwordConfig, err := r.repo.GetPasswordConfig(ctx, orgRow.ID)
	if err != nil {
		zap.L().Error("failed to load password config", zap.Int64("org_id", orgRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve password config: %w", err)
	}

	otpConfig, err := r.repo.GetOTPConfig(ctx, orgRow.ID)
	if err != nil {
		zap.L().Error("failed to load otp config", zap.Int64("org_id", orgRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve otp config: %w", err)
	}

	socialProviders, err := r.repo.ListOAuthIDPConfigs(ctx, orgRow.ID)
	if err != nil {
		zap.L().Error("failed to load social providers", zap.Int64("org_id", orgRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve social providers: %w", err)
	}

	zap.L().Debug("org context resolved", zap.String("host", domainRow.Host), zap.Int64("org_id", orgRow.ID))

	return &Context{
		Domain: domainRow,
		Org:    orgRow,
		// ClientID:        orgRow.Code,
		Branding:        branding,
		AuthProviders:   authProviders,
		PasswordConfig:  passwordConfig,
		OTPConfig:       otpConfig,
		SocialProviders: socialProviders,
	}, nil
}
