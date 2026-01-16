package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/smallbiznis/railzway-auth/internal/domain/oauth"
	"github.com/smallbiznis/railzway-auth/sqlc"
)

// OAuthProviderConfigRepo exposes CRUD operations for org IdP configs.
type OAuthProviderConfigRepo interface {
	GetProvidersByOrg(ctx context.Context, orgID int64) ([]oauth.OAuthProviderConfig, error)
	GetProviderByName(ctx context.Context, orgID int64, name string) (*oauth.OAuthProviderConfig, error)
}

// OAuthStateStore persists short-lived authorization state/nonce structures.
type OAuthStateStore interface {
	SaveState(ctx context.Context, key string, data oauth.OAuthState, ttl time.Duration) error
	GetState(ctx context.Context, key string) (*oauth.OAuthState, error)
	DeleteState(ctx context.Context, key string) error
}

// PostgresOAuthProviderConfigRepo implements OAuthProviderConfigRepo.
type PostgresOAuthProviderConfigRepo struct {
	q *sqlc.Queries
}

var _ OAuthProviderConfigRepo = (*PostgresOAuthProviderConfigRepo)(nil)

func NewPostgresOAuthProviderConfigRepo(q *sqlc.Queries) *PostgresOAuthProviderConfigRepo {
	return &PostgresOAuthProviderConfigRepo{q: q}
}

func (r *PostgresOAuthProviderConfigRepo) GetProvidersByOrg(ctx context.Context, orgID int64) ([]oauth.OAuthProviderConfig, error) {
	rows, err := r.q.ListOAuthIDPConfigs(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list oauth providers: %w", err)
	}
	providers := make([]oauth.OAuthProviderConfig, 0, len(rows))
	for _, row := range rows {
		providers = append(providers, mapOAuthProviderRow(row))
	}
	return providers, nil
}

func (r *PostgresOAuthProviderConfigRepo) GetProviderByName(ctx context.Context, orgID int64, name string) (*oauth.OAuthProviderConfig, error) {
	rows, err := r.q.ListOAuthIDPConfigs(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("load oauth provider: %w", err)
	}
	target := strings.ToLower(strings.TrimSpace(name))
	for _, row := range rows {
		cfg := mapOAuthProviderRow(row)
		if strings.EqualFold(cfg.ProviderName, target) {
			return &cfg, nil
		}
	}
	return nil, fmt.Errorf("provider %s: %w", name, oauth.ErrProviderNotFound)
}

func mapOAuthProviderRow(row sqlc.ListOAuthIDPConfigsRow) oauth.OAuthProviderConfig {
	extra := make(map[string]any)
	if len(row.Extra) > 0 {
		_ = json.Unmarshal(row.Extra, &extra)
	}
	display := defaultProviderDisplay(row.Provider)
	icon := defaultProviderIcon(row.Provider)
	return oauth.OAuthProviderConfig{
		OrgID:        row.TenantID,
		ProviderName: row.Provider,
		DisplayName:  display,
		IconURL:      icon,
		ClientID:     row.ClientID,
		ClientSecret: row.ClientSecret,
		AuthURL:      row.AuthorizationURL,
		TokenURL:     row.TokenURL,
		UserInfoURL:  row.UserinfoURL,
		Scopes:       append([]string{}, row.Scopes...),
		Extra:        extra,
		CreatedAt:    row.CreatedAt,
		UpdatedAt:    row.UpdatedAt,
	}
}

func defaultProviderDisplay(name string) string {
	switch strings.ToLower(name) {
	case "google":
		return "Google"
	case "apple":
		return "Apple"
	case "github":
		return "GitHub"
	case "microsoft":
		return "Microsoft"
	case "oidc":
		return "OpenID Connect"
	default:
		return titleCase(name)
	}
}

func defaultProviderIcon(name string) string {
	switch strings.ToLower(name) {
	case "google":
		return "https://www.gstatic.com/devrel-devsite/prod/vb9089e644d3c4a7cafe313dba2c1f9aeae234c31d1cc40364259ef0a9e740381/firebase/images/lockup.png"
	case "apple":
		return "https://developer.apple.com/assets/elements/icons/apple-logo-black/apple-logo-black-64x64_2x.png"
	case "github":
		return "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"
	case "microsoft":
		return "https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg"
	default:
		return ""
	}
}

func titleCase(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	runes := []rune(trimmed)
	for i, r := range runes {
		if i == 0 {
			runes[i] = unicode.ToUpper(r)
			continue
		}
		runes[i] = unicode.ToLower(r)
	}
	return string(runes)
}
