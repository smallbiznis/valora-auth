package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/bwmarrin/snowflake"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/smallbiznis/railzway-auth/internal/config"
	"github.com/smallbiznis/railzway-auth/internal/domain"
	"github.com/smallbiznis/railzway-auth/internal/password"
	"github.com/smallbiznis/railzway-auth/internal/repository"
)

const adminRole = "admin"

const insertTenantUserSQL = `INSERT INTO tenant_users (tenant_user_id, tenant_id, user_id, role, status, is_default)
VALUES ($1, $2, $3, $4, $5, $6)`

// EnsureAdmin creates a default admin user for dev/e2e if missing.
func EnsureAdmin(lc fx.Lifecycle, cfg config.Config, users repository.UserRepository, orgs repository.OrgRepository, pool *pgxpool.Pool, node *snowflake.Node, logger *zap.Logger) {
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			return ensureAdmin(ctx, cfg, users, orgs, pool, node, logger)
		},
	})
}

func ensureAdmin(ctx context.Context, cfg config.Config, users repository.UserRepository, orgs repository.OrgRepository, pool *pgxpool.Pool, node *snowflake.Node, logger *zap.Logger) error {
	email := strings.ToLower(strings.TrimSpace(cfg.AdminEmail))
	if email == "" || strings.TrimSpace(cfg.AdminPassword) == "" || cfg.DefaultOrgID == 0 {
		return fmt.Errorf("admin bootstrap missing required config")
	}

	if _, err := orgs.GetOrg(ctx, cfg.DefaultOrgID); err != nil {
		return fmt.Errorf("bootstrap org lookup: %w", err)
	}

	if _, err := users.GetByEmail(ctx, cfg.DefaultOrgID, email); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("bootstrap lookup user: %w", err)
	}

	hashed, err := password.Hash(cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("bootstrap hash password: %w", err)
	}

	user := domain.User{
		ID:            node.Generate().Int64(),
		OrgID:         cfg.DefaultOrgID,
		Email:         email,
		EmailVerified: false,
		PasswordHash:  hashed,
		Name:          "Admin",
		Phone:         "",
		PhoneVerified: false,
		AvatarURL:     "",
		Status:        "ACTIVE",
	}

	created, err := users.Create(ctx, user)
	if err != nil {
		return fmt.Errorf("bootstrap create user: %w", err)
	}

	_, err = pool.Exec(ctx, insertTenantUserSQL,
		node.Generate().Int64(),
		cfg.DefaultOrgID,
		created.ID,
		strings.ToUpper(adminRole),
		"ACTIVE",
		true,
	)
	if err != nil {
		return fmt.Errorf("bootstrap create tenant user: %w", err)
	}

	if logger != nil {
		logger.Info("bootstrap admin user created",
			zap.String("email", created.Email),
			zap.Int64("org_id", cfg.DefaultOrgID),
			zap.Int64("user_id", created.ID),
		)
	}
	return nil
}
