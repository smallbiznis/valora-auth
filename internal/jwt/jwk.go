package jwt

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/smallbiznis/valora-auth/internal/domain"
	"github.com/smallbiznis/valora-auth/internal/repository"
)

// KeyManager ensures orgs always have an active signing key.
type KeyManager struct {
	repo repository.KeyRepository
}

// NewKeyManager creates a KeyManager.
func NewKeyManager(repo repository.KeyRepository) *KeyManager {
	return &KeyManager{repo: repo}
}

// EnsureSigningKey returns the active key or creates a new one if missing.
func (m *KeyManager) EnsureSigningKey(ctx context.Context, orgID int64) (domain.OAuthKey, error) {
	key, err := m.repo.GetActiveKey(ctx, orgID)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return domain.OAuthKey{}, fmt.Errorf("ensure signing key: %w", err)
	}

	secret := make([]byte, 64)
	if _, randErr := rand.Read(secret); randErr != nil {
		return domain.OAuthKey{}, fmt.Errorf("generate secret: %w", randErr)
	}

	key = domain.OAuthKey{
		OrgID:     orgID,
		KID:       uuid.NewString(),
		Secret:    secret,
		Algorithm: string(jose.HS256),
		IsActive:  true,
	}

	created, err := m.repo.CreateKey(ctx, key)
	if err != nil {
		return domain.OAuthKey{}, fmt.Errorf("persist signing key: %w", err)
	}

	return created, nil
}

// ActiveKey retrieves an existing signing key without creating a new one.
func (m *KeyManager) ActiveKey(ctx context.Context, orgID int64) (domain.OAuthKey, error) {
	key, err := m.repo.GetActiveKey(ctx, orgID)
	if err != nil {
		return domain.OAuthKey{}, fmt.Errorf("active key: %w", err)
	}
	return key, nil
}

// JSONWebKey converts the domain key to jose.JSONWebKey.
func (m *KeyManager) JSONWebKey(key domain.OAuthKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		KeyID:     key.KID,
		Use:       "sig",
		Algorithm: key.Algorithm,
		Key:       key.Secret,
	}
}

// JWKS returns the public JSON Web Key Set for the org.
func (m *KeyManager) JWKS(ctx context.Context, orgID int64) (jose.JSONWebKeySet, error) {
	key, err := m.EnsureSigningKey(ctx, orgID)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("jwks active key: %w", err)
	}
	jwk := m.JSONWebKey(key)
	if jwk.IsPublic() {
		public := jwk.Public()
		return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}, nil
	}
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}, nil
}
