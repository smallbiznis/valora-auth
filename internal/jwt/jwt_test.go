package jwt_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/smallbiznis/valora-auth/internal/domain"
	customjwt "github.com/smallbiznis/valora-auth/internal/jwt"
)

func TestGeneratorRoundTrip(t *testing.T) {
	repo := &fakeKeyRepo{}
	manager := customjwt.NewKeyManager(repo)
	generator := customjwt.NewGenerator(manager, time.Hour)

	org := domain.Org{ID: 1, Name: "Tenant", Code: "client"}
	user := domain.User{ID: 99, Email: "user@tenant", Name: "Test User"}

	token, err := generator.GenerateAccessToken(context.Background(), org, user, "openid", "https://tenant", []string{"password"})
	require.NoError(t, err)
	require.NotEmpty(t, token)

	claims, custom, err := generator.ValidateAccessToken(context.Background(), org.ID, token, "https://tenant")
	require.NoError(t, err)
	require.Equal(t, "99", claims.Subject)
	require.Equal(t, int64(1), custom.OrgID)
	require.Equal(t, "user@tenant", custom.Email)
}

type fakeKeyRepo struct {
	key domain.OAuthKey
}

func (f *fakeKeyRepo) GetActiveKey(ctx context.Context, orgID int64) (domain.OAuthKey, error) {
	if f.key.ID == 0 {
		return domain.OAuthKey{}, pgx.ErrNoRows
	}
	return f.key, nil
}

func (f *fakeKeyRepo) CreateKey(ctx context.Context, key domain.OAuthKey) (domain.OAuthKey, error) {
	key.ID = 1
	f.key = key
	return key, nil
}
