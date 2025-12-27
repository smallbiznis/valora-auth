package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/smallbiznis/valora-auth/internal/domain/oauth"
	"github.com/smallbiznis/valora-auth/internal/repository"
)

// RedisStateStore implements OAuthStateStore backed by Redis.
type RedisStateStore struct {
	client redis.UniversalClient
}

var _ repository.OAuthStateStore = (*RedisStateStore)(nil)

// NewRedisStateStore constructs a Redis-backed state store.
func NewRedisStateStore(client redis.UniversalClient) *RedisStateStore {
	return &RedisStateStore{client: client}
}

// SaveState stores the encoded OAuth state payload with TTL.
func (s *RedisStateStore) SaveState(ctx context.Context, key string, data oauth.OAuthState, ttl time.Duration) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := s.client.Set(ctx, key, payload, ttl).Err(); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	return nil
}

// GetState loads and decodes the state payload.
func (s *RedisStateStore) GetState(ctx context.Context, key string) (*oauth.OAuthState, error) {
	bytes, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, fmt.Errorf("load state: %w", err)
	}
	var state oauth.OAuthState
	if err := json.Unmarshal(bytes, &state); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	return &state, nil
}

// DeleteState removes the persisted state key.
func (s *RedisStateStore) DeleteState(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, key).Err(); err != nil && err != redis.Nil {
		return fmt.Errorf("delete state: %w", err)
	}
	return nil
}
