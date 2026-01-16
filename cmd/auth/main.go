package main

import (
	"context"
	"fmt"
	"time"

	"github.com/bwmarrin/snowflake"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	cacheadapter "github.com/smallbiznis/railzway-auth/internal/adapter/cache"
	oauthadapter "github.com/smallbiznis/railzway-auth/internal/adapter/oauth"
	"github.com/smallbiznis/railzway-auth/internal/bootstrap"
	"github.com/smallbiznis/railzway-auth/internal/config"
	httptransport "github.com/smallbiznis/railzway-auth/internal/http"
	"github.com/smallbiznis/railzway-auth/internal/http/handler"
	httpmiddleware "github.com/smallbiznis/railzway-auth/internal/http/middleware"
	"github.com/smallbiznis/railzway-auth/internal/jwt"
	apimiddleware "github.com/smallbiznis/railzway-auth/internal/middleware"
	"github.com/smallbiznis/railzway-auth/internal/org"
	"github.com/smallbiznis/railzway-auth/internal/repository"
	"github.com/smallbiznis/railzway-auth/internal/server"
	"github.com/smallbiznis/railzway-auth/internal/service"
	authservice "github.com/smallbiznis/railzway-auth/internal/service/auth"
	"github.com/smallbiznis/railzway-auth/internal/telemetry"
	"github.com/smallbiznis/railzway-auth/sqlc"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

func main() {
	app := fx.New(
		fx.Provide(
			newConfig,
			newLogger,
			newTelemetry,
			newSnowflake,
			newPGXPool,
			newQueries,
			newOrgRepository,
			newUserRepository,
			newTokenRepository,
			newCodeRepository,
			newKeyRepository,
			newOAuthClientRepository,
			newOAuthProviderConfigRepository,
			newRedisClient,
			newOAuthStateStore,
			newOAuthProviderClient,
			newRateLimiter,
			org.NewResolver,
			newKeyManager,
			newTokenGenerator,
			service.NewAuthService,
			authservice.NewOAuthService,
			newDiscoveryService,
			handler.NewAuthHandler,
			newAuthMiddleware,
			httptransport.NewRouter,
			server.NewHTTPServer,
		),
		fx.Invoke(useTelemetry, bootstrap.EnsureAdmin, startHTTPServer),
	)

	app.Run()
}

func newConfig() (config.Config, error) {
	return config.Load()
}

func newLogger(cfg config.Config) (*zap.Logger, error) {
	var (
		logger *zap.Logger
		err    error
	)
	if cfg.Environment == "development" {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		return nil, err
	}
	zap.ReplaceGlobals(logger)
	return logger, nil
}

func newTelemetry(lc fx.Lifecycle, cfg config.Config, logger *zap.Logger) (*telemetry.Provider, error) {
	provider, err := telemetry.New(context.Background(), cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("telemetry init: %w", err)
	}

	lc.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return provider.Shutdown(stopCtx)
		},
	})

	return provider, nil
}

func newSnowflake() (*snowflake.Node, error) {
	node, err := snowflake.NewNode(1)
	return node, err
}

func newPGXPool(lc fx.Lifecycle, cfg config.Config) (*pgxpool.Pool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	lc.Append(fx.Hook{
		OnStop: func(context.Context) error {
			pool.Close()
			return nil
		},
	})

	return pool, nil
}

func newQueries(pool *pgxpool.Pool) *sqlc.Queries {
	return sqlc.New(pool)
}

func newOrgRepository(q *sqlc.Queries) repository.OrgRepository {
	return repository.NewPostgresOrgRepo(q)
}

func newUserRepository(pool *pgxpool.Pool) repository.UserRepository {
	return repository.NewPostgresUserRepo(pool)
}

func newTokenRepository(q *sqlc.Queries) repository.TokenRepository {
	return repository.NewPostgresTokenRepo(q)
}

func newCodeRepository(q *sqlc.Queries) repository.CodeRepository {
	return repository.NewPostgresCodeRepo(q)
}

func newKeyRepository(q *sqlc.Queries) repository.KeyRepository {
	return repository.NewPostgresKeyRepo(q)
}

func newOAuthClientRepository(pool *pgxpool.Pool) repository.OAuthClientRepository {
	return repository.NewPostgresOAuthClientRepo(pool)
}

func newOAuthProviderConfigRepository(q *sqlc.Queries) repository.OAuthProviderConfigRepo {
	return repository.NewPostgresOAuthProviderConfigRepo(q)
}

func newRedisClient(lc fx.Lifecycle, cfg config.Config) (redis.UniversalClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	lc.Append(fx.Hook{
		OnStop: func(context.Context) error {
			return client.Close()
		},
	})
	return client, nil
}

func newOAuthStateStore(client redis.UniversalClient) repository.OAuthStateStore {
	return cacheadapter.NewRedisStateStore(client)
}

func newOAuthProviderClient() oauthadapter.ProviderClient {
	return oauthadapter.NewHTTPProviderClient(nil)
}

func newRateLimiter(cfg config.Config) *apimiddleware.RateLimiter {
	return apimiddleware.NewRateLimiter(cfg.RateLimitRPM)
}

func newKeyManager(repo repository.KeyRepository) *jwt.KeyManager {
	return jwt.NewKeyManager(repo)
}

func newTokenGenerator(manager *jwt.KeyManager, cfg config.Config) *jwt.Generator {
	return jwt.NewGenerator(manager, cfg.AccessTokenTTL)
}

func newDiscoveryService() *service.DiscoveryService {
	return &service.DiscoveryService{}
}

func newAuthMiddleware(authService *service.AuthService) *httpmiddleware.Auth {
	return &httpmiddleware.Auth{AuthService: authService}
}

func startHTTPServer(lc fx.Lifecycle, srv *server.HTTPServer, cfg config.Config, logger *zap.Logger) {
	addr := ":" + cfg.HTTPPort
	var (
		cancel context.CancelFunc
		done   chan struct{}
	)

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			runCtx, stop := context.WithCancel(context.Background())
			cancel = stop
			done = make(chan struct{})

			go func() {
				if err := srv.Run(runCtx, addr); err != nil {
					logger.Error("http server stopped", zap.Error(err))
				}
				close(done)
			}()

			return nil
		},
		OnStop: func(ctx context.Context) error {
			if cancel != nil {
				cancel()
			}
			if done == nil {
				return nil
			}
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
}

func useTelemetry(*telemetry.Provider) {}
