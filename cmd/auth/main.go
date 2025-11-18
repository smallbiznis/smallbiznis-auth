package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/smallbiznis/smallbiznis-auth/internal/config"
	httptransport "github.com/smallbiznis/smallbiznis-auth/internal/http"
	"github.com/smallbiznis/smallbiznis-auth/internal/http/handler"
	httpmiddleware "github.com/smallbiznis/smallbiznis-auth/internal/http/middleware"
	"github.com/smallbiznis/smallbiznis-auth/internal/jwt"
	apimiddleware "github.com/smallbiznis/smallbiznis-auth/internal/middleware"
	"github.com/smallbiznis/smallbiznis-auth/internal/repository"
	"github.com/smallbiznis/smallbiznis-auth/internal/server"
	"github.com/smallbiznis/smallbiznis-auth/internal/service"
	"github.com/smallbiznis/smallbiznis-auth/internal/telemetry"
	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
	"github.com/smallbiznis/smallbiznis-auth/sqlc"
)

func main() {
	app := fx.New(
		fx.Provide(
			newConfig,
			newLogger,
			newTelemetry,
			newPGXPool,
			newQueries,
			newTenantRepository,
			newUserRepository,
			newTokenRepository,
			newCodeRepository,
			newKeyRepository,
			newRateLimiter,
			tenant.NewResolver,
			newKeyManager,
			newTokenGenerator,
			service.NewAuthService,
			newDiscoveryService,
			handler.NewAuthHandler,
			newAuthMiddleware,
			httptransport.NewRouter,
			server.NewHTTPServer,
		),
		fx.Invoke(useTelemetry, startHTTPServer),
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

func newTenantRepository(q *sqlc.Queries) repository.TenantRepository {
	return repository.NewPostgresTenantRepo(q)
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
