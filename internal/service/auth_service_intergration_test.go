//go:build integration

package service_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/smallbiznis/smallbiznis-auth/internal/config"
	"github.com/smallbiznis/smallbiznis-auth/internal/jwt"
	"github.com/smallbiznis/smallbiznis-auth/internal/repository"
	"github.com/smallbiznis/smallbiznis-auth/internal/service"
	"github.com/smallbiznis/smallbiznis-auth/sqlc"
)

func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Fatal("DATABASE_URL must be set for integration tests")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("failed to connect db: %v", err)
	}

	return pool
}

func seedBaseTenant(t *testing.T, db *pgxpool.Pool) (tenantID int64) {
	ctx := context.Background()

	tenantID = 2000

	_, err := db.Exec(ctx, `
		INSERT INTO tenants (id, type, name, code, slug, country_code, timezone, is_default, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			code = EXCLUDED.code,
			slug = EXCLUDED.slug,
			updated_at = NOW()
	`, tenantID, "company", "Kopi Kenangan", "KK", "kopikenangan", "ID", "Asia/Jakarta", false, "active")
	assert.NoError(t, err)

	_, err = db.Exec(ctx, `
		INSERT INTO domains (id, tenant_id, host, is_primary, verified)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (host) DO UPDATE SET tenant_id = EXCLUDED.tenant_id
	`, int64(20001), tenantID, "kopikenangan.localhost", true, true)
	assert.NoError(t, err)

	_, err = db.Exec(ctx, `
		INSERT INTO password_configs (tenant_id)
		VALUES ($1)
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID)
	assert.NoError(t, err)

	_, err = db.Exec(ctx, `
		INSERT INTO oauth_keys (id, tenant_id, kid, secret, algorithm, is_active)
		VALUES ($1,$2,$3,$4,$5,true)
		ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret
	`, int64(30001), tenantID, "test-kid", "super-secret-key", "HS256")
	assert.NoError(t, err)

	return tenantID
}

type seededUser struct {
	ID    int64
	Email string
}

func seedUser(t *testing.T, db *pgxpool.Pool, tenantID int64) seededUser {
	ctx := context.Background()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)

	userID := int64(9001)

	_, err := db.Exec(ctx, `
		INSERT INTO users (id, tenant_id, email, password_hash, name, status)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			name = EXCLUDED.name,
			status = EXCLUDED.status
	`, userID, tenantID, "owner@kopikenangan.com", string(hashed), "Owner KK", "ACTIVE")
	assert.NoError(t, err)

	return seededUser{ID: userID, Email: "owner@kopikenangan.com"}
}

func newRealAuthService(t *testing.T, db *pgxpool.Pool, q *sqlc.Queries) *service.AuthService {
	t.Helper()

	logger := zap.NewExample()
	defer func() { _ = logger.Sync() }()

	cfg := config.Config{
		AccessTokenTTL: time.Hour,
	}

	// tenantRepo := repository.NewPostgresTenantRepo(q)
	userRepo := repository.NewPostgresUserRepo(db)
	tokenRepo := repository.NewPostgresTokenRepo(q)
	codeRepo := repository.NewPostgresCodeRepo(q)
	keyRepo := repository.NewPostgresKeyRepo(q)

	keyManager := jwt.NewKeyManager(keyRepo)
	generator := jwt.NewGenerator(keyManager, cfg.AccessTokenTTL)

	return service.NewAuthService(
		userRepo,
		tokenRepo,
		codeRepo,
		generator,
		keyManager,
		cfg,
		logger,
	)
}

func TestAuthService_LoginWithPassword_Integration(t *testing.T) {
	db := setupDB(t)
	defer db.Close()

	q := sqlc.New(db)

	// Seed tenant
	tenantID := seedBaseTenant(t, db)

	// Seed user
	user := seedUser(t, db, tenantID)

	// New real AuthService
	svc := newRealAuthService(t, db, q)

	// Call service
	ctx := context.Background()
	res, err := svc.LoginWithPassword(
		ctx,
		tenantID,
		user.Email,
		"secret123",
		"console-web",
		"openid profile email",
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, res.AccessToken)
	assert.Equal(t, "Bearer", res.TokenType)
	assert.Greater(t, res.ExpiresIn, int64(0))
	assert.Equal(t, user.ID, res.User.ID)

	// Check refresh token saved in DB
	var refreshToken string
	err = db.QueryRow(ctx, `
		SELECT refresh_token FROM oauth_tokens
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`, tenantID, user.ID).Scan(&refreshToken)
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
}
