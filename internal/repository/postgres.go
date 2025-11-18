package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/smallbiznis/smallbiznis-auth/internal/domain"
	"github.com/smallbiznis/smallbiznis-auth/sqlc"
)

// Compile-time interface assertions.
var (
	_ TenantRepository = (*PostgresTenantRepo)(nil)
	_ UserRepository   = (*PostgresUserRepo)(nil)
	_ TokenRepository  = (*PostgresTokenRepo)(nil)
	_ CodeRepository   = (*PostgresCodeRepo)(nil)
	_ KeyRepository    = (*PostgresKeyRepo)(nil)
)

// PostgresTenantRepo implements TenantRepository using sqlc.
type PostgresTenantRepo struct {
	q *sqlc.Queries
}

func NewPostgresTenantRepo(q *sqlc.Queries) *PostgresTenantRepo {
	return &PostgresTenantRepo{q: q}
}

func (r *PostgresTenantRepo) GetDomainByHost(ctx context.Context, host string) (domain.Domain, error) {
	row, err := r.q.GetDomainByHost(ctx, host)
	if err != nil {
		return domain.Domain{}, fmt.Errorf("get domain: %w", err)
	}
	return domain.Domain{ID: row.ID, Host: row.Host, TenantID: row.TenantID}, nil
}

func (r *PostgresTenantRepo) GetTenant(ctx context.Context, tenantID int64) (domain.Tenant, error) {
	row, err := r.q.GetTenant(ctx, tenantID)
	if err != nil {
		return domain.Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	return domain.Tenant{
		ID:          row.ID,
		Type:        row.Type,
		Name:        row.Name,
		Code:        row.Code,
		Slug:        row.Slug,
		CountryCode: row.CountryCode,
		Timezone:    row.Timezone,
		IsDefault:   row.IsDefault,
		Status:      row.Status,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}, nil
}

func (r *PostgresTenantRepo) GetBranding(ctx context.Context, tenantID int64) (domain.Branding, error) {
	row, err := r.q.GetBranding(ctx, tenantID)
	if err != nil {
		return domain.Branding{}, fmt.Errorf("get branding: %w", err)
	}
	return domain.Branding{TenantID: row.TenantID, LogoURL: &row.LogoURL, PrimaryColor: &row.PrimaryColor}, nil
}

func (r *PostgresTenantRepo) ListAuthProviders(ctx context.Context, tenantID int64) ([]domain.AuthProvider, error) {
	rows, err := r.q.ListAuthProviders(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list auth providers: %w", err)
	}
	providers := make([]domain.AuthProvider, 0, len(rows))
	for _, row := range rows {
		providers = append(providers, domain.AuthProvider{TenantID: row.TenantID, Type: row.Type, Name: row.Name, Enabled: row.Enabled})
	}
	return providers, nil
}

func (r *PostgresTenantRepo) GetPasswordConfig(ctx context.Context, tenantID int64) (domain.PasswordConfig, error) {
	row, err := r.q.GetPasswordConfig(ctx, tenantID)
	if err != nil {
		return domain.PasswordConfig{}, fmt.Errorf("get password config: %w", err)
	}
	return domain.PasswordConfig{TenantID: row.TenantID, Enabled: row.Enabled, MaxAttempts: int(row.MaxAttempts), LockoutInterval: row.LockoutInterval}, nil
}

func (r *PostgresTenantRepo) GetOTPConfig(ctx context.Context, tenantID int64) (domain.OTPConfig, error) {
	row, err := r.q.GetOTPConfig(ctx, tenantID)
	if err != nil {
		return domain.OTPConfig{}, fmt.Errorf("get otp config: %w", err)
	}
	return domain.OTPConfig{TenantID: row.TenantID, Enabled: row.Enabled, Length: int(row.Length), Ttl: row.TTL}, nil
}

func (r *PostgresTenantRepo) ListOAuthIDPConfigs(ctx context.Context, tenantID int64) ([]domain.OAuthIDPConfig, error) {
	rows, err := r.q.ListOAuthIDPConfigs(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list oauth idps: %w", err)
	}
	res := make([]domain.OAuthIDPConfig, 0, len(rows))
	for _, row := range rows {
		res = append(res, domain.OAuthIDPConfig{
			TenantID:      row.TenantID,
			Provider:      row.Provider,
			ClientID:      row.ClientID,
			ClientSecret:  row.ClientSecret,
			RedirectURI:   row.RedirectURI,
			Enabled:       row.Enabled,
			Scopes:        row.Scopes,
			DisplayName:   row.DisplayName,
			Authorization: row.AuthorizationURL,
		})
	}
	return res, nil
}

// PostgresUserRepo implements UserRepository.
type PostgresUserRepo struct {
	q  *sqlc.Queries
	db *pgxpool.Pool
}

func NewPostgresUserRepo(pool *pgxpool.Pool) *PostgresUserRepo {
	return &PostgresUserRepo{q: sqlc.New(pool), db: pool}
}

func (r *PostgresUserRepo) GetByEmail(ctx context.Context, tenantID int64, email string) (domain.User, error) {
	row, err := r.q.GetUserByEmail(ctx, tenantID, email)
	if err != nil {
		return domain.User{}, fmt.Errorf("get user: %w", err)
	}
	return mapUserRow(row), nil
}

func (r *PostgresUserRepo) GetByID(ctx context.Context, tenantID, userID int64) (domain.User, error) {
	row, err := r.q.GetUserByID(ctx, tenantID, userID)
	if err != nil {
		return domain.User{}, fmt.Errorf("get user by id: %w", err)
	}
	return mapUserRow(row), nil
}

func (r *PostgresUserRepo) UpdateLoginStats(ctx context.Context, user domain.User) error {
	if err := r.q.UpdateUserLoginStats(ctx, user.ID, int32(user.FailedAttempts), user.LockedUntil); err != nil {
		return fmt.Errorf("update login stats: %w", err)
	}
	return nil
}

const insertUserSQL = `INSERT INTO users (tenant_id, email, password_hash, name, picture_url, blocked, failed_attempts, locked_until)
VALUES ($1, $2, $3, $4, $5, false, 0, $6)
RETURNING id, tenant_id, email, password_hash, name, picture_url, blocked, failed_attempts, locked_until, created_at, updated_at`

func (r *PostgresUserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	locked := user.LockedUntil
	if locked.IsZero() {
		locked = time.Unix(0, 0).UTC()
	}
	row := r.db.QueryRow(ctx, insertUserSQL,
		user.TenantID,
		user.Email,
		user.PasswordHash,
		user.Name,
		user.PictureURL,
		locked,
	)

	var inserted sqlc.GetUserByEmailRow
	if err := row.Scan(
		&inserted.ID,
		&inserted.TenantID,
		&inserted.Email,
		&inserted.PasswordHash,
		&inserted.Name,
		&inserted.PictureURL,
		&inserted.Blocked,
		&inserted.FailedAttempts,
		&inserted.LockedUntil,
		&inserted.CreatedAt,
		&inserted.UpdatedAt,
	); err != nil {
		return domain.User{}, fmt.Errorf("create user: %w", err)
	}

	return mapUserRow(inserted), nil
}

// PostgresTokenRepo implements TokenRepository.
type PostgresTokenRepo struct {
	q *sqlc.Queries
}

func NewPostgresTokenRepo(q *sqlc.Queries) *PostgresTokenRepo {
	return &PostgresTokenRepo{q: q}
}

func (r *PostgresTokenRepo) CreateToken(ctx context.Context, token domain.OAuthToken) (domain.OAuthToken, error) {
	row, err := r.q.InsertOAuthToken(ctx, token.TenantID, token.UserID, token.ClientID, token.Scope, token.RefreshToken, token.AccessTokenID, token.ExpiresAt)
	if err != nil {
		return domain.OAuthToken{}, fmt.Errorf("insert token: %w", err)
	}
	return domain.OAuthToken{
		ID:            row.ID,
		TenantID:      row.TenantID,
		UserID:        row.UserID,
		ClientID:      row.ClientID,
		Scope:         row.Scope,
		RefreshToken:  row.RefreshToken,
		AccessTokenID: row.AccessTokenID,
		CreatedAt:     row.CreatedAt,
		ExpiresAt:     row.ExpiresAt,
		RotatedAt:     row.RotatedAt,
		Revoked:       row.Revoked,
	}, nil
}

func (r *PostgresTokenRepo) GetByRefreshToken(ctx context.Context, tenantID int64, token string) (domain.OAuthToken, error) {
	row, err := r.q.GetOAuthTokenByRefresh(ctx, tenantID, token)
	if err != nil {
		return domain.OAuthToken{}, fmt.Errorf("get refresh token: %w", err)
	}
	return domain.OAuthToken{
		ID:            row.ID,
		TenantID:      row.TenantID,
		UserID:        row.UserID,
		ClientID:      row.ClientID,
		Scope:         row.Scope,
		RefreshToken:  row.RefreshToken,
		AccessTokenID: row.AccessTokenID,
		CreatedAt:     row.CreatedAt,
		ExpiresAt:     row.ExpiresAt,
		RotatedAt:     row.RotatedAt,
		Revoked:       row.Revoked,
	}, nil
}

func (r *PostgresTokenRepo) RotateRefreshToken(ctx context.Context, tokenID int64, refreshToken string, expiresAt int64) error {
	if err := r.q.RotateRefreshToken(ctx, tokenID, refreshToken, time.Unix(expiresAt, 0)); err != nil {
		return fmt.Errorf("rotate refresh token: %w", err)
	}
	return nil
}

func (r *PostgresTokenRepo) RevokeToken(ctx context.Context, tokenID int64) error {
	if err := r.q.RevokeOAuthToken(ctx, tokenID); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// PostgresCodeRepo implements CodeRepository.
type PostgresCodeRepo struct {
	q *sqlc.Queries
}

func NewPostgresCodeRepo(q *sqlc.Queries) *PostgresCodeRepo {
	return &PostgresCodeRepo{q: q}
}

func (r *PostgresCodeRepo) CreateCode(ctx context.Context, code domain.OAuthCode) error {
	if err := r.q.InsertOAuthCode(ctx, code.Code, code.TenantID, code.UserID, code.ClientID, code.RedirectURI, code.Scope, code.ExpiresAt); err != nil {
		return fmt.Errorf("insert code: %w", err)
	}
	return nil
}

func (r *PostgresCodeRepo) GetCode(ctx context.Context, tenantID int64, code string) (domain.OAuthCode, error) {
	row, err := r.q.GetOAuthCode(ctx, tenantID, code)
	if err != nil {
		return domain.OAuthCode{}, fmt.Errorf("get code: %w", err)
	}
	return domain.OAuthCode{
		Code:        row.Code,
		TenantID:    row.TenantID,
		UserID:      row.UserID,
		ClientID:    row.ClientID,
		RedirectURI: row.RedirectURI,
		Scope:       row.Scope,
		ExpiresAt:   row.ExpiresAt,
		Used:        row.Used,
	}, nil
}

func (r *PostgresCodeRepo) MarkCodeUsed(ctx context.Context, code string) error {
	if err := r.q.MarkOAuthCodeUsed(ctx, code); err != nil {
		return fmt.Errorf("mark code used: %w", err)
	}
	return nil
}

// PostgresKeyRepo implements KeyRepository.
type PostgresKeyRepo struct {
	q *sqlc.Queries
}

func NewPostgresKeyRepo(q *sqlc.Queries) *PostgresKeyRepo {
	return &PostgresKeyRepo{q: q}
}

func (r *PostgresKeyRepo) GetActiveKey(ctx context.Context, tenantID int64) (domain.OAuthKey, error) {
	row, err := r.q.GetActiveOAuthKey(ctx, tenantID)
	if err != nil {
		return domain.OAuthKey{}, fmt.Errorf("get key: %w", err)
	}
	return mapKeyRow(row), nil
}

func (r *PostgresKeyRepo) CreateKey(ctx context.Context, key domain.OAuthKey) (domain.OAuthKey, error) {
	row, err := r.q.InsertOAuthKey(ctx, key.TenantID, key.KID, key.Secret, key.Algorithm)
	if err != nil {
		return domain.OAuthKey{}, fmt.Errorf("insert key: %w", err)
	}
	mapped := mapKeyRow(row)
	mapped.Active = true
	return mapped, nil
}

func mapKeyRow(row sqlc.GetActiveOAuthKeyRow) domain.OAuthKey {
	return domain.OAuthKey{
		ID:        row.ID,
		TenantID:  row.TenantID,
		KID:       row.KID,
		Secret:    row.Secret,
		Algorithm: row.Algorithm,
		Active:    row.Active,
		CreatedAt: row.CreatedAt,
	}
}

func mapUserRow(row sqlc.GetUserByEmailRow) domain.User {
	return domain.User{
		ID:             row.ID,
		TenantID:       row.TenantID,
		Email:          row.Email,
		PasswordHash:   row.PasswordHash,
		Name:           row.Name,
		PictureURL:     row.PictureURL,
		Blocked:        row.Blocked,
		FailedAttempts: int(row.FailedAttempts),
		LockedUntil:    row.LockedUntil,
		CreatedAt:      row.CreatedAt,
		UpdatedAt:      row.UpdatedAt,
	}
}
