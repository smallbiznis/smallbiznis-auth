package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/smallbiznis/smallbiznis-auth/internal/domain"
	"github.com/smallbiznis/smallbiznis-auth/sqlc"
)

// Compile-time interface assertions.
var (
	_ TenantRepository      = (*PostgresTenantRepo)(nil)
	_ UserRepository        = (*PostgresUserRepo)(nil)
	_ TokenRepository       = (*PostgresTokenRepo)(nil)
	_ CodeRepository        = (*PostgresCodeRepo)(nil)
	_ KeyRepository         = (*PostgresKeyRepo)(nil)
	_ OAuthClientRepository = (*PostgresOAuthClientRepo)(nil)
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
	return mapTenantRow(row), nil
}

func (r *PostgresTenantRepo) GetTenantBySlug(ctx context.Context, slug string) (domain.Tenant, error) {
	row, err := r.q.GetTenantBySlug(ctx, slug)
	if err != nil {
		return domain.Tenant{}, fmt.Errorf("get tenant by slug: %w", err)
	}
	return mapTenantRow(row), nil
}

func (r *PostgresTenantRepo) GetPrimaryDomain(ctx context.Context, tenantID int64) (domain.Domain, error) {
	row, err := r.q.GetPrimaryDomain(ctx, tenantID)
	if err != nil {
		return domain.Domain{}, fmt.Errorf("get primary domain: %w", err)
	}
	return domain.Domain{ID: row.ID, Host: row.Host, TenantID: row.TenantID}, nil
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
		var configID *int64
		if row.ProviderConfigID.Valid {
			val := row.ProviderConfigID.Int64
			configID = &val
		}
		providers = append(providers, domain.AuthProvider{
			ID:               row.ID,
			TenantID:         row.TenantID,
			ProviderType:     row.ProviderType,
			ProviderConfigID: configID,
			IsActive:         row.IsActive,
			CreatedAt:        row.CreatedAt,
			UpdatedAt:        row.UpdatedAt,
		})
	}
	return providers, nil
}

func (r *PostgresTenantRepo) GetPasswordConfig(ctx context.Context, tenantID int64) (domain.PasswordConfig, error) {
	row, err := r.q.GetPasswordConfig(ctx, tenantID)
	if err != nil {
		return domain.PasswordConfig{}, fmt.Errorf("get password config: %w", err)
	}
	return domain.PasswordConfig{
		TenantID:               row.TenantID,
		MinLength:              int(row.MinLength),
		RequireUppercase:       row.RequireUppercase,
		RequireNumber:          row.RequireNumber,
		RequireSymbol:          row.RequireSymbol,
		AllowSignup:            row.AllowSignup,
		AllowPasswordReset:     row.AllowPasswordReset,
		LockoutAttempts:        int(row.LockoutAttempts),
		LockoutDurationSeconds: int(row.LockoutDurationSeconds),
		CreatedAt:              row.CreatedAt,
		UpdatedAt:              row.UpdatedAt,
	}, nil
}

func (r *PostgresTenantRepo) GetOTPConfig(ctx context.Context, tenantID int64) (domain.OTPConfig, error) {
	row, err := r.q.GetOTPConfig(ctx, tenantID)
	if err != nil {
		return domain.OTPConfig{}, fmt.Errorf("get otp config: %w", err)
	}
	return domain.OTPConfig{
		TenantID:      row.TenantID,
		Channel:       row.Channel,
		Provider:      row.Provider,
		APIKey:        row.APIKey.String,
		Sender:        row.Sender.String,
		Template:      row.Template.String,
		ExpirySeconds: int(row.ExpirySeconds),
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}, nil
}

func (r *PostgresTenantRepo) ListOAuthIDPConfigs(ctx context.Context, tenantID int64) ([]domain.OAuthIDPConfig, error) {
	rows, err := r.q.ListOAuthIDPConfigs(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list oauth idps: %w", err)
	}
	res := make([]domain.OAuthIDPConfig, 0, len(rows))
	for _, row := range rows {
		var scopes []string
		if len(row.Scopes) > 0 {
			scopes = row.Scopes
		}
		extra := map[string]any{}
		if len(row.Extra) > 0 {
			_ = json.Unmarshal(row.Extra, &extra)
		}
		res = append(res, domain.OAuthIDPConfig{
			TenantID:         row.TenantID,
			Provider:         row.Provider,
			ClientID:         row.ClientID,
			ClientSecret:     row.ClientSecret,
			IssuerURL:        row.IssuerURL,
			AuthorizationURL: row.AuthorizationURL,
			TokenURL:         row.TokenURL,
			UserinfoURL:      row.UserinfoURL,
			JWKSURL:          row.JWKSURL,
			Scopes:           scopes,
			Extra:            extra,
			CreatedAt:        row.CreatedAt,
			UpdatedAt:        row.UpdatedAt,
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

const insertUserSQL = `INSERT INTO users (id, tenant_id, email, email_verified, password_hash, name, phone, phone_verified, avatar_url, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id, tenant_id, email, email_verified, password_hash, name, phone, phone_verified, avatar_url, status, created_at, updated_at`

func (r *PostgresUserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	row := r.db.QueryRow(ctx, insertUserSQL,
		user.ID,
		user.TenantID,
		user.Email,
		user.EmailVerified,
		user.PasswordHash,
		user.Name,
		user.Phone,
		user.PhoneVerified,
		user.AvatarURL,
		user.Status,
	)

	var inserted sqlc.GetUserByEmailRow
	if err := row.Scan(
		&inserted.ID,
		&inserted.TenantID,
		&inserted.Email,
		&inserted.EmailVerified,
		&inserted.PasswordHash,
		&inserted.Name,
		&inserted.Phone,
		&inserted.PhoneVerified,
		&inserted.AvatarURL,
		&inserted.Status,
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
	refresh := sql.NullString{}
	if token.RefreshToken != "" {
		refresh = sql.NullString{String: token.RefreshToken, Valid: true}
	}
	row, err := r.q.InsertOAuthToken(ctx, token.ID, token.TenantID, token.ClientID, token.UserID, token.AccessToken, refresh, token.Scopes, token.ExpiresAt)
	if err != nil {
		return domain.OAuthToken{}, fmt.Errorf("insert token: %w", err)
	}
	return mapTokenRow(row), nil
}

func (r *PostgresTokenRepo) GetByRefreshToken(ctx context.Context, tenantID int64, token string) (domain.OAuthToken, error) {
	row, err := r.q.GetOAuthTokenByRefresh(ctx, tenantID, token)
	if err != nil {
		return domain.OAuthToken{}, fmt.Errorf("get refresh token: %w", err)
	}
	return mapTokenRow(row), nil
}

func (r *PostgresTokenRepo) GetByRefreshTokenValue(ctx context.Context, token string) (domain.OAuthToken, error) {
	row, err := r.q.GetOAuthTokenByRefreshValue(ctx, token)
	if err != nil {
		return domain.OAuthToken{}, fmt.Errorf("get refresh token value: %w", err)
	}
	return mapTokenRow(row), nil
}

func (r *PostgresTokenRepo) GetByAccessToken(ctx context.Context, token string) (domain.OAuthToken, error) {
	row, err := r.q.GetOAuthTokenByAccess(ctx, token)
	if err != nil {
		return domain.OAuthToken{}, fmt.Errorf("get access token: %w", err)
	}
	return mapTokenRow(row), nil
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
	var challenge sql.NullString
	if code.CodeChallenge != "" {
		challenge = sql.NullString{String: code.CodeChallenge, Valid: true}
	}
	var challengeMethod sql.NullString
	if code.CodeChallengeMethod != "" {
		challengeMethod = sql.NullString{String: code.CodeChallengeMethod, Valid: true}
	}
	if err := r.q.InsertOAuthCode(ctx, code.ID, code.TenantID, code.ClientID, code.UserID, code.Code, code.RedirectURI, challenge, challengeMethod, code.ExpiresAt); err != nil {
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
		ID:                  row.ID,
		TenantID:            row.TenantID,
		ClientID:            row.ClientID,
		UserID:              row.UserID,
		Code:                row.Code,
		RedirectURI:         row.RedirectURI,
		CodeChallenge:       row.CodeChallenge.String,
		CodeChallengeMethod: row.CodeChallengeMethod.String,
		ExpiresAt:           row.ExpiresAt,
		Revoked:             row.Revoked,
		CreatedAt:           row.CreatedAt,
	}, nil
}

func (r *PostgresCodeRepo) MarkCodeUsed(ctx context.Context, code string) error {
	if err := r.q.RevokeOAuthCode(ctx, code); err != nil {
		return fmt.Errorf("revoke code: %w", err)
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
	mapped.IsActive = true
	return mapped, nil
}

// PostgresOAuthClientRepo implements OAuthClientRepository.
type PostgresOAuthClientRepo struct {
	db *pgxpool.Pool
}

func NewPostgresOAuthClientRepo(pool *pgxpool.Pool) *PostgresOAuthClientRepo {
	return &PostgresOAuthClientRepo{db: pool}
}

func (r *PostgresOAuthClientRepo) GetClientByID(ctx context.Context, tenantID int64, clientID string) (domain.OAuthClient, error) {
	const query = `
SELECT id, tenant_id, app_id, client_id, client_secret, redirect_uris, grants, scopes, token_endpoint_auth_methods, require_consent, created_at
FROM oauth_clients
WHERE tenant_id = $1 AND client_id = $2
LIMIT 1`

	var (
		rowID        int64
		rowTenantID  int64
		rowAppID     sql.NullInt64
		rowClientID  string
		rowSecret    string
		redirectURIs []string
		grants       []string
		scopes       []string
		authMethods  []string
		requireCons  bool
		createdAt    time.Time
	)

	if err := r.db.QueryRow(ctx, query, tenantID, clientID).Scan(
		&rowID,
		&rowTenantID,
		&rowAppID,
		&rowClientID,
		&rowSecret,
		&redirectURIs,
		&grants,
		&scopes,
		&authMethods,
		&requireCons,
		&createdAt,
	); err != nil {
		return domain.OAuthClient{}, fmt.Errorf("get oauth client: %w", err)
	}

	var appID *int64
	if rowAppID.Valid {
		val := rowAppID.Int64
		appID = &val
	}

	return domain.OAuthClient{
		ID:                       rowID,
		TenantID:                 rowTenantID,
		AppID:                    appID,
		ClientID:                 rowClientID,
		ClientSecret:             rowSecret,
		RedirectURIs:             append([]string{}, redirectURIs...),
		Grants:                   append([]string{}, grants...),
		Scopes:                   append([]string{}, scopes...),
		TokenEndpointAuthMethods: append([]string{}, authMethods...),
		RequireConsent:           requireCons,
		CreatedAt:                createdAt,
	}, nil
}

func mapTenantRow(row sqlc.GetTenantRow) domain.Tenant {
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
	}
}

func mapKeyRow(row sqlc.GetActiveOAuthKeyRow) domain.OAuthKey {
	return domain.OAuthKey{
		ID:        row.ID,
		TenantID:  row.TenantID,
		KID:       row.KID,
		Secret:    row.Secret,
		Algorithm: row.Algorithm,
		IsActive:  row.IsActive,
		CreatedAt: row.CreatedAt,
		RotatedAt: nullableTime(row.RotatedAt),
	}
}

func mapTokenRow(row sqlc.InsertOAuthTokenRow) domain.OAuthToken {
	scopes := row.Scopes
	return domain.OAuthToken{
		ID:           row.ID,
		TenantID:     row.TenantID,
		ClientID:     row.ClientID,
		UserID:       row.UserID,
		AccessToken:  row.AccessToken,
		RefreshToken: row.RefreshToken.String,
		Scopes:       scopes,
		ExpiresAt:    row.ExpiresAt,
		Revoked:      row.Revoked,
		CreatedAt:    row.CreatedAt,
	}
}

func nullableTime(t sql.NullTime) *time.Time {
	if t.Valid {
		return &t.Time
	}
	return nil
}

func mapUserRow(row sqlc.GetUserByEmailRow) domain.User {
	avatar := ""
	if row.AvatarURL.Valid {
		avatar = row.AvatarURL.String
	}
	return domain.User{
		ID:            row.ID,
		TenantID:      row.TenantID,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		PasswordHash:  row.PasswordHash,
		Name:          row.Name,
		Phone:         row.Phone,
		PhoneVerified: row.PhoneVerified,
		AvatarURL:     avatar,
		Status:        row.Status,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
}
