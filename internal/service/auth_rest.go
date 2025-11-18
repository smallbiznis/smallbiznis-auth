package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/smallbiznis/smallbiznis-auth/internal/domain"
	basemiddleware "github.com/smallbiznis/smallbiznis-auth/internal/middleware"
	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

const defaultRESTScope = "openid profile email offline_access"

// LoginWithPassword performs username/password login and returns REST-friendly payload.
func (s *AuthService) LoginWithPassword(ctx context.Context, tenantID int64, email, password, clientID, scope string) (AuthTokensWithUser, error) {
	ctx, span := s.startSpan(ctx, "AuthService.LoginWithPassword")
	defer span.End()

	tenantCtx, err := s.tenantContextFromContext(ctx, tenantID, clientID)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	effectiveScope := coalesce(scope, defaultRESTScope)
	issuer := tenantIssuer(tenantCtx)

	tokenResp, err := s.PasswordGrant(ctx, tenantCtx, email, password, effectiveScope, issuer)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	user, err := s.users.GetByEmail(ctx, tenantID, normalizeIdentifier(email))
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("load user profile: %w", err)
	}

	s.audit("rest.password_login.success", "tenant_id", tenantID, "user_id", user.ID)
	return newAuthTokensWithUser(user, tokenResp), nil
}

func (s *AuthService) RegisterWithPassword(ctx context.Context, tenantID int64, email, password, name string) (AuthTokensWithUser, error) {
	ctx, span := s.startSpan(ctx, "AuthService.RegisterWithPassword")
	defer span.End()

	tenantCtx, err := s.tenantContextFromContext(ctx, tenantID, "")
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	normalized := normalizeIdentifier(email)
	if normalized == "" {
		return AuthTokensWithUser{}, newOAuthError("invalid_request", "Email is required.", http.StatusBadRequest)
	}
	if strings.TrimSpace(password) == "" {
		return AuthTokensWithUser{}, newOAuthError("invalid_request", "Password is required.", http.StatusBadRequest)
	}

	if _, err := s.users.GetByEmail(ctx, tenantID, normalized); err == nil {
		return AuthTokensWithUser{}, newOAuthError("invalid_request", "Email already registered.", http.StatusBadRequest)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("check existing user: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("hash password: %w", err)
	}

	model := domain.User{
		TenantID:     tenantID,
		Email:        normalized,
		PasswordHash: string(hashed),
		Name:         strings.TrimSpace(name),
		PictureURL:   "",
		LockedUntil:  time.Unix(0, 0).UTC(),
	}

	created, err := s.users.Create(ctx, model)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("create user: %w", err)
	}

	providers := make([]string, 0, len(tenantCtx.AuthProviders))
	for _, provider := range tenantCtx.AuthProviders {
		if provider.Enabled {
			providers = append(providers, provider.Type)
		}
	}

	tokenResp, err := s.issueTokens(ctx, tenantCtx, created, defaultRESTScope, tenantIssuer(tenantCtx), providers)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	s.audit("rest.password_register.success", "tenant_id", tenantID, "user_id", created.ID)
	return newAuthTokensWithUser(created, tokenResp), nil
}

// ForgotPassword kicks off password reset notifications.
func (s *AuthService) ForgotPassword(ctx context.Context, tenantID int64, email string) error {
	ctx, span := s.startSpan(ctx, "AuthService.ForgotPassword")
	defer span.End()

	normalized := normalizeIdentifier(email)
	if normalized == "" {
		return newOAuthError("invalid_request", "Email is required.", http.StatusBadRequest)
	}

	if _, err := s.users.GetByEmail(ctx, tenantID, normalized); err != nil {
		span.RecordError(err)
		if logger := s.log(); logger != nil {
			logger.Warn("password reset requested for unknown user",
				zap.Int64("tenant_id", tenantID),
				zap.String("email", normalized),
				zap.Error(err),
			)
		}
	}

	s.audit("rest.password_forgot.request", "tenant_id", tenantID, "email", normalized)
	return nil
}

// RequestOTP generates an OTP code for passwordless login.
func (s *AuthService) RequestOTP(ctx context.Context, tenantID int64, phone, channel string) error {
	ctx, span := s.startSpan(ctx, "AuthService.RequestOTP")
	defer span.End()

	tenantCtx, err := s.tenantContextFromContext(ctx, tenantID, "")
	if err != nil {
		span.RecordError(err)
		return err
	}
	if !tenantCtx.OTPConfig.Enabled {
		return newOAuthError("unsupported_grant_type", "OTP login disabled for tenant.", http.StatusBadRequest)
	}

	identifier := normalizeIdentifier(phone)
	if identifier == "" {
		return newOAuthError("invalid_request", "Phone identifier is required.", http.StatusBadRequest)
	}

	user, err := s.users.GetByEmail(ctx, tenantID, identifier)
	if err != nil {
		span.RecordError(err)
		return newOAuthError("invalid_request", "Account not eligible for OTP login.", http.StatusBadRequest)
	}

	_ = generateOTP(user.PasswordHash, tenantCtx.OTPConfig.Length, tenantCtx.OTPConfig.Ttl)
	s.audit("rest.otp_request.accepted", "tenant_id", tenantID, "user_id", user.ID, "channel", channel)

	return nil
}

// VerifyOTP validates OTP and issues OAuth tokens.
func (s *AuthService) VerifyOTP(ctx context.Context, tenantID int64, phone, code, clientID, scope string) (AuthTokensWithUser, error) {
	ctx, span := s.startSpan(ctx, "AuthService.VerifyOTP")
	defer span.End()

	tenantCtx, err := s.tenantContextFromContext(ctx, tenantID, clientID)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	effectiveScope := coalesce(scope, defaultRESTScope)
	issuer := tenantIssuer(tenantCtx)

	tokenResp, err := s.OTPGrant(ctx, tenantCtx, phone, code, effectiveScope, issuer)
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, err
	}

	user, err := s.users.GetByEmail(ctx, tenantID, normalizeIdentifier(phone))
	if err != nil {
		span.RecordError(err)
		return AuthTokensWithUser{}, fmt.Errorf("load user profile: %w", err)
	}

	s.audit("rest.otp_verify.success", "tenant_id", tenantID, "user_id", user.ID)
	return newAuthTokensWithUser(user, tokenResp), nil
}

func (s *AuthService) GetUserInfo(ctx context.Context, tenantID int64, userID int64) (UserViewModel, error) {
	ctx, span := s.startSpan(ctx, "AuthService.GetUserInfo")
	defer span.End()

	user, err := s.users.GetByID(ctx, tenantID, userID)
	if err != nil {
		span.RecordError(err)
		return UserViewModel{}, fmt.Errorf("load user: %w", err)
	}

	return UserViewModel{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		AvatarURL: user.PictureURL,
	}, nil
}

func (s *AuthService) tenantContextFromContext(ctx context.Context, tenantID int64, clientID string) (*tenant.Context, error) {
	tenantCtx, ok := basemiddleware.TenantContextFromContext(ctx)
	if !ok || tenantCtx == nil {
		return nil, newOAuthError("invalid_request", "Tenant context missing.", http.StatusBadRequest)
	}
	if tenantID != 0 && tenantCtx.Tenant.ID != tenantID {
		return nil, newOAuthError("invalid_request", "Tenant mismatch.", http.StatusBadRequest)
	}
	if clientID != "" {
		tenantCtx.ClientID = clientID
	}
	return tenantCtx, nil
}

func tenantIssuer(ctx *tenant.Context) string {
	if ctx.Domain.Host != "" {
		return fmt.Sprintf("https://%s", ctx.Domain.Host)
	}
	return ""
}

func newAuthTokensWithUser(user domain.User, tokenResp *TokenResponse) AuthTokensWithUser {
	return AuthTokensWithUser{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      "",
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    int64(tokenResp.ExpiresIn),
		User: UserViewModel{
			ID:        user.ID,
			Email:     user.Email,
			Name:      user.Name,
			AvatarURL: user.PictureURL,
		},
	}
}

func normalizeIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
