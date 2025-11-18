package tenant

import (
	"context"
	"fmt"
	"strings"

	"github.com/smallbiznis/smallbiznis-auth/internal/domain"
	"github.com/smallbiznis/smallbiznis-auth/internal/repository"
	"go.uber.org/zap"
)

// Context stores resolved tenant metadata used throughout the request lifecycle.
type Context struct {
	Domain          domain.Domain
	Tenant          domain.Tenant
	ClientID        string
	Branding        domain.Branding
	AuthProviders   []domain.AuthProvider
	PasswordConfig  domain.PasswordConfig
	OTPConfig       domain.OTPConfig
	SocialProviders []domain.OAuthIDPConfig
}

// Resolver loads tenant metadata from repositories.
type Resolver struct {
	repo repository.TenantRepository
}

// NewResolver creates a tenant resolver.
func NewResolver(repo repository.TenantRepository) *Resolver {
	return &Resolver{repo: repo}
}

// Resolve loads tenant information from host header.
func (r *Resolver) Resolve(ctx context.Context, host string) (*Context, error) {
	cleaned := strings.ToLower(strings.TrimSpace(host))
	if cleaned == "" {
		zap.L().Warn("tenant resolver received empty host")
		return nil, fmt.Errorf("resolve tenant: empty host")
	}

	domainRow, err := r.repo.GetDomainByHost(ctx, cleaned)
	if err != nil {
		zap.L().Error("failed to resolve domain", zap.String("host", cleaned), zap.Error(err))
		return nil, fmt.Errorf("resolve domain: %w", err)
	}

	tenantRow, err := r.repo.GetTenant(ctx, domainRow.TenantID)
	if err != nil {
		zap.L().Error("failed to resolve tenant", zap.String("host", cleaned), zap.Int64("tenant_id", domainRow.TenantID), zap.Error(err))
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}

	branding, err := r.repo.GetBranding(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to resolve branding", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve branding: %w", err)
	}

	authProviders, err := r.repo.ListAuthProviders(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to list auth providers", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve auth providers: %w", err)
	}

	passwordConfig, err := r.repo.GetPasswordConfig(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to load password config", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve password config: %w", err)
	}

	otpConfig, err := r.repo.GetOTPConfig(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to load otp config", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve otp config: %w", err)
	}

	socialProviders, err := r.repo.ListOAuthIDPConfigs(ctx, tenantRow.ID)
	if err != nil {
		zap.L().Error("failed to load social providers", zap.Int64("tenant_id", tenantRow.ID), zap.Error(err))
		return nil, fmt.Errorf("resolve social providers: %w", err)
	}

	zap.L().Debug("tenant context resolved", zap.String("host", cleaned), zap.Int64("tenant_id", tenantRow.ID))

	return &Context{
		Domain:          domainRow,
		Tenant:          tenantRow,
		ClientID:        tenantRow.Code,
		Branding:        branding,
		AuthProviders:   authProviders,
		PasswordConfig:  passwordConfig,
		OTPConfig:       otpConfig,
		SocialProviders: socialProviders,
	}, nil
}
