package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smallbiznis/smallbiznis-auth/internal/domain"
	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

func TestResolverResolve(t *testing.T) {
	repo := &mockTenantRepo{}
	resolver := tenant.NewResolver(repo)

	ctx, err := resolver.Resolve(context.Background(), "tenant.smallbiznis.test")
	require.NoError(t, err)
	require.Equal(t, int64(1), ctx.Tenant.ID)
	require.Equal(t, "SmallBiznis", ctx.Tenant.Name)
	require.Equal(t, "client", ctx.ClientID)
	require.Len(t, ctx.AuthProviders, 1)
	require.True(t, ctx.PasswordConfig.Enabled)
}

type mockTenantRepo struct{}

func (m *mockTenantRepo) GetDomainByHost(ctx context.Context, host string) (domain.Domain, error) {
	return domain.Domain{ID: 1, Host: host, TenantID: 1}, nil
}

func (m *mockTenantRepo) GetTenant(ctx context.Context, tenantID int64) (domain.Tenant, error) {
	return domain.Tenant{ID: tenantID, Name: "SmallBiznis", Code: "client", Slug: "smallbiznis"}, nil
}

func (m *mockTenantRepo) GetBranding(ctx context.Context, tenantID int64) (domain.Branding, error) {
	return domain.Branding{TenantID: tenantID, LogoURL: strPtr("https://cdn/logo.png")}, nil
}

func (m *mockTenantRepo) ListAuthProviders(ctx context.Context, tenantID int64) ([]domain.AuthProvider, error) {
	return []domain.AuthProvider{{TenantID: tenantID, Type: "password", Enabled: true}}, nil
}

func (m *mockTenantRepo) GetPasswordConfig(ctx context.Context, tenantID int64) (domain.PasswordConfig, error) {
	return domain.PasswordConfig{TenantID: tenantID, Enabled: true, MaxAttempts: 5}, nil
}

func (m *mockTenantRepo) GetOTPConfig(ctx context.Context, tenantID int64) (domain.OTPConfig, error) {
	return domain.OTPConfig{TenantID: tenantID, Enabled: true, Length: 6}, nil
}

func (m *mockTenantRepo) ListOAuthIDPConfigs(ctx context.Context, tenantID int64) ([]domain.OAuthIDPConfig, error) {
	return []domain.OAuthIDPConfig{{TenantID: tenantID, Provider: "google", Enabled: true}}, nil
}

func strPtr(s string) *string {
	return &s
}
