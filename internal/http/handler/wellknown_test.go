package handler_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/smallbiznis/smallbiznis-auth/internal/config"
	"github.com/smallbiznis/smallbiznis-auth/internal/domain"
	httpHandler "github.com/smallbiznis/smallbiznis-auth/internal/http/handler"
	"github.com/smallbiznis/smallbiznis-auth/internal/jwt"
	"github.com/smallbiznis/smallbiznis-auth/internal/repository"
	"github.com/smallbiznis/smallbiznis-auth/internal/service"
	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

func TestJWKSHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenantCtx := testTenantCtx()
	authSvc := newTestAuthService()
	handler := httpHandler.NewAuthHandler(authSvc, &service.DiscoveryService{})

	req := httptest.NewRequest(http.MethodGet, "https://tenant.smallbiznis/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("tenantContext", tenantCtx)

	handler.JWKS(c)

	res := w.Result()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	t.Logf("jwks response: %s", string(body))
	require.Contains(t, string(body), "keys")
}

func TestOpenIDConfigurationResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tenantCtx := testTenantCtx()
	handler := httpHandler.NewAuthHandler(newTestAuthService(), &service.DiscoveryService{})

	req := httptest.NewRequest(http.MethodGet, "https://tenant.smallbiznis/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("tenantContext", tenantCtx)

	handler.OpenIDConfig(c)

	res := w.Result()
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	require.Equal(t, http.StatusOK, res.StatusCode)
	require.Contains(t, string(body), "authorization_endpoint")
	require.Contains(t, string(body), "jwks_uri")
}

func testTenantCtx() *tenant.Context {
	return &tenant.Context{
		Domain:         domain.Domain{Host: "tenant.smallbiznis"},
		Tenant:         domain.Tenant{ID: 1, Name: "SmallBiznis", Code: "client", Timezone: "Asia/Singapore"},
		ClientID:       "client",
		Branding:       domain.Branding{TenantID: 1, LogoURL: strPtr("https://cdn/logo.png")},
		AuthProviders:  []domain.AuthProvider{{TenantID: 1, ProviderType: "password", IsActive: true}},
		PasswordConfig: domain.PasswordConfig{TenantID: 1, MinLength: 8, LockoutAttempts: 5, LockoutDurationSeconds: 300},
		OTPConfig:      domain.OTPConfig{TenantID: 1, Channel: "sms", ExpirySeconds: 300},
	}
}

func newTestAuthService() *service.AuthService {
	keyRepo := &inMemoryKeyRepo{}
	keyManager := jwt.NewKeyManager(keyRepo)
	generator := jwt.NewGenerator(keyManager, time.Minute)
	cfg := config.Config{AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, RefreshTokenBytes: 32}
	logger := zap.NewNop()
	return service.NewAuthService(&noopUserRepo{}, &noopTokenRepo{}, &noopCodeRepo{}, generator, keyManager, cfg, logger)
}

type noopUserRepo struct{}

type noopTokenRepo struct{}

type noopCodeRepo struct{}

type inMemoryKeyRepo struct{ key domain.OAuthKey }

var _ repository.UserRepository = (*noopUserRepo)(nil)
var _ repository.TokenRepository = (*noopTokenRepo)(nil)
var _ repository.CodeRepository = (*noopCodeRepo)(nil)
var _ repository.KeyRepository = (*inMemoryKeyRepo)(nil)

func (n *noopUserRepo) GetByEmail(ctx context.Context, tenantID int64, email string) (domain.User, error) {
	return domain.User{}, fmt.Errorf("not implemented")
}

func (n *noopUserRepo) GetByID(ctx context.Context, tenantID, userID int64) (domain.User, error) {
	return domain.User{}, fmt.Errorf("not implemented")
}

func (n *noopUserRepo) Create(ctx context.Context, user domain.User) (domain.User, error) {
	return user, fmt.Errorf("not implemented")
}

func (n *noopTokenRepo) CreateToken(ctx context.Context, token domain.OAuthToken) (domain.OAuthToken, error) {
	return token, nil
}

func (n *noopTokenRepo) GetByRefreshToken(ctx context.Context, tenantID int64, token string) (domain.OAuthToken, error) {
	return domain.OAuthToken{}, fmt.Errorf("not implemented")
}

func (n *noopTokenRepo) RotateRefreshToken(ctx context.Context, tokenID int64, refreshToken string, expiresAt int64) error {
	return nil
}

func (n *noopTokenRepo) RevokeToken(ctx context.Context, tokenID int64) error { return nil }

func (n *noopCodeRepo) CreateCode(ctx context.Context, code domain.OAuthCode) error { return nil }

func (n *noopCodeRepo) GetCode(ctx context.Context, tenantID int64, code string) (domain.OAuthCode, error) {
	return domain.OAuthCode{}, fmt.Errorf("not implemented")
}

func (n *noopCodeRepo) MarkCodeUsed(ctx context.Context, code string) error { return nil }

func (i *inMemoryKeyRepo) GetActiveKey(ctx context.Context, tenantID int64) (domain.OAuthKey, error) {
	if i.key.ID == 0 {
		return domain.OAuthKey{}, pgx.ErrNoRows
	}
	return i.key, nil
}

func (i *inMemoryKeyRepo) CreateKey(ctx context.Context, key domain.OAuthKey) (domain.OAuthKey, error) {
	key.ID = 1
	i.key = key
	return key, nil
}

func strPtr(s string) *string {
	return &s
}
