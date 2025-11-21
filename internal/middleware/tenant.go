package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

const ginTenantContextKey = "tenantContext"

type tenantContextKey struct{}

// Tenant resolves the tenant from the Host header and stores it in Gin and request contexts.
func Tenant(resolver *tenant.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantSlug := strings.TrimSpace(c.Request.Header.Get("X-Tenant-ID"))

		var (
			tenantCtx *tenant.Context
			err       error
		)

		if tenantSlug != "" {
			tenantCtx, err = resolver.ResolveBySlug(c.Request.Context(), tenantSlug)
		} else {
			host := stripPort(c.Request.Host)
			tenantCtx, err = resolver.Resolve(c.Request.Context(), host)
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Unknown tenant."})
			return
		}

		ctx := context.WithValue(c.Request.Context(), tenantContextKey{}, tenantCtx)
		c.Request = c.Request.WithContext(ctx)

		c.Set(ginTenantContextKey, tenantCtx)
		c.Set("tenant_id", tenantCtx.Tenant.ID)

		c.Next()
	}
}

// TenantContextFromContext extracts the tenant context from a standard context.
func TenantContextFromContext(ctx context.Context) (*tenant.Context, bool) {
	value := ctx.Value(tenantContextKey{})
	if value == nil {
		return nil, false
	}
	tenantCtx, ok := value.(*tenant.Context)
	return tenantCtx, ok
}

func stripPort(host string) string {
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
	}
	return host
}
