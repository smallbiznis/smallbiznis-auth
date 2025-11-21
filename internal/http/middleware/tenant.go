package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

const tenantContextKey = "tenantContext"

// Tenant attaches tenant metadata to the gin context.
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
		c.Set(tenantContextKey, tenantCtx)
		c.Next()
	}
}

// GetTenantContext extracts the tenant context from gin.
func GetTenantContext(c *gin.Context) (*tenant.Context, bool) {
	value, ok := c.Get(tenantContextKey)
	if !ok {
		return nil, false
	}
	tenantCtx, ok := value.(*tenant.Context)
	return tenantCtx, ok
}

func stripPort(host string) string {
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			return h
		}
	}
	return host
}
