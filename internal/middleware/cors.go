package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smallbiznis/smallbiznis-auth/internal/config"
	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

// TenantCORS applies CORS headers per tenant with global fallbacks.
func TenantCORS(cfg config.Config) gin.HandlerFunc {
	joinedMethods := strings.Join(cfg.CORSAllowedMethods, ", ")
	joinedHeaders := strings.Join(cfg.CORSAllowedHeaders, ", ")

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		allowedOrigins := buildAllowedOrigins(cfg.CORSAllowedOrigins, tenantOrigins(c))
		if !originAllowed(origin, allowedOrigins) {
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
			return
		}

		header := c.Writer.Header()
		header.Set("Vary", "Origin")
		header.Set("Access-Control-Allow-Methods", joinedMethods)
		header.Set("Access-Control-Allow-Headers", joinedHeaders)
		if cfg.CORSAllowCredentials {
			header.Set("Access-Control-Allow-Credentials", "true")
		}

		if containsWildcard(allowedOrigins) && !cfg.CORSAllowCredentials {
			header.Set("Access-Control-Allow-Origin", "*")
		} else {
			header.Set("Access-Control-Allow-Origin", origin)
		}

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func tenantOrigins(c *gin.Context) []string {
	tc, ok := tenantContextFromGin(c)
	if !ok || tc == nil {
		return nil
	}

	var origins []string
	appendIf := func(val string) {
		if val != "" {
			origins = append(origins, val)
		}
	}

	appendIf(tc.Tenant.Name)
	if host := tc.Domain.Host; host != "" {
		appendIf("https://" + host)
		appendIf("http://" + host)
	}

	return origins
}

func buildAllowedOrigins(global []string, tenantSpecific []string) []string {
	if len(tenantSpecific) == 0 {
		return global
	}

	seen := make(map[string]struct{}, len(global)+len(tenantSpecific))
	var result []string
	for _, item := range append(global, tenantSpecific...) {
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result
}

func originAllowed(origin string, allowed []string) bool {
	for _, candidate := range allowed {
		if candidate == "*" || strings.EqualFold(candidate, origin) {
			return true
		}
	}
	return false
}

func containsWildcard(origins []string) bool {
	for _, o := range origins {
		if o == "*" {
			return true
		}
	}
	return false
}

func tenantContextFromGin(c *gin.Context) (*tenant.Context, bool) {
	value, ok := c.Get(ginTenantContextKey)
	if !ok {
		return nil, false
	}
	tc, ok := value.(*tenant.Context)
	return tc, ok
}
