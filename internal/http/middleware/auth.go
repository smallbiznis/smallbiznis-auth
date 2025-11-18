package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/smallbiznis/smallbiznis-auth/internal/jwt"
	"github.com/smallbiznis/smallbiznis-auth/internal/service"
)

const (
	accessClaimsKey = "accessClaims"
	stdClaimsKey    = "stdClaims"
)

// Auth validates Authorization header and attaches claims.
type Auth struct {
	AuthService *service.AuthService
}

// ValidateJWT ensures the request has a valid bearer token.
func (m *Auth) ValidateJWT(c *gin.Context) {
	tenantCtx, ok := GetTenantContext(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_tenant", "error_description": "Tenant missing."})
		return
	}
	header := c.GetHeader("Authorization")
	if header == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Authorization header required."})
		return
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Bearer token required."})
		return
	}
	issuer := fmt.Sprintf("https://%s", stripPortHost(c.Request.Host))
	claims, custom, err := m.AuthService.ValidateToken(c.Request.Context(), tenantCtx.Tenant.ID, parts[1], issuer)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Invalid access token."})
		return
	}
	c.Set(stdClaimsKey, claims)
	c.Set(accessClaimsKey, custom)
	c.Next()
}

// GetAccessClaims exposes custom access token claims to handlers.
func GetAccessClaims(c *gin.Context) (*jwt.AccessTokenClaims, bool) {
	value, ok := c.Get(accessClaimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := value.(*jwt.AccessTokenClaims)
	return claims, ok
}

// GetStdClaims returns standard JWT claims set.
func GetStdClaims(c *gin.Context) (*gojwt.Claims, bool) {
	value, ok := c.Get(stdClaimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := value.(*gojwt.Claims)
	return claims, ok
}

func stripPortHost(host string) string {
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
	}
	return host
}
