package handler

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smallbiznis/smallbiznis-auth/internal/http/middleware"
	"github.com/smallbiznis/smallbiznis-auth/internal/service"
)

// AuthHandler orchestrates OAuth endpoints.
type AuthHandler struct {
	Auth      *service.AuthService
	Discovery *service.DiscoveryService
}

// NewAuthHandler creates the handler set.
func NewAuthHandler(auth *service.AuthService, discovery *service.DiscoveryService) *AuthHandler {
	return &AuthHandler{Auth: auth, Discovery: discovery}
}

// TenantDiscovery returns metadata.
func (h *AuthHandler) TenantDiscovery(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Tenant not resolved."})
		return
	}
	c.JSON(http.StatusOK, h.Discovery.TenantMetadata(tenantCtx))
}

// OpenIDConfig returns OpenID discovery document.
func (h *AuthHandler) OpenIDConfig(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Tenant not resolved."})
		return
	}
	c.JSON(http.StatusOK, h.Discovery.OpenIDConfigurationResponse(hostOnly(c.Request), tenantCtx))
}

// JWKS exposes tenant public keys.
func (h *AuthHandler) JWKS(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Tenant not resolved."})
		return
	}
	jwks, err := h.Auth.JWKS(c.Request.Context(), tenantCtx.Tenant.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	c.JSON(http.StatusOK, jwks)
}

// Token handles OAuth token grant exchanges.
func (h *AuthHandler) Token(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Tenant not resolved."})
		return
	}

	var req struct {
		GrantType    string `form:"grant_type" binding:"required"`
		Username     string `form:"username"`
		Password     string `form:"password"`
		Scope        string `form:"scope"`
		RefreshToken string `form:"refresh_token"`
		Code         string `form:"code"`
		RedirectURI  string `form:"redirect_uri"`
		OTP          string `form:"otp"`
	}
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "Invalid token request."})
		return
	}

	issuer := "https://" + hostOnly(c.Request)
	var (
		resp *service.TokenResponse
		err  error
	)

	switch strings.ToLower(req.GrantType) {
	case "password":
		resp, err = h.Auth.PasswordGrant(c.Request.Context(), tenantCtx, req.Username, req.Password, req.Scope, issuer)
	case "refresh_token":
		resp, err = h.Auth.RefreshGrant(c.Request.Context(), tenantCtx, req.RefreshToken, req.Scope, issuer)
	case "authorization_code":
		resp, err = h.Auth.AuthorizationCodeGrant(c.Request.Context(), tenantCtx, req.Code, req.RedirectURI, req.Scope, issuer)
	case "client_credentials":
		resp, err = h.Auth.ClientCredentialsGrant(c.Request.Context())
	case "device_code":
		resp, err = h.Auth.DeviceCodeGrant(c.Request.Context())
	case "otp", "http://auth0.com/oauth/grant-type/passwordless/otp":
		resp, err = h.Auth.OTPGrant(c.Request.Context(), tenantCtx, req.Username, req.OTP, req.Scope, issuer)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type", "error_description": "Unsupported grant type."})
		return
	}

	if err != nil {
		if oauthErr, ok := err.(*service.OAuthError); ok {
			c.JSON(oauthErr.Status, gin.H{"error": oauthErr.Code, "error_description": oauthErr.Description})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Authorize currently stubs the interactive authorization endpoint.
func (h *AuthHandler) Authorize(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented", "error_description": "Interactive authorization UI is not implemented."})
}

// UserInfo returns profile from access token.
func (h *AuthHandler) UserInfo(c *gin.Context) {
	claims, ok := middleware.GetAccessClaims(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Missing claims."})
		return
	}
	std, _ := middleware.GetStdClaims(c)
	sub := ""
	if std != nil {
		sub = std.Subject
	}
	c.JSON(http.StatusOK, gin.H{
		"sub":       sub,
		"email":     claims.Email,
		"name":      claims.Name,
		"picture":   claims.Picture,
		"tenant_id": claims.TenantID,
		"scope":     claims.Scope,
	})
}

func hostOnly(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
	}
	return host
}
