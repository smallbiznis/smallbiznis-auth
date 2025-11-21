package handler

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	domainoauth "github.com/smallbiznis/smallbiznis-auth/internal/domain/oauth"
	"github.com/smallbiznis/smallbiznis-auth/internal/http/middleware"
	"github.com/smallbiznis/smallbiznis-auth/internal/service"
	authsvc "github.com/smallbiznis/smallbiznis-auth/internal/service/auth"
)

// AuthHandler orchestrates OAuth endpoints.
type AuthHandler struct {
	Auth      *service.AuthService
	OAuth     authsvc.OAuthService
	Discovery *service.DiscoveryService
}

// NewAuthHandler creates the handler set.
func NewAuthHandler(auth *service.AuthService, oauth authsvc.OAuthService, discovery *service.DiscoveryService) *AuthHandler {
	return &AuthHandler{Auth: auth, OAuth: oauth, Discovery: discovery}
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

	issuer := fmt.Sprintf("%s://%s", schemeOnly(c.Request), hostOnly(c.Request))
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

// OAuthListProviders exposes enabled IdPs by tenant.
func (h *AuthHandler) OAuthListProviders(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Tenant not resolved."})
		return
	}
	providers, err := h.OAuth.ListProviders(c.Request.Context(), tenantCtx.Tenant.ID)
	if err != nil {
		h.respondOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, providers)
}

// OAuthStart generates authorization URLs with PKCE and state.
func (h *AuthHandler) OAuthStart(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Tenant not resolved."})
		return
	}
	provider := strings.TrimSpace(c.Query("provider"))
	redirectURI := strings.TrimSpace(c.Query("redirect_uri"))
	if provider == "" || redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "provider and redirect_uri are required."})
		return
	}
	var scopes []string
	if scopeParam := strings.TrimSpace(c.Query("scope")); scopeParam != "" {
		scopes = strings.Fields(scopeParam)
	}
	output, err := h.OAuth.StartAuthorization(c.Request.Context(), tenantCtx.Tenant.ID, authsvc.StartAuthorizationInput{
		Provider:    provider,
		RedirectURI: redirectURI,
		Scopes:      scopes,
	})
	if err != nil {
		h.respondOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"authorization_url": output.AuthorizationURL,
		"state":             output.State,
		"nonce":             output.Nonce,
	})
}

// OAuthCallback handles provider callbacks, issues session cookie, and redirects to client.
func (h *AuthHandler) OAuthCallback(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Tenant not resolved."})
		return
	}
	input := authsvc.OAuthCallbackInput{
		Provider:    c.Query("provider"),
		Code:        c.Query("code"),
		State:       c.Query("state"),
		RedirectURI: c.Query("redirect_uri"),
	}
	if strings.TrimSpace(input.Provider) == "" || strings.TrimSpace(input.Code) == "" || strings.TrimSpace(input.State) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "provider, code, and state are required."})
		return
	}
	issuer := fmt.Sprintf("%s://%s", schemeOnly(c.Request), hostOnly(c.Request))
	ctx := authsvc.WithIssuer(c.Request.Context(), issuer)
	session, err := h.OAuth.HandleCallback(ctx, tenantCtx.Tenant.ID, input)
	if err != nil {
		h.respondOAuthServiceError(c, err)
		return
	}

	expiry := time.Now().Add(time.Duration(session.ExpiresIn) * time.Second)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "sbn_session",
		Value:    session.AccessToken,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	redirect := strings.TrimSpace(c.Query("redirect_uri"))
	if redirect == "" {
		redirect = "/"
	}
	c.Redirect(http.StatusFound, redirect)
}

// OAuthIntrospect validates tokens per RFC 7662.
func (h *AuthHandler) OAuthIntrospect(c *gin.Context) {
	var req struct {
		Token string `form:"token" json:"token" binding:"required"`
	}
	if err := c.ShouldBind(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "token is required."})
		return
	}
	result, err := h.OAuth.IntrospectToken(c.Request.Context(), req.Token)
	if err != nil {
		h.respondOAuthServiceError(c, err)
		return
	}
	if result == nil || !result.Active {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"active":    true,
		"sub":       result.Subject,
		"scope":     result.Scope,
		"exp":       result.ExpiresAt,
		"iat":       result.IssuedAt,
		"client_id": result.ClientID,
		"tenant_id": result.TenantID,
	})
}

// OAuthRevoke processes RFC 7009 token revocation.
func (h *AuthHandler) OAuthRevoke(c *gin.Context) {
	var req struct {
		Token string `form:"token" json:"token" binding:"required"`
	}
	if err := c.ShouldBind(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "token is required."})
		return
	}
	if err := h.OAuth.RevokeToken(c.Request.Context(), req.Token); err != nil {
		h.respondOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// OAuthUserInfo returns standard OIDC userinfo data.
func (h *AuthHandler) OAuthUserInfo(c *gin.Context) {
	authz := c.GetHeader("Authorization")
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		c.Header("WWW-Authenticate", "Bearer")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Authorization header missing or invalid."})
		return
	}
	info, err := h.OAuth.UserInfo(c.Request.Context(), strings.TrimSpace(parts[1]))
	if err != nil {
		h.respondOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, info)
}

func (h *AuthHandler) OAuthAuthorize(c *gin.Context) {
	tenantCtx, ok := middleware.GetTenantContext(c)
	if !ok {
		h.oauthErrorRedirect(c, "invalid_tenant", "Tenant could not be resolved.")
		return
	}

	var req struct {
		ClientID            string `form:"client_id"`
		ResponseType        string `form:"response_type"`
		RedirectURI         string `form:"redirect_uri"`
		Scope               string `form:"scope"`
		CodeChallenge       string `form:"code_challenge"`
		CodeChallengeMethod string `form:"code_challenge_method"`
		State               string `form:"state"`
		Nonce               string `form:"nonce"`
	}
	if err := c.ShouldBindQuery(&req); err != nil {
		h.oauthErrorRedirect(c, "invalid_request", "Invalid authorize request.")
		return
	}

	responseType := strings.TrimSpace(req.ResponseType)
	if responseType == "" {
		responseType = "code"
	}
	if !strings.EqualFold(responseType, "code") {
		h.oauthErrorRedirect(c, "unsupported_response_type", "Only response_type=code is supported.")
		return
	}

	redirectURI := strings.TrimSpace(req.RedirectURI)
	if redirectURI == "" {
		h.oauthErrorRedirect(c, "invalid_request", "redirect_uri is required.")
		return
	}

	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil || parsedRedirect.Scheme == "" || parsedRedirect.Host == "" {
		h.oauthErrorRedirect(c, "invalid_request", "redirect_uri must be absolute.")
		return
	}

	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		h.oauthErrorRedirect(c, "invalid_request", "client_id is required.")
		return
	}

	if !h.Auth.IsValidRedirectURI(c.Request.Context(), tenantCtx.Tenant.ID, clientID, redirectURI) {
		h.oauthErrorRedirect(c, "invalid_request", "redirect_uri not registered for this client.")
		return
	}

	codeChallenge := strings.TrimSpace(req.CodeChallenge)
	codeChallengeMethod := strings.TrimSpace(req.CodeChallengeMethod)

	if codeChallengeMethod != "" {
		m := strings.ToUpper(codeChallengeMethod)
		if m != "S256" && m != "PLAIN" {
			h.oauthErrorRedirect(c, "invalid_request", "code_challenge_method must be S256 or plain.")
			return
		}
		codeChallengeMethod = m
	}

	// Only session cookie authentication is allowed for /oauth/authorize
	token, _ := c.Cookie("sb_session")
	if strings.TrimSpace(token) == "" {
		loginURL := &url.URL{
			Scheme: schemeOnly(c.Request),
			Host:   hostOnly(c.Request),
			Path:   "/login",
		}

		q := loginURL.Query()
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		q.Set("response_type", responseType)
		if req.Scope != "" {
			q.Set("scope", req.Scope)
		}
		if req.State != "" {
			q.Set("state", req.State)
		}
		if req.Nonce != "" {
			q.Set("nonce", req.Nonce)
		}
		if codeChallenge != "" {
			q.Set("code_challenge", codeChallenge)
		}
		if codeChallengeMethod != "" {
			q.Set("code_challenge_method", codeChallengeMethod)
		}

		loginURL.RawQuery = q.Encode()
		c.Redirect(http.StatusFound, loginURL.String())
		return
	}

	issuer := fmt.Sprintf("%s://%s", schemeOnly(c.Request), hostOnly(c.Request))
	stdClaims, _, err := h.Auth.ValidateToken(
		c.Request.Context(),
		tenantCtx.Tenant.ID,
		token,
		issuer,
	)
	if err != nil {
		h.oauthErrorRedirect(c, "invalid_token", "Invalid access token.")
		return
	}

	if stdClaims == nil || strings.TrimSpace(stdClaims.Subject) == "" {
		h.oauthErrorRedirect(c, "invalid_token", "Missing subject claim.")
		return
	}

	userID, err := strconv.ParseInt(stdClaims.Subject, 10, 64)
	if err != nil || userID <= 0 {
		h.oauthErrorRedirect(c, "invalid_token", "Invalid subject claim.")
		return
	}

	code, err := h.Auth.CreateAuthorizationCode(
		c.Request.Context(),
		tenantCtx,
		userID,
		clientID,
		redirectURI,
		codeChallenge,
		codeChallengeMethod,
	)
	if err != nil {
		if oauthErr, ok := err.(*service.OAuthError); ok {
			h.oauthErrorRedirect(c, oauthErr.Code, oauthErr.Description)
			return
		}
		h.oauthErrorRedirect(c, "server_error", err.Error())
		return
	}

	q := parsedRedirect.Query()
	q.Set("code", code)

	if req.State != "" {
		q.Set("state", req.State)
	}

	parsedRedirect.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, parsedRedirect.String())
}

// Redirect helper
func (h *AuthHandler) oauthErrorRedirect(c *gin.Context, code, desc string) {
	errURL := url.URL{
		Scheme: schemeOnly(c.Request),
		Host:   hostOnly(c.Request),
		Path:   "/error/oauth",
	}

	q := errURL.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	errURL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, errURL.String())
}

func (h *AuthHandler) respondOAuthServiceError(c *gin.Context, err error) {
	logger := zap.L()
	switch {
	case errors.Is(err, domainoauth.ErrProviderNotFound):
		logger.Warn("oauth provider not found", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "provider_not_found", "error_description": "OAuth provider not configured for tenant."})
	case errors.Is(err, domainoauth.ErrInvalidState), errors.Is(err, domainoauth.ErrInvalidRequest):
		logger.Warn("oauth invalid request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
	case errors.Is(err, domainoauth.ErrTokenInvalid):
		logger.Warn("oauth token invalid", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Token could not be verified."})
	case errors.Is(err, domainoauth.ErrUserNotFound):
		logger.Warn("oauth user missing", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found", "error_description": "Identity not linked to a user."})
	default:
		logger.Error("oauth service failure", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": "Internal server error."})
	}
}

func schemeOnly(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return scheme
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
