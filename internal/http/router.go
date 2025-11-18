package http

import (
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/smallbiznis/smallbiznis-auth/internal/config"
	"github.com/smallbiznis/smallbiznis-auth/internal/http/handler"
	httpmiddleware "github.com/smallbiznis/smallbiznis-auth/internal/http/middleware"
	"github.com/smallbiznis/smallbiznis-auth/internal/middleware"
	"github.com/smallbiznis/smallbiznis-auth/internal/tenant"
)

// NewRouter wires Gin routes and middleware.
func NewRouter(cfg config.Config, authHandler *handler.AuthHandler, authMiddleware *httpmiddleware.Auth, resolver *tenant.Resolver, rateLimiter *middleware.RateLimiter) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	if rateLimiter != nil {
		r.Use(rateLimiter.Handler())
	}
	r.Use(middleware.Tenant(resolver))
	r.Use(middleware.TenantCORS(cfg))
	r.Use(otelgin.Middleware(cfg.ServiceName))

	authGroup := r.Group("/auth")
	{
		password := authGroup.Group("/password")
		{
			password.POST("/login", authHandler.PasswordLogin)
			password.POST("/register", authHandler.PasswordRegister)
			password.POST("/forgot", authHandler.PasswordForgot)
		}

		otp := authGroup.Group("/otp")
		{
			otp.POST("/request", authHandler.OTPRequest)
			otp.POST("/verify", authHandler.OTPVerify)
		}

		authGroup.GET("/me", authMiddleware.ValidateJWT, authHandler.Me)
	}

	r.GET("/.well-known/tenant", authHandler.TenantDiscovery)
	r.GET("/.well-known/openid-configuration", authHandler.OpenIDConfig)
	r.GET("/.well-known/jwks.json", authHandler.JWKS)

	oauth := r.Group("/oauth")
	{
		oauth.POST("/token", authHandler.Token)
		oauth.GET("/authorize", authHandler.Authorize)
	}

	r.GET("/userinfo", authMiddleware.ValidateJWT, authHandler.UserInfo)

	return r
}
