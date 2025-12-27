package http

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/smallbiznis/valora-auth/internal/config"
	"github.com/smallbiznis/valora-auth/internal/http/handler"
	httpmiddleware "github.com/smallbiznis/valora-auth/internal/http/middleware"
	"github.com/smallbiznis/valora-auth/internal/middleware"
	"github.com/smallbiznis/valora-auth/internal/org"
)

// NewRouter wires Gin routes and middleware.
func NewRouter(cfg config.Config, authHandler *handler.AuthHandler, authMiddleware *httpmiddleware.Auth, resolver *org.Resolver, rateLimiter *middleware.RateLimiter) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(httpmiddleware.RequestLogger(nil))
	if rateLimiter != nil {
		r.Use(rateLimiter.Handler())
	}
	r.Use(middleware.Org(resolver))
	r.Use(middleware.OrgCORS(cfg))
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
		authGroup.GET("/oauth/providers", authHandler.OAuthListProviders)
		authGroup.GET("/oauth/start", authHandler.OAuthStart)
		authGroup.GET("/oauth/callback", authHandler.OAuthCallback)
	}

	// r.GET("/.well-known/org", authHandler.OrgDiscovery)
	// r.GET("/.well-known/tenant", authHandler.OrgDiscovery)
	r.GET("/.well-known/openid-configuration", authHandler.OpenIDConfig)
	r.GET("/.well-known/jwks.json", authHandler.JWKS)

	oauth := r.Group("/oauth")
	{
		oauth.POST("/token", authHandler.Token)
		oauth.GET("/authorize", authHandler.OAuthAuthorize)
		oauth.POST("/introspect", authHandler.OAuthIntrospect)
		oauth.POST("/revoke", authHandler.OAuthRevoke)
		oauth.GET("/userinfo", authHandler.OAuthUserInfo)
	}

	// r.GET("/userinfo", authMiddleware.ValidateJWT, authHandler.GetUserInfo)

	// UI is served only as static files; auth/OAuth logic stays on the API routes.
	attachUIRoutes(r, filepath.Join("ui", "dist"))

	return r
}

func attachUIRoutes(r *gin.Engine, distDir string) {
	indexPath := filepath.Join(distDir, "index.html")

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if isAPIPath(path) {
			c.Status(http.StatusNotFound)
			return
		}

		if filePath, ok := safeJoin(distDir, path); ok {
			if info, err := os.Stat(filePath); err == nil && !info.IsDir() {
				c.File(filePath)
				return
			}
		}

		c.File(indexPath)
	})
}

func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/auth") ||
		strings.HasPrefix(path, "/oauth") ||
		strings.HasPrefix(path, "/.well-known")
}

func safeJoin(baseDir, requestPath string) (string, bool) {
	trimmed := strings.TrimPrefix(requestPath, "/")
	cleaned := filepath.Clean(trimmed)
	if cleaned == "." {
		return filepath.Join(baseDir, cleaned), true
	}
	if strings.HasPrefix(cleaned, "..") {
		return "", false
	}
	return filepath.Join(baseDir, cleaned), true
}
