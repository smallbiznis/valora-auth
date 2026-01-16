package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	gojwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/smallbiznis/railzway-auth/internal/jwt"
	"github.com/smallbiznis/railzway-auth/internal/service"
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
	orgCtx, ok := GetOrgContext(c)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_tenant", "error_description": "Org missing."})
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
	issuer := fmt.Sprintf("%s://%s", schemeOnly(c.Request), hostOnly(c.Request))
	claims, custom, err := m.AuthService.ValidateToken(c.Request.Context(), orgCtx.Org.ID, parts[1], issuer)
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

func hostOnly(r *http.Request) string {
	host := r.Host
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
	}
	return host
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
