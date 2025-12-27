package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/smallbiznis/valora-auth/internal/org"
)

const (
	orgContextKey    = "orgContext"
	tenantContextKey = "tenantContext"
)

// Org attaches org metadata to the gin context.
func Org(resolver *org.Resolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		orgSlug := strings.TrimSpace(c.Request.Header.Get("X-Org-ID"))
		if orgSlug == "" {
			orgSlug = strings.TrimSpace(c.Request.Header.Get("X-Tenant-ID"))
		}

		var (
			orgCtx *org.Context
			err    error
		)

		if orgSlug != "" {
			orgCtx, err = resolver.ResolveBySlug(c.Request.Context(), orgSlug)
		} else {
			host := stripPort(c.Request.Host)
			orgCtx, err = resolver.Resolve(c.Request.Context(), host)
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "invalid_tenant", "error_description": "Unknown org."})
			return
		}
		c.Set(orgContextKey, orgCtx)
		c.Set(tenantContextKey, orgCtx)
		c.Next()
	}
}

// GetOrgContext extracts the org context from gin.
func GetOrgContext(c *gin.Context) (*org.Context, bool) {
	value, ok := c.Get(orgContextKey)
	if !ok {
		return nil, false
	}
	orgCtx, ok := value.(*org.Context)
	return orgCtx, ok
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
