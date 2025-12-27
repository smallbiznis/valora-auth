package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/smallbiznis/valora-auth/internal/org"
)

const (
	ginOrgContextKey    = "orgContext"
	ginTenantContextKey = "tenantContext"
)

type orgContextKey struct{}

// Org resolves the org from the Host header and stores it in Gin and request contexts.
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

		ctx := context.WithValue(c.Request.Context(), orgContextKey{}, orgCtx)
		// Legacy context keys for compatibility across handlers.
		ctx = context.WithValue(ctx, "org_id", orgCtx.Org.ID)
		ctx = context.WithValue(ctx, "tenant_id", orgCtx.Org.ID)
		c.Request = c.Request.WithContext(ctx)

		c.Set(ginOrgContextKey, orgCtx)
		c.Set(ginTenantContextKey, orgCtx)
		c.Set("org_id", orgCtx.Org.ID)
		c.Set("tenant_id", orgCtx.Org.ID)

		c.Next()
	}
}

// OrgContextFromContext extracts the org context from a standard context.
func OrgContextFromContext(ctx context.Context) (*org.Context, bool) {
	value := ctx.Value(orgContextKey{})
	if value == nil {
		return nil, false
	}
	orgCtx, ok := value.(*org.Context)
	return orgCtx, ok
}

func stripPort(host string) string {
	if strings.Contains(host, ":") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			return h
		}
	}
	return host
}
