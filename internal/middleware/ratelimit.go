package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter enforces per-client throttling.
type RateLimiter struct {
	limit   rate.Limit
	burst   int
	window  time.Duration
	mu      sync.Mutex
	clients map[string]*clientLimiter
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a limiter for the provided requests-per-minute budget.
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	if requestsPerMinute <= 0 {
		return nil
	}
	limit := rate.Limit(float64(requestsPerMinute) / 60.0)
	burst := requestsPerMinute / 10
	if burst < 1 {
		burst = 1
	}
	return &RateLimiter{
		limit:   limit,
		burst:   burst,
		window:  5 * time.Minute,
		clients: make(map[string]*clientLimiter),
	}
}

// Handler returns the gin middleware enforcing throttling behaviour.
func (r *RateLimiter) Handler() gin.HandlerFunc {
	if r == nil {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		key := c.ClientIP()
		limiter := r.getLimiter(key)
		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":             "rate_limited",
				"error_description": "Too many requests. Please slow down.",
			})
			return
		}

		c.Next()
	}
}

func (r *RateLimiter) getLimiter(key string) *rate.Limiter {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.clients[key]; ok {
		entry.lastSeen = now
		return entry.limiter
	}

	limiter := rate.NewLimiter(r.limit, r.burst)
	r.clients[key] = &clientLimiter{limiter: limiter, lastSeen: now}
	r.cleanupLocked(now)
	return limiter
}

func (r *RateLimiter) cleanupLocked(now time.Time) {
	for key, entry := range r.clients {
		if now.Sub(entry.lastSeen) > r.window {
			delete(r.clients, key)
		}
	}
}
