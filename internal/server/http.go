package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

// HTTPServer wraps a gin.Engine with graceful shutdown helpers.
type HTTPServer struct {
	Engine *gin.Engine
}

// NewHTTPServer creates a server with sane defaults such as recovery middleware.
func NewHTTPServer(router *gin.Engine) *HTTPServer {
	router.HandleMethodNotAllowed = true
	router.ForwardedByClientIP = true
	return &HTTPServer{Engine: router}
}

// Run starts the HTTP server on the provided addr and shuts it down when ctx is done.
func (s *HTTPServer) Run(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s.Engine,
	}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("listen: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	})

	return g.Wait()
}
