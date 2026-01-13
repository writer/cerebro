// Package server provides HTTP server with graceful shutdown support.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Config holds server configuration.
type Config struct {
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// DefaultConfig returns sensible defaults for production.
func DefaultConfig(port int) Config {
	return Config{
		Port:            port,
		ReadTimeout:     15 * time.Second,
		WriteTimeout:    60 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 30 * time.Second,
	}
}

// Server wraps http.Server with graceful shutdown.
type Server struct {
	httpServer *http.Server
	config     Config
	logger     *slog.Logger
}

// New creates a new server.
func New(handler http.Handler, cfg Config, logger *slog.Logger) *Server {
	return &Server{
		httpServer: &http.Server{
			Addr:         fmt.Sprintf(":%d", cfg.Port),
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
		},
		config: cfg,
		logger: logger,
	}
}

// Run starts the server and blocks until shutdown signal is received.
// It performs graceful shutdown, allowing in-flight requests to complete.
func (s *Server) Run(ctx context.Context) error {
	// Channel to receive errors from ListenAndServe
	errCh := make(chan error, 1)

	// Start server in background
	go func() {
		s.logger.Info("starting HTTP server", "addr", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for shutdown signal or context cancellation
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	case sig := <-sigCh:
		s.logger.Info("received shutdown signal", "signal", sig)
	case <-ctx.Done():
		s.logger.Info("context canceled, shutting down")
	}

	// Graceful shutdown
	return s.Shutdown()
}

// Shutdown gracefully shuts down the server with the configured timeout.
func (s *Server) Shutdown() error {
	return s.ShutdownWithContext(context.Background())
}

// ShutdownWithContext gracefully shuts down the server with a parent context.
// The shutdown timeout is applied on top of any deadline from the parent context.
func (s *Server) ShutdownWithContext(parent context.Context) error {
	s.logger.Info("initiating graceful shutdown", "timeout", s.config.ShutdownTimeout)

	ctx, cancel := context.WithTimeout(parent, s.config.ShutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Error("graceful shutdown failed", "error", err)
		return fmt.Errorf("shutdown: %w", err)
	}

	s.logger.Info("server stopped gracefully")
	return nil
}

// ListenAndServe is a convenience function that creates a server and runs it
// with graceful shutdown on SIGINT/SIGTERM.
func ListenAndServe(ctx context.Context, handler http.Handler, port int, logger *slog.Logger) error {
	srv := New(handler, DefaultConfig(port), logger)
	return srv.Run(ctx)
}

// RunWithCleanup runs a server and executes cleanup functions on shutdown.
type CleanupFunc func() error

func RunWithCleanup(ctx context.Context, handler http.Handler, cfg Config, logger *slog.Logger, cleanups ...CleanupFunc) error {
	srv := New(handler, cfg, logger)

	// Run server (blocks until shutdown)
	err := srv.Run(ctx)

	// Execute cleanup functions
	for _, cleanup := range cleanups {
		if cleanupErr := cleanup(); cleanupErr != nil {
			logger.Error("cleanup failed", "error", cleanupErr)
		}
	}

	return err
}
