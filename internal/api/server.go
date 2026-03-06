package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	apicontract "github.com/writer/cerebro/api"
	"github.com/writer/cerebro/internal/app"
	"github.com/writer/cerebro/internal/metrics"
	"github.com/writer/cerebro/internal/snowflake"
)

// Server is the fully wired API server
type Server struct {
	app         *app.App
	router      *chi.Mux
	auditLogger auditLogWriter
	rateLimiter *RateLimiter
}

type auditLogWriter interface {
	Log(ctx context.Context, entry *snowflake.AuditEntry) error
}

// NewServer creates a new server with all services wired
func NewServer(application *app.App) *Server {
	s := &Server{
		app:         application,
		router:      chi.NewRouter(),
		auditLogger: application.AuditRepo,
	}
	s.setupMiddleware()
	s.setupRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) Run() error {
	addr := fmt.Sprintf(":%d", s.app.Config.Port)
	s.app.Logger.Info("starting server", "addr", addr)
	defer func() {
		if s.rateLimiter != nil {
			s.rateLimiter.Close()
		}
	}()

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

// Health endpoints

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	ready := true

	if s.app.Snowflake != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := s.app.Snowflake.Ping(ctx); err != nil {
			checks["snowflake"] = "unhealthy: " + err.Error()
			ready = false
		} else {
			checks["snowflake"] = "healthy"
		}
	} else {
		checks["snowflake"] = "not configured"
	}

	checks["policies"] = fmt.Sprintf("%d loaded", len(s.app.Policy.ListPolicies()))
	checks["agents"] = fmt.Sprintf("%d registered", len(s.app.Agents.ListAgents()))
	checks["providers"] = fmt.Sprintf("%d registered", len(s.app.Providers.List()))

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}

	s.json(w, status, map[string]interface{}{
		"ready":  ready,
		"checks": checks,
	})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	// Use Prometheus metrics handler
	metrics.Handler().ServeHTTP(w, r)
}

func (s *Server) openAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(apicontract.OpenAPIYAML)
}

func (s *Server) swaggerUI(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cerebro API Documentation</title>
  <style>
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      max-width: 900px;
      margin: 2rem auto;
      padding: 0 1rem;
      line-height: 1.5;
      color: #0f172a;
      background: #f8fafc;
    }
    .panel {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 1rem 1.25rem;
      margin-bottom: 1rem;
      box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    }
    code {
      background: #f1f5f9;
      border-radius: 6px;
      padding: 0.15rem 0.35rem;
    }
    a {
      color: #0f4c81;
    }
    h1, h2 {
      margin-top: 0;
    }
    ul {
      padding-left: 1.1rem;
    }
  </style>
</head>
<body>
  <h1>Cerebro API Docs</h1>
  <div class="panel">
    <p>
      Download the OpenAPI contract directly at
      <a href="/openapi.yaml"><code>/openapi.yaml</code></a>.
    </p>
    <p>
      This page is intentionally self-hosted and does not depend on external CDNs.
    </p>
  </div>
  <div class="panel">
    <h2>Quick Links</h2>
    <ul>
      <li><a href="/health"><code>/health</code></a></li>
      <li><a href="/ready"><code>/ready</code></a></li>
      <li><a href="/metrics"><code>/metrics</code></a></li>
      <li><a href="/api/v1/tables"><code>/api/v1/tables</code></a></li>
      <li><a href="/api/v1/findings"><code>/api/v1/findings</code></a></li>
    </ul>
  </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(html))
}

// Admin health dashboard
func (s *Server) adminHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"timestamp": time.Now().UTC(),
	}

	// Snowflake status
	if s.app.Snowflake != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		start := time.Now()
		err := s.app.Snowflake.Ping(ctx)
		cancel()
		latency := time.Since(start).Milliseconds()

		if err != nil {
			health["snowflake"] = map[string]interface{}{
				"status":     "unhealthy",
				"error":      err.Error(),
				"latency_ms": latency,
			}
		} else {
			health["snowflake"] = map[string]interface{}{
				"status":     "healthy",
				"latency_ms": latency,
			}
		}
	} else {
		health["snowflake"] = map[string]interface{}{"status": "not_configured"}
	}

	// Findings stats
	stats := s.app.Findings.Stats()
	health["findings"] = map[string]interface{}{
		"total":    stats.Total,
		"open":     stats.ByStatus["OPEN"],
		"critical": stats.BySeverity["critical"],
		"high":     stats.BySeverity["high"],
		"medium":   stats.BySeverity["medium"],
		"low":      stats.BySeverity["low"],
	}

	// Cache stats
	cacheStats := s.app.Cache.Stats()
	health["cache"] = cacheStats

	// Policies and agents
	health["policies"] = map[string]interface{}{
		"loaded": len(s.app.Policy.ListPolicies()),
	}
	health["agents"] = map[string]interface{}{
		"registered": len(s.app.Agents.ListAgents()),
	}
	health["providers"] = map[string]interface{}{
		"registered": len(s.app.Providers.List()),
	}

	// Scheduler status
	if s.app.Scheduler != nil {
		health["scheduler"] = map[string]interface{}{
			"configured": true,
		}
	}

	if s.app.Webhooks != nil {
		health["event_publisher"] = s.app.Webhooks.EventPublisherStatus(r.Context())
	}

	s.json(w, http.StatusOK, health)
}
