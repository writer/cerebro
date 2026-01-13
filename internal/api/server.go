package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/writerinternal/cerebro/internal/compliance"
	"github.com/writerinternal/cerebro/internal/config"
	"github.com/writerinternal/cerebro/internal/findings"
	"github.com/writerinternal/cerebro/internal/policy"
	"github.com/writerinternal/cerebro/internal/snowflake"
)

type Server struct {
	config   *config.Config
	router   *chi.Mux
	sf       *snowflake.Client
	policy   *policy.Engine
	findings *findings.Store
	logger   *slog.Logger
}

func NewServer(cfg *config.Config, sf *snowflake.Client, pe *policy.Engine, logger *slog.Logger) *Server {
	s := &Server{
		config:   cfg,
		router:   chi.NewRouter(),
		sf:       sf,
		policy:   pe,
		findings: findings.NewStore(),
		logger:   logger,
	}
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.router.Use(middleware.RequestID)
	s.router.Use(middleware.RealIP)
	s.router.Use(middleware.Logger)
	s.router.Use(middleware.Recoverer)
	s.router.Use(middleware.Timeout(60 * time.Second))

	s.router.Get("/health", s.handleHealth)
	s.router.Get("/ready", s.handleReady)

	s.router.Route("/api/v1", func(r chi.Router) {
		r.Get("/tables", s.handleListTables)
		r.Post("/query", s.handleQuery)
		
		r.Route("/assets", func(r chi.Router) {
			r.Get("/{table}", s.handleListAssets)
			r.Get("/{table}/{id}", s.handleGetAsset)
			r.Get("/{table}/count", s.handleCountAssets)
		})

		r.Route("/policies", func(r chi.Router) {
			r.Get("/", s.handleListPolicies)
			r.Get("/{id}", s.handleGetPolicy)
			r.Post("/", s.handleCreatePolicy)
			r.Post("/evaluate", s.handleEvaluate)
		})

		r.Route("/findings", func(r chi.Router) {
			r.Get("/", s.handleListFindings)
			r.Get("/stats", s.handleFindingsStats)
			r.Post("/scan", s.handleScanFindings)
			r.Post("/{id}/resolve", s.handleResolveFindings)
			r.Post("/{id}/suppress", s.handleSuppressFindings)
		})

		r.Route("/compliance", func(r chi.Router) {
			r.Get("/frameworks", s.handleListFrameworks)
			r.Get("/frameworks/{id}", s.handleGetFramework)
		})
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.sf != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := s.sf.Ping(ctx); err != nil {
			s.json(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "error": err.Error()})
			return
		}
	}
	s.json(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleListTables(w http.ResponseWriter, r *http.Request) {
	if s.sf == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	tables, err := s.sf.ListTables(r.Context())
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"tables": tables})
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if s.sf == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	var req struct {
		Query string `json:"query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := s.sf.Query(r.Context(), req.Query)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, result)
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	if s.sf == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	filter := snowflake.AssetFilter{
		Account: r.URL.Query().Get("account"),
		Region:  r.URL.Query().Get("region"),
	}

	assets, err := s.sf.GetAssets(r.Context(), table, filter)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"assets": assets, "count": len(assets)})
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	if s.sf == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	id := chi.URLParam(r, "id")

	asset, err := s.sf.GetAssetByID(r.Context(), table, id)
	if err != nil {
		s.error(w, http.StatusNotFound, err.Error())
		return
	}
	s.json(w, http.StatusOK, asset)
}

func (s *Server) handleCountAssets(w http.ResponseWriter, r *http.Request) {
	if s.sf == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	table := chi.URLParam(r, "table")
	count, err := s.sf.CountAssets(r.Context(), table)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, map[string]int64{"count": count})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies := s.policy.ListPolicies()
	s.json(w, http.StatusOK, map[string]interface{}{"policies": policies, "count": len(policies)})
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	p, ok := s.policy.GetPolicy(id)
	if !ok {
		s.error(w, http.StatusNotFound, "policy not found")
		return
	}
	s.json(w, http.StatusOK, p)
}

func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.policy.AddPolicy(&p)
	s.json(w, http.StatusCreated, p)
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	var req policy.EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := s.policy.Evaluate(r.Context(), &req)
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.json(w, http.StatusOK, resp)
}

func (s *Server) handleScanFindings(w http.ResponseWriter, r *http.Request) {
	if s.sf == nil {
		s.error(w, http.StatusServiceUnavailable, "snowflake not configured")
		return
	}

	var req struct {
		Table string `json:"table"`
		Limit int    `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Limit == 0 {
		req.Limit = 100
	}

	assets, err := s.sf.GetAssets(r.Context(), req.Table, snowflake.AssetFilter{Limit: req.Limit})
	if err != nil {
		s.error(w, http.StatusInternalServerError, err.Error())
		return
	}

	var allFindings []policy.Finding
	for _, asset := range assets {
		findings, err := s.policy.EvaluateAsset(r.Context(), asset)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	s.json(w, http.StatusOK, map[string]interface{}{
		"findings": allFindings,
		"count":    len(allFindings),
		"scanned":  len(assets),
	})
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	filter := findings.FindingFilter{
		Severity: r.URL.Query().Get("severity"),
		Status:   r.URL.Query().Get("status"),
		PolicyID: r.URL.Query().Get("policy_id"),
	}
	list := s.findings.List(filter)
	s.json(w, http.StatusOK, map[string]interface{}{"findings": list, "count": len(list)})
}

func (s *Server) handleFindingsStats(w http.ResponseWriter, r *http.Request) {
	stats := s.findings.Stats()
	s.json(w, http.StatusOK, stats)
}

func (s *Server) handleResolveFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.findings.Resolve(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "resolved"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) handleSuppressFindings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.findings.Suppress(id) {
		s.json(w, http.StatusOK, map[string]string{"status": "suppressed"})
	} else {
		s.error(w, http.StatusNotFound, "finding not found")
	}
}

func (s *Server) handleListFrameworks(w http.ResponseWriter, r *http.Request) {
	frameworks := compliance.GetFrameworks()
	s.json(w, http.StatusOK, map[string]interface{}{"frameworks": frameworks, "count": len(frameworks)})
}

func (s *Server) handleGetFramework(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f := compliance.GetFramework(id)
	if f == nil {
		s.error(w, http.StatusNotFound, "framework not found")
		return
	}
	s.json(w, http.StatusOK, f)
}

func (s *Server) json(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) error(w http.ResponseWriter, status int, message string) {
	s.json(w, status, map[string]string{"error": message})
}

func (s *Server) Run() error {
	addr := fmt.Sprintf(":%d", s.config.Port)
	s.logger.Info("starting server", "addr", addr)
	return http.ListenAndServe(addr, s.router)
}
