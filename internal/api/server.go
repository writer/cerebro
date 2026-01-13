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

		// Agent endpoints (investigation workflows)
		r.Route("/agents", func(r chi.Router) {
			r.Get("/", s.handleListAgents)
			r.Post("/sessions", s.handleCreateSession)
			r.Get("/sessions/{id}", s.handleGetSession)
			r.Post("/sessions/{id}/messages", s.handleSendMessage)
		})

		// Ticketing endpoints
		r.Route("/tickets", func(r chi.Router) {
			r.Get("/", s.handleListTickets)
			r.Post("/", s.handleCreateTicket)
			r.Get("/{id}", s.handleGetTicket)
			r.Post("/{id}/comment", s.handleAddComment)
		})

		// Identity/Access Review endpoints
		r.Route("/identity", func(r chi.Router) {
			r.Get("/reviews", s.handleListReviews)
			r.Post("/reviews", s.handleCreateReview)
			r.Get("/reviews/{id}", s.handleGetReview)
			r.Post("/reviews/{id}/start", s.handleStartReview)
			r.Post("/reviews/{id}/items/{itemId}/decide", s.handleRecordDecision)
		})

		// Attack Path endpoints
		r.Route("/attack-paths", func(r chi.Router) {
			r.Get("/", s.handleListAttackPaths)
			r.Post("/analyze", s.handleAnalyzeAttackPaths)
			r.Get("/{id}", s.handleGetAttackPath)
		})

		// Provider endpoints
		r.Route("/providers", func(r chi.Router) {
			r.Get("/", s.handleListProviders)
			r.Post("/{name}/sync", s.handleSyncProvider)
			r.Get("/{name}/schema", s.handleProviderSchema)
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

// Agent handlers

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{
		"agents": []map[string]interface{}{
			{"id": "security-analyst", "name": "Security Analyst", "description": "Investigates security findings and incidents"},
			{"id": "incident-responder", "name": "Incident Responder", "description": "Handles security incident triage and response"},
		},
	})
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentID    string   `json:"agent_id"`
		FindingIDs []string `json:"finding_ids,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.json(w, http.StatusCreated, map[string]interface{}{"session_id": "session-" + req.AgentID + "-001", "agent_id": req.AgentID, "status": "active"})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.json(w, http.StatusOK, map[string]interface{}{"id": id, "status": "active", "messages": []interface{}{}})
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.json(w, http.StatusOK, map[string]interface{}{"role": "assistant", "content": "I'll help you investigate. Let me analyze the findings..."})
}

// Ticketing handlers

func (s *Server) handleListTickets(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{"tickets": []interface{}{}, "count": 0})
}

func (s *Server) handleCreateTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Priority    string   `json:"priority"`
		FindingIDs  []string `json:"finding_ids,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.json(w, http.StatusCreated, map[string]interface{}{"id": "ticket-001", "title": req.Title, "status": "open", "priority": req.Priority})
}

func (s *Server) handleGetTicket(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.json(w, http.StatusOK, map[string]interface{}{"id": id, "status": "open"})
}

func (s *Server) handleAddComment(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusCreated, map[string]string{"status": "comment added"})
}

// Identity/Access Review handlers

func (s *Server) handleListReviews(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{"reviews": []interface{}{}, "count": 0})
}

func (s *Server) handleCreateReview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string   `json:"name"`
		Type      string   `json:"type"`
		Reviewers []string `json:"reviewers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.json(w, http.StatusCreated, map[string]interface{}{"id": "review-001", "name": req.Name, "status": "draft"})
}

func (s *Server) handleGetReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.json(w, http.StatusOK, map[string]interface{}{"id": id, "status": "draft", "items": []interface{}{}})
}

func (s *Server) handleStartReview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.json(w, http.StatusOK, map[string]interface{}{"id": id, "status": "in_progress"})
}

func (s *Server) handleRecordDecision(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string `json:"action"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	s.json(w, http.StatusOK, map[string]string{"status": "decision recorded"})
}

// Attack Path handlers

func (s *Server) handleListAttackPaths(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{"paths": []interface{}{}, "count": 0})
}

func (s *Server) handleAnalyzeAttackPaths(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusAccepted, map[string]interface{}{"job_id": "analysis-001", "status": "running"})
}

func (s *Server) handleGetAttackPath(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.json(w, http.StatusOK, map[string]interface{}{"id": id, "severity": "high", "steps": []interface{}{}})
}

// Provider handlers

func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	s.json(w, http.StatusOK, map[string]interface{}{
		"providers": []map[string]interface{}{
			{"name": "cloudquery", "type": "cloud", "status": "configured"},
			{"name": "crowdstrike", "type": "endpoint", "status": "not_configured"},
			{"name": "okta", "type": "identity", "status": "not_configured"},
		},
	})
}

func (s *Server) handleSyncProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	s.json(w, http.StatusAccepted, map[string]interface{}{"provider": name, "job_id": "sync-" + name + "-001", "status": "running"})
}

func (s *Server) handleProviderSchema(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	s.json(w, http.StatusOK, map[string]interface{}{"provider": name, "tables": []interface{}{}})
}
