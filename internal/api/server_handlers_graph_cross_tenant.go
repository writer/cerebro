package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/graph"
	"github.com/evalops/cerebro/internal/metrics"
	"github.com/evalops/cerebro/internal/snowflake"
)

type crossTenantBuildRequest struct {
	TenantID   string `json:"tenant_id"`
	WindowDays int    `json:"window_days,omitempty"`
}

type crossTenantIngestRequest struct {
	Samples []graph.AnonymizedPatternSample `json:"samples"`
}

func (s *Server) buildCrossTenantPatternSamples(w http.ResponseWriter, r *http.Request) {
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req crossTenantBuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		s.error(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.WindowDays <= 0 {
		req.WindowDays = 90
	}

	samples, err := engine.BuildAnonymizedPatternSamples(req.TenantID, time.Duration(req.WindowDays)*24*time.Hour)
	if err != nil {
		s.logCrossTenantRead(r.Context(), r, "build_samples", req.TenantID, 0, "error")
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logCrossTenantRead(r.Context(), r, "build_samples", req.TenantID, len(samples), "allowed")
	s.json(w, http.StatusOK, map[string]any{
		"count":   len(samples),
		"samples": samples,
	})
}

func (s *Server) ingestCrossTenantPatternSamples(w http.ResponseWriter, r *http.Request) {
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		metrics.RecordGraphCrossTenantIngest("read_error", 0)
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.verifyCrossTenantIngestAuth(r, body); err != nil {
		metrics.RecordGraphCrossTenantIngest("auth_failed", 0)
		status := http.StatusUnauthorized
		message := err.Error()
		var authErr crossTenantAuthError
		if errors.As(err, &authErr) {
			status = authErr.status
			message = authErr.message
		}
		s.error(w, status, message)
		return
	}

	var req crossTenantIngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		metrics.RecordGraphCrossTenantIngest("decode_error", 0)
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Samples) == 0 {
		metrics.RecordGraphCrossTenantIngest("empty_samples", 0)
		s.error(w, http.StatusBadRequest, "samples is required")
		return
	}

	summary := engine.IngestAnonymizedPatternSamples(req.Samples)
	s.persistRiskEngineState(r.Context(), engine)
	metrics.RecordGraphCrossTenantIngest("accepted", summary.Received)
	s.json(w, http.StatusOK, summary)
}

func (s *Server) listCrossTenantPatterns(w http.ResponseWriter, r *http.Request) {
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	minTenants := 1
	if raw := strings.TrimSpace(r.URL.Query().Get("min_tenants")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid min_tenants: %q", raw))
			return
		}
		minTenants = parsed
	}

	patterns := engine.CrossTenantPatterns(minTenants)
	metrics.RecordGraphCrossTenantPatterns(len(patterns))
	s.logCrossTenantRead(r.Context(), r, "list_patterns", "aggregate_library", len(patterns), "allowed")
	s.json(w, http.StatusOK, map[string]any{
		"count":    len(patterns),
		"patterns": patterns,
	})
}

func (s *Server) matchCrossTenantPatterns(w http.ResponseWriter, r *http.Request) {
	engine := s.graphRiskEngine()
	if engine == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	minProbability := 0.60
	if raw := strings.TrimSpace(r.URL.Query().Get("min_probability")); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil || parsed <= 0 || parsed > 1 {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid min_probability: %q", raw))
			return
		}
		minProbability = parsed
	}
	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid limit: %q", raw))
			return
		}
		limit = parsed
	}

	matches := engine.MatchCrossTenantPatterns(minProbability, limit)
	metrics.RecordGraphCrossTenantMatches(len(matches))
	s.logCrossTenantRead(r.Context(), r, "match_patterns", "aggregate_library", len(matches), "allowed")
	s.json(w, http.StatusOK, map[string]any{
		"count":   len(matches),
		"matches": matches,
	})
}

func (s *Server) logCrossTenantRead(ctx context.Context, r *http.Request, operation, targetTenant string, resultCount int, outcome string) {
	requestingTenant := strings.TrimSpace(GetTenantID(ctx))
	auditRequestingTenant := requestingTenant
	if auditRequestingTenant == "" {
		auditRequestingTenant = "unknown"
	}
	targetTenant = strings.TrimSpace(targetTenant)
	auditTargetTenant := targetTenant
	if auditTargetTenant == "" {
		auditTargetTenant = "unknown"
	}
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if outcome == "" {
		outcome = "unknown"
	}

	metrics.RecordGraphCrossTenantRead(
		operation,
		crossTenantRequestScope(requestingTenant),
		crossTenantTargetScope(targetTenant),
		outcome,
	)

	details := map[string]any{
		"requesting_tenant": auditRequestingTenant,
		"target_tenant":     auditTargetTenant,
		"operation":         strings.TrimSpace(operation),
		"result_count":      resultCount,
		"outcome":           outcome,
		"timestamp":         time.Now().UTC().Format(time.RFC3339Nano),
	}

	if auditLoggerIsNil(s.auditLogger) {
		if s.app != nil && s.app.Logger != nil {
			s.app.Logger.Info("cross-tenant graph read", "requesting_tenant", auditRequestingTenant, "target_tenant", auditTargetTenant, "operation", operation, "result_count", resultCount, "outcome", outcome)
		}
		return
	}

	actorID := strings.TrimSpace(GetUserID(ctx))
	if actorID == "" {
		actorID = "api"
	}
	entry := &snowflake.AuditEntry{
		Action:       "graph.cross_tenant.read",
		ActorID:      actorID,
		ActorType:    "user",
		ResourceType: "graph_cross_tenant",
		ResourceID:   strings.TrimSpace(operation) + ":" + auditTargetTenant,
		Details:      details,
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	}
	if err := s.auditLogger.Log(ctx, entry); err != nil && s.app != nil && s.app.Logger != nil {
		s.app.Logger.Warn("failed to persist cross-tenant graph audit log", "error", err, "operation", operation, "requesting_tenant", auditRequestingTenant, "target_tenant", auditTargetTenant)
	}
}

func crossTenantRequestScope(requestingTenant string) string {
	if strings.TrimSpace(requestingTenant) == "" {
		return "global"
	}
	return "tenant"
}

func crossTenantTargetScope(targetTenant string) string {
	targetTenant = strings.TrimSpace(targetTenant)
	switch targetTenant {
	case "":
		return "unknown"
	case "aggregate_library":
		return "aggregate"
	default:
		return "tenant"
	}
}
