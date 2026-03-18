package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/evalops/cerebro/internal/graph"
)

type graphSchemaRegisterRequest struct {
	NodeKinds []graph.NodeKindDefinition `json:"node_kinds"`
	EdgeKinds []graph.EdgeKindDefinition `json:"edge_kinds"`
}

func (s *Server) getGraphSchema(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, map[string]any{
		"schema_version": graph.SchemaVersion(),
		"node_kinds":     graph.RegisteredNodeKinds(),
		"edge_kinds":     graph.RegisteredEdgeKinds(),
	})
}

func (s *Server) registerGraphSchema(w http.ResponseWriter, r *http.Request) {
	var req graphSchemaRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.NodeKinds) == 0 && len(req.EdgeKinds) == 0 {
		s.error(w, http.StatusBadRequest, "node_kinds or edge_kinds is required")
		return
	}
	beforeVersion := graph.SchemaVersion()

	registeredNodeKinds := make([]graph.NodeKindDefinition, 0, len(req.NodeKinds))
	for _, nodeKind := range req.NodeKinds {
		registered, err := graph.RegisterNodeKindDefinition(nodeKind)
		if err != nil {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid node kind definition: %v", err))
			return
		}
		registeredNodeKinds = append(registeredNodeKinds, registered)
	}

	registeredEdgeKinds := make([]graph.EdgeKindDefinition, 0, len(req.EdgeKinds))
	for _, edgeKind := range req.EdgeKinds {
		registered, err := graph.RegisterEdgeKindDefinition(edgeKind)
		if err != nil {
			s.error(w, http.StatusBadRequest, fmt.Sprintf("invalid edge kind definition: %v", err))
			return
		}
		registeredEdgeKinds = append(registeredEdgeKinds, registered)
	}
	afterVersion := graph.SchemaVersion()
	drift := graph.SchemaDriftSince(beforeVersion)

	s.json(w, http.StatusOK, map[string]any{
		"schema_version":         afterVersion,
		"schema_drift":           drift,
		"compatibility_warnings": drift.CompatibilityWarnings,
		"registered_node_kinds":  registeredNodeKinds,
		"registered_edge_kinds":  registeredEdgeKinds,
		"node_kinds":             graph.RegisteredNodeKinds(),
		"edge_kinds":             graph.RegisteredEdgeKinds(),
	})
}

func (s *Server) getGraphSchemaHealth(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	historyLimit := 20
	if raw := r.URL.Query().Get("history_limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "history_limit must be between 1 and 200")
			return
		}
		historyLimit = parsed
	}

	var sinceVersion int64
	if raw := r.URL.Query().Get("since_version"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 1 {
			s.error(w, http.StatusBadRequest, "since_version must be a positive integer")
			return
		}
		sinceVersion = parsed
	}

	report := graph.AnalyzeSchemaHealth(g, historyLimit, sinceVersion)
	s.json(w, http.StatusOK, report)
}
