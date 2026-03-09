package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/evalops/cerebro/internal/graph"
)

type graphSchemaRegisterRequest struct {
	NodeKinds []graph.NodeKindDefinition `json:"node_kinds"`
	EdgeKinds []graph.EdgeKindDefinition `json:"edge_kinds"`
}

func (s *Server) getGraphSchema(w http.ResponseWriter, _ *http.Request) {
	s.json(w, http.StatusOK, map[string]any{
		"node_kinds": graph.RegisteredNodeKinds(),
		"edge_kinds": graph.RegisteredEdgeKinds(),
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

	s.json(w, http.StatusOK, map[string]any{
		"registered_node_kinds": registeredNodeKinds,
		"registered_edge_kinds": registeredEdgeKinds,
		"node_kinds":            graph.RegisteredNodeKinds(),
		"edge_kinds":            graph.RegisteredEdgeKinds(),
	})
}
