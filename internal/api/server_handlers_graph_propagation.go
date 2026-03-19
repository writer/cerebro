package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/graph"
)

type graphEvaluateChangeRequest struct {
	ID                   string               `json:"id"`
	Source               string               `json:"source"`
	Reason               string               `json:"reason"`
	Nodes                []graph.NodeMutation `json:"nodes"`
	Edges                []graph.EdgeMutation `json:"edges"`
	Mutations            []map[string]any     `json:"mutations"`
	ApprovalARRThreshold *float64             `json:"approval_arr_threshold,omitempty"`
}

func (s *Server) evaluateGraphChange(w http.ResponseWriter, r *http.Request) {
	g, err := s.currentTenantSecurityGraphView(r.Context())
	if err != nil {
		s.errorFromErr(w, err)
		return
	}
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}

	var req graphEvaluateChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	delta := graph.GraphDelta{
		Nodes: append([]graph.NodeMutation(nil), req.Nodes...),
		Edges: append([]graph.EdgeMutation(nil), req.Edges...),
	}
	if len(req.Mutations) > 0 {
		parsed, err := parseGraphMutations(req.Mutations)
		if err != nil {
			s.error(w, http.StatusBadRequest, err.Error())
			return
		}
		delta.Nodes = append(delta.Nodes, parsed.Nodes...)
		delta.Edges = append(delta.Edges, parsed.Edges...)
	}
	if len(delta.Nodes) == 0 && len(delta.Edges) == 0 {
		s.error(w, http.StatusBadRequest, "at least one mutation is required")
		return
	}

	proposal := &graph.ChangeProposal{
		ID:     strings.TrimSpace(req.ID),
		Source: strings.TrimSpace(req.Source),
		Reason: strings.TrimSpace(req.Reason),
		Delta:  delta,
	}

	options := make([]graph.PropagationOption, 0, 1)
	if req.ApprovalARRThreshold != nil {
		options = append(options, graph.WithApprovalARRThreshold(*req.ApprovalARRThreshold))
	}

	engine := graph.NewPropagationEngine(g, options...)
	result, err := engine.Evaluate(proposal)
	if err != nil {
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, result)
}
