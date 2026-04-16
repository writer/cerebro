package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/graph"
	risk "github.com/writer/cerebro/internal/graph/risk"
)

func (s *Server) graphQueryTemplates(w http.ResponseWriter, _ *http.Request) {
	templates := graph.DefaultGraphQueryTemplates()
	s.json(w, http.StatusOK, map[string]any{
		"templates": templates,
		"count":     len(templates),
	})
}

type graphQueryNeighborResult struct {
	Direction string      `json:"direction"`
	Edge      *graph.Edge `json:"edge"`
	Node      *graph.Node `json:"node,omitempty"`
}

func (s *Server) graphQuery(w http.ResponseWriter, r *http.Request) {
	g := s.currentGraphIntelligenceGraph(r.Context())
	if g == nil {
		s.error(w, http.StatusServiceUnavailable, "graph platform not initialized")
		return
	}
	queryGraph := g

	var asOf time.Time
	asOfRaw := strings.TrimSpace(r.URL.Query().Get("as_of"))
	if asOfRaw != "" {
		parsed, err := time.Parse(time.RFC3339, asOfRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "as_of must be RFC3339")
			return
		}
		asOf = parsed.UTC()
		queryGraph = g.SubgraphAt(asOf)
	}

	var from time.Time
	var to time.Time
	fromRaw := strings.TrimSpace(r.URL.Query().Get("from"))
	toRaw := strings.TrimSpace(r.URL.Query().Get("to"))
	if fromRaw != "" || toRaw != "" {
		if fromRaw == "" || toRaw == "" {
			s.error(w, http.StatusBadRequest, "both from and to query parameters are required (RFC3339)")
			return
		}
		parsedFrom, err := time.Parse(time.RFC3339, fromRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "from must be RFC3339")
			return
		}
		parsedTo, err := time.Parse(time.RFC3339, toRaw)
		if err != nil {
			s.error(w, http.StatusBadRequest, "to must be RFC3339")
			return
		}
		from = parsedFrom.UTC()
		to = parsedTo.UTC()
		queryGraph = g.SubgraphBetween(from, to)
	}

	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	if mode == "" {
		mode = "neighbors"
	}

	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		s.error(w, http.StatusBadRequest, "node_id is required")
		return
	}
	if _, ok := queryGraph.GetNode(nodeID); !ok {
		s.error(w, http.StatusNotFound, fmt.Sprintf("node not found in selected scope: %s", nodeID))
		return
	}

	temporalScope := map[string]any{}
	if !asOf.IsZero() {
		temporalScope["as_of"] = asOf
	}
	if !from.IsZero() || !to.IsZero() {
		temporalScope["from"] = from
		temporalScope["to"] = to
	}

	switch mode {
	case "neighbors":
		s.graphQueryNeighbors(w, r, queryGraph, nodeID, temporalScope)
	case "paths", "path":
		s.graphQueryPaths(w, r, queryGraph, nodeID, temporalScope)
	default:
		s.error(w, http.StatusBadRequest, "mode must be one of neighbors, paths")
	}
}

func (s *Server) graphQueryNeighbors(w http.ResponseWriter, r *http.Request, g *graph.Graph, nodeID string, temporalScope map[string]any) {
	direction := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("direction")))
	if direction == "" {
		direction = "both"
	}
	if direction != "out" && direction != "in" && direction != "both" {
		s.error(w, http.StatusBadRequest, "direction must be one of out, in, both")
		return
	}

	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			s.error(w, http.StatusBadRequest, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}

	results := make([]graphQueryNeighborResult, 0)
	edgesScanned := 0
	if direction == "out" || direction == "both" {
		for _, edge := range g.GetOutEdges(nodeID) {
			edgesScanned++
			targetNode, _ := g.GetNode(edge.Target)
			results = append(results, graphQueryNeighborResult{Direction: "out", Edge: edge, Node: targetNode})
		}
	}
	if direction == "in" || direction == "both" {
		for _, edge := range g.GetInEdges(nodeID) {
			edgesScanned++
			sourceNode, _ := g.GetNode(edge.Source)
			results = append(results, graphQueryNeighborResult{Direction: "in", Edge: edge, Node: sourceNode})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Direction == results[j].Direction {
			if results[i].Edge.Source == results[j].Edge.Source {
				if results[i].Edge.Target == results[j].Edge.Target {
					return string(results[i].Edge.Kind) < string(results[j].Edge.Kind)
				}
				return results[i].Edge.Target < results[j].Edge.Target
			}
			return results[i].Edge.Source < results[j].Edge.Source
		}
		return results[i].Direction < results[j].Direction
	})

	total := len(results)
	if len(results) > limit {
		results = results[:limit]
	}

	s.json(w, http.StatusOK, map[string]any{
		"mode":      "neighbors",
		"node_id":   nodeID,
		"direction": direction,
		"temporal":  temporalScope,
		"total":     total,
		"count":     len(results),
		"limit":     limit,
		"truncated": total > len(results),
		"neighbors": results,
		"explain": map[string]any{
			"edge_scan_count": edgesScanned,
			"guardrails":      []string{"limit<=200", "mode=neighbors", "direction in|out|both", "as_of RFC3339", "from/to RFC3339"},
		},
	})
}

func (s *Server) graphQueryPaths(w http.ResponseWriter, r *http.Request, g *graph.Graph, nodeID string, temporalScope map[string]any) {
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	if targetID == "" {
		s.error(w, http.StatusBadRequest, "target_id is required for paths mode")
		return
	}
	if _, ok := g.GetNode(targetID); !ok {
		s.error(w, http.StatusNotFound, fmt.Sprintf("target node not found: %s", targetID))
		return
	}

	k := 3
	if raw := strings.TrimSpace(r.URL.Query().Get("k")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 10 {
			s.error(w, http.StatusBadRequest, "k must be between 1 and 10")
			return
		}
		k = parsed
	}

	maxDepth := 6
	if raw := strings.TrimSpace(r.URL.Query().Get("max_depth")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 12 {
			s.error(w, http.StatusBadRequest, "max_depth must be between 1 and 12")
			return
		}
		maxDepth = parsed
	}

	simulator := risk.NewAttackPathSimulator(g)
	paths := simulator.KShortestPaths(nodeID, targetID, k, maxDepth)
	pathsExamined := 0
	for _, path := range paths {
		if path == nil {
			continue
		}
		pathsExamined += len(path.Steps)
	}

	s.json(w, http.StatusOK, map[string]any{
		"mode":      "paths",
		"source_id": nodeID,
		"target_id": targetID,
		"temporal":  temporalScope,
		"k":         k,
		"max_depth": maxDepth,
		"count":     len(paths),
		"paths":     paths,
		"explain": map[string]any{
			"path_step_count": pathsExamined,
			"guardrails":      []string{"k<=10", "max_depth<=12", "mode=paths", "as_of RFC3339", "from/to RFC3339"},
		},
	})
}
