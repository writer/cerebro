package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/evalops/cerebro/internal/graph"
)

type graphSimulateRequest struct {
	Nodes     []graph.NodeMutation `json:"nodes"`
	Edges     []graph.EdgeMutation `json:"edges"`
	Mutations []map[string]any     `json:"mutations"`
}

func (s *Server) simulateGraph(w http.ResponseWriter, r *http.Request) {
	var req graphSimulateRequest
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

	result, err := s.graphSimulation.Simulate(r.Context(), delta)
	if err != nil {
		if errors.Is(err, graph.ErrStoreUnavailable) {
			s.errorFromErr(w, err)
			return
		}
		s.error(w, http.StatusBadRequest, err.Error())
		return
	}

	s.json(w, http.StatusOK, result)
}

func parseGraphMutations(raw []map[string]any) (graph.GraphDelta, error) {
	delta := graph.GraphDelta{}
	for idx, mutation := range raw {
		mutationType := strings.ToLower(strings.TrimSpace(stringValue(mutation["type"])))
		mutationType = strings.ReplaceAll(mutationType, "-", "_")

		switch mutationType {
		case "add_node":
			node, err := decodeMutationNode(mutation["node"])
			if err != nil {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: %w", idx, err)
			}
			delta.Nodes = append(delta.Nodes, graph.NodeMutation{Action: "add", Node: node})
		case "remove_node":
			nodeID := strings.TrimSpace(stringValue(mutation["id"]))
			delta.Nodes = append(delta.Nodes, graph.NodeMutation{Action: "remove", ID: nodeID})
		case "modify_node":
			nodeID := strings.TrimSpace(stringValue(mutation["id"]))
			properties, ok := mutation["properties"].(map[string]any)
			if !ok {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: modify_node requires properties object", idx)
			}
			delta.Nodes = append(delta.Nodes, graph.NodeMutation{Action: "modify", ID: nodeID, Properties: properties})
		case "add_edge":
			edge, err := decodeMutationEdge(mutation)
			if err != nil {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: %w", idx, err)
			}
			delta.Edges = append(delta.Edges, graph.EdgeMutation{Action: "add", Edge: edge})
		case "remove_edge":
			edge, err := decodeMutationEdge(mutation)
			if err != nil {
				return graph.GraphDelta{}, fmt.Errorf("mutation %d: %w", idx, err)
			}
			delta.Edges = append(delta.Edges, graph.EdgeMutation{Action: "remove", Source: edge.Source, Target: edge.Target, Kind: edge.Kind})
		default:
			return graph.GraphDelta{}, fmt.Errorf("mutation %d: unsupported type %q", idx, mutationType)
		}
	}
	return delta, nil
}

func decodeMutationNode(raw any) (*graph.Node, error) {
	if raw == nil {
		return nil, fmt.Errorf("add_node requires node object")
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encode node payload: %w", err)
	}
	var node graph.Node
	if err := json.Unmarshal(encoded, &node); err != nil {
		return nil, fmt.Errorf("decode node payload: %w", err)
	}
	return &node, nil
}

func decodeMutationEdge(raw map[string]any) (*graph.Edge, error) {
	if nested, ok := raw["edge"]; ok && nested != nil {
		encoded, err := json.Marshal(nested)
		if err != nil {
			return nil, fmt.Errorf("encode edge payload: %w", err)
		}
		var edge graph.Edge
		if err := json.Unmarshal(encoded, &edge); err != nil {
			return nil, fmt.Errorf("decode edge payload: %w", err)
		}
		return &edge, nil
	}

	edge := &graph.Edge{
		Source: strings.TrimSpace(stringValue(raw["source"])),
		Target: strings.TrimSpace(stringValue(raw["target"])),
		Kind:   graph.EdgeKind(strings.TrimSpace(stringValue(raw["kind"]))),
	}
	if edge.Source == "" || edge.Target == "" || strings.TrimSpace(string(edge.Kind)) == "" {
		return nil, fmt.Errorf("edge mutation requires source, target, and kind")
	}
	return edge, nil
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		if value == nil {
			return ""
		}
		return fmt.Sprintf("%v", value)
	}
}
