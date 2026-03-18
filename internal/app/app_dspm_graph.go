package app

import (
	"context"
	"reflect"
	"strings"

	"github.com/evalops/cerebro/internal/dspm"
	"github.com/evalops/cerebro/internal/graph"
)

func (a *App) enrichSecurityGraphWithDSPMResult(target *dspm.ScanTarget, result *dspm.ScanResult) {
	if a == nil || a.DSPM == nil || target == nil {
		return
	}
	if err := a.requireGraphWriterLease("enrich security graph with DSPM result"); err != nil {
		if a.Logger != nil {
			a.Logger.Debug("skipping DSPM graph enrichment without writer lease", "target_id", target.ID, "error", err)
		}
		return
	}

	exactNodeIDs, fallbackNames := dspmGraphNodeLookupCandidates(target)
	if len(exactNodeIDs) == 0 && len(fallbackNames) == 0 {
		return
	}

	props := a.DSPM.EnrichGraphNode(result)
	if len(props) == 0 {
		return
	}

	current := a.CurrentSecurityGraph()
	var (
		updatedLive          *graph.Graph
		builderSecurityGraph *graph.Graph
	)
	if a.SecurityGraphBuilder != nil {
		builderSecurityGraph = a.SecurityGraphBuilder.Graph()
	}

	if current != nil {
		candidate, err := a.MutateSecurityGraphMaybe(context.Background(), func(g *graph.Graph) (bool, error) {
			return applyDSPMPropertiesToGraph(g, target, exactNodeIDs, fallbackNames, props), nil
		})
		if err != nil {
			if a.Logger != nil {
				a.Logger.Warn("failed to enrich live security graph with DSPM result", "target_id", target.ID, "error", err)
			}
			return
		}
		updatedLive = candidate
		if a.SecurityGraphBuilder != nil && builderSecurityGraph == current && updatedLive != nil {
			a.SecurityGraphBuilder.ReplaceGraph(updatedLive)
			builderSecurityGraph = updatedLive
		}
	}

	if builderSecurityGraph != nil && builderSecurityGraph != updatedLive {
		a.graphUpdateMu.Lock()
		changed := applyDSPMPropertiesToGraph(builderSecurityGraph, target, exactNodeIDs, fallbackNames, props)
		if changed {
			builderSecurityGraph.BuildIndex()
		}
		a.graphUpdateMu.Unlock()
	}
}

func applyDSPMPropertiesToGraph(g *graph.Graph, target *dspm.ScanTarget, exactNodeIDs, fallbackNames []string, props map[string]any) bool {
	if g == nil || len(props) == 0 {
		return false
	}

	if nodeID, ok := firstDSPMGraphNodeIDMatch(g, exactNodeIDs); ok {
		return applyDSPMPropertiesToNode(g, nodeID, props)
	}
	if nodeID, ok := scopedDSPMGraphNodeNameMatch(g, target, fallbackNames); ok {
		return applyDSPMPropertiesToNode(g, nodeID, props)
	}

	return false
}

func applyDSPMPropertiesToNode(g *graph.Graph, nodeID string, props map[string]any) bool {
	node, ok := g.GetNode(nodeID)
	if !ok || node == nil {
		return false
	}
	changed := false
	for key, value := range props {
		existing, exists := node.Properties[key]
		if exists && reflect.DeepEqual(existing, value) {
			continue
		}
		g.SetNodeProperty(nodeID, key, value)
		changed = true
	}
	return changed
}

func firstDSPMGraphNodeIDMatch(g *graph.Graph, candidates []string) (string, bool) {
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if node, ok := g.GetNode(candidate); ok && node != nil {
			return node.ID, true
		}
	}
	return "", false
}

func scopedDSPMGraphNodeNameMatch(g *graph.Graph, target *dspm.ScanTarget, candidates []string) (string, bool) {
	if g == nil || target == nil || len(candidates) == 0 {
		return "", false
	}

	provider := strings.ToLower(strings.TrimSpace(target.Provider))
	account := strings.TrimSpace(target.Account)
	region := strings.TrimSpace(target.Region)
	if provider == "" || account == "" || region == "" {
		return "", false
	}

	var matchedID string
	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		if strings.ToLower(strings.TrimSpace(node.Provider)) != provider ||
			strings.TrimSpace(node.Account) != account ||
			strings.TrimSpace(node.Region) != region {
			continue
		}
		for _, candidate := range candidates {
			if !dspmGraphNodeNameMatches(node, candidate) {
				continue
			}
			if matchedID != "" && matchedID != node.ID {
				return "", false
			}
			matchedID = node.ID
			break
		}
	}
	if matchedID == "" {
		return "", false
	}
	return matchedID, true
}

func dspmGraphNodeNameMatches(node *graph.Node, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if node == nil || candidate == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(node.Name), candidate) {
		return true
	}
	if node.Properties == nil {
		return false
	}
	for _, key := range []string{"name", "bucket_name", "resource_name"} {
		if strings.EqualFold(firstNonEmptyString(node.Properties, key), candidate) {
			return true
		}
	}
	return false
}

func dspmGraphNodeLookupCandidates(target *dspm.ScanTarget) ([]string, []string) {
	if target == nil {
		return nil, nil
	}

	exactIDs := make([]string, 0, 6)
	fallbackNames := make([]string, 0, 3)
	if target.Properties != nil {
		appendUniqueGraphNodeIDs(&exactIDs,
			firstNonEmptyString(target.Properties, "arn", "resource_arn"),
			firstNonEmptyString(target.Properties, "resource_id", "id"),
		)
		appendUniqueGraphNodeIDs(&fallbackNames, firstNonEmptyString(target.Properties, "bucket_name", "name"))
	}
	appendUniqueGraphNodeIDs(&exactIDs, target.ARN, target.ID)
	appendUniqueGraphNodeIDs(&fallbackNames, target.Name)
	if target.Properties != nil {
		appendUniqueGraphNodeIDs(&exactIDs, firstNonEmptyString(target.Properties, "_cq_id"))
	}
	return exactIDs, fallbackNames
}

func appendUniqueGraphNodeIDs(ids *[]string, values ...string) {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		exists := false
		for _, existing := range *ids {
			if existing == trimmed {
				exists = true
				break
			}
		}
		if !exists {
			*ids = append(*ids, trimmed)
		}
	}
}
