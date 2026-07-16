package securitypathdelta

import "sort"

// RankCandidateEdgeCuts ranks observed relationships by the number of material
// routes and paths that include them. The result is evidence for review, not a
// claim that changing an edge is safe or supported by its provider.
func RankCandidateEdgeCuts(paths []SecurityPath) []CandidateEdgeCut {
	type coverage struct {
		edge   ProofEdge
		routes map[string]struct{}
		paths  map[string]struct{}
	}
	byEdge := map[string]*coverage{}
	orderedPaths := append([]SecurityPath(nil), paths...)
	sortSecurityPaths(orderedPaths)
	for _, path := range orderedPaths {
		seenInPath := map[string]struct{}{}
		for _, edge := range path.ProofEdges {
			if edge.ID == "" {
				continue
			}
			if _, seen := seenInPath[edge.ID]; seen {
				continue
			}
			seenInPath[edge.ID] = struct{}{}
			item := byEdge[edge.ID]
			if item == nil {
				item = &coverage{edge: edge, routes: map[string]struct{}{}, paths: map[string]struct{}{}}
				byEdge[edge.ID] = item
			}
			item.routes[path.RouteID] = struct{}{}
			item.paths[path.ID] = struct{}{}
		}
	}

	candidates := make([]CandidateEdgeCut, 0, len(byEdge))
	for _, item := range byEdge {
		routeIDs := setStrings(item.routes)
		pathIDs := setStrings(item.paths)
		candidates = append(candidates, CandidateEdgeCut{
			State:           candidateEdgeCutState,
			Edge:            item.edge,
			CoveredRouteIDs: routeIDs,
			CoveredPathIDs:  pathIDs,
			RouteCoverage:   len(routeIDs),
			PathCoverage:    len(pathIDs),
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].RouteCoverage != candidates[j].RouteCoverage {
			return candidates[i].RouteCoverage > candidates[j].RouteCoverage
		}
		if candidates[i].PathCoverage != candidates[j].PathCoverage {
			return candidates[i].PathCoverage > candidates[j].PathCoverage
		}
		if left, right := candidateEdgeCutPriority(candidates[i].Edge.Relation), candidateEdgeCutPriority(candidates[j].Edge.Relation); left != right {
			return left < right
		}
		return candidates[i].Edge.ID < candidates[j].Edge.ID
	})
	for index := range candidates {
		candidates[index].Rank = index + 1
	}
	return candidates
}

func candidateEdgeCutPriority(relation string) int {
	switch relation {
	case "can_reach":
		return 0
	case "can_admin", "can_perform", "can_assume", "can_impersonate":
		return 1
	case "runs_as", "attached_to", "assigned_to", "member_of", "depends_on":
		return 2
	case "belongs_to":
		return 4
	default:
		return 3
	}
}

func setStrings(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
