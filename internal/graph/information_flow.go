package graph

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRecommendedConnectionsLimit = 10
	maxClockSpeedCategorySamples       = 32
)

// InformationPath describes how information travels between two endpoints.
type InformationPath struct {
	Source           string  `json:"source"`
	Destination      string  `json:"destination"`
	Hops             int     `json:"hops"`
	Path             []*Node `json:"path,omitempty"`
	Bottlenecks      []*Node `json:"bottlenecks,omitempty"`
	EstimatedLatency string  `json:"estimated_latency"`

	latency time.Duration
}

// PathMetrics summarizes path latency/hop characteristics for one flow category.
type PathMetrics struct {
	SampleSize     int               `json:"sample_size"`
	PathCount      int               `json:"path_count"`
	AverageHops    float64           `json:"average_hops"`
	MedianLatency  string            `json:"median_latency"`
	Representative []InformationPath `json:"representative_paths,omitempty"`
}

// ClockSpeed captures category-specific and aggregate organizational information-flow speed.
type ClockSpeed struct {
	CustomerIssueToResolver     PathMetrics       `json:"customer_issue_to_resolver"`
	SecurityFindingToRemediator PathMetrics       `json:"security_finding_to_remediator"`
	SalesInsightToProduct       PathMetrics       `json:"sales_insight_to_product"`
	IncidentToExecVisibility    PathMetrics       `json:"incident_to_exec_visibility"`
	AverageHops                 float64           `json:"average_hops"`
	MedianLatency               string            `json:"median_latency"`
	LongestPaths                []InformationPath `json:"longest_paths,omitempty"`
	MostOverloadedNodes         []*Node           `json:"most_overloaded_nodes,omitempty"`
}

// EdgeRecommendation suggests a missing connection that would improve org flow.
type EdgeRecommendation struct {
	PersonA         string  `json:"person_a"`
	PersonB         string  `json:"person_b"`
	CurrentDistance int     `json:"current_distance"`
	PathsImproved   int     `json:"paths_improved"`
	AvgHopsReduced  float64 `json:"avg_hops_reduced"`
	Reason          string  `json:"reason"`
	Suggestion      string  `json:"suggestion"`
}

type flowPairCandidate struct {
	recommendation EdgeRecommendation
	score          float64
}

type flowContext struct {
	customers map[string]struct{}
	systems   map[string]struct{}
}

// ShortestInformationPath computes the shortest interaction path between two endpoints.
func ShortestInformationPath(g *Graph, from, to string) *InformationPath {
	if g == nil {
		return nil
	}
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if from == "" || to == "" {
		return nil
	}

	sources := resolveInformationFlowSelector(g, from)
	targets := resolveInformationFlowSelector(g, to)
	if len(sources) == 0 || len(targets) == 0 {
		return nil
	}

	adjacency, edgeByPair := buildInformationFlowAdjacency(g)
	pathIDs := shortestPathBetweenSets(adjacency, sources, targets)
	if len(pathIDs) == 0 {
		return nil
	}

	path := buildInformationPath(g, pathIDs, edgeByPair)
	path.Source = from
	path.Destination = to
	return &path
}

// ComputeClockSpeed summarizes information-flow speed across key operational categories.
func ComputeClockSpeed(g *Graph) ClockSpeed {
	clock := ClockSpeed{
		MedianLatency: "0s",
	}
	if g == nil {
		return clock
	}

	adjacency, edgeByPair := buildInformationFlowAdjacency(g)

	customerMetrics, customerPaths := computeFlowCategoryMetrics(g, adjacency, edgeByPair,
		customerIssueSources(g), resolverTargets(g), maxClockSpeedCategorySamples)
	securityMetrics, securityPaths := computeFlowCategoryMetrics(g, adjacency, edgeByPair,
		securityFindingSources(g), remediatorTargets(g), maxClockSpeedCategorySamples)
	salesMetrics, salesPaths := computeFlowCategoryMetrics(g, adjacency, edgeByPair,
		salesInsightSources(g), productTargets(g), maxClockSpeedCategorySamples)
	incidentMetrics, incidentPaths := computeFlowCategoryMetrics(g, adjacency, edgeByPair,
		incidentSources(g), executiveTargets(g), maxClockSpeedCategorySamples)

	clock.CustomerIssueToResolver = customerMetrics
	clock.SecurityFindingToRemediator = securityMetrics
	clock.SalesInsightToProduct = salesMetrics
	clock.IncidentToExecVisibility = incidentMetrics

	allPaths := append([]InformationPath{}, customerPaths...)
	allPaths = append(allPaths, securityPaths...)
	allPaths = append(allPaths, salesPaths...)
	allPaths = append(allPaths, incidentPaths...)
	if len(allPaths) == 0 {
		return clock
	}

	totalHops := 0.0
	latencies := make([]time.Duration, 0, len(allPaths))
	overloadedCounts := make(map[string]int)

	for _, path := range allPaths {
		totalHops += float64(path.Hops)
		latencies = append(latencies, path.latency)

		for _, node := range path.Path {
			if node == nil || node.Kind != NodeKindPerson {
				continue
			}
			overloadedCounts[node.ID]++
		}
	}

	clock.AverageHops = totalHops / float64(len(allPaths))
	clock.MedianLatency = formatInformationLatency(durationMedian(latencies))

	sort.Slice(allPaths, func(i, j int) bool {
		if allPaths[i].latency == allPaths[j].latency {
			if allPaths[i].Hops == allPaths[j].Hops {
				return allPaths[i].Source < allPaths[j].Source
			}
			return allPaths[i].Hops > allPaths[j].Hops
		}
		return allPaths[i].latency > allPaths[j].latency
	})
	if len(allPaths) > 5 {
		clock.LongestPaths = allPaths[:5]
	} else {
		clock.LongestPaths = allPaths
	}

	clock.MostOverloadedNodes = overloadedNodesByCount(g, overloadedCounts)
	return clock
}

// RecommendEdges finds missing person-to-person connections that would reduce flow distance.
func RecommendEdges(g *Graph, topN int) []EdgeRecommendation {
	if g == nil {
		return nil
	}
	if topN <= 0 {
		topN = defaultRecommendedConnectionsLimit
	}

	adjacency := personInteractionAdjacency(g)
	people := g.GetNodesByKind(NodeKindPerson)
	if len(people) < 2 {
		return nil
	}

	personByID := make(map[string]*Node, len(people))
	personIDs := make([]string, 0, len(people))
	for _, person := range people {
		if person == nil {
			continue
		}
		personByID[person.ID] = person
		personIDs = append(personIDs, person.ID)
	}
	sort.Strings(personIDs)

	contexts := make(map[string]flowContext, len(personIDs))
	for _, personID := range personIDs {
		contexts[personID] = gatherPersonFlowContext(g, personID)
	}

	candidatePairs := make([]flowPairCandidate, 0)
	for i := 0; i < len(personIDs); i++ {
		for j := i + 1; j < len(personIDs); j++ {
			a := personIDs[i]
			b := personIDs[j]
			if _, connected := adjacency[a][b]; connected {
				continue
			}

			distance := informationFlowDistance(adjacency, a, b)
			if distance == 1 {
				continue
			}
			if distance == 0 {
				distance = 6
			}

			sharedCustomers, sharedSystems := sharedFlowContext(contexts[a], contexts[b])
			pathsImproved := sharedCustomers + sharedSystems
			if pathsImproved == 0 {
				continue
			}

			reduction := float64(maxInt(1, distance-1))
			aName := infoFlowNodeDisplayName(personByID[a])
			bName := infoFlowNodeDisplayName(personByID[b])
			reason := buildEdgeRecommendationReason(aName, bName, sharedCustomers, sharedSystems)
			suggestion := edgeRecommendationSuggestion(personByID[a], personByID[b])

			rec := EdgeRecommendation{
				PersonA:         a,
				PersonB:         b,
				CurrentDistance: distance,
				PathsImproved:   pathsImproved,
				AvgHopsReduced:  reduction,
				Reason:          reason,
				Suggestion:      suggestion,
			}
			candidatePairs = append(candidatePairs, flowPairCandidate{
				recommendation: rec,
				score:          float64(pathsImproved) * reduction,
			})
		}
	}

	sort.Slice(candidatePairs, func(i, j int) bool {
		if candidatePairs[i].score == candidatePairs[j].score {
			if candidatePairs[i].recommendation.PathsImproved == candidatePairs[j].recommendation.PathsImproved {
				if candidatePairs[i].recommendation.CurrentDistance == candidatePairs[j].recommendation.CurrentDistance {
					if candidatePairs[i].recommendation.PersonA == candidatePairs[j].recommendation.PersonA {
						return candidatePairs[i].recommendation.PersonB < candidatePairs[j].recommendation.PersonB
					}
					return candidatePairs[i].recommendation.PersonA < candidatePairs[j].recommendation.PersonA
				}
				return candidatePairs[i].recommendation.CurrentDistance > candidatePairs[j].recommendation.CurrentDistance
			}
			return candidatePairs[i].recommendation.PathsImproved > candidatePairs[j].recommendation.PathsImproved
		}
		return candidatePairs[i].score > candidatePairs[j].score
	})

	if topN > len(candidatePairs) {
		topN = len(candidatePairs)
	}
	recommendations := make([]EdgeRecommendation, 0, topN)
	for i := 0; i < topN; i++ {
		recommendations = append(recommendations, candidatePairs[i].recommendation)
	}
	return recommendations
}

func computeFlowCategoryMetrics(
	g *Graph,
	adjacency map[string]map[string]struct{},
	edgeByPair map[string]*Edge,
	sources []string,
	targets []string,
	maxSamples int,
) (PathMetrics, []InformationPath) {
	metrics := PathMetrics{MedianLatency: "0s"}
	if g == nil || len(sources) == 0 || len(targets) == 0 {
		return metrics, nil
	}
	if maxSamples <= 0 {
		maxSamples = maxClockSpeedCategorySamples
	}

	sourceSet := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		sourceSet[source] = struct{}{}
	}
	targetSet := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		targetSet[target] = struct{}{}
	}
	if len(sourceSet) == 0 || len(targetSet) == 0 {
		return metrics, nil
	}

	sortedSources := sortedSet(sourceSet)
	metrics.SampleSize = len(sortedSources)
	paths := make([]InformationPath, 0)
	latencies := make([]time.Duration, 0)

	for _, source := range sortedSources {
		if len(paths) >= maxSamples {
			break
		}
		singleSource := map[string]struct{}{source: {}}
		pathIDs := shortestPathBetweenSets(adjacency, singleSource, targetSet)
		if len(pathIDs) == 0 {
			continue
		}
		path := buildInformationPath(g, pathIDs, edgeByPair)
		path.Source = source
		path.Destination = pathIDs[len(pathIDs)-1]
		paths = append(paths, path)
		latencies = append(latencies, path.latency)
	}

	if len(paths) == 0 {
		return metrics, nil
	}

	metrics.PathCount = len(paths)
	totalHops := 0.0
	for _, path := range paths {
		totalHops += float64(path.Hops)
	}
	metrics.AverageHops = totalHops / float64(len(paths))
	metrics.MedianLatency = formatInformationLatency(durationMedian(latencies))

	sort.Slice(paths, func(i, j int) bool {
		if paths[i].latency == paths[j].latency {
			if paths[i].Hops == paths[j].Hops {
				return paths[i].Source < paths[j].Source
			}
			return paths[i].Hops > paths[j].Hops
		}
		return paths[i].latency > paths[j].latency
	})
	if len(paths) > 3 {
		metrics.Representative = paths[:3]
	} else {
		metrics.Representative = paths
	}

	return metrics, paths
}

func resolveInformationFlowSelector(g *Graph, selector string) map[string]struct{} {
	results := make(map[string]struct{})
	if g == nil {
		return results
	}
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return results
	}

	if node, ok := g.GetNode(selector); ok && node != nil {
		results[node.ID] = struct{}{}
		return results
	}

	lower := strings.ToLower(selector)
	if strings.HasPrefix(lower, "team/") || strings.HasPrefix(lower, "department/") {
		query := selector[strings.Index(selector, "/")+1:]
		addDepartmentSelectorMatches(g, query, results, true)
		return results
	}
	if strings.HasPrefix(lower, "system/") {
		query := selector[strings.Index(selector, "/")+1:]
		addSystemSelectorMatches(g, query, results)
		return results
	}
	if strings.HasPrefix(lower, "customer/") {
		query := selector[strings.Index(selector, "/")+1:]
		addKindSelectorMatches(g, NodeKindCustomer, query, results)
		return results
	}
	if strings.HasPrefix(lower, "person/") {
		query := selector[strings.Index(selector, "/")+1:]
		addKindSelectorMatches(g, NodeKindPerson, query, results)
		return results
	}

	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		if informationFlowTextMatch(node.ID, selector) || informationFlowTextMatch(node.Name, selector) {
			results[node.ID] = struct{}{}
		}
	}
	if len(results) == 0 {
		addDepartmentSelectorMatches(g, selector, results, true)
	}
	return results
}

func addDepartmentSelectorMatches(g *Graph, query string, results map[string]struct{}, includeMembers bool) {
	if g == nil {
		return
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return
	}

	departmentIDs := make(map[string]struct{})
	for _, department := range g.GetNodesByKind(NodeKindDepartment) {
		if department == nil {
			continue
		}
		if !informationFlowTextMatch(department.ID, query) && !informationFlowTextMatch(department.Name, query) {
			continue
		}
		results[department.ID] = struct{}{}
		departmentIDs[department.ID] = struct{}{}
	}

	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}
		if informationFlowTextMatch(readString(person.Properties, "department", "team"), query) {
			results[person.ID] = struct{}{}
		}
	}

	if !includeMembers || len(departmentIDs) == 0 {
		return
	}
	for departmentID := range departmentIDs {
		for _, edge := range g.GetInEdges(departmentID) {
			if edge == nil || edge.Kind != EdgeKindMemberOf {
				continue
			}
			if person, ok := g.GetNode(edge.Source); ok && person != nil && person.Kind == NodeKindPerson {
				results[person.ID] = struct{}{}
			}
		}
		for _, edge := range g.GetOutEdges(departmentID) {
			if edge == nil || edge.Kind != EdgeKindMemberOf {
				continue
			}
			if person, ok := g.GetNode(edge.Target); ok && person != nil && person.Kind == NodeKindPerson {
				results[person.ID] = struct{}{}
			}
		}
	}
}

func addSystemSelectorMatches(g *Graph, query string, results map[string]struct{}) {
	if g == nil {
		return
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return
	}

	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		if !isSystemNodeKind(node.Kind) {
			continue
		}
		if informationFlowTextMatch(node.ID, query) || informationFlowTextMatch(node.Name, query) {
			results[node.ID] = struct{}{}
		}
	}
}

func addKindSelectorMatches(g *Graph, kind NodeKind, query string, results map[string]struct{}) {
	if g == nil {
		return
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return
	}
	for _, node := range g.GetNodesByKind(kind) {
		if node == nil {
			continue
		}
		if informationFlowTextMatch(node.ID, query) || informationFlowTextMatch(node.Name, query) {
			results[node.ID] = struct{}{}
		}
	}
}

func buildInformationFlowAdjacency(g *Graph) (map[string]map[string]struct{}, map[string]*Edge) {
	adjacency := make(map[string]map[string]struct{})
	edgeByPair := make(map[string]*Edge)
	if g == nil {
		return adjacency, edgeByPair
	}

	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		adjacency[node.ID] = make(map[string]struct{})
	}

	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || !isInformationFlowEdge(edge.Kind) {
				continue
			}
			source, sourceOK := g.GetNode(edge.Source)
			target, targetOK := g.GetNode(edge.Target)
			if !sourceOK || !targetOK || source == nil || target == nil || source.ID == target.ID {
				continue
			}

			if _, exists := adjacency[source.ID]; !exists {
				adjacency[source.ID] = make(map[string]struct{})
			}
			if _, exists := adjacency[target.ID]; !exists {
				adjacency[target.ID] = make(map[string]struct{})
			}
			adjacency[source.ID][target.ID] = struct{}{}
			adjacency[target.ID][source.ID] = struct{}{}

			key := undirectedPairKey(source.ID, target.ID)
			if current, exists := edgeByPair[key]; !exists || informationFlowEdgeLatency(edge) < informationFlowEdgeLatency(current) {
				edgeByPair[key] = edge
			}
		}
	}

	return adjacency, edgeByPair
}

func shortestPathBetweenSets(adjacency map[string]map[string]struct{}, sources, targets map[string]struct{}) []string {
	if len(sources) == 0 || len(targets) == 0 {
		return nil
	}

	nodeIDs := NewNodeIDIndex()
	for nodeID, neighbors := range adjacency {
		nodeIDs.Intern(nodeID)
		for neighbor := range neighbors {
			nodeIDs.Intern(neighbor)
		}
	}

	queue := make([]NodeOrdinal, 0, len(sources))
	visited := newOrdinalVisitSet(nodeIDs)
	prev := make(map[NodeOrdinal]NodeOrdinal, len(adjacency))

	for _, source := range sortedSet(sources) {
		if _, exists := adjacency[source]; !exists {
			continue
		}
		sourceOrdinal, ok := nodeIDs.Lookup(source)
		if !ok || !visited.markOrdinal(sourceOrdinal) {
			continue
		}
		queue = append(queue, sourceOrdinal)
		prev[sourceOrdinal] = InvalidNodeOrdinal
		if _, isTarget := targets[source]; isTarget {
			return []string{source}
		}
	}
	if len(queue) == 0 {
		return nil
	}

	for head := 0; head < len(queue); head++ {
		currentOrdinal := queue[head]
		current, ok := nodeIDs.Resolve(currentOrdinal)
		if !ok {
			continue
		}

		for _, neighbor := range sortedSet(adjacency[current]) {
			neighborOrdinal, ok := nodeIDs.Lookup(neighbor)
			if !ok || !visited.markOrdinal(neighborOrdinal) {
				continue
			}
			prev[neighborOrdinal] = currentOrdinal
			if _, isTarget := targets[neighbor]; isTarget {
				return rebuildInformationOrdinalPath(prev, neighborOrdinal, nodeIDs)
			}
			queue = append(queue, neighborOrdinal)
		}
	}

	return nil
}

func rebuildInformationOrdinalPath(prev map[NodeOrdinal]NodeOrdinal, destination NodeOrdinal, nodeIDs *NodeIDIndex) []string {
	if destination == InvalidNodeOrdinal || nodeIDs == nil {
		return nil
	}
	destinationID, ok := nodeIDs.Resolve(destination)
	if !ok || strings.TrimSpace(destinationID) == "" {
		return nil
	}
	path := []string{destinationID}
	for cursor := destination; ; {
		parent, exists := prev[cursor]
		if !exists || parent == InvalidNodeOrdinal {
			break
		}
		parentID, ok := nodeIDs.Resolve(parent)
		if !ok {
			break
		}
		path = append(path, parentID)
		cursor = parent
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

func buildInformationPath(g *Graph, pathIDs []string, edgeByPair map[string]*Edge) InformationPath {
	result := InformationPath{EstimatedLatency: "0s"}
	if g == nil || len(pathIDs) == 0 {
		return result
	}

	result.Source = pathIDs[0]
	result.Destination = pathIDs[len(pathIDs)-1]
	result.Path = make([]*Node, 0, len(pathIDs))

	totalLatency := time.Duration(0)
	for i, nodeID := range pathIDs {
		node, _ := g.GetNode(nodeID)
		if node != nil {
			result.Path = append(result.Path, node)
		}
		if i >= len(pathIDs)-1 {
			continue
		}
		key := undirectedPairKey(nodeID, pathIDs[i+1])
		totalLatency += informationFlowEdgeLatency(edgeByPair[key])
	}

	hops := 0
	for idx := 1; idx < len(pathIDs)-1; idx++ {
		node, ok := g.GetNode(pathIDs[idx])
		if !ok || node == nil {
			continue
		}
		if node.Kind == NodeKindPerson {
			hops++
		}
	}
	if hops == 0 && len(pathIDs) > 2 {
		hops = len(pathIDs) - 2
	}
	result.Hops = hops
	result.latency = totalLatency
	result.EstimatedLatency = formatInformationLatency(totalLatency)
	result.Bottlenecks = informationPathBottlenecks(g, pathIDs)
	return result
}

func informationPathBottlenecks(g *Graph, pathIDs []string) []*Node {
	if g == nil || len(pathIDs) == 0 {
		return nil
	}
	centrality := betweennessCentrality(personInteractionAdjacency(g))

	type scoredPerson struct {
		node  *Node
		score float64
	}
	scored := make([]scoredPerson, 0)
	for _, nodeID := range pathIDs {
		node, ok := g.GetNode(nodeID)
		if !ok || node == nil || node.Kind != NodeKindPerson {
			continue
		}
		scored = append(scored, scoredPerson{node: node, score: centrality[node.ID]})
	}
	if len(scored) == 0 {
		return nil
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].node.ID < scored[j].node.ID
		}
		return scored[i].score > scored[j].score
	})

	if scored[0].score <= 0 {
		return []*Node{scored[0].node}
	}

	maxScore := scored[0].score
	bottlenecks := make([]*Node, 0, 3)
	for _, item := range scored {
		if len(bottlenecks) >= 3 {
			break
		}
		if item.score < maxScore {
			break
		}
		bottlenecks = append(bottlenecks, item.node)
	}
	if len(bottlenecks) > 0 {
		return bottlenecks
	}
	return []*Node{scored[0].node}
}

func informationFlowEdgeLatency(edge *Edge) time.Duration {
	if edge == nil {
		return 24 * time.Hour
	}

	switch edge.Kind {
	case EdgeKindInteractedWith:
		frequency := readFloat(edge.Properties, "frequency", "interaction_count")
		if frequency <= 0 {
			frequency = readFloat(edge.Properties, "call_count") +
				readFloat(edge.Properties, "co_actions") +
				readFloat(edge.Properties, "shared_groups") +
				readFloat(edge.Properties, "shared_apps")
		}
		if frequency <= 0 {
			frequency = 1
		}

		baseHours := 72.0 / (1.0 + math.Log1p(frequency))
		if baseHours < 1 {
			baseHours = 1
		}

		if lastSeen := firstTimeFromMap(edge.Properties, "last_seen", "last_interaction", "updated_at"); !lastSeen.IsZero() {
			days := orgHealthNowUTC().Sub(lastSeen).Hours() / 24
			if days > 7 {
				baseHours *= 1 + math.Min(days/30, 4)
			}
		}

		return clampInformationLatency(baseHours)
	case EdgeKindEscalatedTo, EdgeKindRefers:
		return 4 * time.Hour
	case EdgeKindReportsTo:
		return 8 * time.Hour
	case EdgeKindManagedBy, EdgeKindOwns, EdgeKindAssignedTo, EdgeKindWorksAt:
		return 10 * time.Hour
	case EdgeKindMemberOf:
		return 12 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func clampInformationLatency(hours float64) time.Duration {
	if hours < 1 {
		hours = 1
	}
	if hours > 24*30 {
		hours = 24 * 30
	}
	return time.Duration(hours * float64(time.Hour))
}

func formatInformationLatency(latency time.Duration) string {
	if latency <= 0 {
		return "0s"
	}
	if latency < time.Minute {
		return latency.Round(time.Second).String()
	}
	return latency.Round(time.Minute).String()
}

func durationMedian(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	copyValues := append([]time.Duration(nil), values...)
	sort.Slice(copyValues, func(i, j int) bool { return copyValues[i] < copyValues[j] })
	mid := len(copyValues) / 2
	if len(copyValues)%2 == 1 {
		return copyValues[mid]
	}
	return (copyValues[mid-1] + copyValues[mid]) / 2
}

func overloadedNodesByCount(g *Graph, counts map[string]int) []*Node {
	if g == nil || len(counts) == 0 {
		return nil
	}
	type scoredNode struct {
		node  *Node
		count int
		score float64
	}

	centrality := betweennessCentrality(personInteractionAdjacency(g))
	scored := make([]scoredNode, 0, len(counts))
	for personID, count := range counts {
		if count <= 0 {
			continue
		}
		node, ok := g.GetNode(personID)
		if !ok || node == nil || node.Kind != NodeKindPerson {
			continue
		}
		scored = append(scored, scoredNode{node: node, count: count, score: centrality[personID]})
	}
	if len(scored) == 0 {
		return nil
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].count == scored[j].count {
			if scored[i].score == scored[j].score {
				return scored[i].node.ID < scored[j].node.ID
			}
			return scored[i].score > scored[j].score
		}
		return scored[i].count > scored[j].count
	})

	limit := 5
	if limit > len(scored) {
		limit = len(scored)
	}
	result := make([]*Node, 0, limit)
	for i := 0; i < limit; i++ {
		result = append(result, scored[i].node)
	}
	return result
}

func customerIssueSources(g *Graph) []string {
	sources := make(map[string]struct{})
	for _, node := range g.GetNodesByKind(NodeKindTicket, NodeKindCustomer) {
		if node == nil {
			continue
		}
		sources[node.ID] = struct{}{}
	}
	return sortedSet(sources)
}

func resolverTargets(g *Graph) []string {
	targets := make(map[string]struct{})
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}
		hasResolverEdge := false
		for _, edge := range g.GetOutEdges(person.ID) {
			if edge == nil {
				continue
			}
			if edge.Kind == EdgeKindOwns || edge.Kind == EdgeKindManagedBy || edge.Kind == EdgeKindAssignedTo || edge.Kind == EdgeKindWorksAt {
				hasResolverEdge = true
				break
			}
		}
		if hasResolverEdge {
			targets[person.ID] = struct{}{}
		}
	}
	return sortedSet(targets)
}

func securityFindingSources(g *Graph) []string {
	sources := make(map[string]struct{})
	for _, node := range g.GetAllNodes() {
		if node == nil || node.Kind == NodeKindPerson || node.Kind == NodeKindDepartment || node.Kind == NodeKindLocation {
			continue
		}
		if node.Risk == RiskHigh || node.Risk == RiskCritical {
			sources[node.ID] = struct{}{}
		}
	}
	return sortedSet(sources)
}

func remediatorTargets(g *Graph) []string {
	targets := make(map[string]struct{})
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}
		for _, edge := range g.GetOutEdges(person.ID) {
			if edge == nil {
				continue
			}
			if edge.Kind == EdgeKindCanWrite || edge.Kind == EdgeKindCanAdmin || edge.Kind == EdgeKindManagedBy || edge.Kind == EdgeKindOwns || edge.Kind == EdgeKindAssignedTo {
				targets[person.ID] = struct{}{}
				break
			}
		}
	}
	return sortedSet(targets)
}

func salesInsightSources(g *Graph) []string {
	sources := make(map[string]struct{})
	for _, node := range g.GetNodesByKind(NodeKindLead, NodeKindOpportunity, NodeKindDeal, NodeKindCustomer) {
		if node == nil {
			continue
		}
		sources[node.ID] = struct{}{}
	}
	return sortedSet(sources)
}

func productTargets(g *Graph) []string {
	targets := make(map[string]struct{})
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}
		if infoFlowPersonMatchesDepartment(g, person.ID, "product") ||
			informationFlowTextMatch(readString(person.Properties, "title", "role"), "product") {
			targets[person.ID] = struct{}{}
		}
	}
	return sortedSet(targets)
}

func incidentSources(g *Graph) []string {
	sources := make(map[string]struct{})
	for _, node := range g.GetNodesByKind(NodeKindTicket, NodeKindActivity) {
		if node == nil {
			continue
		}
		severity := strings.ToLower(strings.TrimSpace(readString(node.Properties, "severity", "priority")))
		title := strings.ToLower(strings.TrimSpace(firstNonEmpty(node.Name, readString(node.Properties, "title", "summary"))))
		if severity == "critical" || severity == "high" || strings.Contains(title, "incident") || strings.Contains(title, "pagerduty") {
			sources[node.ID] = struct{}{}
		}
	}
	return sortedSet(sources)
}

func executiveTargets(g *Graph) []string {
	targets := make(map[string]struct{})
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}
		title := strings.ToLower(strings.TrimSpace(readString(person.Properties, "title", "role")))
		if title == "" {
			continue
		}
		if strings.Contains(title, "chief") || strings.Contains(title, "vp") || strings.Contains(title, "vice president") ||
			strings.Contains(title, "director") || strings.Contains(title, "head of") {
			targets[person.ID] = struct{}{}
		}
	}
	return sortedSet(targets)
}

func gatherPersonFlowContext(g *Graph, personID string) flowContext {
	ctx := flowContext{
		customers: make(map[string]struct{}),
		systems:   make(map[string]struct{}),
	}
	if g == nil || strings.TrimSpace(personID) == "" {
		return ctx
	}

	collect := func(edge *Edge, oppositeID string) {
		if edge == nil || strings.TrimSpace(oppositeID) == "" {
			return
		}
		opposite, ok := g.GetNode(oppositeID)
		if !ok || opposite == nil {
			return
		}

		switch opposite.Kind {
		case NodeKindCustomer:
			ctx.customers[opposite.ID] = struct{}{}
		default:
			if isSystemNodeKind(opposite.Kind) {
				ctx.systems[opposite.ID] = struct{}{}
			}
		}
	}

	for _, edge := range g.GetOutEdges(personID) {
		collect(edge, edge.Target)
	}
	for _, edge := range g.GetInEdges(personID) {
		collect(edge, edge.Source)
	}
	return ctx
}

func sharedFlowContext(a flowContext, b flowContext) (int, int) {
	sharedCustomers := 0
	for customerID := range a.customers {
		if _, ok := b.customers[customerID]; ok {
			sharedCustomers++
		}
	}
	sharedSystems := 0
	for systemID := range a.systems {
		if _, ok := b.systems[systemID]; ok {
			sharedSystems++
		}
	}
	return sharedCustomers, sharedSystems
}

func buildEdgeRecommendationReason(aName, bName string, sharedCustomers, sharedSystems int) string {
	parts := make([]string, 0, 2)
	if sharedCustomers > 0 {
		parts = append(parts, intToString(sharedCustomers)+" shared customer relationships")
	}
	if sharedSystems > 0 {
		parts = append(parts, intToString(sharedSystems)+" shared systems")
	}
	if len(parts) == 0 {
		parts = append(parts, "adjacent operational scope")
	}
	return firstNonEmpty(aName, "Person A") + " and " + firstNonEmpty(bName, "Person B") + " have " + strings.Join(parts, " and ") + " but no direct interaction edge"
}

func edgeRecommendationSuggestion(personA, personB *Node) string {
	if personA == nil || personB == nil {
		return "Add to weekly sync"
	}
	deptA := strings.TrimSpace(readString(personA.Properties, "department", "team"))
	deptB := strings.TrimSpace(readString(personB.Properties, "department", "team"))
	if deptA != "" && deptB != "" && !strings.EqualFold(deptA, deptB) {
		return "Create shared Slack channel"
	}
	return "Add to weekly sync"
}

func infoFlowPersonMatchesDepartment(g *Graph, personID, query string) bool {
	if g == nil || strings.TrimSpace(personID) == "" || strings.TrimSpace(query) == "" {
		return false
	}
	person, ok := g.GetNode(personID)
	if ok && person != nil && informationFlowTextMatch(readString(person.Properties, "department", "team"), query) {
		return true
	}

	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		if dept, ok := g.GetNode(edge.Target); ok && dept != nil && dept.Kind == NodeKindDepartment {
			if informationFlowTextMatch(dept.Name, query) || informationFlowTextMatch(dept.ID, query) {
				return true
			}
		}
	}
	for _, edge := range g.GetInEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		if dept, ok := g.GetNode(edge.Source); ok && dept != nil && dept.Kind == NodeKindDepartment {
			if informationFlowTextMatch(dept.Name, query) || informationFlowTextMatch(dept.ID, query) {
				return true
			}
		}
	}
	return false
}

func informationFlowDistance(adjacency map[string]map[string]struct{}, source, destination string) int {
	source = strings.TrimSpace(source)
	destination = strings.TrimSpace(destination)
	if source == "" || destination == "" {
		return 0
	}
	if source == destination {
		return 0
	}
	if _, exists := adjacency[source]; !exists {
		return 0
	}

	type queueItem struct {
		node  string
		depth int
	}
	queue := []queueItem{{node: source, depth: 0}}
	visited := map[string]bool{source: true}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		for _, neighbor := range sortedSet(adjacency[item.node]) {
			if visited[neighbor] {
				continue
			}
			nextDepth := item.depth + 1
			if neighbor == destination {
				return nextDepth
			}
			visited[neighbor] = true
			queue = append(queue, queueItem{node: neighbor, depth: nextDepth})
		}
	}
	return 0
}

func infoFlowNodeDisplayName(node *Node) string {
	if node == nil {
		return ""
	}
	if strings.TrimSpace(node.Name) != "" {
		return strings.TrimSpace(node.Name)
	}
	return strings.TrimSpace(node.ID)
}

func informationFlowTextMatch(candidate, query string) bool {
	candidate = normalizeOrgKey(candidate)
	query = normalizeOrgKey(query)
	if candidate == "" || query == "" {
		return false
	}
	return candidate == query || strings.Contains(candidate, query)
}

func isInformationFlowEdge(kind EdgeKind) bool {
	switch kind {
	case EdgeKindResolvesTo, EdgeKindCanRead, EdgeKindCanWrite, EdgeKindCanDelete, EdgeKindCanAdmin:
		return false
	default:
		return true
	}
}

func isSystemNodeKind(kind NodeKind) bool {
	switch kind {
	case NodeKindApplication, NodeKindRepository, NodeKindDatabase, NodeKindFunction, NodeKindServiceAccount, NodeKindDeployment:
		return true
	default:
		return false
	}
}

func intToString(value int) string {
	return strconv.Itoa(value)
}
