package graph

import (
	"math"
	"sort"
	"strings"
	"time"
)

const (
	defaultBusFactorActiveWindow      = 90 * 24 * time.Hour
	defaultRelationshipDecayThreshold = 0.3
	defaultPreviousStrongRelationship = 0.7
	defaultTopBottleneckFraction      = 0.10
	defaultPenaltySaturationCount     = 5.0
)

var orgHealthNowUTC = func() time.Time {
	return time.Now().UTC()
}

// BusFactorResult summarizes knowledge concentration for one target node.
type BusFactorResult struct {
	TargetID        string    `json:"target_id"`
	TargetKind      NodeKind  `json:"target_kind"`
	Total           int       `json:"total"`
	Active          int       `json:"active"`
	BusFactor       int       `json:"bus_factor"`
	Risk            RiskLevel `json:"risk"`
	PersonIDs       []string  `json:"person_ids,omitempty"`
	ActivePersonIDs []string  `json:"active_person_ids,omitempty"`
}

// Silo captures two departments that share dependencies but have no interactions.
type Silo struct {
	TeamAID              string   `json:"team_a_id"`
	TeamAName            string   `json:"team_a_name"`
	TeamBID              string   `json:"team_b_id"`
	TeamBName            string   `json:"team_b_name"`
	SharedDependencies   []string `json:"shared_dependencies"`
	InteractionEdgeCount int      `json:"interaction_edge_count"`
}

// BottleneckResult identifies a person who may be a communication bridge.
type BottleneckResult struct {
	PersonID              string  `json:"person_id"`
	PersonName            string  `json:"person_name"`
	BetweennessCentrality float64 `json:"betweenness_centrality"`
	BridgedTeams          int     `json:"bridged_teams"`
	IsSoleBridge          bool    `json:"is_sole_bridge"`
}

// DecayAlert identifies a relationship that weakened materially.
type DecayAlert struct {
	EdgeID            string    `json:"edge_id"`
	SourceID          string    `json:"source_id"`
	TargetID          string    `json:"target_id"`
	CurrentStrength   float64   `json:"current_strength"`
	PreviousStrength  float64   `json:"previous_strength"`
	Trend             float64   `json:"trend"`
	LastInteractionAt time.Time `json:"last_interaction_at,omitempty"`
}

// OrgHealthScore summarizes organizational topology health.
type OrgHealthScore struct {
	KnowledgeDistribution   float64            `json:"knowledge_distribution"`
	CommunicationDensity    float64            `json:"communication_density"`
	SinglePointsOfFailure   int                `json:"single_points_of_failure"`
	RelationshipDecay       float64            `json:"relationship_decay"`
	SiloCount               int                `json:"silo_count"`
	BottleneckConcentration float64            `json:"bottleneck_concentration"`
	OverallScore            float64            `json:"overall_score"`
	BusFactors              []BusFactorResult  `json:"bus_factors,omitempty"`
	Silos                   []Silo             `json:"silos,omitempty"`
	Bottlenecks             []BottleneckResult `json:"bottlenecks,omitempty"`
	DecayAlerts             []DecayAlert       `json:"decay_alerts,omitempty"`
}

// BusFactor computes person coverage for one target node using a 90-day active window.
func BusFactor(g *Graph, targetID string) BusFactorResult {
	return BusFactorWithWindow(g, targetID, defaultBusFactorActiveWindow)
}

// BusFactorWithWindow computes person coverage for one target node with a custom active window.
func BusFactorWithWindow(g *Graph, targetID string, activeWithin time.Duration) BusFactorResult {
	result := BusFactorResult{TargetID: strings.TrimSpace(targetID)}
	if g == nil || result.TargetID == "" {
		return result
	}
	if activeWithin <= 0 {
		activeWithin = defaultBusFactorActiveWindow
	}

	if target, ok := g.GetNode(result.TargetID); ok && target != nil {
		result.TargetKind = target.Kind
	}

	totalPeople, activePeople := connectedPersonsForTarget(g, result.TargetID, activeWithin)
	result.PersonIDs = sortedSet(totalPeople)
	result.ActivePersonIDs = sortedSet(activePeople)
	result.Total = len(result.PersonIDs)
	result.Active = len(result.ActivePersonIDs)
	result.BusFactor = result.Active
	result.Risk = busFactorRiskForActiveCount(result.Active)
	return result
}

// DetectSilos finds department pairs with shared dependencies and no interactions.
func DetectSilos(g *Graph) []Silo {
	if g == nil {
		return nil
	}

	departmentMembers, departmentNames := departmentMembersByID(g)
	if len(departmentMembers) == 0 {
		return nil
	}

	departmentDependencies := make(map[string]map[string]struct{}, len(departmentMembers))
	departmentIDs := make([]string, 0, len(departmentMembers))
	for deptID, members := range departmentMembers {
		if len(members) == 0 {
			continue
		}
		departmentIDs = append(departmentIDs, deptID)
		departmentDependencies[deptID] = dependenciesForMembers(g, members)
	}
	sort.Strings(departmentIDs)

	silos := make([]Silo, 0)
	for i := 0; i < len(departmentIDs); i++ {
		for j := i + 1; j < len(departmentIDs); j++ {
			teamA := departmentIDs[i]
			teamB := departmentIDs[j]

			shared := intersectStringSets(departmentDependencies[teamA], departmentDependencies[teamB])
			if len(shared) == 0 {
				continue
			}

			interactions := interactionEdgesBetweenMemberSets(g, departmentMembers[teamA], departmentMembers[teamB])
			if interactions > 0 {
				continue
			}

			silos = append(silos, Silo{
				TeamAID:              teamA,
				TeamAName:            firstNonEmpty(departmentNames[teamA], teamA),
				TeamBID:              teamB,
				TeamBName:            firstNonEmpty(departmentNames[teamB], teamB),
				SharedDependencies:   shared,
				InteractionEdgeCount: interactions,
			})
		}
	}

	sort.Slice(silos, func(i, j int) bool {
		if silos[i].TeamAID == silos[j].TeamAID {
			return silos[i].TeamBID < silos[j].TeamBID
		}
		return silos[i].TeamAID < silos[j].TeamAID
	})
	return silos
}

// Bottlenecks computes person betweenness centrality and bridge concentration indicators.
func Bottlenecks(g *Graph) []BottleneckResult {
	if g == nil {
		return nil
	}

	adjacency := personInteractionAdjacency(g)
	if len(adjacency) == 0 {
		return nil
	}

	centrality := betweennessCentrality(adjacency)
	articulation := articulationPointSet(adjacency)
	departmentsByPerson := departmentsByPerson(g)

	results := make([]BottleneckResult, 0, len(adjacency))
	for personID := range adjacency {
		score := centrality[personID]
		soleBridge := articulation[personID]
		if score <= 0 && !soleBridge {
			continue
		}

		name := personID
		if person, ok := g.GetNode(personID); ok && person != nil && strings.TrimSpace(person.Name) != "" {
			name = person.Name
		}

		results = append(results, BottleneckResult{
			PersonID:              personID,
			PersonName:            name,
			BetweennessCentrality: score,
			BridgedTeams:          bridgedTeamCount(personID, adjacency, departmentsByPerson),
			IsSoleBridge:          soleBridge,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].BetweennessCentrality == results[j].BetweennessCentrality {
			return results[i].PersonID < results[j].PersonID
		}
		return results[i].BetweennessCentrality > results[j].BetweennessCentrality
	})
	return results
}

// DecayingRelationships returns weakened relationship alerts using a strength threshold.
func DecayingRelationships(g *Graph, threshold float64) []DecayAlert {
	alerts, _ := decayingRelationshipsWithStats(g, threshold)
	return alerts
}

// ComputeOrgHealthScore computes organizational topology metrics and a weighted 0-100 score.
func ComputeOrgHealthScore(g *Graph) OrgHealthScore {
	score := OrgHealthScore{
		KnowledgeDistribution: 1,
		CommunicationDensity:  1,
		OverallScore:          100,
	}
	if g == nil {
		return score
	}

	targets := orgHealthTargets(g)
	busFactors := make([]BusFactorResult, 0, len(targets))
	activeKnowledgeByPerson := make(map[string]float64)
	singlePointsOfFailure := 0

	for _, target := range targets {
		bus := BusFactor(g, target.ID)
		if bus.Total == 0 {
			continue
		}
		busFactors = append(busFactors, bus)
		if bus.Active <= 1 {
			singlePointsOfFailure++
		}
		for _, personID := range bus.ActivePersonIDs {
			activeKnowledgeByPerson[personID]++
		}
	}

	sort.Slice(busFactors, func(i, j int) bool {
		if busFactors[i].BusFactor == busFactors[j].BusFactor {
			return busFactors[i].TargetID < busFactors[j].TargetID
		}
		return busFactors[i].BusFactor < busFactors[j].BusFactor
	})

	knowledgeDistribution := 1.0
	if len(activeKnowledgeByPerson) > 0 {
		values := make([]float64, 0, len(activeKnowledgeByPerson))
		for _, count := range activeKnowledgeByPerson {
			values = append(values, count)
		}
		knowledgeDistribution = 1 - giniCoefficient(values)
	}

	communicationDensity := personInteractionDensity(g)
	silos := DetectSilos(g)
	bottlenecks := Bottlenecks(g)
	bottleneckConcentration := bottleneckConcentrationScore(bottlenecks)
	decayAlerts, keyRelationships := decayingRelationshipsWithStats(g, defaultRelationshipDecayThreshold)

	relationshipDecay := 0.0
	if keyRelationships > 0 {
		relationshipDecay = float64(len(decayAlerts)) / float64(keyRelationships)
	}

	score = OrgHealthScore{
		KnowledgeDistribution:   clampUnitInterval(knowledgeDistribution),
		CommunicationDensity:    clampUnitInterval(communicationDensity),
		SinglePointsOfFailure:   singlePointsOfFailure,
		RelationshipDecay:       clampUnitInterval(relationshipDecay),
		SiloCount:               len(silos),
		BottleneckConcentration: clampUnitInterval(bottleneckConcentration),
		BusFactors:              busFactors,
		Silos:                   silos,
		Bottlenecks:             bottlenecks,
		DecayAlerts:             decayAlerts,
	}
	score.OverallScore = computeOverallOrgHealth(
		score.KnowledgeDistribution,
		score.CommunicationDensity,
		score.SinglePointsOfFailure,
		score.RelationshipDecay,
		score.SiloCount,
		score.BottleneckConcentration,
	)

	return score
}

func connectedPersonsForTarget(g *Graph, targetID string, activeWithin time.Duration) (map[string]struct{}, map[string]struct{}) {
	total := make(map[string]struct{})
	active := make(map[string]struct{})

	register := func(personID string, edge *Edge) {
		if strings.TrimSpace(personID) == "" || edge == nil {
			return
		}
		if !isKnowledgeFlowEdge(edge.Kind) {
			return
		}
		person, ok := g.GetNode(personID)
		if !ok || person == nil || person.Kind != NodeKindPerson {
			return
		}
		total[personID] = struct{}{}
		if edgeRecencyActive(edge, activeWithin) {
			active[personID] = struct{}{}
		}
	}

	for _, edge := range g.GetOutEdges(targetID) {
		register(edge.Target, edge)
	}
	for _, edge := range g.GetInEdges(targetID) {
		register(edge.Source, edge)
	}

	return total, active
}

func busFactorRiskForActiveCount(active int) RiskLevel {
	switch {
	case active <= 1:
		return RiskCritical
	case active == 2:
		return RiskHigh
	case active == 3:
		return RiskMedium
	default:
		return RiskLow
	}
}

func isKnowledgeFlowEdge(kind EdgeKind) bool {
	switch kind {
	case EdgeKindMemberOf, EdgeKindResolvesTo, EdgeKindReportsTo, EdgeKindLocatedIn:
		return false
	default:
		return true
	}
}

func edgeRecencyActive(edge *Edge, activeWithin time.Duration) bool {
	if edge == nil || activeWithin <= 0 {
		return true
	}
	last := firstTimeFromMap(edge.Properties, "last_seen", "last_interaction", "last_activity", "updated_at")
	if last.IsZero() {
		return true
	}
	cutoff := orgHealthNowUTC().Add(-activeWithin)
	return !last.Before(cutoff)
}

func departmentMembersByID(g *Graph) (map[string]map[string]struct{}, map[string]string) {
	members := make(map[string]map[string]struct{})
	names := make(map[string]string)

	for _, department := range g.GetNodesByKind(NodeKindDepartment) {
		members[department.ID] = make(map[string]struct{})
		names[department.ID] = department.Name
	}

	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || edge.Kind != EdgeKindMemberOf {
				continue
			}

			source, sourceOK := g.GetNode(edge.Source)
			target, targetOK := g.GetNode(edge.Target)
			if !sourceOK || !targetOK || source == nil || target == nil {
				continue
			}

			if source.Kind == NodeKindPerson && target.Kind == NodeKindDepartment {
				if _, exists := members[target.ID]; !exists {
					members[target.ID] = make(map[string]struct{})
				}
				if names[target.ID] == "" {
					names[target.ID] = target.Name
				}
				members[target.ID][source.ID] = struct{}{}
				continue
			}
			if target.Kind == NodeKindPerson && source.Kind == NodeKindDepartment {
				if _, exists := members[source.ID]; !exists {
					members[source.ID] = make(map[string]struct{})
				}
				if names[source.ID] == "" {
					names[source.ID] = source.Name
				}
				members[source.ID][target.ID] = struct{}{}
			}
		}
	}

	return members, names
}

func dependenciesForMembers(g *Graph, members map[string]struct{}) map[string]struct{} {
	dependencies := make(map[string]struct{})
	for personID := range members {
		for _, edge := range g.GetOutEdges(personID) {
			if edge == nil || !isDependencyEdge(edge.Kind) {
				continue
			}
			targetNode, ok := g.GetNode(edge.Target)
			if !ok || targetNode == nil || isOrganizationalNode(targetNode.Kind) {
				continue
			}
			dependencies[targetNode.ID] = struct{}{}
		}
		for _, edge := range g.GetInEdges(personID) {
			if edge == nil || !isDependencyEdge(edge.Kind) {
				continue
			}
			sourceNode, ok := g.GetNode(edge.Source)
			if !ok || sourceNode == nil || isOrganizationalNode(sourceNode.Kind) {
				continue
			}
			dependencies[sourceNode.ID] = struct{}{}
		}
	}
	return dependencies
}

func isDependencyEdge(kind EdgeKind) bool {
	switch kind {
	case EdgeKindMemberOf, EdgeKindResolvesTo, EdgeKindReportsTo, EdgeKindLocatedIn, EdgeKindInteractedWith:
		return false
	default:
		return true
	}
}

func isOrganizationalNode(kind NodeKind) bool {
	switch kind {
	case NodeKindPerson, NodeKindDepartment, NodeKindLocation:
		return true
	default:
		return false
	}
}

func interactionEdgesBetweenMemberSets(g *Graph, teamA map[string]struct{}, teamB map[string]struct{}) int {
	if len(teamA) == 0 || len(teamB) == 0 {
		return 0
	}
	seen := make(map[string]struct{})

	scan := func(team map[string]struct{}, opposite map[string]struct{}) {
		for personID := range team {
			for _, edge := range g.GetOutEdges(personID) {
				if edge == nil || edge.Kind != EdgeKindInteractedWith {
					continue
				}
				if _, ok := opposite[edge.Target]; !ok {
					continue
				}
				seen[undirectedPairKey(edge.Source, edge.Target)] = struct{}{}
			}
		}
	}

	scan(teamA, teamB)
	scan(teamB, teamA)
	return len(seen)
}

func intersectStringSets(a map[string]struct{}, b map[string]struct{}) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	shared := make([]string, 0)
	for key := range a {
		if _, ok := b[key]; !ok {
			continue
		}
		shared = append(shared, key)
	}
	sort.Strings(shared)
	return shared
}

func personInteractionAdjacency(g *Graph) map[string]map[string]struct{} {
	adj := make(map[string]map[string]struct{})
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		adj[person.ID] = make(map[string]struct{})
	}

	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || edge.Kind != EdgeKindInteractedWith {
				continue
			}
			source, sourceOK := g.GetNode(edge.Source)
			target, targetOK := g.GetNode(edge.Target)
			if !sourceOK || !targetOK || source == nil || target == nil {
				continue
			}
			if source.Kind != NodeKindPerson || target.Kind != NodeKindPerson {
				continue
			}
			if source.ID == target.ID {
				continue
			}
			if _, exists := adj[source.ID]; !exists {
				adj[source.ID] = make(map[string]struct{})
			}
			if _, exists := adj[target.ID]; !exists {
				adj[target.ID] = make(map[string]struct{})
			}
			adj[source.ID][target.ID] = struct{}{}
			adj[target.ID][source.ID] = struct{}{}
		}
	}

	return adj
}

func betweennessCentrality(adjacency map[string]map[string]struct{}) map[string]float64 {
	nodes := sortedMapKeys(adjacency)
	centrality := make(map[string]float64, len(nodes))
	for _, nodeID := range nodes {
		centrality[nodeID] = 0
	}
	if len(nodes) == 0 {
		return centrality
	}

	for _, source := range nodes {
		stack := make([]string, 0, len(nodes))
		predecessors := make(map[string][]string, len(nodes))
		pathCount := make(map[string]float64, len(nodes))
		distance := make(map[string]int, len(nodes))

		for _, nodeID := range nodes {
			distance[nodeID] = -1
			pathCount[nodeID] = 0
		}
		pathCount[source] = 1
		distance[source] = 0

		queue := []string{source}
		for len(queue) > 0 {
			v := queue[0]
			queue = queue[1:]
			stack = append(stack, v)

			for _, w := range sortedSet(adjacency[v]) {
				if distance[w] < 0 {
					queue = append(queue, w)
					distance[w] = distance[v] + 1
				}
				if distance[w] == distance[v]+1 {
					pathCount[w] += pathCount[v]
					predecessors[w] = append(predecessors[w], v)
				}
			}
		}

		dependency := make(map[string]float64, len(nodes))
		for len(stack) > 0 {
			w := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			for _, v := range predecessors[w] {
				if pathCount[w] == 0 {
					continue
				}
				dependency[v] += (pathCount[v] / pathCount[w]) * (1 + dependency[w])
			}
			if w != source {
				centrality[w] += dependency[w]
			}
		}
	}

	// Undirected graph normalization.
	for nodeID := range centrality {
		centrality[nodeID] /= 2
	}
	n := len(nodes)
	if n > 2 {
		scale := 1 / ((float64(n-1) * float64(n-2)) / 2)
		for nodeID := range centrality {
			centrality[nodeID] *= scale
		}
	}

	return centrality
}

func articulationPointSet(adjacency map[string]map[string]struct{}) map[string]bool {
	ap := make(map[string]bool)
	if len(adjacency) == 0 {
		return ap
	}

	visited := make(map[string]bool, len(adjacency))
	discovery := make(map[string]int, len(adjacency))
	low := make(map[string]int, len(adjacency))
	parent := make(map[string]string, len(adjacency))
	timeIndex := 0

	var dfs func(string)
	dfs = func(node string) {
		visited[node] = true
		timeIndex++
		discovery[node] = timeIndex
		low[node] = timeIndex
		children := 0

		for _, neighbor := range sortedSet(adjacency[node]) {
			if !visited[neighbor] {
				children++
				parent[neighbor] = node
				dfs(neighbor)

				if low[neighbor] < low[node] {
					low[node] = low[neighbor]
				}
				if parent[node] == "" && children > 1 {
					ap[node] = true
				}
				if parent[node] != "" && low[neighbor] >= discovery[node] {
					ap[node] = true
				}
				continue
			}
			if neighbor == parent[node] {
				continue
			}
			if discovery[neighbor] < low[node] {
				low[node] = discovery[neighbor]
			}
		}
	}

	for _, node := range sortedMapKeys(adjacency) {
		if visited[node] {
			continue
		}
		parent[node] = ""
		dfs(node)
	}
	return ap
}

func departmentsByPerson(g *Graph) map[string]map[string]struct{} {
	departments := make(map[string]map[string]struct{})
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		departments[person.ID] = make(map[string]struct{})
	}

	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || edge.Kind != EdgeKindMemberOf {
				continue
			}
			source, sourceOK := g.GetNode(edge.Source)
			target, targetOK := g.GetNode(edge.Target)
			if !sourceOK || !targetOK || source == nil || target == nil {
				continue
			}

			switch {
			case source.Kind == NodeKindPerson && target.Kind == NodeKindDepartment:
				departments[source.ID][target.ID] = struct{}{}
			case target.Kind == NodeKindPerson && source.Kind == NodeKindDepartment:
				departments[target.ID][source.ID] = struct{}{}
			}
		}
	}

	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if len(departments[person.ID]) > 0 {
			continue
		}
		dept := strings.TrimSpace(readString(person.Properties, "department"))
		if dept == "" {
			continue
		}
		departmentID := "department:" + normalizeOrgKey(dept)
		if strings.TrimSpace(departmentID) != "department:" {
			departments[person.ID][departmentID] = struct{}{}
		}
	}

	return departments
}

func bridgedTeamCount(personID string, adjacency map[string]map[string]struct{}, departments map[string]map[string]struct{}) int {
	teams := make(map[string]struct{})
	for neighbor := range adjacency[personID] {
		for departmentID := range departments[neighbor] {
			teams[departmentID] = struct{}{}
		}
	}
	return len(teams)
}

func decayingRelationshipsWithStats(g *Graph, threshold float64) ([]DecayAlert, int) {
	if g == nil {
		return nil, 0
	}
	if threshold <= 0 {
		threshold = defaultRelationshipDecayThreshold
	}

	now := orgHealthNowUTC()
	alerts := make([]DecayAlert, 0)
	keyRelationships := 0

	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || !isTrackableRelationshipEdge(g, edge) {
				continue
			}

			currentStrength, previousStrength, lastInteraction := relationshipStrengthTrend(now, edge)
			if previousStrength < defaultPreviousStrongRelationship {
				continue
			}
			keyRelationships++

			if currentStrength >= threshold {
				continue
			}

			trend := 0.0
			if previousStrength > 0 {
				trend = (currentStrength - previousStrength) / previousStrength
			}

			alerts = append(alerts, DecayAlert{
				EdgeID:            edge.ID,
				SourceID:          edge.Source,
				TargetID:          edge.Target,
				CurrentStrength:   currentStrength,
				PreviousStrength:  previousStrength,
				Trend:             trend,
				LastInteractionAt: lastInteraction,
			})
		}
	}

	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].CurrentStrength == alerts[j].CurrentStrength {
			return alerts[i].EdgeID < alerts[j].EdgeID
		}
		return alerts[i].CurrentStrength < alerts[j].CurrentStrength
	})

	return alerts, keyRelationships
}

func isTrackableRelationshipEdge(g *Graph, edge *Edge) bool {
	if edge == nil {
		return false
	}
	if edge.Kind == EdgeKindInteractedWith {
		return true
	}

	source, sourceOK := g.GetNode(edge.Source)
	target, targetOK := g.GetNode(edge.Target)
	if !sourceOK || !targetOK || source == nil || target == nil {
		return false
	}
	isPersonCustomer := (source.Kind == NodeKindPerson && target.Kind == NodeKindCustomer) ||
		(source.Kind == NodeKindCustomer && target.Kind == NodeKindPerson)
	if !isPersonCustomer {
		return false
	}

	switch edge.Kind {
	case EdgeKindManagedBy, EdgeKindOwns, EdgeKindAssignedTo, EdgeKindInteractedWith, EdgeKindRenews, EdgeKindEscalatedTo:
		return true
	default:
		return false
	}
}

func relationshipStrengthTrend(now time.Time, edge *Edge) (float64, float64, time.Time) {
	lastInteraction := firstTimeFromMap(edge.Properties, "last_seen", "last_interaction", "last_activity")
	frequency := readFloat(edge.Properties, "frequency")
	if frequency <= 0 {
		frequency = float64(int64FromValue(edge.Properties["call_count"]) +
			int64FromValue(edge.Properties["co_actions"]) +
			int64FromValue(edge.Properties["shared_groups"]) +
			int64FromValue(edge.Properties["shared_apps"]))
	}

	currentStrength := readFloat(edge.Properties, "strength", "relationship_strength")
	if currentStrength <= 0 && (frequency > 0 || !lastInteraction.IsZero()) {
		currentStrength = relationshipStrengthAt(now, lastInteraction, frequency)
	}
	if currentStrength < 0 {
		currentStrength = 0
	}

	previousStrength := readFloat(edge.Properties, "previous_strength", "previousStrength", "prior_strength", "baseline_strength")
	if previousStrength <= 0 {
		previousFrequency := readFloat(edge.Properties, "previous_frequency", "prior_frequency", "baseline_frequency")
		if previousFrequency <= 0 {
			previousFrequency = frequency
		}
		previousLastSeen := firstTimeFromMap(edge.Properties, "previous_last_seen", "previous_last_interaction", "baseline_last_seen")
		if previousLastSeen.IsZero() {
			previousLastSeen = now
		}
		previousStrength = relationshipStrengthAt(previousLastSeen, previousLastSeen, previousFrequency)
	}
	if previousStrength < 0 {
		previousStrength = 0
	}

	return currentStrength, previousStrength, lastInteraction
}

func relationshipStrengthAt(now time.Time, lastInteraction time.Time, frequency float64) float64 {
	if frequency <= 0 {
		return 0
	}
	if lastInteraction.IsZero() {
		lastInteraction = now
	}
	daysSince := now.Sub(lastInteraction).Hours() / 24
	if daysSince < 0 {
		daysSince = 0
	}
	recency := math.Exp(-daysSince / 30)
	return recency * math.Log1p(frequency)
}

func orgHealthTargets(g *Graph) []*Node {
	targets := make([]*Node, 0)
	for _, node := range g.GetAllNodes() {
		if node == nil || node.Kind == NodeKindPerson || node.Kind == NodeKindDepartment || node.Kind == NodeKindLocation || node.Kind == NodeKindInternet {
			continue
		}
		if isOrgHealthTargetKind(node.Kind) || isHighCriticalityNode(node) {
			targets = append(targets, node)
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })
	return targets
}

func isOrgHealthTargetKind(kind NodeKind) bool {
	switch kind {
	case NodeKindRepository, NodeKindApplication, NodeKindDatabase, NodeKindFunction, NodeKindBucket, NodeKindCustomer, NodeKindCompany, NodeKindVendor:
		return true
	default:
		return false
	}
}

func isHighCriticalityNode(node *Node) bool {
	if node == nil {
		return false
	}
	criticality := strings.ToLower(strings.TrimSpace(readString(node.Properties, "criticality", "business_criticality", "tier", "priority")))
	switch criticality {
	case "high", "critical", "p0", "tier0", "tier-0":
		return true
	default:
		return false
	}
}

func personInteractionDensity(g *Graph) float64 {
	people := g.GetNodesByKind(NodeKindPerson)
	count := len(people)
	if count <= 1 {
		return 1
	}
	personSet := make(map[string]struct{}, count)
	for _, person := range people {
		personSet[person.ID] = struct{}{}
	}

	edges := make(map[string]struct{})
	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || edge.Kind != EdgeKindInteractedWith {
				continue
			}
			if _, ok := personSet[edge.Source]; !ok {
				continue
			}
			if _, ok := personSet[edge.Target]; !ok {
				continue
			}
			edges[undirectedPairKey(edge.Source, edge.Target)] = struct{}{}
		}
	}

	expected := (count * (count - 1)) / 2
	if expected <= 0 {
		return 1
	}
	return clampUnitInterval(float64(len(edges)) / float64(expected))
}

func bottleneckConcentrationScore(results []BottleneckResult) float64 {
	if len(results) == 0 {
		return 0
	}
	scored := make([]float64, 0, len(results))
	total := 0.0
	for _, result := range results {
		if result.BetweennessCentrality <= 0 {
			continue
		}
		scored = append(scored, result.BetweennessCentrality)
		total += result.BetweennessCentrality
	}
	if len(scored) == 0 || total <= 0 {
		return 0
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i] > scored[j] })

	topN := int(math.Ceil(float64(len(scored)) * defaultTopBottleneckFraction))
	if topN < 1 {
		topN = 1
	}
	if topN > len(scored) {
		topN = len(scored)
	}

	top := 0.0
	for i := 0; i < topN; i++ {
		top += scored[i]
	}
	return clampUnitInterval(top / total)
}

func computeOverallOrgHealth(knowledgeDistribution float64, communicationDensity float64, singlePointsOfFailure int, relationshipDecay float64, siloCount int, bottleneckConcentration float64) float64 {
	knowledgeScore := clampUnitInterval(knowledgeDistribution) * 100
	communicationScore := clampUnitInterval(communicationDensity) * 100
	spofPenalty := math.Min(1, float64(singlePointsOfFailure)/defaultPenaltySaturationCount)
	spofScore := (1 - spofPenalty) * 100
	decayScore := (1 - clampUnitInterval(relationshipDecay)) * 100
	siloPenalty := math.Min(1, float64(siloCount)/defaultPenaltySaturationCount)
	siloScore := (1 - siloPenalty) * 100
	bottleneckScore := (1 - clampUnitInterval(bottleneckConcentration)) * 100

	overall := (knowledgeScore * 0.20) +
		(communicationScore * 0.20) +
		(spofScore * 0.20) +
		(decayScore * 0.15) +
		(siloScore * 0.15) +
		(bottleneckScore * 0.10)
	return clampScore(overall)
}

func giniCoefficient(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := make([]float64, 0, len(values))
	total := 0.0
	for _, value := range values {
		if value < 0 {
			value = 0
		}
		sorted = append(sorted, value)
		total += value
	}
	if total <= 0 {
		return 0
	}
	sort.Float64s(sorted)

	n := float64(len(sorted))
	acc := 0.0
	for idx, value := range sorted {
		i := float64(idx + 1)
		acc += ((2 * i) - n - 1) * value
	}
	gini := acc / (n * total)
	return clampUnitInterval(gini)
}

func firstTimeFromMap(values map[string]any, keys ...string) time.Time {
	if len(values) == 0 || len(keys) == 0 {
		return time.Time{}
	}
	for _, key := range keys {
		typed := strings.TrimSpace(key)
		if typed == "" {
			continue
		}
		raw, ok := values[typed]
		if !ok {
			continue
		}
		if parsed := parseCDCEventTime(raw); !parsed.IsZero() {
			return parsed
		}
	}
	return time.Time{}
}

func sortedMapKeys(values map[string]map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func undirectedPairKey(a string, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

func clampUnitInterval(value float64) float64 {
	switch {
	case value < 0:
		return 0
	case value > 1:
		return 1
	default:
		return value
	}
}
