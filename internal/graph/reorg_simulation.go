package graph

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ReorgChange describes one requested organizational change in a reorg simulation.
type ReorgChange struct {
	Person        string   `json:"person,omitempty"`
	NewDepartment string   `json:"new_department,omitempty"`
	NewManager    string   `json:"new_manager,omitempty"`
	MergeTeams    []string `json:"merge_teams,omitempty"`
	SplitTeam     string   `json:"split_team,omitempty"`
	Into          []string `json:"into,omitempty"`
}

// ReorgImpact summarizes projected communication, knowledge, and customer impacts.
type ReorgImpact struct {
	BrokenBridges          []BrokenBridge    `json:"broken_bridges,omitempty"`
	WeakenedPaths          []PathChange      `json:"weakened_paths,omitempty"`
	SeveredCustomerLinks   []CustomerImpact  `json:"severed_customer_links,omitempty"`
	BusFactorChanges       []BusFactorDelta  `json:"bus_factor_changes,omitempty"`
	KnowledgeOrphaned      []string          `json:"knowledge_orphaned,omitempty"`
	InteractionEdgesLost   int               `json:"interaction_edges_lost"`
	InteractionEdgesGained int               `json:"interaction_edges_gained"`
	CohesionBefore         float64           `json:"cohesion_before"`
	CohesionAfter          float64           `json:"cohesion_after"`
	AvgPathLengthBefore    float64           `json:"avg_path_length_before"`
	AvgPathLengthAfter     float64           `json:"avg_path_length_after"`
	RecommendedActions     []ReorgMitigation `json:"recommended_actions,omitempty"`
}

// BrokenBridge captures a team-to-team communication bridge severed by reorg changes.
type BrokenBridge struct {
	TeamA                string `json:"team_a"`
	TeamB                string `json:"team_b"`
	BridgePerson         string `json:"bridge_person,omitempty"`
	InteractionsPerMonth int    `json:"interactions_per_month"`
	AlternativePaths     int    `json:"alternative_paths"`
	Mitigation           string `json:"mitigation"`
}

// PathChange summarizes information-flow degradation between two endpoints.
type PathChange struct {
	From          string `json:"from"`
	To            string `json:"to"`
	HopsBefore    int    `json:"hops_before"`
	HopsAfter     int    `json:"hops_after"`
	LatencyBefore string `json:"latency_before"`
	LatencyAfter  string `json:"latency_after"`
	Impact        string `json:"impact"`
}

// CustomerImpact captures customer relationship topology degradation after reorg.
type CustomerImpact struct {
	CustomerID        string  `json:"customer_id"`
	CustomerName      string  `json:"customer_name,omitempty"`
	TouchpointsBefore int     `json:"touchpoints_before"`
	TouchpointsAfter  int     `json:"touchpoints_after"`
	HealthBefore      float64 `json:"health_before"`
	HealthAfter       float64 `json:"health_after"`
	Impact            string  `json:"impact"`
}

// BusFactorDelta captures bus-factor movement for one target entity.
type BusFactorDelta struct {
	TargetID string `json:"target_id"`
	Before   int    `json:"before"`
	After    int    `json:"after"`
	Delta    int    `json:"delta"`
}

// ReorgMitigation is one concrete action to reduce predicted reorg risk.
type ReorgMitigation struct {
	Action     string `json:"action"`
	Reason     string `json:"reason"`
	Priority   string `json:"priority"`
	BeforeDate string `json:"before_date"`
}

// SimulateReorg applies reorg changes to a cloned graph and returns impact analysis.
func SimulateReorg(g *Graph, changes []ReorgChange) (*ReorgImpact, error) {
	if g == nil {
		return nil, fmt.Errorf("graph is nil")
	}
	if len(changes) == 0 {
		return nil, fmt.Errorf("at least one reorg change is required")
	}

	delta, changedPeople, err := buildReorgDelta(g, changes)
	if err != nil {
		return nil, err
	}
	if len(delta.Nodes) == 0 && len(delta.Edges) == 0 {
		return nil, fmt.Errorf("no actionable reorg changes were provided")
	}

	after := g.Fork()
	if err := after.ApplyDelta(delta); err != nil {
		return nil, err
	}
	after.BuildIndex()

	impact := buildReorgImpact(g, after, changedPeople)
	return impact, nil
}

func buildReorgImpact(before *Graph, after *Graph, changedPeople map[string]struct{}) *ReorgImpact {
	impact := &ReorgImpact{}
	if before == nil || after == nil {
		return impact
	}

	beforeOrg := ComputeOrgHealthScore(before)
	afterOrg := ComputeOrgHealthScore(after)
	beforeClock := ComputeClockSpeed(before)
	afterClock := ComputeClockSpeed(after)

	impact.CohesionBefore = beforeOrg.CommunicationDensity
	impact.CohesionAfter = afterOrg.CommunicationDensity
	impact.AvgPathLengthBefore = beforeClock.AverageHops
	impact.AvgPathLengthAfter = afterClock.AverageHops

	beforeInteractions := countUndirectedInteractionEdges(before)
	afterInteractions := countUndirectedInteractionEdges(after)
	if afterInteractions < beforeInteractions {
		impact.InteractionEdgesLost = beforeInteractions - afterInteractions
	}
	if afterInteractions > beforeInteractions {
		impact.InteractionEdgesGained = afterInteractions - beforeInteractions
	}

	impact.BrokenBridges = detectBrokenBridges(before, after, changedPeople)
	impact.WeakenedPaths = detectWeakenedPaths(before, after, impact.BrokenBridges)
	impact.SeveredCustomerLinks = detectSeveredCustomerLinks(before, after)
	impact.BusFactorChanges, impact.KnowledgeOrphaned = detectBusFactorDeltas(beforeOrg, afterOrg)
	impact.RecommendedActions = buildReorgMitigations(impact)

	return impact
}

func buildReorgDelta(g *Graph, changes []ReorgChange) (GraphDelta, map[string]struct{}, error) {
	delta := GraphDelta{
		Nodes: make([]NodeMutation, 0),
		Edges: make([]EdgeMutation, 0),
	}
	changedPeople := make(map[string]struct{})
	addedDepartments := make(map[string]struct{})

	for idx, change := range changes {
		handled := false

		if strings.TrimSpace(change.Person) != "" {
			personID := resolveReorgPersonID(g, change.Person)
			if personID == "" {
				return GraphDelta{}, nil, fmt.Errorf("change %d: unknown person %q", idx, change.Person)
			}
			changedPeople[personID] = struct{}{}
			handled = true

			if deptName := strings.TrimSpace(change.NewDepartment); deptName != "" {
				deptID, deptNode := resolveOrCreateDepartment(g, deptName)
				if _, exists := addedDepartments[deptID]; !exists {
					if _, ok := g.GetNode(deptID); !ok {
						delta.Nodes = append(delta.Nodes, NodeMutation{Action: "add", Node: deptNode})
					}
					addedDepartments[deptID] = struct{}{}
				}

				delta.Edges = append(delta.Edges, removePersonMembershipMutations(g, personID)...)
				delta.Edges = append(delta.Edges, EdgeMutation{Action: "add", Edge: &Edge{
					ID:     fmt.Sprintf("reorg:%s:member_of:%s", personID, deptID),
					Source: personID,
					Target: deptID,
					Kind:   EdgeKindMemberOf,
					Effect: EdgeEffectAllow,
				}})
				delta.Nodes = append(delta.Nodes, NodeMutation{Action: "modify", ID: personID, Properties: map[string]any{"department": deptNode.Name}})
			}

			if mgrRef := strings.TrimSpace(change.NewManager); mgrRef != "" {
				managerID := resolveReorgPersonID(g, mgrRef)
				if managerID == "" {
					return GraphDelta{}, nil, fmt.Errorf("change %d: unknown manager %q", idx, mgrRef)
				}
				if managerID != personID {
					for _, edge := range g.GetOutEdges(personID) {
						if edge == nil || edge.Kind != EdgeKindReportsTo {
							continue
						}
						delta.Edges = append(delta.Edges, EdgeMutation{Action: "remove", Source: edge.Source, Target: edge.Target, Kind: edge.Kind})
					}
					delta.Edges = append(delta.Edges, EdgeMutation{Action: "add", Edge: &Edge{
						ID:     fmt.Sprintf("reorg:%s:reports_to:%s", personID, managerID),
						Source: personID,
						Target: managerID,
						Kind:   EdgeKindReportsTo,
						Effect: EdgeEffectAllow,
					}})
				}
			}
		}

		if len(change.MergeTeams) >= 2 {
			handled = true
			teamIDs := make([]string, 0, len(change.MergeTeams))
			for _, teamRef := range change.MergeTeams {
				resolved := resolveReorgDepartmentIDs(g, teamRef)
				if len(resolved) == 0 {
					continue
				}
				teamIDs = append(teamIDs, resolved[0])
			}
			if len(teamIDs) >= 2 {
				mergedName := ""
				nameParts := make([]string, 0, len(teamIDs))
				for _, teamID := range teamIDs {
					teamName := teamID
					if teamNode, ok := g.GetNode(teamID); ok && teamNode != nil && strings.TrimSpace(teamNode.Name) != "" {
						teamName = teamNode.Name
					}
					nameParts = append(nameParts, teamName)
				}
				mergedName = strings.Join(nameParts, "+")
				mergedID, mergedNode := resolveOrCreateDepartment(g, mergedName)
				if _, exists := addedDepartments[mergedID]; !exists {
					if _, ok := g.GetNode(mergedID); !ok {
						delta.Nodes = append(delta.Nodes, NodeMutation{Action: "add", Node: mergedNode})
					}
					addedDepartments[mergedID] = struct{}{}
				}

				memberSet := make(map[string]struct{})
				for _, teamID := range teamIDs {
					for _, memberID := range reorgDepartmentMembers(g, teamID) {
						memberSet[memberID] = struct{}{}
					}
				}
				for _, memberID := range sortedSet(memberSet) {
					changedPeople[memberID] = struct{}{}
					delta.Edges = append(delta.Edges, removePersonMembershipMutations(g, memberID)...)
					delta.Edges = append(delta.Edges, EdgeMutation{Action: "add", Edge: &Edge{
						ID:     fmt.Sprintf("reorg:%s:member_of:%s", memberID, mergedID),
						Source: memberID,
						Target: mergedID,
						Kind:   EdgeKindMemberOf,
						Effect: EdgeEffectAllow,
					}})
					delta.Nodes = append(delta.Nodes, NodeMutation{Action: "modify", ID: memberID, Properties: map[string]any{"department": mergedNode.Name}})
				}
			}
		}

		if strings.TrimSpace(change.SplitTeam) != "" && len(change.Into) >= 2 {
			handled = true
			fromIDs := resolveReorgDepartmentIDs(g, change.SplitTeam)
			if len(fromIDs) > 0 {
				fromID := fromIDs[0]
				members := reorgDepartmentMembers(g, fromID)
				if len(members) > 0 {
					targetIDs := make([]string, 0, len(change.Into))
					targetNodes := make([]*Node, 0, len(change.Into))
					for _, targetRef := range change.Into {
						targetID, targetNode := resolveOrCreateDepartment(g, targetRef)
						targetIDs = append(targetIDs, targetID)
						targetNodes = append(targetNodes, targetNode)
						if _, exists := addedDepartments[targetID]; !exists {
							if _, ok := g.GetNode(targetID); !ok {
								delta.Nodes = append(delta.Nodes, NodeMutation{Action: "add", Node: targetNode})
							}
							addedDepartments[targetID] = struct{}{}
						}
					}

					for idxMember, memberID := range members {
						changedPeople[memberID] = struct{}{}
						targetIndex := idxMember % len(targetIDs)
						targetID := targetIDs[targetIndex]
						targetNode := targetNodes[targetIndex]
						delta.Edges = append(delta.Edges, removePersonMembershipMutations(g, memberID)...)
						delta.Edges = append(delta.Edges, EdgeMutation{Action: "add", Edge: &Edge{
							ID:     fmt.Sprintf("reorg:%s:member_of:%s", memberID, targetID),
							Source: memberID,
							Target: targetID,
							Kind:   EdgeKindMemberOf,
							Effect: EdgeEffectAllow,
						}})
						delta.Nodes = append(delta.Nodes, NodeMutation{Action: "modify", ID: memberID, Properties: map[string]any{"department": targetNode.Name}})
					}
				}
			}
		}

		if !handled {
			return GraphDelta{}, nil, fmt.Errorf("change %d: no supported reorg fields found", idx)
		}
	}

	return delta, changedPeople, nil
}

func detectBrokenBridges(before, after *Graph, changedPeople map[string]struct{}) []BrokenBridge {
	if before == nil || after == nil {
		return nil
	}
	beforeMembers, beforeNames := departmentMembersByID(before)
	afterMembers, _ := departmentMembersByID(after)

	teamIDs := make([]string, 0, len(beforeMembers))
	for teamID := range beforeMembers {
		teamIDs = append(teamIDs, teamID)
	}
	sort.Strings(teamIDs)

	bridges := make([]BrokenBridge, 0)
	for i := 0; i < len(teamIDs); i++ {
		for j := i + 1; j < len(teamIDs); j++ {
			teamA := teamIDs[i]
			teamB := teamIDs[j]
			beforeInteractions := interactionEdgesBetweenMemberSets(before, beforeMembers[teamA], beforeMembers[teamB])
			if beforeInteractions == 0 {
				continue
			}
			afterInteractions := interactionEdgesBetweenMemberSets(after, afterMembers[teamA], afterMembers[teamB])
			if afterInteractions > 0 {
				continue
			}

			bridgePerson := findBridgePersonForTeamPair(before, teamA, teamB, changedPeople)
			interactionsPerMonth := crossTeamInteractionVolume(before, beforeMembers[teamA], beforeMembers[teamB])
			if interactionsPerMonth <= 0 {
				interactionsPerMonth = beforeInteractions
			}

			bridges = append(bridges, BrokenBridge{
				TeamA:                firstNonEmpty(beforeNames[teamA], teamA),
				TeamB:                firstNonEmpty(beforeNames[teamB], teamB),
				BridgePerson:         bridgePerson,
				InteractionsPerMonth: interactionsPerMonth,
				AlternativePaths:     afterInteractions,
				Mitigation:           "Create explicit cross-team channel and assign liaison",
			})
		}
	}

	sort.Slice(bridges, func(i, j int) bool {
		if bridges[i].InteractionsPerMonth == bridges[j].InteractionsPerMonth {
			if bridges[i].TeamA == bridges[j].TeamA {
				return bridges[i].TeamB < bridges[j].TeamB
			}
			return bridges[i].TeamA < bridges[j].TeamA
		}
		return bridges[i].InteractionsPerMonth > bridges[j].InteractionsPerMonth
	})

	return bridges
}

func detectWeakenedPaths(before, after *Graph, brokenBridges []BrokenBridge) []PathChange {
	if before == nil || after == nil || len(brokenBridges) == 0 {
		return nil
	}

	changes := make([]PathChange, 0)
	for _, bridge := range brokenBridges {
		beforePath := ShortestInformationPath(before, bridge.TeamA, bridge.TeamB)
		if beforePath == nil {
			continue
		}
		afterPath := ShortestInformationPath(after, bridge.TeamA, bridge.TeamB)
		if afterPath != nil && afterPath.Hops <= beforePath.Hops {
			continue
		}

		hopsAfter := -1
		latencyAfter := "disconnected"
		impact := "information path disconnected"
		if afterPath != nil {
			hopsAfter = afterPath.Hops
			latencyAfter = afterPath.EstimatedLatency
			impact = fmt.Sprintf("path length increased by %d hop(s)", afterPath.Hops-beforePath.Hops)
		}

		changes = append(changes, PathChange{
			From:          bridge.TeamA,
			To:            bridge.TeamB,
			HopsBefore:    beforePath.Hops,
			HopsAfter:     hopsAfter,
			LatencyBefore: beforePath.EstimatedLatency,
			LatencyAfter:  latencyAfter,
			Impact:        impact,
		})
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].HopsBefore == changes[j].HopsBefore {
			if changes[i].From == changes[j].From {
				return changes[i].To < changes[j].To
			}
			return changes[i].From < changes[j].From
		}
		return changes[i].HopsBefore > changes[j].HopsBefore
	})
	return changes
}

func detectSeveredCustomerLinks(before, after *Graph) []CustomerImpact {
	beforeHealth := ComputeCustomerRelationshipHealth(before)
	afterHealth := ComputeCustomerRelationshipHealth(after)
	if len(beforeHealth) == 0 || len(afterHealth) == 0 {
		return nil
	}

	afterByCustomer := make(map[string]CustomerRelationshipHealth, len(afterHealth))
	for _, health := range afterHealth {
		afterByCustomer[health.CustomerID] = health
	}

	impacts := make([]CustomerImpact, 0)
	for _, prior := range beforeHealth {
		afterValue, ok := afterByCustomer[prior.CustomerID]
		if !ok {
			continue
		}
		healthDrop := prior.HealthScore - afterValue.HealthScore
		touchpointDrop := prior.TouchpointCount - afterValue.TouchpointCount
		if healthDrop < 5 && touchpointDrop <= 0 {
			continue
		}

		name := prior.CustomerID
		if customer, ok := before.GetNode(prior.CustomerID); ok && customer != nil && strings.TrimSpace(customer.Name) != "" {
			name = customer.Name
		}

		impactText := fmt.Sprintf("health score dropped %.1f points", healthDrop)
		if touchpointDrop > 0 {
			impactText = fmt.Sprintf("%d touchpoint(s) lost, health dropped %.1f", touchpointDrop, healthDrop)
		}

		impacts = append(impacts, CustomerImpact{
			CustomerID:        prior.CustomerID,
			CustomerName:      name,
			TouchpointsBefore: prior.TouchpointCount,
			TouchpointsAfter:  afterValue.TouchpointCount,
			HealthBefore:      prior.HealthScore,
			HealthAfter:       afterValue.HealthScore,
			Impact:            impactText,
		})
	}

	sort.Slice(impacts, func(i, j int) bool {
		dropI := impacts[i].HealthBefore - impacts[i].HealthAfter
		dropJ := impacts[j].HealthBefore - impacts[j].HealthAfter
		if dropI == dropJ {
			return impacts[i].CustomerID < impacts[j].CustomerID
		}
		return dropI > dropJ
	})
	return impacts
}

func detectBusFactorDeltas(beforeOrg, afterOrg OrgHealthScore) ([]BusFactorDelta, []string) {
	beforeByTarget := indexBusFactorsByTarget(beforeOrg)
	afterByTarget := indexBusFactorsByTarget(afterOrg)

	deltas := make([]BusFactorDelta, 0)
	orphaned := make([]string, 0)
	for targetID, beforeBus := range beforeByTarget {
		afterBus := afterByTarget[targetID]
		if beforeBus.BusFactor == afterBus.BusFactor {
			continue
		}
		delta := BusFactorDelta{
			TargetID: targetID,
			Before:   beforeBus.BusFactor,
			After:    afterBus.BusFactor,
			Delta:    afterBus.BusFactor - beforeBus.BusFactor,
		}
		deltas = append(deltas, delta)
		if beforeBus.BusFactor > 0 && afterBus.BusFactor == 0 {
			orphaned = append(orphaned, targetID)
		}
	}

	sort.Slice(deltas, func(i, j int) bool {
		if math.Abs(float64(deltas[i].Delta)) == math.Abs(float64(deltas[j].Delta)) {
			return deltas[i].TargetID < deltas[j].TargetID
		}
		return math.Abs(float64(deltas[i].Delta)) > math.Abs(float64(deltas[j].Delta))
	})
	sort.Strings(orphaned)
	return deltas, orphaned
}

func buildReorgMitigations(impact *ReorgImpact) []ReorgMitigation {
	if impact == nil {
		return nil
	}

	actions := make([]ReorgMitigation, 0)
	for _, bridge := range impact.BrokenBridges {
		priority := "high"
		if bridge.AlternativePaths == 0 {
			priority = "critical"
		}
		actions = append(actions, ReorgMitigation{
			Action:     "Assign bridge role and create cross-team channel",
			Reason:     fmt.Sprintf("%s ↔ %s bridge is severed", bridge.TeamA, bridge.TeamB),
			Priority:   priority,
			BeforeDate: "Complete before reorg effective date",
		})
	}
	for _, targetID := range impact.KnowledgeOrphaned {
		actions = append(actions, ReorgMitigation{
			Action:     "Schedule knowledge transfer session",
			Reason:     fmt.Sprintf("Knowledge area %s is orphaned", targetID),
			Priority:   "critical",
			BeforeDate: "Complete before reorg effective date",
		})
	}
	for _, customer := range impact.SeveredCustomerLinks {
		actions = append(actions, ReorgMitigation{
			Action:     "Create customer reassignment and warm-intro plan",
			Reason:     fmt.Sprintf("Customer %s relationship weakened", firstNonEmpty(customer.CustomerName, customer.CustomerID)),
			Priority:   "high",
			BeforeDate: "Complete before reorg effective date",
		})
	}
	for _, path := range impact.WeakenedPaths {
		actions = append(actions, ReorgMitigation{
			Action:     "Define explicit escalation routing",
			Reason:     fmt.Sprintf("Path %s → %s weakened", path.From, path.To),
			Priority:   "medium",
			BeforeDate: "Within 30 days after reorg effective date",
		})
	}

	rank := map[string]int{"critical": 0, "high": 1, "medium": 2}
	sort.Slice(actions, func(i, j int) bool {
		ri, rj := rank[actions[i].Priority], rank[actions[j].Priority]
		if ri == rj {
			if actions[i].Action == actions[j].Action {
				return actions[i].Reason < actions[j].Reason
			}
			return actions[i].Action < actions[j].Action
		}
		return ri < rj
	})

	if len(actions) > 20 {
		actions = actions[:20]
	}
	return actions
}

func resolveReorgPersonID(g *Graph, ref string) string {
	if g == nil {
		return ""
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if node, ok := g.GetNode(ref); ok && node != nil && node.Kind == NodeKindPerson {
		return node.ID
	}

	lower := strings.ToLower(ref)
	if strings.HasPrefix(lower, "person/") {
		candidate := "person:" + strings.TrimSpace(ref[strings.Index(ref, "/")+1:])
		if node, ok := g.GetNode(candidate); ok && node != nil && node.Kind == NodeKindPerson {
			return node.ID
		}
	}

	target := normalizeOrgKey(ref)
	if target == "" {
		return ""
	}

	matches := make([]string, 0)
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}
		if informationFlowTextMatch(person.ID, target) || informationFlowTextMatch(person.Name, target) {
			matches = append(matches, person.ID)
		}
	}
	if len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	return matches[0]
}

func resolveReorgDepartmentIDs(g *Graph, ref string) []string {
	if g == nil {
		return nil
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	if node, ok := g.GetNode(ref); ok && node != nil && node.Kind == NodeKindDepartment {
		return []string{node.ID}
	}

	if strings.HasPrefix(strings.ToLower(ref), "team/") || strings.HasPrefix(strings.ToLower(ref), "department/") {
		ref = ref[strings.Index(ref, "/")+1:]
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}

	matches := make([]string, 0)
	for _, dept := range g.GetNodesByKind(NodeKindDepartment) {
		if dept == nil {
			continue
		}
		if informationFlowTextMatch(dept.ID, ref) || informationFlowTextMatch(dept.Name, ref) {
			matches = append(matches, dept.ID)
		}
	}
	sort.Strings(matches)
	return matches
}

func resolveOrCreateDepartment(g *Graph, name string) (string, *Node) {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(strings.ToLower(name), "team/") || strings.HasPrefix(strings.ToLower(name), "department/") {
		name = strings.TrimSpace(name[strings.Index(name, "/")+1:])
	}
	if name == "" {
		name = "Unknown"
	}
	deptID := "department:" + normalizeOrgKey(name)
	if deptID == "department:" {
		deptID = "department:unknown"
	}
	if g != nil {
		if node, ok := g.GetNode(deptID); ok && node != nil {
			return node.ID, &Node{ID: node.ID, Kind: NodeKindDepartment, Name: firstNonEmpty(node.Name, name)}
		}
	}
	return deptID, &Node{ID: deptID, Kind: NodeKindDepartment, Name: name}
}

func removePersonMembershipMutations(g *Graph, personID string) []EdgeMutation {
	mutations := make([]EdgeMutation, 0)
	seen := make(map[string]struct{})
	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		key := edge.Source + "|" + edge.Target + "|" + string(edge.Kind)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		mutations = append(mutations, EdgeMutation{Action: "remove", Source: edge.Source, Target: edge.Target, Kind: edge.Kind})
	}
	for _, edge := range g.GetInEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		key := edge.Source + "|" + edge.Target + "|" + string(edge.Kind)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		mutations = append(mutations, EdgeMutation{Action: "remove", Source: edge.Source, Target: edge.Target, Kind: edge.Kind})
	}
	return mutations
}

func reorgDepartmentMembers(g *Graph, departmentID string) []string {
	members := make(map[string]struct{})
	if g == nil || strings.TrimSpace(departmentID) == "" {
		return nil
	}

	for _, edge := range g.GetInEdges(departmentID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		if person, ok := g.GetNode(edge.Source); ok && person != nil && person.Kind == NodeKindPerson {
			members[person.ID] = struct{}{}
		}
	}
	for _, edge := range g.GetOutEdges(departmentID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		if person, ok := g.GetNode(edge.Target); ok && person != nil && person.Kind == NodeKindPerson {
			members[person.ID] = struct{}{}
		}
	}
	return sortedSet(members)
}

func findBridgePersonForTeamPair(before *Graph, teamA, teamB string, changedPeople map[string]struct{}) string {
	if before == nil {
		return ""
	}
	members, _ := departmentMembersByID(before)
	teamAMembers := members[teamA]
	teamBMembers := members[teamB]
	if len(teamAMembers) == 0 || len(teamBMembers) == 0 {
		return ""
	}

	candidateIDs := sortedSet(changedPeople)
	if len(candidateIDs) == 0 {
		return ""
	}

	for _, personID := range candidateIDs {
		_, inA := teamAMembers[personID]
		_, inB := teamBMembers[personID]
		if !inA && !inB {
			continue
		}
		if inA && personInteractsWithAny(before, personID, teamBMembers) {
			return personID
		}
		if inB && personInteractsWithAny(before, personID, teamAMembers) {
			return personID
		}
	}
	return ""
}

func personInteractsWithAny(g *Graph, personID string, targets map[string]struct{}) bool {
	if g == nil || len(targets) == 0 {
		return false
	}
	for _, edge := range g.GetOutEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindInteractedWith {
			continue
		}
		if _, ok := targets[edge.Target]; ok {
			return true
		}
	}
	for _, edge := range g.GetInEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindInteractedWith {
			continue
		}
		if _, ok := targets[edge.Source]; ok {
			return true
		}
	}
	return false
}

func crossTeamInteractionVolume(g *Graph, teamA, teamB map[string]struct{}) int {
	if g == nil || len(teamA) == 0 || len(teamB) == 0 {
		return 0
	}
	seen := make(map[string]struct{})
	total := 0
	collect := func(member string, opposite map[string]struct{}) {
		for _, edge := range g.GetOutEdges(member) {
			if edge == nil || edge.Kind != EdgeKindInteractedWith {
				continue
			}
			if _, ok := opposite[edge.Target]; !ok {
				continue
			}
			key := undirectedPairKey(edge.Source, edge.Target)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			freq := readInt(edge.Properties, "frequency", "interaction_count", "call_count")
			if freq <= 0 {
				freq = 1
			}
			total += freq
		}
	}
	for member := range teamA {
		collect(member, teamB)
	}
	for member := range teamB {
		collect(member, teamA)
	}
	return total
}

func countUndirectedInteractionEdges(g *Graph) int {
	if g == nil {
		return 0
	}
	seen := make(map[string]struct{})
	for _, edgeList := range g.GetAllEdges() {
		for _, edge := range edgeList {
			if edge == nil || edge.Kind != EdgeKindInteractedWith {
				continue
			}
			seen[undirectedPairKey(edge.Source, edge.Target)] = struct{}{}
		}
	}
	return len(seen)
}
