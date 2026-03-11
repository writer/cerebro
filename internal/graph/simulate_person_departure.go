package graph

import (
	"sort"
	"strings"
)

// PersonDepartureImpact summarizes downstream impact when a person node is removed.
type PersonDepartureImpact struct {
	Person *Node `json:"person,omitempty"`

	// Knowledge impact
	SystemsBusFactor0 []*Node  `json:"systems_bus_factor_0,omitempty"`
	SystemsBusFactor1 []*Node  `json:"systems_bus_factor_1,omitempty"`
	ReposNoMaintainer []*Node  `json:"repos_no_maintainer,omitempty"`
	OrphanedKnowledge []string `json:"orphaned_knowledge,omitempty"`

	// Relationship impact
	CustomersNoContact   []*Node  `json:"customers_no_contact,omitempty"`
	AffectedARR          float64  `json:"affected_arr"`
	BrokenBridges        []Bridge `json:"broken_bridges,omitempty"`
	ApprovalChainsBroken []string `json:"approval_chains_broken,omitempty"`

	// Operational impact
	OpenIssuesOrphaned int `json:"open_issues_orphaned"`
	PendingReviews     int `json:"pending_reviews"`
	ScheduledMeetings  int `json:"scheduled_meetings"`

	// Security impact
	AccessToRevoke []Access `json:"access_to_revoke,omitempty"`
	SecretsKnown   []string `json:"secrets_known,omitempty"`

	// Recovery estimate
	KnowledgeRecoveryWeeks int                `json:"knowledge_recovery_weeks"`
	SuggestedSuccessors    map[string][]*Node `json:"suggested_successors,omitempty"`
}

// Bridge describes an inter-team communication bridge severed by person departure.
type Bridge struct {
	TeamAID     string `json:"team_a_id"`
	TeamAName   string `json:"team_a_name,omitempty"`
	TeamBID     string `json:"team_b_id"`
	TeamBName   string `json:"team_b_name,omitempty"`
	ViaPersonID string `json:"via_person_id"`
}

// Access describes an access relationship that should be revoked.
type Access struct {
	ResourceID   string   `json:"resource_id"`
	ResourceName string   `json:"resource_name,omitempty"`
	ResourceKind NodeKind `json:"resource_kind,omitempty"`
	AccessKind   EdgeKind `json:"access_kind"`
}

func buildPersonDepartureImpact(before *Graph, after *Graph, personID string) *PersonDepartureImpact {
	if before == nil || after == nil {
		return nil
	}
	person, ok := before.GetNode(personID)
	if !ok || person == nil || person.Kind != NodeKindPerson {
		return nil
	}

	impact := &PersonDepartureImpact{
		Person:              person,
		SuggestedSuccessors: make(map[string][]*Node),
	}

	beforeHealth := ComputeOrgHealthScore(before)
	afterHealth := ComputeOrgHealthScore(after)
	beforeBus := indexBusFactorsByTarget(beforeHealth)
	afterBus := indexBusFactorsByTarget(afterHealth)

	impactedTargets := make([]string, 0)
	for targetID, beforeResult := range beforeBus {
		if beforeResult.BusFactor <= 0 {
			continue
		}
		afterResult, ok := afterBus[targetID]
		if !ok {
			afterResult = BusFactorResult{TargetID: targetID, BusFactor: 0}
		}
		if afterResult.BusFactor >= beforeResult.BusFactor {
			continue
		}

		targetNode, targetExists := before.GetNode(targetID)
		if afterResult.BusFactor == 0 {
			impact.OrphanedKnowledge = append(impact.OrphanedKnowledge, targetID)
			impactedTargets = append(impactedTargets, targetID)
			if targetExists && targetNode != nil {
				impact.SystemsBusFactor0 = append(impact.SystemsBusFactor0, targetNode)
				if targetNode.Kind == NodeKindRepository {
					impact.ReposNoMaintainer = append(impact.ReposNoMaintainer, targetNode)
				}
				if targetNode.Kind == NodeKindCustomer {
					impact.CustomersNoContact = append(impact.CustomersNoContact, targetNode)
					impact.AffectedARR += readFloat(targetNode.Properties, "arr", "annual_recurring_revenue", "contract_value", "amount", "value")
				}
			}
			continue
		}

		if afterResult.BusFactor == 1 && targetExists && targetNode != nil {
			impact.SystemsBusFactor1 = append(impact.SystemsBusFactor1, targetNode)
			impactedTargets = append(impactedTargets, targetID)
		}
	}

	sortNodeSliceByID(impact.SystemsBusFactor0)
	sortNodeSliceByID(impact.SystemsBusFactor1)
	sortNodeSliceByID(impact.ReposNoMaintainer)
	sortNodeSliceByID(impact.CustomersNoContact)
	sort.Strings(impact.OrphanedKnowledge)

	impact.BrokenBridges = brokenBridgesAfterDeparture(before, after, personID)
	impact.OpenIssuesOrphaned, impact.PendingReviews, impact.ScheduledMeetings = operationalDepartureCounts(before, personID)
	impact.ApprovalChainsBroken = approvalChainsForPerson(person)
	impact.AccessToRevoke, impact.SecretsKnown = securityDepartureImpact(before, personID)
	impact.KnowledgeRecoveryWeeks = estimateKnowledgeRecoveryWeeks(len(impact.SystemsBusFactor0), len(impact.SystemsBusFactor1))
	impact.SuggestedSuccessors = rankedSuccessors(before, after, personID, impactedTargets)

	return impact
}

func indexBusFactorsByTarget(score OrgHealthScore) map[string]BusFactorResult {
	index := make(map[string]BusFactorResult, len(score.BusFactors))
	for _, item := range score.BusFactors {
		index[item.TargetID] = item
	}
	return index
}

func sortNodeSliceByID(nodes []*Node) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i] == nil {
			return false
		}
		if nodes[j] == nil {
			return true
		}
		return nodes[i].ID < nodes[j].ID
	})
}

func brokenBridgesAfterDeparture(before *Graph, after *Graph, personID string) []Bridge {
	beforeMembers, beforeNames := departmentMembersByID(before)
	afterMembers, _ := departmentMembersByID(after)
	departmentsByPersonBefore := departmentsByPerson(before)
	neighborDepartments := make(map[string]struct{})

	registerNeighbor := func(otherID string) {
		for deptID := range departmentsByPersonBefore[otherID] {
			neighborDepartments[deptID] = struct{}{}
		}
	}

	for _, edge := range before.GetOutEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindInteractedWith {
			continue
		}
		registerNeighbor(edge.Target)
	}
	for _, edge := range before.GetInEdges(personID) {
		if edge == nil || edge.Kind != EdgeKindInteractedWith {
			continue
		}
		registerNeighbor(edge.Source)
	}

	departmentIDs := sortedSet(neighborDepartments)
	if len(departmentIDs) < 2 {
		return nil
	}

	seen := make(map[string]struct{})
	bridges := make([]Bridge, 0)
	for i := 0; i < len(departmentIDs); i++ {
		for j := i + 1; j < len(departmentIDs); j++ {
			teamA := departmentIDs[i]
			teamB := departmentIDs[j]
			beforeInteractions := interactionEdgesBetweenMemberSets(before, beforeMembers[teamA], beforeMembers[teamB])
			if beforeInteractions == 0 {
				continue
			}
			afterInteractions := interactionEdgesBetweenMemberSets(after, afterMembers[teamA], afterMembers[teamB])
			if afterInteractions > 0 {
				continue
			}
			key := teamA + "|" + teamB
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			bridges = append(bridges, Bridge{
				TeamAID:     teamA,
				TeamAName:   firstNonEmpty(beforeNames[teamA], teamA),
				TeamBID:     teamB,
				TeamBName:   firstNonEmpty(beforeNames[teamB], teamB),
				ViaPersonID: personID,
			})
		}
	}

	sort.Slice(bridges, func(i, j int) bool {
		if bridges[i].TeamAID == bridges[j].TeamAID {
			return bridges[i].TeamBID < bridges[j].TeamBID
		}
		return bridges[i].TeamAID < bridges[j].TeamAID
	})
	return bridges
}

func operationalDepartureCounts(before *Graph, personID string) (int, int, int) {
	openIssues := 0
	pendingReviews := 0
	scheduledMeetings := 0

	for _, edge := range before.GetInEdges(personID) {
		if edge == nil {
			continue
		}
		source, ok := before.GetNode(edge.Source)
		if !ok || source == nil {
			continue
		}
		switch source.Kind {
		case NodeKindTicket:
			status := strings.ToLower(strings.TrimSpace(readString(source.Properties, "status", "state")))
			if status != "closed" && status != "resolved" && status != "done" && status != "complete" {
				openIssues++
			}
		case NodeKindRepository:
			if edge.Kind == EdgeKindAssignedTo {
				pendingReviews++
			}
		case NodeKindActivity:
			if isFutureActivity(source) {
				scheduledMeetings++
			}
		}
	}

	if person, ok := before.GetNode(personID); ok && person != nil {
		openIssues += readInt(person.Properties, "open_issues", "open_issues_orphaned")
		pendingReviews += readInt(person.Properties, "pending_reviews", "pending_review_count")
		scheduledMeetings += readInt(person.Properties, "scheduled_meetings", "upcoming_meetings")
	}

	return openIssues, pendingReviews, scheduledMeetings
}

func approvalChainsForPerson(person *Node) []string {
	if person == nil {
		return nil
	}
	chains := stringSliceFromValue(person.Properties["approval_chains"])
	if len(chains) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(chains))
	for _, chain := range chains {
		if trimmed := strings.TrimSpace(chain); trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}
	sort.Strings(filtered)
	return filtered
}

func isFutureActivity(node *Node) bool {
	if node == nil {
		return false
	}
	start := firstTimeFromMap(node.Properties, "start_time", "starts_at", "scheduled_for")
	if start.IsZero() {
		return false
	}
	return start.After(orgHealthNowUTC())
}

func securityDepartureImpact(before *Graph, personID string) ([]Access, []string) {
	accesses := make([]Access, 0)
	secrets := make(map[string]struct{})
	seenAccess := make(map[string]struct{})

	for _, edge := range before.GetOutEdges(personID) {
		if edge == nil {
			continue
		}
		if !isRevocableAccessKind(edge.Kind) {
			continue
		}

		target, ok := before.GetNode(edge.Target)
		if !ok || target == nil {
			continue
		}

		key := edge.Target + "|" + string(edge.Kind)
		if _, exists := seenAccess[key]; !exists {
			seenAccess[key] = struct{}{}
			accesses = append(accesses, Access{
				ResourceID:   target.ID,
				ResourceName: target.Name,
				ResourceKind: target.Kind,
				AccessKind:   edge.Kind,
			})
		}

		if target.Kind == NodeKindSecret {
			secrets[target.ID] = struct{}{}
		}
	}

	sort.Slice(accesses, func(i, j int) bool {
		if accesses[i].ResourceID == accesses[j].ResourceID {
			return accesses[i].AccessKind < accesses[j].AccessKind
		}
		return accesses[i].ResourceID < accesses[j].ResourceID
	})

	secretIDs := sortedSet(secrets)
	return accesses, secretIDs
}

func isRevocableAccessKind(kind EdgeKind) bool {
	switch kind {
	case EdgeKindCanRead, EdgeKindCanWrite, EdgeKindCanDelete, EdgeKindCanAdmin, EdgeKindCanAssume, EdgeKindMemberOf:
		return true
	default:
		return false
	}
}

func estimateKnowledgeRecoveryWeeks(busFactor0Count int, busFactor1Count int) int {
	if busFactor0Count <= 0 && busFactor1Count <= 0 {
		return 0
	}
	weeks := busFactor0Count*4 + busFactor1Count*2
	if weeks < 1 {
		weeks = 1
	}
	if weeks > 52 {
		weeks = 52
	}
	return weeks
}

type successorCandidate struct {
	person *Node
	score  float64
}

func rankedSuccessors(before *Graph, after *Graph, personID string, impactedTargets []string) map[string][]*Node {
	if len(impactedTargets) == 0 {
		return nil
	}
	candidatesByTarget := make(map[string][]*Node)
	departmentsByPersonBefore := departmentsByPerson(before)
	departedDepartments := departmentsByPersonBefore[personID]
	interactionAdjacency := personInteractionAdjacency(before)
	departedNeighbors := interactionAdjacency[personID]

	afterPeople := after.GetNodesByKind(NodeKindPerson)
	if len(afterPeople) == 0 {
		return nil
	}

	seenTargets := make(map[string]struct{})
	for _, targetID := range impactedTargets {
		if strings.TrimSpace(targetID) == "" {
			continue
		}
		if _, exists := seenTargets[targetID]; exists {
			continue
		}
		seenTargets[targetID] = struct{}{}

		totalOnTarget, activeOnTarget := connectedPersonsForTarget(after, targetID, defaultBusFactorActiveWindow)
		scored := make([]successorCandidate, 0, len(afterPeople))
		for _, person := range afterPeople {
			if person == nil || strings.TrimSpace(person.ID) == "" {
				continue
			}
			score := 0.0
			if _, ok := activeOnTarget[person.ID]; ok {
				score += 4
			}
			if _, ok := totalOnTarget[person.ID]; ok {
				score += 1
			}
			if sameDepartment(person.ID, departedDepartments, departmentsByPersonBefore) {
				score += 2
			}
			if _, ok := departedNeighbors[person.ID]; ok {
				score += 3
			}
			if external, ok := person.Properties["external"].(bool); ok && external {
				score -= 1
			}
			if score <= 0 {
				continue
			}
			scored = append(scored, successorCandidate{person: person, score: score})
		}

		sort.Slice(scored, func(i, j int) bool {
			if scored[i].score == scored[j].score {
				return scored[i].person.ID < scored[j].person.ID
			}
			return scored[i].score > scored[j].score
		})

		limit := 3
		if len(scored) < limit {
			limit = len(scored)
		}
		if limit == 0 {
			continue
		}
		top := make([]*Node, 0, limit)
		for idx := 0; idx < limit; idx++ {
			top = append(top, scored[idx].person)
		}
		candidatesByTarget[targetID] = top
	}

	if len(candidatesByTarget) == 0 {
		return nil
	}
	return candidatesByTarget
}

func sameDepartment(personID string, targetDepartments map[string]struct{}, departmentsByPerson map[string]map[string]struct{}) bool {
	if len(targetDepartments) == 0 {
		return false
	}
	for deptID := range departmentsByPerson[personID] {
		if _, ok := targetDepartments[deptID]; ok {
			return true
		}
	}
	return false
}
