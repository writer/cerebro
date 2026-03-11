package graph

import (
	"math"
	"sort"
	"strings"
)

// TeamRecommendationRequest is the request contract for graph-based team formation.
type TeamRecommendationRequest struct {
	TargetSystems []string                      `json:"target_systems"`
	Domains       []string                      `json:"domains,omitempty"`
	TeamSize      int                           `json:"team_size"`
	Constraints   TeamRecommendationConstraints `json:"constraints,omitempty"`
}

// TeamRecommendationConstraints controls recommendation filtering and weighting.
type TeamRecommendationConstraints struct {
	MaxBusFactorImpact          int  `json:"max_bus_factor_impact,omitempty"`
	PreferExistingCollaboration bool `json:"prefer_existing_collaboration,omitempty"`
}

// TeamCandidatePerson is a minimal public profile for one candidate.
type TeamCandidatePerson struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Department string `json:"department,omitempty"`
}

// TeamCandidate contains score components for one recommended person.
type TeamCandidate struct {
	Person             *TeamCandidatePerson `json:"person,omitempty"`
	KnowledgeScore     float64              `json:"knowledge_score"`
	CollaborationScore float64              `json:"collaboration_score"`
	BridgeScore        float64              `json:"bridge_score"`
	AvailabilityScore  float64              `json:"availability_score"`
	BusFactorImpact    int                  `json:"bus_factor_impact"`
	OverallFit         float64              `json:"overall_fit"`
	Rationale          string               `json:"rationale,omitempty"`

	node *Node `json:"-"`
}

// TeamImpact captures bus-factor movement when pulling recommended members.
type TeamImpact struct {
	TargetID string `json:"target_id"`
	Before   int    `json:"before"`
	After    int    `json:"after"`
	Delta    int    `json:"delta"`
	Risk     string `json:"risk"`
}

// TeamAnalysis summarizes coverage/cohesion/risk for the recommended team.
type TeamAnalysis struct {
	KnowledgeCoverage float64      `json:"knowledge_coverage"`
	InternalCohesion  float64      `json:"internal_cohesion"`
	ExternalBridges   int          `json:"external_bridges"`
	KnowledgeOverlap  float64      `json:"knowledge_overlap"`
	GapsIdentified    []string     `json:"gaps_identified,omitempty"`
	BusFactorImpacts  []TeamImpact `json:"bus_factor_impacts,omitempty"`
}

// TeamAlternative suggests a lower-risk candidate swap.
type TeamAlternative struct {
	Recommended string `json:"recommended"`
	Alternative string `json:"alternative"`
	Risk        string `json:"risk"`
	Tradeoff    string `json:"tradeoff"`
}

// TeamRecommendationResult is the full output for team recommendation.
type TeamRecommendationResult struct {
	TargetSystems   []string          `json:"target_systems"`
	Domains         []string          `json:"domains,omitempty"`
	TeamSize        int               `json:"team_size"`
	Candidates      []TeamCandidate   `json:"candidates,omitempty"`
	RecommendedTeam []TeamCandidate   `json:"recommended_team,omitempty"`
	Analysis        TeamAnalysis      `json:"analysis"`
	Alternatives    []TeamAlternative `json:"alternatives,omitempty"`
}

// RecommendTeam computes graph-based team recommendations for requested systems/domains.
func RecommendTeam(g *Graph, req TeamRecommendationRequest) TeamRecommendationResult {
	result := TeamRecommendationResult{Analysis: TeamAnalysis{}}
	if g == nil {
		return result
	}

	targetSystemIDs := resolveTeamTargetSystems(g, req.TargetSystems)
	domains := normalizeDomainList(req.Domains)
	if req.TeamSize <= 0 {
		req.TeamSize = 5
	}
	if req.Constraints.MaxBusFactorImpact < 0 {
		req.Constraints.MaxBusFactorImpact = 0
	}

	result.TargetSystems = targetSystemIDs
	result.Domains = domains
	result.TeamSize = req.TeamSize
	if len(targetSystemIDs) == 0 {
		return result
	}

	candidates := scoreTeamCandidates(g, targetSystemIDs, domains, req.Constraints)
	if len(candidates) == 0 {
		result.Analysis.GapsIdentified = append(result.Analysis.GapsIdentified, targetSystemIDs...)
		sort.Strings(result.Analysis.GapsIdentified)
		return result
	}

	result.Candidates = candidates
	teamSize := req.TeamSize
	if teamSize > len(candidates) {
		teamSize = len(candidates)
	}
	selected := append([]TeamCandidate(nil), candidates[:teamSize]...)

	selected = recomputeCollaborationAndFit(g, selected, req.Constraints)
	sort.Slice(selected, func(i, j int) bool {
		leftID := ""
		if selected[i].Person != nil {
			leftID = selected[i].Person.ID
		}
		rightID := ""
		if selected[j].Person != nil {
			rightID = selected[j].Person.ID
		}
		if selected[i].OverallFit == selected[j].OverallFit {
			return leftID < rightID
		}
		return selected[i].OverallFit > selected[j].OverallFit
	})

	result.RecommendedTeam = selected
	result.Analysis = analyzeRecommendedTeam(g, selected, targetSystemIDs, domains)
	result.Alternatives = buildTeamAlternatives(selected, candidates)
	return result
}

func scoreTeamCandidates(g *Graph, targetSystems, domains []string, constraints TeamRecommendationConstraints) []TeamCandidate {
	if g == nil || len(targetSystems) == 0 {
		return nil
	}

	candidates := make([]TeamCandidate, 0)
	for _, person := range g.GetNodesByKind(NodeKindPerson) {
		if person == nil {
			continue
		}

		knowledge := candidateKnowledgeScore(g, person.ID, targetSystems)
		if knowledge <= 0 {
			continue
		}
		bridge := candidateBridgeScore(person, domains)
		availability := candidateAvailabilityScore(person)
		busImpact := candidateBusFactorImpact(g, person.ID, targetSystems)

		if constraints.MaxBusFactorImpact > 0 && busImpact > constraints.MaxBusFactorImpact {
			continue
		}

		profile := teamCandidatePersonFromNode(person)
		if profile == nil {
			continue
		}

		candidate := TeamCandidate{
			Person:             profile,
			KnowledgeScore:     knowledge,
			BridgeScore:        bridge,
			AvailabilityScore:  availability,
			BusFactorImpact:    busImpact,
			CollaborationScore: 0,
			node:               person,
		}
		candidate.OverallFit = candidateOverallFit(candidate, constraints.PreferExistingCollaboration)
		candidate.Rationale = candidateRationale(candidate)
		candidates = append(candidates, candidate)
	}

	sort.Slice(candidates, func(i, j int) bool {
		leftID := ""
		if candidates[i].Person != nil {
			leftID = candidates[i].Person.ID
		}
		rightID := ""
		if candidates[j].Person != nil {
			rightID = candidates[j].Person.ID
		}
		if candidates[i].OverallFit == candidates[j].OverallFit {
			if candidates[i].KnowledgeScore == candidates[j].KnowledgeScore {
				return leftID < rightID
			}
			return candidates[i].KnowledgeScore > candidates[j].KnowledgeScore
		}
		return candidates[i].OverallFit > candidates[j].OverallFit
	})
	return candidates
}

func recomputeCollaborationAndFit(g *Graph, selected []TeamCandidate, constraints TeamRecommendationConstraints) []TeamCandidate {
	if g == nil || len(selected) == 0 {
		return selected
	}

	ids := make([]string, 0, len(selected))
	for _, candidate := range selected {
		if candidate.Person == nil {
			continue
		}
		ids = append(ids, candidate.Person.ID)
	}

	for idx := range selected {
		if selected[idx].Person == nil {
			continue
		}
		total := 0.0
		count := 0
		for _, peerID := range ids {
			if peerID == selected[idx].Person.ID {
				continue
			}
			total += pairCollaborationScore(g, selected[idx].Person.ID, peerID)
			count++
		}
		if count > 0 {
			selected[idx].CollaborationScore = clampUnitInterval(total / float64(count))
		}
		selected[idx].OverallFit = candidateOverallFit(selected[idx], constraints.PreferExistingCollaboration)
		selected[idx].Rationale = candidateRationale(selected[idx])
	}
	return selected
}

func analyzeRecommendedTeam(g *Graph, team []TeamCandidate, targetSystems, domains []string) TeamAnalysis {
	analysis := TeamAnalysis{}
	if g == nil || len(team) == 0 {
		analysis.GapsIdentified = append([]string(nil), targetSystems...)
		sort.Strings(analysis.GapsIdentified)
		return analysis
	}

	memberSet := make(map[string]struct{}, len(team))
	for _, candidate := range team {
		if candidate.Person == nil {
			continue
		}
		memberSet[candidate.Person.ID] = struct{}{}
	}

	coveredSystems := make(map[string]int)
	for _, systemID := range targetSystems {
		for memberID := range memberSet {
			if candidateSystemKnowledgeScore(g, memberID, systemID) > 0 {
				coveredSystems[systemID]++
			}
		}
	}
	if len(targetSystems) > 0 {
		analysis.KnowledgeCoverage = float64(len(coveredSystems)) / float64(len(targetSystems))
	}

	totalPairs := 0
	connectedPairs := 0
	memberIDs := sortedSet(memberSet)
	for i := 0; i < len(memberIDs); i++ {
		for j := i + 1; j < len(memberIDs); j++ {
			totalPairs++
			if pairCollaborationScore(g, memberIDs[i], memberIDs[j]) > 0 {
				connectedPairs++
			}
		}
	}
	if totalPairs > 0 {
		analysis.InternalCohesion = float64(connectedPairs) / float64(totalPairs)
	}

	externalTeams := make(map[string]struct{})
	departments := departmentsByPerson(g)
	for memberID := range memberSet {
		for _, edge := range g.GetOutEdges(memberID) {
			if edge == nil || edge.Kind != EdgeKindInteractedWith {
				continue
			}
			if _, inTeam := memberSet[edge.Target]; inTeam {
				continue
			}
			for teamID := range departments[edge.Target] {
				externalTeams[teamID] = struct{}{}
			}
		}
	}
	analysis.ExternalBridges = len(externalTeams)

	redundancyAccumulator := 0.0
	for _, count := range coveredSystems {
		redundancyAccumulator += float64(count)
	}
	if len(coveredSystems) > 0 && len(team) > 0 {
		analysis.KnowledgeOverlap = redundancyAccumulator / (float64(len(coveredSystems)) * float64(len(team)))
	}

	gaps := make([]string, 0)
	for _, target := range targetSystems {
		if _, ok := coveredSystems[target]; !ok {
			gaps = append(gaps, target)
		}
	}
	for _, domain := range domains {
		hasDomain := false
		for _, candidate := range team {
			if candidate.node == nil {
				continue
			}
			if candidateBridgeScore(candidate.node, []string{domain}) > 0 {
				hasDomain = true
				break
			}
		}
		if !hasDomain {
			gaps = append(gaps, "domain:"+domain)
		}
	}
	sort.Strings(gaps)
	analysis.GapsIdentified = gaps
	analysis.BusFactorImpacts = teamBusFactorImpacts(g, memberSet, targetSystems)
	return analysis
}

func buildTeamAlternatives(selected, all []TeamCandidate) []TeamAlternative {
	if len(selected) == 0 || len(all) == 0 {
		return nil
	}
	selectedSet := make(map[string]struct{}, len(selected))
	for _, candidate := range selected {
		if candidate.Person == nil {
			continue
		}
		selectedSet[candidate.Person.ID] = struct{}{}
	}

	alternatives := make([]TeamAlternative, 0)
	for _, recommended := range selected {
		if recommended.Person == nil || recommended.BusFactorImpact <= 0 {
			continue
		}
		var bestAlternative *TeamCandidate
		for idx := range all {
			candidate := all[idx]
			if candidate.Person == nil {
				continue
			}
			if _, alreadySelected := selectedSet[candidate.Person.ID]; alreadySelected {
				continue
			}
			if candidate.BusFactorImpact >= recommended.BusFactorImpact {
				continue
			}
			if bestAlternative == nil || candidate.OverallFit > bestAlternative.OverallFit {
				copyCandidate := candidate
				bestAlternative = &copyCandidate
			}
		}
		if bestAlternative == nil {
			continue
		}

		knowledgeDelta := recommended.KnowledgeScore - bestAlternative.KnowledgeScore
		tradeoffPct := clampUnitInterval(knowledgeDelta) * 100
		alternatives = append(alternatives, TeamAlternative{
			Recommended: recommended.Person.ID,
			Alternative: bestAlternative.Person.ID,
			Risk:        "Bus-factor impact reduced from " + intToString(recommended.BusFactorImpact) + " to " + intToString(bestAlternative.BusFactorImpact),
			Tradeoff:    "~" + intToString(int(math.Round(tradeoffPct))) + "% less direct target-system knowledge",
		})
	}

	sort.Slice(alternatives, func(i, j int) bool {
		if alternatives[i].Recommended == alternatives[j].Recommended {
			return alternatives[i].Alternative < alternatives[j].Alternative
		}
		return alternatives[i].Recommended < alternatives[j].Recommended
	})
	return alternatives
}

func resolveTeamTargetSystems(g *Graph, targets []string) []string {
	if g == nil || len(targets) == 0 {
		return nil
	}
	resolved := make(map[string]struct{})
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if node, ok := g.GetNode(target); ok && node != nil && isSystemNodeKind(node.Kind) {
			resolved[node.ID] = struct{}{}
			continue
		}
		selectorMatches := make(map[string]struct{})
		addSystemSelectorMatches(g, target, selectorMatches)
		for systemID := range selectorMatches {
			resolved[systemID] = struct{}{}
		}
	}
	return sortedSet(resolved)
}

func normalizeDomainList(domains []string) []string {
	normalized := make(map[string]struct{})
	for _, domain := range domains {
		domain = normalizeOrgKey(domain)
		if domain == "" {
			continue
		}
		normalized[domain] = struct{}{}
	}
	return sortedSet(normalized)
}

func candidateKnowledgeScore(g *Graph, personID string, targetSystems []string) float64 {
	if g == nil || len(targetSystems) == 0 {
		return 0
	}
	total := 0.0
	for _, systemID := range targetSystems {
		total += candidateSystemKnowledgeScore(g, personID, systemID)
	}
	score := total / float64(len(targetSystems))
	return clampUnitInterval(score)
}

func candidateSystemKnowledgeScore(g *Graph, personID, systemID string) float64 {
	if g == nil || strings.TrimSpace(personID) == "" || strings.TrimSpace(systemID) == "" {
		return 0
	}

	score := 0.0
	accumulate := func(edge *Edge, sourceToTarget bool) {
		if edge == nil {
			return
		}
		if sourceToTarget {
			if edge.Source != personID || edge.Target != systemID {
				return
			}
		} else {
			if edge.Source != systemID || edge.Target != personID {
				return
			}
		}
		weight := knowledgeEdgeWeight(edge.Kind)
		if weight <= 0 {
			return
		}
		candidate := weight
		candidate += math.Min(readFloat(edge.Properties, "strength", "interaction_frequency")*0.1, 0.1)
		candidate += math.Min(float64(readInt(edge.Properties, "commit_count", "review_count", "issue_count"))/100, 0.1)
		if candidate > score {
			score = candidate
		}
	}

	for _, edge := range g.GetOutEdges(personID) {
		accumulate(edge, true)
	}
	for _, edge := range g.GetInEdges(personID) {
		accumulate(edge, false)
	}
	return clampUnitInterval(score)
}

func knowledgeEdgeWeight(kind EdgeKind) float64 {
	switch kind {
	case EdgeKindOwns:
		return 1.0
	case EdgeKindManagedBy:
		return 0.9
	case EdgeKindAssignedTo:
		return 0.75
	case EdgeKindCanAdmin:
		return 0.7
	case EdgeKindCanWrite:
		return 0.6
	case EdgeKindCanRead:
		return 0.4
	default:
		return 0
	}
}

func candidateBridgeScore(person *Node, domains []string) float64 {
	if person == nil {
		return 0
	}
	if len(domains) == 0 {
		return 0.5
	}

	profileParts := make([]string, 0, 8)
	profileParts = append(profileParts, stringSliceFromValue(person.Properties["domains"])...)
	profileParts = append(profileParts, stringSliceFromValue(person.Properties["skills"])...)
	if focus := readString(person.Properties, "domain", "focus_area", "team"); focus != "" {
		profileParts = append(profileParts, focus)
	}

	profileTokens := strings.Join(profileParts, " ")
	profile := normalizeOrgKey(profileTokens)
	if profile == "" {
		return 0
	}

	matches := 0
	for _, domain := range domains {
		if strings.Contains(profile, normalizeOrgKey(domain)) {
			matches++
		}
	}
	return clampUnitInterval(float64(matches) / float64(len(domains)))
}

func candidateAvailabilityScore(person *Node) float64 {
	if person == nil {
		return 0
	}
	workload := 0.0
	workload += float64(readInt(person.Properties, "open_issues", "issue_count"))
	workload += float64(readInt(person.Properties, "team_count", "active_teams")) * 3
	workload += readFloat(person.Properties, "meeting_hours", "meeting_load", "calendar_load")
	workload += float64(readInt(person.Properties, "pending_reviews"))
	if workload < 0 {
		workload = 0
	}
	score := 1.0 / (1.0 + (workload / 10.0))
	return clampUnitInterval(score)
}

func candidateBusFactorImpact(g *Graph, personID string, targetSystems []string) int {
	if g == nil || strings.TrimSpace(personID) == "" || len(targetSystems) == 0 {
		return 0
	}
	impact := 0
	for _, systemID := range targetSystems {
		bus := BusFactor(g, systemID)
		if bus.BusFactor <= 0 {
			continue
		}
		if !containsString(bus.ActivePersonIDs, personID) {
			continue
		}
		after := bus.BusFactor - 1
		if after < 2 {
			impact++
		}
	}
	return impact
}

func pairCollaborationScore(g *Graph, personA, personB string) float64 {
	if g == nil || strings.TrimSpace(personA) == "" || strings.TrimSpace(personB) == "" || personA == personB {
		return 0
	}
	score := 0.0
	collect := func(edge *Edge) {
		if edge == nil || edge.Kind != EdgeKindInteractedWith {
			return
		}
		if (edge.Source != personA || edge.Target != personB) && (edge.Source != personB || edge.Target != personA) {
			return
		}
		candidate := readFloat(edge.Properties, "strength")
		if candidate <= 0 {
			frequency := readFloat(edge.Properties, "frequency", "interaction_count")
			if frequency > 0 {
				candidate = math.Min(frequency/20.0, 1.0)
			}
		}
		if candidate <= 0 {
			candidate = 0.35
		}
		if candidate > score {
			score = candidate
		}
	}
	for _, edge := range g.GetOutEdges(personA) {
		collect(edge)
	}
	for _, edge := range g.GetOutEdges(personB) {
		collect(edge)
	}
	return clampUnitInterval(score)
}

func candidateOverallFit(candidate TeamCandidate, preferCollaboration bool) float64 {
	collabWeight := 0.15
	if preferCollaboration {
		collabWeight = 0.25
	}
	knowledgeWeight := 0.45
	bridgeWeight := 0.15
	availabilityWeight := 0.15
	penaltyWeight := 0.10

	score := (candidate.KnowledgeScore * knowledgeWeight) +
		(candidate.CollaborationScore * collabWeight) +
		(candidate.BridgeScore * bridgeWeight) +
		(candidate.AvailabilityScore * availabilityWeight)
	penalty := clampUnitInterval(float64(candidate.BusFactorImpact) / 2.0)
	score -= penalty * penaltyWeight
	return clampUnitInterval(score)
}

func candidateRationale(candidate TeamCandidate) string {
	if candidate.Person == nil {
		return ""
	}
	reason := []string{
		"knowledge=" + intToString(int(math.Round(candidate.KnowledgeScore*100))),
		"collab=" + intToString(int(math.Round(candidate.CollaborationScore*100))),
		"availability=" + intToString(int(math.Round(candidate.AvailabilityScore*100))),
	}
	if candidate.BusFactorImpact > 0 {
		reason = append(reason, "bus_factor_impact="+intToString(candidate.BusFactorImpact))
	}
	return strings.Join(reason, ", ")
}

func teamCandidatePersonFromNode(node *Node) *TeamCandidatePerson {
	if node == nil || strings.TrimSpace(node.ID) == "" {
		return nil
	}
	person := &TeamCandidatePerson{
		ID:   node.ID,
		Name: strings.TrimSpace(node.Name),
	}
	person.Department = readString(node.Properties, "department", "team", "organization")
	return person
}

func teamBusFactorImpacts(g *Graph, memberSet map[string]struct{}, targetSystems []string) []TeamImpact {
	if g == nil || len(memberSet) == 0 || len(targetSystems) == 0 {
		return nil
	}
	impacts := make([]TeamImpact, 0)
	for _, systemID := range targetSystems {
		bus := BusFactor(g, systemID)
		if bus.BusFactor <= 0 {
			continue
		}
		removed := 0
		for _, personID := range bus.ActivePersonIDs {
			if _, selected := memberSet[personID]; selected {
				removed++
			}
		}
		after := bus.BusFactor - removed
		if after < 0 {
			after = 0
		}
		if after == bus.BusFactor {
			continue
		}
		risk := "low"
		switch {
		case after < 1:
			risk = "critical"
		case after < 2:
			risk = "high"
		case after < 3:
			risk = "medium"
		}
		impacts = append(impacts, TeamImpact{
			TargetID: systemID,
			Before:   bus.BusFactor,
			After:    after,
			Delta:    after - bus.BusFactor,
			Risk:     risk,
		})
	}
	sort.Slice(impacts, func(i, j int) bool {
		if impacts[i].Risk == impacts[j].Risk {
			return impacts[i].TargetID < impacts[j].TargetID
		}
		severity := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
		return severity[impacts[i].Risk] < severity[impacts[j].Risk]
	})
	return impacts
}
