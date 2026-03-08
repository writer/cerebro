package graph

import (
	"math"
	"sort"
	"strings"
	"time"
)

const (
	defaultKnowledgeRoutingLimit = 5
	maxKnowledgeRoutingLimit     = 25
)

// KnowledgeQuery describes a who-knows lookup request.
type KnowledgeQuery struct {
	Topic         string `json:"topic,omitempty"`
	Customer      string `json:"customer,omitempty"`
	System        string `json:"system,omitempty"`
	AvailableOnly bool   `json:"available_only,omitempty"`
	Limit         int    `json:"limit,omitempty"`
}

// KnowledgeTarget is a graph target used for knowledge routing.
type KnowledgeTarget struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Kind NodeKind `json:"kind"`
}

// KnowledgeCandidate is a scored expert for a knowledge query.
type KnowledgeCandidate struct {
	Person             *Node     `json:"person,omitempty"`
	KnowledgeScore     float64   `json:"knowledge_score"`
	ContributionScore  float64   `json:"contribution_score"`
	InteractionScore   float64   `json:"interaction_score"`
	OwnershipScore     float64   `json:"ownership_score"`
	RecencyScore       float64   `json:"recency_score"`
	AccessibilityScore float64   `json:"accessibility_score"`
	Available          bool      `json:"available"`
	LastActive         time.Time `json:"last_active,omitempty"`
	Relationship       string    `json:"relationship"`
}

// KnowledgeRoutingResult contains targets and ranked experts for a query.
type KnowledgeRoutingResult struct {
	Query      KnowledgeQuery       `json:"query"`
	Targets    []KnowledgeTarget    `json:"targets,omitempty"`
	Candidates []KnowledgeCandidate `json:"candidates,omitempty"`
	Count      int                  `json:"count"`
}

type knowledgeCandidateSignals struct {
	personID         string
	person           *Node
	rawContribution  float64
	rawInteraction   float64
	rawOwnership     float64
	lastActive       time.Time
	hasDirectSignals bool
	accessibility    float64
	available        bool
}

// WhoKnows ranks people likely to have the requested domain knowledge.
func WhoKnows(g *Graph, query KnowledgeQuery) KnowledgeRoutingResult {
	normalized := normalizeKnowledgeQuery(query)
	result := KnowledgeRoutingResult{Query: normalized}
	if g == nil {
		return result
	}

	targets := resolveKnowledgeTargets(g, normalized)
	if len(targets) == 0 {
		return result
	}

	result.Targets = make([]KnowledgeTarget, 0, len(targets))
	for _, target := range targets {
		if target == nil {
			continue
		}
		result.Targets = append(result.Targets, KnowledgeTarget{
			ID:   target.ID,
			Name: target.Name,
			Kind: target.Kind,
		})
	}
	if len(result.Targets) == 0 {
		return result
	}

	signals := collectKnowledgeSignals(g, targets)
	if len(signals) == 0 {
		return result
	}

	maxContribution := 0.0
	maxInteraction := 0.0
	maxOwnership := 0.0
	for _, signal := range signals {
		if signal == nil || signal.person == nil {
			continue
		}
		if signal.rawContribution > maxContribution {
			maxContribution = signal.rawContribution
		}
		if signal.rawInteraction > maxInteraction {
			maxInteraction = signal.rawInteraction
		}
		if signal.rawOwnership > maxOwnership {
			maxOwnership = signal.rawOwnership
		}
	}

	candidates := make([]KnowledgeCandidate, 0, len(signals))
	for _, signal := range signals {
		if signal == nil || signal.person == nil {
			continue
		}

		contribution := normalizeRelativeScore(signal.rawContribution, maxContribution)
		interaction := normalizeRelativeScore(signal.rawInteraction, maxInteraction)
		ownership := normalizeRelativeScore(signal.rawOwnership, maxOwnership)
		recency := knowledgeRecencyScore(signal.lastActive)
		accessibility := clampUnitInterval(signal.accessibility)

		// If we only have stale/noisy signals and no direct topic relationship, skip.
		if !signal.hasDirectSignals && interaction <= 0 {
			continue
		}

		knowledgeScore := clampUnitInterval(
			(contribution * 0.30) +
				(interaction * 0.25) +
				(ownership * 0.20) +
				(recency * 0.15) +
				(accessibility * 0.10),
		)

		candidate := KnowledgeCandidate{
			Person:             signal.person,
			KnowledgeScore:     knowledgeScore,
			ContributionScore:  contribution,
			InteractionScore:   interaction,
			OwnershipScore:     ownership,
			RecencyScore:       recency,
			AccessibilityScore: accessibility,
			Available:          signal.available,
			LastActive:         signal.lastActive,
			Relationship:       relationshipLabel(signal, contribution, interaction, ownership, recency),
		}
		if normalized.AvailableOnly && !candidate.Available {
			continue
		}
		candidates = append(candidates, candidate)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].KnowledgeScore == candidates[j].KnowledgeScore {
			if candidates[i].LastActive.Equal(candidates[j].LastActive) {
				leftID := ""
				rightID := ""
				if candidates[i].Person != nil {
					leftID = candidates[i].Person.ID
				}
				if candidates[j].Person != nil {
					rightID = candidates[j].Person.ID
				}
				return leftID < rightID
			}
			return candidates[i].LastActive.After(candidates[j].LastActive)
		}
		return candidates[i].KnowledgeScore > candidates[j].KnowledgeScore
	})

	if len(candidates) > normalized.Limit {
		candidates = candidates[:normalized.Limit]
	}
	result.Candidates = candidates
	result.Count = len(candidates)
	return result
}

func normalizeKnowledgeQuery(query KnowledgeQuery) KnowledgeQuery {
	query.Topic = strings.TrimSpace(query.Topic)
	query.Customer = strings.TrimSpace(query.Customer)
	query.System = strings.TrimSpace(query.System)

	if query.Limit <= 0 {
		query.Limit = defaultKnowledgeRoutingLimit
	}
	if query.Limit > maxKnowledgeRoutingLimit {
		query.Limit = maxKnowledgeRoutingLimit
	}
	return query
}

func resolveKnowledgeTargets(g *Graph, query KnowledgeQuery) []*Node {
	if g == nil {
		return nil
	}

	targets := make([]*Node, 0)
	seen := make(map[string]struct{})

	appendUnique := func(nodes []*Node) {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			if _, ok := seen[node.ID]; ok {
				continue
			}
			seen[node.ID] = struct{}{}
			targets = append(targets, node)
		}
	}

	if query.Customer != "" {
		appendUnique(matchKnowledgeTargets(g, query.Customer, map[NodeKind]struct{}{
			NodeKindCustomer: {},
			NodeKindCompany:  {},
		}, 3))
	}
	if query.System != "" {
		appendUnique(matchKnowledgeTargets(g, query.System, map[NodeKind]struct{}{
			NodeKindApplication: {},
			NodeKindRepository:  {},
			NodeKindDatabase:    {},
			NodeKindFunction:    {},
			NodeKindBucket:      {},
			NodeKindInstance:    {},
			NodeKindNetwork:     {},
		}, 3))
	}
	if query.Topic != "" {
		appendUnique(matchKnowledgeTargets(g, query.Topic, nil, 5))
	}

	return targets
}

type scoredTarget struct {
	node  *Node
	score float64
}

func matchKnowledgeTargets(g *Graph, term string, allowedKinds map[NodeKind]struct{}, limit int) []*Node {
	normalizedTerm := strings.ToLower(strings.TrimSpace(term))
	if g == nil || normalizedTerm == "" {
		return nil
	}
	if limit <= 0 {
		limit = 1
	}

	scored := make([]scoredTarget, 0)
	for _, node := range g.GetAllNodes() {
		if node == nil {
			continue
		}
		if isOrganizationalNode(node.Kind) || node.Kind == NodeKindInternet {
			continue
		}
		if len(allowedKinds) > 0 {
			if _, ok := allowedKinds[node.Kind]; !ok {
				continue
			}
		}
		score := nodeMatchScore(node, normalizedTerm)
		if score <= 0 {
			continue
		}
		scored = append(scored, scoredTarget{node: node, score: score})
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].node.ID < scored[j].node.ID
		}
		return scored[i].score > scored[j].score
	})

	if len(scored) > limit {
		scored = scored[:limit]
	}

	nodes := make([]*Node, 0, len(scored))
	for _, item := range scored {
		nodes = append(nodes, item.node)
	}
	return nodes
}

func nodeMatchScore(node *Node, term string) float64 {
	if node == nil || term == "" {
		return 0
	}

	nodeID := strings.ToLower(strings.TrimSpace(node.ID))
	nodeName := strings.ToLower(strings.TrimSpace(node.Name))
	if nodeID == term {
		return 120
	}
	if nodeName == term {
		return 110
	}
	if strings.HasPrefix(nodeName, term) {
		return 98
	}
	if strings.HasPrefix(nodeID, term) {
		return 92
	}
	if strings.Contains(nodeName, term) {
		return 84
	}
	if strings.Contains(nodeID, term) {
		return 78
	}
	if matchesNodeText(node, term) {
		return 65
	}
	return 0
}

func matchesNodeText(node *Node, term string) bool {
	if node == nil || term == "" {
		return false
	}
	for _, key := range []string{"slug", "display_name", "service", "system", "topic", "domain", "repository", "repo"} {
		value := strings.ToLower(readString(node.Properties, key))
		if strings.Contains(value, term) {
			return true
		}
	}
	for _, value := range node.Tags {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), term) {
			return true
		}
	}
	return false
}

func collectKnowledgeSignals(g *Graph, targets []*Node) map[string]*knowledgeCandidateSignals {
	signals := make(map[string]*knowledgeCandidateSignals)
	if g == nil || len(targets) == 0 {
		return signals
	}

	primaryExperts := make(map[string]struct{})

	ensureSignal := func(personID string) *knowledgeCandidateSignals {
		if strings.TrimSpace(personID) == "" {
			return nil
		}
		existing, ok := signals[personID]
		if ok {
			return existing
		}
		node, exists := g.GetNode(personID)
		if !exists || node == nil || node.Kind != NodeKindPerson {
			return nil
		}
		signal := &knowledgeCandidateSignals{personID: personID, person: node}
		signals[personID] = signal
		return signal
	}

	registerDirect := func(personID string, edge *Edge) {
		if edge == nil || !isKnowledgeFlowEdge(edge.Kind) {
			return
		}
		signal := ensureSignal(personID)
		if signal == nil {
			return
		}
		signal.hasDirectSignals = true
		signal.rawContribution += edgeContributionWeight(edge)
		signal.rawOwnership += edgeOwnershipWeight(edge)
		if last := firstTimeFromMap(edge.Properties, "last_seen", "last_interaction", "last_activity", "updated_at", "created_at"); last.After(signal.lastActive) {
			signal.lastActive = last
		}
		primaryExperts[personID] = struct{}{}
	}

	for _, target := range targets {
		if target == nil {
			continue
		}
		for _, edge := range g.GetOutEdges(target.ID) {
			if edge == nil {
				continue
			}
			registerDirect(edge.Target, edge)
		}
		for _, edge := range g.GetInEdges(target.ID) {
			if edge == nil {
				continue
			}
			registerDirect(edge.Source, edge)
		}
	}

	adjacency := personInteractionAdjacency(g)
	seenPairs := make(map[string]struct{})
	for primaryID := range primaryExperts {
		neighbors := adjacency[primaryID]
		for neighborID := range neighbors {
			if primaryID == neighborID {
				continue
			}
			pair := undirectedPairKey(primaryID, neighborID)
			if _, done := seenPairs[pair]; done {
				continue
			}
			seenPairs[pair] = struct{}{}

			strength, last := interactionStrengthBetween(g, primaryID, neighborID)
			if strength <= 0 {
				continue
			}

			if left := ensureSignal(primaryID); left != nil {
				left.rawInteraction += strength
				if last.After(left.lastActive) {
					left.lastActive = last
				}
			}
			if right := ensureSignal(neighborID); right != nil {
				right.rawInteraction += strength
				if last.After(right.lastActive) {
					right.lastActive = last
				}
			}
		}
	}

	for personID, signal := range signals {
		if signal == nil || signal.person == nil {
			delete(signals, personID)
			continue
		}
		if signal.lastActive.IsZero() {
			signal.lastActive = firstTimeFromMap(signal.person.Properties, "last_active", "last_activity", "last_seen", "last_login", "updated_at")
		}
		signal.accessibility, signal.available = personAccessibility(signal.person)
	}

	return signals
}

func interactionStrengthBetween(g *Graph, personA string, personB string) (float64, time.Time) {
	if g == nil || strings.TrimSpace(personA) == "" || strings.TrimSpace(personB) == "" {
		return 0, time.Time{}
	}

	total := 0.0
	last := time.Time{}
	addEdge := func(edge *Edge) {
		if edge == nil || edge.Kind != EdgeKindInteractedWith {
			return
		}
		frequency := readFloat(edge.Properties, "frequency", "interaction_count", "call_count", "co_actions", "shared_groups", "shared_apps")
		strength := readFloat(edge.Properties, "strength", "relationship_strength")
		weight := 0.2
		if frequency > 0 {
			weight += math.Log1p(frequency)
		}
		if strength > 0 {
			weight += strength
		}
		total += weight
		if seen := firstTimeFromMap(edge.Properties, "last_seen", "last_interaction", "last_activity", "updated_at"); seen.After(last) {
			last = seen
		}
	}

	for _, edge := range g.GetOutEdges(personA) {
		if edge != nil && edge.Target == personB {
			addEdge(edge)
		}
	}
	for _, edge := range g.GetOutEdges(personB) {
		if edge != nil && edge.Target == personA {
			addEdge(edge)
		}
	}

	return total, last
}

func edgeContributionWeight(edge *Edge) float64 {
	if edge == nil {
		return 0
	}

	score := 0.4
	switch edge.Kind {
	case EdgeKindManagedBy:
		score += 1.0
	case EdgeKindOwns:
		score += 0.9
	case EdgeKindAssignedTo:
		score += 0.8
	case EdgeKindCanAdmin:
		score += 0.7
	case EdgeKindCanWrite:
		score += 0.55
	case EdgeKindCanRead:
		score += 0.35
	case EdgeKindInteractedWith:
		score += 0.25
	default:
		score += 0.3
	}

	activity := readFloat(
		edge.Properties,
		"contribution_score",
		"contribution_count",
		"commit_count",
		"commits",
		"pull_request_count",
		"pr_count",
		"review_count",
		"reviews",
		"interaction_count",
		"frequency",
		"call_count",
	)
	if activity > 0 {
		score += math.Log1p(activity)
	}

	if edgeRecencyActive(edge, 45*24*time.Hour) {
		score += 0.2
	}
	return score
}

func edgeOwnershipWeight(edge *Edge) float64 {
	if edge == nil {
		return 0
	}

	weight := 0.0
	switch edge.Kind {
	case EdgeKindManagedBy:
		weight += 1.0
	case EdgeKindOwns:
		weight += 0.9
	case EdgeKindAssignedTo:
		weight += 0.8
	case EdgeKindCanAdmin:
		weight += 0.6
	case EdgeKindCanWrite:
		weight += 0.45
	case EdgeKindCanRead:
		weight += 0.25
	}

	role := strings.ToLower(readString(edge.Properties, "role", "relationship", "ownership", "responsibility", "title"))
	if strings.Contains(role, "owner") || strings.Contains(role, "maintainer") || strings.Contains(role, "lead") || strings.Contains(role, "sponsor") {
		weight += 0.45
	}
	if strings.Contains(role, "former") || strings.Contains(role, "past") {
		weight -= 0.25
	}
	if weight < 0 {
		return 0
	}
	return weight
}

func personAccessibility(person *Node) (float64, bool) {
	if person == nil {
		return 0, false
	}

	status := strings.ToLower(strings.TrimSpace(readString(person.Properties, "status", "availability", "calendar_status")))
	score := 1.0
	if isUnavailableStatus(status) {
		score = 0.05
	} else if status != "" && (strings.Contains(status, "busy") || strings.Contains(status, "meeting")) {
		score -= 0.25
	}

	if raw, ok := person.Properties["available"]; ok {
		switch typed := raw.(type) {
		case bool:
			if !typed {
				score -= 0.4
			}
		case string:
			normalized := strings.ToLower(strings.TrimSpace(typed))
			if normalized == "false" || normalized == "no" || normalized == "0" || normalized == "off" {
				score -= 0.4
			}
		}
	}

	meetingLoad := readFloat(person.Properties, "meeting_load", "calendar_load", "calendar_utilization", "meeting_hours", "meeting_hours_today")
	if meetingLoad > 0 {
		norm := meetingLoad
		if norm > 1 {
			norm /= 8 // treat >1 as hours/day.
		}
		if norm > 1 {
			norm = 1
		}
		score -= 0.4 * norm
	}

	workload := readFloat(person.Properties, "workload", "current_workload", "utilization")
	if workload > 0 {
		norm := workload
		if norm > 1 {
			norm /= 100 // treat >1 as percentage.
		}
		if norm > 1 {
			norm = 1
		}
		score -= 0.35 * norm
	}

	pending := float64(readInt(person.Properties, "pending_reviews", "open_issues", "open_tickets"))
	if pending > 0 {
		score -= math.Min(0.30, pending/25.0)
	}

	score = clampUnitInterval(score)
	return score, score >= 0.45 && !isUnavailableStatus(status)
}

func isUnavailableStatus(status string) bool {
	normalized := strings.ToLower(strings.TrimSpace(status))
	if normalized == "" {
		return false
	}
	switch normalized {
	case "ooo", "out_of_office", "on_leave", "leave", "vacation", "inactive", "terminated", "offline":
		return true
	}
	return strings.Contains(normalized, "leave") ||
		strings.Contains(normalized, "vacation") ||
		strings.Contains(normalized, "out_of_office") ||
		strings.Contains(normalized, "inactive")
}

func knowledgeRecencyScore(lastActive time.Time) float64 {
	if lastActive.IsZero() {
		return 0.2
	}
	daysSince := orgHealthNowUTC().Sub(lastActive).Hours() / 24
	if daysSince < 0 {
		daysSince = 0
	}
	return clampUnitInterval(math.Exp(-daysSince / 45))
}

func normalizeRelativeScore(value float64, max float64) float64 {
	if value <= 0 || max <= 0 {
		return 0
	}
	return clampUnitInterval(value / max)
}

func relationshipLabel(signal *knowledgeCandidateSignals, contribution float64, interaction float64, ownership float64, recency float64) string {
	if signal == nil {
		return "domain collaborator"
	}
	if ownership >= 0.75 && contribution >= 0.55 && recency >= 0.35 {
		return "primary maintainer"
	}
	if ownership >= 0.60 {
		return "account owner"
	}
	if recency < 0.25 && (ownership >= 0.5 || contribution >= 0.5) {
		return "former owner"
	}
	if contribution >= 0.65 {
		return "frequent contributor"
	}
	if interaction >= 0.65 && !signal.hasDirectSignals {
		return "trusted collaborator"
	}
	if signal.hasDirectSignals {
		return "domain contributor"
	}
	return "routed collaborator"
}
