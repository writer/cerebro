package graph

import (
	"sort"
	"strings"
	"time"
)

const (
	onboardingRepoLimit     = 8
	onboardingPeopleLimit   = 10
	onboardingAccessLimit   = 10
	onboardingChannelLimit  = 8
	onboardingProjectLimit  = 8
	onboardingCustomerLimit = 8
)

var onboardingNowUTC = func() time.Time {
	return time.Now().UTC()
}

// OnboardingPlan is a personalized onboarding guide generated from peer graph behavior.
type OnboardingPlan struct {
	PersonID        string                  `json:"person_id"`
	GeneratedAt     time.Time               `json:"generated_at"`
	CohortSize      int                     `json:"cohort_size"`
	CohortPersonIDs []string                `json:"cohort_person_ids,omitempty"`
	PredecessorID   string                  `json:"predecessor_id,omitempty"`
	Repositories    []RepoRecommendation    `json:"repositories,omitempty"`
	KeyPeople       []IntroRecommendation   `json:"key_people,omitempty"`
	SystemAccess    []AccessRecommendation  `json:"system_access,omitempty"`
	Channels        []ChannelRecommendation `json:"channels,omitempty"`
	Projects        []ProjectContext        `json:"projects,omitempty"`
	CustomerContext []CustomerBrief         `json:"customer_context,omitempty"`
}

// RepoRecommendation captures repository onboarding context from cohort contribution patterns.
type RepoRecommendation struct {
	RepositoryID      string  `json:"repository_id"`
	RepositoryName    string  `json:"repository_name"`
	ContributionScore float64 `json:"contribution_score"`
	CohortCoverage    float64 `json:"cohort_coverage"`
}

// IntroRecommendation identifies people a new hire should meet early.
type IntroRecommendation struct {
	PersonID         string  `json:"person_id"`
	PersonName       string  `json:"person_name"`
	InteractionScore float64 `json:"interaction_score"`
	CohortCoverage   float64 `json:"cohort_coverage"`
}

// AccessRecommendation describes systems/tools commonly used by the peer cohort.
type AccessRecommendation struct {
	SystemID       string   `json:"system_id"`
	SystemName     string   `json:"system_name"`
	AccessKinds    []string `json:"access_kinds,omitempty"`
	CohortCoverage float64  `json:"cohort_coverage"`
}

// ChannelRecommendation captures communication channels peers actively use.
type ChannelRecommendation struct {
	ChannelID      string  `json:"channel_id"`
	ChannelName    string  `json:"channel_name"`
	CohortCoverage float64 `json:"cohort_coverage"`
}

// ProjectContext captures high-signal projects/tickets peers are active in.
type ProjectContext struct {
	ProjectID      string  `json:"project_id"`
	ProjectName    string  `json:"project_name"`
	ActivityScore  float64 `json:"activity_score"`
	CohortCoverage float64 `json:"cohort_coverage"`
}

// CustomerBrief summarizes customer relationships the cohort (or predecessor) maintains.
type CustomerBrief struct {
	CustomerID           string  `json:"customer_id"`
	CustomerName         string  `json:"customer_name"`
	RelationshipStrength float64 `json:"relationship_strength"`
	CohortCoverage       float64 `json:"cohort_coverage"`
}

// GenerateOnboardingPlan computes a personalized onboarding plan for a person node.
func GenerateOnboardingPlan(g *Graph, personID string) *OnboardingPlan {
	personID = strings.TrimSpace(personID)
	if g == nil || personID == "" {
		return nil
	}

	person, ok := g.GetNode(personID)
	if !ok || person == nil || person.Kind != NodeKindPerson {
		return nil
	}

	peers, predecessor := onboardingPeerCohort(g, person)
	peerIDs := make([]string, 0, len(peers))
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		peerIDs = append(peerIDs, peer.ID)
	}
	sort.Strings(peerIDs)

	plan := &OnboardingPlan{
		PersonID:        person.ID,
		GeneratedAt:     onboardingNowUTC(),
		CohortSize:      len(peerIDs),
		CohortPersonIDs: peerIDs,
	}
	if predecessor != nil {
		plan.PredecessorID = predecessor.ID
	}

	signalPeople := onboardingSignalPeople(peers, predecessor)
	if len(signalPeople) == 0 {
		return plan
	}

	plan.Repositories = onboardingRepositories(g, signalPeople, len(peerIDs))
	plan.KeyPeople = onboardingKeyPeople(g, signalPeople, person.ID, peerIDs, predecessor)
	plan.SystemAccess = onboardingSystemAccess(g, signalPeople, len(peerIDs))
	plan.Channels = onboardingChannels(g, signalPeople, len(peerIDs))
	plan.Projects = onboardingProjects(g, signalPeople, len(peerIDs))
	plan.CustomerContext = onboardingCustomerContext(g, signalPeople, len(peerIDs))
	return plan
}

type onboardingSignalPerson struct {
	person        *Node
	isPredecessor bool
}

func onboardingSignalPeople(peers []*Node, predecessor *Node) []onboardingSignalPerson {
	seen := make(map[string]struct{})
	signals := make([]onboardingSignalPerson, 0, len(peers)+1)
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		if _, exists := seen[peer.ID]; exists {
			continue
		}
		seen[peer.ID] = struct{}{}
		signals = append(signals, onboardingSignalPerson{person: peer})
	}
	if predecessor != nil {
		if _, exists := seen[predecessor.ID]; !exists {
			signals = append(signals, onboardingSignalPerson{person: predecessor, isPredecessor: true})
		}
	}
	return signals
}

func onboardingPeerCohort(g *Graph, person *Node) ([]*Node, *Node) {
	if g == nil || person == nil {
		return nil, nil
	}

	targetDept := normalizeOrgKey(readString(person.Properties, "department"))
	targetTitle := normalizeOrgKey(readString(person.Properties, "title", "role"))
	targetTeam := normalizeOrgKey(readString(person.Properties, "team", "squad"))

	activeMatches := make([]*Node, 0)
	inactiveMatches := make([]*Node, 0)
	for _, candidate := range g.GetNodesByKind(NodeKindPerson) {
		if candidate == nil || candidate.ID == person.ID {
			continue
		}
		if !onboardingProfileMatch(candidate, targetDept, targetTitle, targetTeam) {
			continue
		}
		if onboardingPersonInactive(candidate) {
			inactiveMatches = append(inactiveMatches, candidate)
			continue
		}
		activeMatches = append(activeMatches, candidate)
	}

	if len(activeMatches) == 0 {
		activeMatches = onboardingFallbackPeers(g, person, targetDept, targetTitle)
	}

	sort.Slice(activeMatches, func(i, j int) bool {
		return activeMatches[i].ID < activeMatches[j].ID
	})

	predecessor := onboardingChoosePredecessor(inactiveMatches)
	return activeMatches, predecessor
}

func onboardingProfileMatch(candidate *Node, department, title, team string) bool {
	if candidate == nil {
		return false
	}
	if department != "" && normalizeOrgKey(readString(candidate.Properties, "department")) != department {
		return false
	}
	if title != "" && normalizeOrgKey(readString(candidate.Properties, "title", "role")) != title {
		return false
	}
	if team != "" && normalizeOrgKey(readString(candidate.Properties, "team", "squad")) != team {
		return false
	}
	return true
}

func onboardingFallbackPeers(g *Graph, person *Node, department, title string) []*Node {
	if g == nil || person == nil {
		return nil
	}

	peers := make([]*Node, 0)
	if department != "" {
		for _, candidate := range g.GetNodesByKind(NodeKindPerson) {
			if candidate == nil || candidate.ID == person.ID || onboardingPersonInactive(candidate) {
				continue
			}
			if normalizeOrgKey(readString(candidate.Properties, "department")) == department {
				peers = append(peers, candidate)
			}
		}
		if len(peers) > 0 {
			return peers
		}
	}

	if title != "" {
		for _, candidate := range g.GetNodesByKind(NodeKindPerson) {
			if candidate == nil || candidate.ID == person.ID || onboardingPersonInactive(candidate) {
				continue
			}
			if normalizeOrgKey(readString(candidate.Properties, "title", "role")) == title {
				peers = append(peers, candidate)
			}
		}
	}
	return peers
}

func onboardingPersonInactive(person *Node) bool {
	if person == nil {
		return true
	}
	status := strings.ToLower(strings.TrimSpace(readString(person.Properties, "status", "employment_status", "state")))
	switch status {
	case "inactive", "terminated", "offboarded", "departed", "left", "former", "disabled":
		return true
	default:
		return false
	}
}

func onboardingChoosePredecessor(candidates []*Node) *Node {
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		left := onboardingDepartureSignal(candidates[i])
		right := onboardingDepartureSignal(candidates[j])
		if left.Equal(right) {
			return candidates[i].ID < candidates[j].ID
		}
		return left.After(right)
	})
	return candidates[0]
}

func onboardingDepartureSignal(person *Node) time.Time {
	if person == nil {
		return time.Time{}
	}
	if t := firstTimeFromMap(person.Properties, "termination_date", "end_date", "offboarded_at", "updated_at", "last_seen"); !t.IsZero() {
		return t
	}
	if !person.UpdatedAt.IsZero() {
		return person.UpdatedAt
	}
	return person.CreatedAt
}

type onboardingRepoAccumulator struct {
	id       string
	name     string
	score    float64
	coverage map[string]struct{}
}

func onboardingRepositories(g *Graph, signals []onboardingSignalPerson, cohortSize int) []RepoRecommendation {
	if g == nil || len(signals) == 0 {
		return nil
	}
	agg := make(map[string]*onboardingRepoAccumulator)
	for _, signal := range signals {
		if signal.person == nil {
			continue
		}
		for _, edge := range onboardingEdgesForPerson(g, signal.person.ID) {
			if edge == nil {
				continue
			}
			targetID := onboardingCounterpart(edge, signal.person.ID)
			target, ok := g.GetNode(targetID)
			if !ok || target == nil || target.Kind != NodeKindRepository {
				continue
			}

			weight := onboardingRepositoryEdgeWeight(edge.Kind)
			if weight <= 0 {
				continue
			}
			weight += onboardingMinFloat(readFloat(edge.Properties, "strength", "interaction_frequency")*0.1, 0.1)
			weight += onboardingMinFloat(float64(readInt(edge.Properties, "commit_count", "review_count", "issue_count"))/100.0, 0.25)
			if signal.isPredecessor {
				weight *= 1.15
			}

			item, exists := agg[target.ID]
			if !exists {
				item = &onboardingRepoAccumulator{
					id:       target.ID,
					name:     onboardingNodeName(target),
					coverage: make(map[string]struct{}),
				}
				agg[target.ID] = item
			}
			item.score += weight
			item.coverage[signal.person.ID] = struct{}{}
		}
	}

	repos := make([]RepoRecommendation, 0, len(agg))
	coverageDenominator := float64(onboardingMaxInt(cohortSize, 1))
	for _, item := range agg {
		coverage := float64(len(item.coverage)) / coverageDenominator
		repos = append(repos, RepoRecommendation{
			RepositoryID:      item.id,
			RepositoryName:    item.name,
			ContributionScore: item.score,
			CohortCoverage:    clampUnitInterval(coverage),
		})
	}

	sort.Slice(repos, func(i, j int) bool {
		if repos[i].ContributionScore == repos[j].ContributionScore {
			return repos[i].RepositoryID < repos[j].RepositoryID
		}
		return repos[i].ContributionScore > repos[j].ContributionScore
	})
	return truncateRepos(repos, onboardingRepoLimit)
}

func onboardingRepositoryEdgeWeight(kind EdgeKind) float64 {
	switch kind {
	case EdgeKindOwns:
		return 1.0
	case EdgeKindManagedBy:
		return 0.85
	case EdgeKindAssignedTo:
		return 0.70
	case EdgeKindCanAdmin:
		return 0.65
	case EdgeKindCanWrite:
		return 0.55
	case EdgeKindCanRead:
		return 0.35
	case EdgeKindDeployedFrom, EdgeKindOriginatedFrom:
		return 0.45
	default:
		return 0
	}
}

type onboardingIntroAccumulator struct {
	id       string
	name     string
	score    float64
	coverage map[string]struct{}
}

func onboardingKeyPeople(g *Graph, signals []onboardingSignalPerson, personID string, cohortIDs []string, predecessor *Node) []IntroRecommendation {
	if g == nil || len(signals) == 0 {
		return nil
	}

	cohortSet := make(map[string]struct{}, len(cohortIDs))
	for _, id := range cohortIDs {
		cohortSet[id] = struct{}{}
	}

	agg := make(map[string]*onboardingIntroAccumulator)
	for _, signal := range signals {
		if signal.person == nil {
			continue
		}
		for _, edge := range onboardingEdgesForPerson(g, signal.person.ID) {
			if edge == nil || edge.Kind != EdgeKindInteractedWith {
				continue
			}
			peerID := onboardingCounterpart(edge, signal.person.ID)
			if strings.TrimSpace(peerID) == "" || peerID == personID {
				continue
			}
			if _, inCohort := cohortSet[peerID]; inCohort {
				continue
			}
			peer, ok := g.GetNode(peerID)
			if !ok || peer == nil || peer.Kind != NodeKindPerson || onboardingPersonInactive(peer) {
				continue
			}

			score := readFloat(edge.Properties, "strength")
			if score <= 0 {
				score = onboardingMinFloat(readFloat(edge.Properties, "frequency", "interaction_count")/20.0, 1.0)
			}
			if score <= 0 {
				score = 0.35
			}
			if signal.isPredecessor || (predecessor != nil && signal.person.ID == predecessor.ID) {
				score *= 1.30
			}

			item, exists := agg[peer.ID]
			if !exists {
				item = &onboardingIntroAccumulator{
					id:       peer.ID,
					name:     onboardingNodeName(peer),
					coverage: make(map[string]struct{}),
				}
				agg[peer.ID] = item
			}
			item.score += score
			item.coverage[signal.person.ID] = struct{}{}
		}
	}

	recommendations := make([]IntroRecommendation, 0, len(agg))
	coverageDenominator := float64(onboardingMaxInt(len(cohortIDs), 1))
	for _, item := range agg {
		coverage := float64(len(item.coverage)) / coverageDenominator
		recommendations = append(recommendations, IntroRecommendation{
			PersonID:         item.id,
			PersonName:       item.name,
			InteractionScore: item.score,
			CohortCoverage:   clampUnitInterval(coverage),
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].InteractionScore == recommendations[j].InteractionScore {
			return recommendations[i].PersonID < recommendations[j].PersonID
		}
		return recommendations[i].InteractionScore > recommendations[j].InteractionScore
	})
	return truncateIntro(recommendations, onboardingPeopleLimit)
}

type onboardingAccessAccumulator struct {
	id       string
	name     string
	score    float64
	coverage map[string]struct{}
	kinds    map[string]struct{}
}

func onboardingSystemAccess(g *Graph, signals []onboardingSignalPerson, cohortSize int) []AccessRecommendation {
	if g == nil || len(signals) == 0 {
		return nil
	}

	agg := make(map[string]*onboardingAccessAccumulator)
	for _, signal := range signals {
		if signal.person == nil {
			continue
		}
		for _, edge := range onboardingEdgesForPerson(g, signal.person.ID) {
			if edge == nil {
				continue
			}
			targetID := onboardingCounterpart(edge, signal.person.ID)
			target, ok := g.GetNode(targetID)
			if !ok || target == nil || !onboardingSystemNode(target) {
				continue
			}

			weight := onboardingAccessEdgeWeight(edge.Kind)
			if weight <= 0 {
				continue
			}
			if signal.isPredecessor {
				weight *= 1.10
			}

			item, exists := agg[target.ID]
			if !exists {
				item = &onboardingAccessAccumulator{
					id:       target.ID,
					name:     onboardingNodeName(target),
					coverage: make(map[string]struct{}),
					kinds:    make(map[string]struct{}),
				}
				agg[target.ID] = item
			}
			item.score += weight
			item.coverage[signal.person.ID] = struct{}{}
			item.kinds[string(edge.Kind)] = struct{}{}
		}
	}

	recommendations := make([]AccessRecommendation, 0, len(agg))
	coverageDenominator := float64(onboardingMaxInt(cohortSize, 1))
	for _, item := range agg {
		coverage := float64(len(item.coverage)) / coverageDenominator
		recommendations = append(recommendations, AccessRecommendation{
			SystemID:       item.id,
			SystemName:     item.name,
			AccessKinds:    sortedSet(item.kinds),
			CohortCoverage: clampUnitInterval(coverage),
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].CohortCoverage == recommendations[j].CohortCoverage {
			return recommendations[i].SystemID < recommendations[j].SystemID
		}
		return recommendations[i].CohortCoverage > recommendations[j].CohortCoverage
	})
	return truncateAccess(recommendations, onboardingAccessLimit)
}

func onboardingSystemNode(node *Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case NodeKindApplication, NodeKindServiceAccount, NodeKindGroup, NodeKindRole:
		return true
	default:
		return false
	}
}

func onboardingAccessEdgeWeight(kind EdgeKind) float64 {
	switch kind {
	case EdgeKindCanAdmin:
		return 1.0
	case EdgeKindCanWrite:
		return 0.8
	case EdgeKindCanDelete:
		return 0.75
	case EdgeKindCanRead:
		return 0.6
	case EdgeKindAssignedTo:
		return 0.7
	case EdgeKindMemberOf:
		return 0.5
	default:
		return 0
	}
}

type onboardingChannelAccumulator struct {
	id       string
	name     string
	score    float64
	coverage map[string]struct{}
}

func onboardingChannels(g *Graph, signals []onboardingSignalPerson, cohortSize int) []ChannelRecommendation {
	if g == nil || len(signals) == 0 {
		return nil
	}

	agg := make(map[string]*onboardingChannelAccumulator)
	for _, signal := range signals {
		if signal.person == nil {
			continue
		}
		for _, edge := range onboardingEdgesForPerson(g, signal.person.ID) {
			if edge == nil {
				continue
			}
			targetID := onboardingCounterpart(edge, signal.person.ID)
			target, ok := g.GetNode(targetID)
			if !ok || target == nil || !onboardingChannelNode(target) {
				continue
			}
			if edge.Kind != EdgeKindMemberOf && edge.Kind != EdgeKindAssignedTo && edge.Kind != EdgeKindCanRead {
				continue
			}

			item, exists := agg[target.ID]
			if !exists {
				item = &onboardingChannelAccumulator{
					id:       target.ID,
					name:     onboardingNodeName(target),
					coverage: make(map[string]struct{}),
				}
				agg[target.ID] = item
			}
			item.score += 1
			item.coverage[signal.person.ID] = struct{}{}
		}
	}

	recommendations := make([]ChannelRecommendation, 0, len(agg))
	coverageDenominator := float64(onboardingMaxInt(cohortSize, 1))
	for _, item := range agg {
		coverage := float64(len(item.coverage)) / coverageDenominator
		recommendations = append(recommendations, ChannelRecommendation{
			ChannelID:      item.id,
			ChannelName:    item.name,
			CohortCoverage: clampUnitInterval(coverage),
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].CohortCoverage == recommendations[j].CohortCoverage {
			return recommendations[i].ChannelID < recommendations[j].ChannelID
		}
		return recommendations[i].CohortCoverage > recommendations[j].CohortCoverage
	})
	return truncateChannels(recommendations, onboardingChannelLimit)
}

func onboardingChannelNode(node *Node) bool {
	if node == nil || node.Kind != NodeKindGroup {
		return false
	}
	text := strings.ToLower(strings.TrimSpace(firstNonEmpty(node.ID, node.Name, readString(node.Properties, "type", "provider"))))
	if strings.Contains(text, "slack") || strings.Contains(text, "channel") || strings.HasPrefix(text, "#") {
		return true
	}
	if strings.EqualFold(readString(node.Properties, "group_type", "type"), "channel") {
		return true
	}
	return false
}

type onboardingProjectAccumulator struct {
	id       string
	name     string
	score    float64
	coverage map[string]struct{}
}

func onboardingProjects(g *Graph, signals []onboardingSignalPerson, cohortSize int) []ProjectContext {
	if g == nil || len(signals) == 0 {
		return nil
	}

	agg := make(map[string]*onboardingProjectAccumulator)
	for _, signal := range signals {
		if signal.person == nil {
			continue
		}
		for _, edge := range onboardingEdgesForPerson(g, signal.person.ID) {
			if edge == nil {
				continue
			}
			targetID := onboardingCounterpart(edge, signal.person.ID)
			target, ok := g.GetNode(targetID)
			if !ok || target == nil || !onboardingProjectNode(target) {
				continue
			}

			weight := onboardingProjectEdgeWeight(edge.Kind)
			if weight <= 0 {
				continue
			}
			weight += onboardingMinFloat(float64(readInt(edge.Properties, "commit_count", "review_count", "issue_count"))/100.0, 0.15)
			weight += onboardingMinFloat(readFloat(target.Properties, "decision_count", "recent_activity", "activity_score")/100.0, 0.20)
			if signal.isPredecessor {
				weight *= 1.10
			}

			item, exists := agg[target.ID]
			if !exists {
				item = &onboardingProjectAccumulator{
					id:       target.ID,
					name:     onboardingNodeName(target),
					coverage: make(map[string]struct{}),
				}
				agg[target.ID] = item
			}
			item.score += weight
			item.coverage[signal.person.ID] = struct{}{}
		}
	}

	recommendations := make([]ProjectContext, 0, len(agg))
	coverageDenominator := float64(onboardingMaxInt(cohortSize, 1))
	for _, item := range agg {
		coverage := float64(len(item.coverage)) / coverageDenominator
		recommendations = append(recommendations, ProjectContext{
			ProjectID:      item.id,
			ProjectName:    item.name,
			ActivityScore:  item.score,
			CohortCoverage: clampUnitInterval(coverage),
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].ActivityScore == recommendations[j].ActivityScore {
			return recommendations[i].ProjectID < recommendations[j].ProjectID
		}
		return recommendations[i].ActivityScore > recommendations[j].ActivityScore
	})
	return truncateProjects(recommendations, onboardingProjectLimit)
}

func onboardingProjectNode(node *Node) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case NodeKindActivity, NodeKindTicket:
		return true
	}
	if readString(node.Properties, "project", "project_key", "jira_project", "project_id") != "" {
		return true
	}
	name := strings.ToLower(strings.TrimSpace(node.Name))
	return strings.Contains(name, "project") || strings.Contains(name, "jira")
}

func onboardingProjectEdgeWeight(kind EdgeKind) float64 {
	switch kind {
	case EdgeKindAssignedTo:
		return 0.9
	case EdgeKindOwns:
		return 1.0
	case EdgeKindManagedBy:
		return 0.8
	case EdgeKindCanWrite:
		return 0.7
	case EdgeKindCanRead:
		return 0.5
	default:
		return 0
	}
}

type onboardingCustomerAccumulator struct {
	id       string
	name     string
	score    float64
	coverage map[string]struct{}
}

func onboardingCustomerContext(g *Graph, signals []onboardingSignalPerson, cohortSize int) []CustomerBrief {
	if g == nil || len(signals) == 0 {
		return nil
	}

	agg := make(map[string]*onboardingCustomerAccumulator)
	for _, signal := range signals {
		if signal.person == nil {
			continue
		}
		for _, edge := range onboardingEdgesForPerson(g, signal.person.ID) {
			if edge == nil {
				continue
			}
			targetID := onboardingCounterpart(edge, signal.person.ID)
			target, ok := g.GetNode(targetID)
			if !ok || target == nil {
				continue
			}
			if target.Kind != NodeKindCustomer && target.Kind != NodeKindCompany {
				continue
			}

			weight := onboardingCustomerEdgeWeight(edge.Kind)
			if weight <= 0 {
				continue
			}
			weight += onboardingMinFloat(readFloat(edge.Properties, "strength", "interaction_frequency")*0.1, 0.1)
			if signal.isPredecessor {
				weight *= 1.30
			}

			item, exists := agg[target.ID]
			if !exists {
				item = &onboardingCustomerAccumulator{
					id:       target.ID,
					name:     onboardingNodeName(target),
					coverage: make(map[string]struct{}),
				}
				agg[target.ID] = item
			}
			item.score += weight
			item.coverage[signal.person.ID] = struct{}{}
		}
	}

	recommendations := make([]CustomerBrief, 0, len(agg))
	coverageDenominator := float64(onboardingMaxInt(cohortSize, 1))
	for _, item := range agg {
		coverage := float64(len(item.coverage)) / coverageDenominator
		recommendations = append(recommendations, CustomerBrief{
			CustomerID:           item.id,
			CustomerName:         item.name,
			RelationshipStrength: item.score,
			CohortCoverage:       clampUnitInterval(coverage),
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].RelationshipStrength == recommendations[j].RelationshipStrength {
			return recommendations[i].CustomerID < recommendations[j].CustomerID
		}
		return recommendations[i].RelationshipStrength > recommendations[j].RelationshipStrength
	})
	return truncateCustomers(recommendations, onboardingCustomerLimit)
}

func onboardingCustomerEdgeWeight(kind EdgeKind) float64 {
	switch kind {
	case EdgeKindOwns:
		return 1.0
	case EdgeKindManagedBy:
		return 0.8
	case EdgeKindAssignedTo:
		return 0.7
	case EdgeKindInteractedWith:
		return 0.6
	default:
		return 0
	}
}

func onboardingEdgesForPerson(g *Graph, personID string) []*Edge {
	if g == nil || strings.TrimSpace(personID) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	edges := make([]*Edge, 0)
	add := func(edge *Edge) {
		if edge == nil {
			return
		}
		key := edge.ID
		if key == "" {
			key = edge.Source + "|" + edge.Target + "|" + string(edge.Kind)
		}
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		edges = append(edges, edge)
	}

	for _, edge := range g.GetOutEdges(personID) {
		add(edge)
	}
	for _, edge := range g.GetInEdges(personID) {
		add(edge)
	}
	return edges
}

func onboardingCounterpart(edge *Edge, personID string) string {
	if edge == nil {
		return ""
	}
	if edge.Source == personID {
		return edge.Target
	}
	if edge.Target == personID {
		return edge.Source
	}
	return ""
}

func onboardingNodeName(node *Node) string {
	if node == nil {
		return ""
	}
	if strings.TrimSpace(node.Name) != "" {
		return strings.TrimSpace(node.Name)
	}
	return strings.TrimSpace(node.ID)
}

func truncateRepos(values []RepoRecommendation, limit int) []RepoRecommendation {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func truncateIntro(values []IntroRecommendation, limit int) []IntroRecommendation {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func truncateAccess(values []AccessRecommendation, limit int) []AccessRecommendation {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func truncateChannels(values []ChannelRecommendation, limit int) []ChannelRecommendation {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func truncateProjects(values []ProjectContext, limit int) []ProjectContext {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func truncateCustomers(values []CustomerBrief, limit int) []CustomerBrief {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func onboardingMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func onboardingMinFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
