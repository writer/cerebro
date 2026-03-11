package graph

import (
	"math"
	"sort"
	"strings"
	"time"
)

const customerHealthActiveWindow = 90 * 24 * time.Hour

// CustomerRelationshipHealth captures structural customer-topology health.
type CustomerRelationshipHealth struct {
	CustomerID string `json:"customer_id"`

	// Structural metrics
	TouchpointCount      int     `json:"touchpoint_count"`
	RoleDiversity        float64 `json:"role_diversity"`
	InteractionFrequency float64 `json:"interaction_frequency"`
	InternalCohesion     float64 `json:"internal_cohesion"`
	RecencyScore         float64 `json:"recency_score"`

	// Trend metrics
	TouchpointTrend string `json:"touchpoint_trend"`
	FrequencyTrend  string `json:"frequency_trend"`

	// Comparison
	CohortPercentile int     `json:"cohort_percentile"`
	IdealGap         float64 `json:"ideal_gap"`

	// Composite
	HealthScore float64 `json:"health_score"`
}

// IdealRelationshipTemplate describes a healthy relationship topology baseline.
type IdealRelationshipTemplate struct {
	MinTouchpoints      int      `json:"min_touchpoints"`
	MinRoleDiversity    float64  `json:"min_role_diversity"`
	MinInteractionFreq  float64  `json:"min_interaction_freq"`
	MinInternalCohesion float64  `json:"min_internal_cohesion"`
	RequiredRoles       []string `json:"required_roles,omitempty"`
}

type customerRelationshipComputation struct {
	health             CustomerRelationshipHealth
	roleSet            map[string]struct{}
	currentTouchpoint  int
	previousTouchpoint int
	currentFrequency   float64
	previousFrequency  float64
}

type scoredCustomerHealth struct {
	computation customerRelationshipComputation
	score       float64
}

// ComputeCustomerRelationshipHealth scores all customers using a learned ideal template.
func ComputeCustomerRelationshipHealth(g *Graph) []CustomerRelationshipHealth {
	template := BuildIdealRelationshipTemplate(g)
	return ComputeCustomerRelationshipHealthWithTemplate(g, template)
}

// ComputeCustomerRelationshipHealthWithTemplate scores all customers against the provided template.
func ComputeCustomerRelationshipHealthWithTemplate(g *Graph, template IdealRelationshipTemplate) []CustomerRelationshipHealth {
	if g == nil {
		return nil
	}
	template = normalizeIdealTemplate(template)

	customers := g.GetNodesByKind(NodeKindCustomer)
	if len(customers) == 0 {
		return nil
	}

	computations := make([]customerRelationshipComputation, 0, len(customers))
	for _, customer := range customers {
		if customer == nil || strings.TrimSpace(customer.ID) == "" {
			continue
		}
		computations = append(computations, computeRelationshipHealthCore(g, customer.ID, template))
	}
	if len(computations) == 0 {
		return nil
	}

	assignCustomerCohortPercentiles(g, computations)

	results := make([]CustomerRelationshipHealth, 0, len(computations))
	for _, computation := range computations {
		results = append(results, computation.health)
	}

	sort.Slice(results, func(i, j int) bool { return results[i].CustomerID < results[j].CustomerID })
	return results
}

// ComputeRelationshipHealth computes one customer's relationship-topology health.
func ComputeRelationshipHealth(g *Graph, customerID string) CustomerRelationshipHealth {
	template := BuildIdealRelationshipTemplate(g)
	return ComputeRelationshipHealthWithTemplate(g, customerID, template)
}

// ComputeRelationshipHealthWithTemplate computes one customer's relationship-topology health with a fixed template.
func ComputeRelationshipHealthWithTemplate(g *Graph, customerID string, template IdealRelationshipTemplate) CustomerRelationshipHealth {
	if g == nil {
		return CustomerRelationshipHealth{CustomerID: strings.TrimSpace(customerID)}
	}
	template = normalizeIdealTemplate(template)
	customerID = strings.TrimSpace(customerID)
	if customerID == "" {
		return CustomerRelationshipHealth{}
	}

	for _, health := range ComputeCustomerRelationshipHealthWithTemplate(g, template) {
		if health.CustomerID == customerID {
			return health
		}
	}
	return computeRelationshipHealthCore(g, customerID, template).health
}

// BuildIdealRelationshipTemplate derives template minimums from top healthy customer cohorts.
func BuildIdealRelationshipTemplate(g *Graph) IdealRelationshipTemplate {
	template := defaultIdealRelationshipTemplate()
	if g == nil {
		return template
	}

	customers := g.GetNodesByKind(NodeKindCustomer)
	if len(customers) == 0 {
		return template
	}

	baseline := make([]customerRelationshipComputation, 0, len(customers))
	for _, customer := range customers {
		if customer == nil || strings.TrimSpace(customer.ID) == "" {
			continue
		}
		baseline = append(baseline, computeRelationshipHealthCore(g, customer.ID, template))
	}
	if len(baseline) == 0 {
		return template
	}

	scored := make([]scoredCustomerHealth, 0, len(baseline))
	for _, computation := range baseline {
		customer, ok := g.GetNode(computation.health.CustomerID)
		if !ok || customer == nil {
			continue
		}

		score := computation.health.HealthScore

		nps := readFloat(customer.Properties, "nps", "nps_score")
		if nps > 1 {
			nps = nps / 100
		}
		score += clampUnitInterval(nps) * 20

		tenureYears := readFloat(customer.Properties, "tenure_years", "customer_tenure_years")
		if tenureYears <= 0 {
			tenureYears = readFloat(customer.Properties, "tenure_months") / 12
		}
		if tenureYears > 0 {
			score += clampUnitInterval(tenureYears/5) * 15
		}

		renewal := readFloat(customer.Properties, "renewal_rate", "renewal_probability", "renewal_score")
		if renewal > 1 {
			renewal = renewal / 100
		}
		if renewal > 0 {
			score += clampUnitInterval(renewal) * 15
		}

		scored = append(scored, scoredCustomerHealth{
			computation: computation,
			score:       score,
		})
	}
	if len(scored) == 0 {
		return template
	}

	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return scored[i].computation.health.CustomerID < scored[j].computation.health.CustomerID
		}
		return scored[i].score > scored[j].score
	})

	healthyCount := int(math.Ceil(float64(len(scored)) * 0.25))
	if healthyCount < 1 {
		healthyCount = 1
	}
	if healthyCount > len(scored) {
		healthyCount = len(scored)
	}
	selected := scored[:healthyCount]

	touchpoints := make([]int, 0, len(selected))
	roleDiversities := make([]float64, 0, len(selected))
	frequencies := make([]float64, 0, len(selected))
	cohesions := make([]float64, 0, len(selected))
	roleCounts := make(map[string]int)

	for _, item := range selected {
		health := item.computation.health
		touchpoints = append(touchpoints, health.TouchpointCount)
		roleDiversities = append(roleDiversities, health.RoleDiversity)
		frequencies = append(frequencies, health.InteractionFrequency)
		cohesions = append(cohesions, health.InternalCohesion)
		for role := range item.computation.roleSet {
			roleCounts[role]++
		}
	}

	template.MinTouchpoints = maxInt(1, percentileInt(touchpoints, 0.25))
	template.MinRoleDiversity = percentileFloat(roleDiversities, 0.25)
	template.MinInteractionFreq = percentileFloat(frequencies, 0.25)
	template.MinInternalCohesion = percentileFloat(cohesions, 0.25)
	template.RequiredRoles = deriveRequiredRoles(roleCounts, healthyCount)

	return normalizeIdealTemplate(template)
}

// ChurnRiskFromTopology estimates churn risk by similarity to historically churned-customer topology.
func ChurnRiskFromTopology(g *Graph, customerID string) float64 {
	if g == nil || strings.TrimSpace(customerID) == "" {
		return 0
	}
	template := BuildIdealRelationshipTemplate(g)
	health := ComputeCustomerRelationshipHealthWithTemplate(g, template)
	if len(health) == 0 {
		return 0
	}

	var current *CustomerRelationshipHealth
	churned := make([]CustomerRelationshipHealth, 0)
	for idx := range health {
		item := health[idx]
		if item.CustomerID == customerID {
			current = &item
		}
		if isChurnedCustomer(g, item.CustomerID) {
			churned = append(churned, item)
		}
	}
	if current == nil {
		return 0
	}
	if len(churned) == 0 {
		return clampUnitInterval((100 - current.HealthScore) / 100 * 0.5)
	}

	churnAverage := averageCustomerTopology(churned)
	similarity := structuralSimilarity(*current, churnAverage)
	risk := clampUnitInterval((similarity * 0.7) + ((100 - current.HealthScore) / 100 * 0.3))
	if current.TouchpointTrend == "declining" {
		risk = clampUnitInterval(risk + 0.05)
	}
	if current.FrequencyTrend == "decreasing" {
		risk = clampUnitInterval(risk + 0.05)
	}
	return risk
}

func computeRelationshipHealthCore(g *Graph, customerID string, template IdealRelationshipTemplate) customerRelationshipComputation {
	computation := customerRelationshipComputation{
		health: CustomerRelationshipHealth{
			CustomerID:      customerID,
			TouchpointTrend: "stable",
			FrequencyTrend:  "stable",
		},
		roleSet: make(map[string]struct{}),
	}
	if g == nil || strings.TrimSpace(customerID) == "" {
		return computation
	}
	if customer, ok := g.GetNode(customerID); !ok || customer == nil || customer.Kind != NodeKindCustomer {
		return computation
	}

	touchpointEdges := customerTouchpointEdges(g, customerID)
	computation.health.TouchpointCount = len(touchpointEdges)
	if len(touchpointEdges) == 0 {
		computation.health.TouchpointTrend = "declining"
		computation.health.FrequencyTrend = "decreasing"
		computation.health.IdealGap = computeCustomerIdealGap(computation.health, template, computation.roleSet)
		computation.health.HealthScore = computeCustomerHealthScore(computation.health, template)
		return computation
	}

	roleCounts := make(map[string]float64)
	currentTouchpoints := make(map[string]struct{})
	previousTouchpoints := make(map[string]struct{})
	latestInteraction := time.Time{}
	now := orgHealthNowUTC()

	for personID, edges := range touchpointEdges {
		if strings.TrimSpace(personID) == "" || len(edges) == 0 {
			continue
		}
		person, _ := g.GetNode(personID)
		category, role := customerRoleForPerson(person, edges)
		roleCounts[category]++
		if role != "" {
			computation.roleSet[role] = struct{}{}
		}

		isCurrent := false
		isPrevious := false
		for _, edge := range edges {
			if edge == nil {
				continue
			}
			currentStrength, previousStrength, lastInteraction := relationshipStrengthTrend(now, edge)
			computation.currentFrequency += currentStrength
			computation.previousFrequency += previousStrength

			if lastInteraction.After(latestInteraction) {
				latestInteraction = lastInteraction
			}
			if edgeRecencyActive(edge, customerHealthActiveWindow) || currentStrength >= 0.25 {
				isCurrent = true
			}
			if previousStrength >= 0.25 {
				isPrevious = true
			}
		}
		if isCurrent {
			currentTouchpoints[personID] = struct{}{}
		}
		if isPrevious {
			previousTouchpoints[personID] = struct{}{}
		}
	}

	if computation.currentFrequency <= 0 {
		computation.currentFrequency = float64(len(touchpointEdges)) * 0.2
	}
	if computation.previousFrequency <= 0 {
		computation.previousFrequency = computation.currentFrequency
	}

	computation.currentTouchpoint = len(currentTouchpoints)
	if computation.currentTouchpoint == 0 {
		computation.currentTouchpoint = len(touchpointEdges)
	}
	computation.previousTouchpoint = len(previousTouchpoints)
	if computation.previousTouchpoint < computation.currentTouchpoint {
		computation.previousTouchpoint = computation.currentTouchpoint
	}

	computation.health.RoleDiversity = normalizedEntropy(roleCounts)
	computation.health.InteractionFrequency = normalizeCustomerInteractionFrequency(computation.currentFrequency)
	computation.health.InternalCohesion = customerInternalCohesion(g, sortedMapKeysForEdges(touchpointEdges))
	computation.health.RecencyScore = knowledgeRecencyScore(latestInteraction)
	computation.health.TouchpointTrend = classifyTouchpointTrend(computation.currentTouchpoint, computation.previousTouchpoint)
	computation.health.FrequencyTrend = classifyCustomerFrequencyTrend(computation.currentFrequency, computation.previousFrequency)
	computation.health.IdealGap = computeCustomerIdealGap(computation.health, template, computation.roleSet)
	computation.health.HealthScore = computeCustomerHealthScore(computation.health, template)

	return computation
}

func customerTouchpointEdges(g *Graph, customerID string) map[string][]*Edge {
	touchpoints := make(map[string][]*Edge)
	if g == nil || strings.TrimSpace(customerID) == "" {
		return touchpoints
	}

	register := func(personID string, edge *Edge) {
		if edge == nil || strings.TrimSpace(personID) == "" {
			return
		}
		person, ok := g.GetNode(personID)
		if !ok || person == nil || person.Kind != NodeKindPerson {
			return
		}
		if !isCustomerTouchpointEdge(edge.Kind) {
			return
		}
		touchpoints[personID] = append(touchpoints[personID], edge)
	}

	for _, edge := range g.GetOutEdges(customerID) {
		if edge == nil {
			continue
		}
		register(edge.Target, edge)
	}
	for _, edge := range g.GetInEdges(customerID) {
		if edge == nil {
			continue
		}
		register(edge.Source, edge)
	}

	return touchpoints
}

func isCustomerTouchpointEdge(kind EdgeKind) bool {
	switch kind {
	case EdgeKindManagedBy, EdgeKindOwns, EdgeKindAssignedTo, EdgeKindInteractedWith, EdgeKindRenews, EdgeKindEscalatedTo, EdgeKindCanRead, EdgeKindCanWrite, EdgeKindCanAdmin:
		return true
	default:
		return false
	}
}

func customerRoleForPerson(person *Node, edges []*Edge) (string, string) {
	canonical := ""
	for _, edge := range edges {
		role := normalizeCustomerRole(readString(edge.Properties, "role", "relationship_role", "responsibility", "title"))
		if role != "" {
			canonical = role
			break
		}
	}
	if canonical == "" && person != nil {
		canonical = normalizeCustomerRole(readString(person.Properties, "role", "title", "job_title"))
	}
	if canonical == "" {
		return "other", ""
	}
	switch canonical {
	case "account_owner", "commercial_owner":
		return "commercial", canonical
	case "technical_contact":
		return "technical", canonical
	case "executive_sponsor":
		return "executive", canonical
	case "support_contact":
		return "support", canonical
	default:
		return "other", canonical
	}
}

func normalizeCustomerRole(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "" {
		return ""
	}
	switch {
	case strings.Contains(normalized, "executive"), strings.Contains(normalized, "sponsor"), strings.Contains(normalized, "chief"), strings.Contains(normalized, "cto"), strings.Contains(normalized, "ceo"), strings.Contains(normalized, "vp"), strings.Contains(normalized, "director"):
		return "executive_sponsor"
	case strings.Contains(normalized, "technical"), strings.Contains(normalized, "engineer"), strings.Contains(normalized, "architect"), strings.Contains(normalized, "developer"), strings.Contains(normalized, "sre"), strings.Contains(normalized, "platform"), strings.Contains(normalized, "maintainer"):
		return "technical_contact"
	case strings.Contains(normalized, "support"), strings.Contains(normalized, "tam"), strings.Contains(normalized, "service"):
		return "support_contact"
	case strings.Contains(normalized, "account owner"), strings.Contains(normalized, "account_owner"), strings.Contains(normalized, "owner"):
		return "account_owner"
	case strings.Contains(normalized, "sales"), strings.Contains(normalized, "commercial"), strings.Contains(normalized, "success"), strings.Contains(normalized, "csm"), strings.Contains(normalized, "am"):
		return "commercial_owner"
	default:
		return ""
	}
}

func normalizedEntropy(counts map[string]float64) float64 {
	if len(counts) == 0 {
		return 0
	}
	total := 0.0
	for _, count := range counts {
		if count > 0 {
			total += count
		}
	}
	if total <= 0 {
		return 0
	}

	entropy := 0.0
	for _, count := range counts {
		if count <= 0 {
			continue
		}
		p := count / total
		entropy -= p * math.Log(p)
	}
	maxEntropy := math.Log(float64(len(counts)))
	if maxEntropy <= 0 {
		return 0
	}
	return clampUnitInterval(entropy / maxEntropy)
}

func normalizeCustomerInteractionFrequency(value float64) float64 {
	if value <= 0 {
		return 0
	}
	return clampUnitInterval(1 - math.Exp(-value/3.0))
}

func customerInternalCohesion(g *Graph, personIDs []string) float64 {
	if g == nil || len(personIDs) <= 1 {
		return 1
	}
	set := make(map[string]struct{}, len(personIDs))
	for _, personID := range personIDs {
		set[personID] = struct{}{}
	}

	edges := make(map[string]struct{})
	for _, personID := range personIDs {
		for _, edge := range g.GetOutEdges(personID) {
			if edge == nil || edge.Kind != EdgeKindInteractedWith {
				continue
			}
			if _, ok := set[edge.Target]; !ok {
				continue
			}
			edges[undirectedPairKey(edge.Source, edge.Target)] = struct{}{}
		}
	}

	expected := (len(personIDs) * (len(personIDs) - 1)) / 2
	if expected <= 0 {
		return 1
	}
	return clampUnitInterval(float64(len(edges)) / float64(expected))
}

func sortedMapKeysForEdges(values map[string][]*Edge) []string {
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

func classifyTouchpointTrend(current, previous int) string {
	if previous <= 0 {
		if current > 0 {
			return "growing"
		}
		return "stable"
	}
	if current >= previous+1 && float64(current) >= float64(previous)*1.2 {
		return "growing"
	}
	if current+1 <= previous && float64(current) <= float64(previous)*0.8 {
		return "declining"
	}
	if current < previous {
		return "declining"
	}
	return "stable"
}

func classifyCustomerFrequencyTrend(current, previous float64) string {
	if previous <= 0 {
		if current > 0 {
			return "increasing"
		}
		return "stable"
	}
	if current > previous*1.1 {
		return "increasing"
	}
	if current < previous*0.9 {
		return "decreasing"
	}
	return "stable"
}

func computeCustomerIdealGap(health CustomerRelationshipHealth, template IdealRelationshipTemplate, roleSet map[string]struct{}) float64 {
	template = normalizeIdealTemplate(template)
	touchGap := 0.0
	if template.MinTouchpoints > 0 && health.TouchpointCount < template.MinTouchpoints {
		touchGap = float64(template.MinTouchpoints-health.TouchpointCount) / float64(template.MinTouchpoints)
	}

	roleGap := templateMetricGap(health.RoleDiversity, template.MinRoleDiversity)
	frequencyGap := templateMetricGap(health.InteractionFrequency, template.MinInteractionFreq)
	cohesionGap := templateMetricGap(health.InternalCohesion, template.MinInternalCohesion)

	requiredGap := 0.0
	if len(template.RequiredRoles) > 0 {
		missing := 0
		for _, role := range template.RequiredRoles {
			if _, ok := roleSet[role]; !ok {
				missing++
			}
		}
		requiredGap = float64(missing) / float64(len(template.RequiredRoles))
	}

	return clampUnitInterval((touchGap + roleGap + frequencyGap + cohesionGap + requiredGap) / 5.0)
}

func templateMetricGap(actual, expected float64) float64 {
	if expected <= 0 || actual >= expected {
		return 0
	}
	return clampUnitInterval((expected - actual) / expected)
}

func computeCustomerHealthScore(health CustomerRelationshipHealth, template IdealRelationshipTemplate) float64 {
	template = normalizeIdealTemplate(template)
	touchpointScore := clampUnitInterval(float64(health.TouchpointCount) / float64(maxInt(1, template.MinTouchpoints)))
	roleScore := templateMetricAttainment(health.RoleDiversity, template.MinRoleDiversity)
	frequencyScore := templateMetricAttainment(health.InteractionFrequency, template.MinInteractionFreq)
	cohesionScore := templateMetricAttainment(health.InternalCohesion, template.MinInternalCohesion)
	recencyScore := clampUnitInterval(health.RecencyScore)

	base := (touchpointScore * 0.22) +
		(roleScore * 0.18) +
		(frequencyScore * 0.24) +
		(cohesionScore * 0.18) +
		(recencyScore * 0.18)

	switch health.TouchpointTrend {
	case "growing":
		base += 0.03
	case "declining":
		base -= 0.06
	}
	switch health.FrequencyTrend {
	case "increasing":
		base += 0.03
	case "decreasing":
		base -= 0.08
	}
	base = clampUnitInterval(base)

	score := base * (1 - clampUnitInterval(health.IdealGap)*0.5) * 100
	if health.TouchpointCount < 2 {
		score -= 10
	}
	return clampScore(score)
}

func templateMetricAttainment(actual, expected float64) float64 {
	if expected <= 0 {
		return clampUnitInterval(actual)
	}
	if actual >= expected {
		return 1
	}
	return clampUnitInterval(actual / expected)
}

func normalizeIdealTemplate(template IdealRelationshipTemplate) IdealRelationshipTemplate {
	defaults := defaultIdealRelationshipTemplate()

	if template.MinTouchpoints <= 0 {
		template.MinTouchpoints = defaults.MinTouchpoints
	}
	if template.MinRoleDiversity <= 0 {
		template.MinRoleDiversity = defaults.MinRoleDiversity
	}
	if template.MinInteractionFreq <= 0 {
		template.MinInteractionFreq = defaults.MinInteractionFreq
	}
	if template.MinInternalCohesion <= 0 {
		template.MinInternalCohesion = defaults.MinInternalCohesion
	}
	if len(template.RequiredRoles) == 0 {
		template.RequiredRoles = append([]string(nil), defaults.RequiredRoles...)
	} else {
		normalized := make([]string, 0, len(template.RequiredRoles))
		seen := make(map[string]struct{})
		for _, role := range template.RequiredRoles {
			canonical := normalizeCustomerRole(role)
			if canonical == "" {
				continue
			}
			if _, ok := seen[canonical]; ok {
				continue
			}
			seen[canonical] = struct{}{}
			normalized = append(normalized, canonical)
		}
		if len(normalized) == 0 {
			template.RequiredRoles = append([]string(nil), defaults.RequiredRoles...)
		} else {
			sort.Strings(normalized)
			template.RequiredRoles = normalized
		}
	}

	return template
}

func defaultIdealRelationshipTemplate() IdealRelationshipTemplate {
	return IdealRelationshipTemplate{
		MinTouchpoints:      3,
		MinRoleDiversity:    0.50,
		MinInteractionFreq:  0.40,
		MinInternalCohesion: 0.35,
		RequiredRoles: []string{
			"account_owner",
			"technical_contact",
		},
	}
}

func deriveRequiredRoles(roleCounts map[string]int, total int) []string {
	if total <= 0 || len(roleCounts) == 0 {
		return nil
	}
	threshold := int(math.Ceil(float64(total) * 0.5))
	if threshold < 1 {
		threshold = 1
	}

	roles := make([]string, 0)
	for role, count := range roleCounts {
		if count >= threshold {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	return roles
}

func assignCustomerCohortPercentiles(g *Graph, computations []customerRelationshipComputation) {
	if len(computations) == 0 {
		return
	}

	tiers := make(map[string][]int)
	for idx := range computations {
		customer, ok := g.GetNode(computations[idx].health.CustomerID)
		tier := "unknown"
		if ok && customer != nil {
			tier = customerARRTier(customer)
		}
		tiers[tier] = append(tiers[tier], idx)
	}

	for _, indexes := range tiers {
		sort.Slice(indexes, func(i, j int) bool {
			left := computations[indexes[i]].health
			right := computations[indexes[j]].health
			if left.HealthScore == right.HealthScore {
				return left.CustomerID < right.CustomerID
			}
			return left.HealthScore < right.HealthScore
		})

		n := len(indexes)
		for rank, compIdx := range indexes {
			percentile := 100
			if n > 1 {
				percentile = int(math.Round(float64(rank) / float64(n-1) * 100))
			}
			computations[compIdx].health.CohortPercentile = percentile
		}
	}
}

func customerARRTier(customer *Node) string {
	if customer == nil {
		return "unknown"
	}
	arr := readFloat(customer.Properties, "arr", "annual_recurring_revenue", "contract_value", "amount")
	switch {
	case arr >= 1000000:
		return "enterprise"
	case arr >= 200000:
		return "mid_market"
	case arr > 0:
		return "smb"
	default:
		return "unknown"
	}
}

func percentileInt(values []int, percentile float64) int {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	idx := int(math.Round(clampUnitInterval(percentile) * float64(len(sorted)-1)))
	return sorted[idx]
}

func percentileFloat(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	idx := int(math.Round(clampUnitInterval(percentile) * float64(len(sorted)-1)))
	return clampUnitInterval(sorted[idx])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func isChurnedCustomer(g *Graph, customerID string) bool {
	if g == nil || strings.TrimSpace(customerID) == "" {
		return false
	}
	customer, ok := g.GetNode(customerID)
	if !ok || customer == nil {
		return false
	}
	if readBool(customer.Properties, "churned", "is_churned", "cancelled", "canceled") {
		return true
	}
	status := strings.ToLower(readString(customer.Properties, "status", "customer_status", "lifecycle", "lifecycle_stage", "renewal_status"))
	switch status {
	case "churned", "cancelled", "canceled", "lost", "inactive":
		return true
	default:
		return false
	}
}

func averageCustomerTopology(values []CustomerRelationshipHealth) CustomerRelationshipHealth {
	if len(values) == 0 {
		return CustomerRelationshipHealth{}
	}

	sum := CustomerRelationshipHealth{}
	for _, value := range values {
		sum.TouchpointCount += value.TouchpointCount
		sum.RoleDiversity += value.RoleDiversity
		sum.InteractionFrequency += value.InteractionFrequency
		sum.InternalCohesion += value.InternalCohesion
		sum.RecencyScore += value.RecencyScore
		sum.HealthScore += value.HealthScore
	}
	count := float64(len(values))
	return CustomerRelationshipHealth{
		TouchpointCount:      int(math.Round(float64(sum.TouchpointCount) / count)),
		RoleDiversity:        clampUnitInterval(sum.RoleDiversity / count),
		InteractionFrequency: clampUnitInterval(sum.InteractionFrequency / count),
		InternalCohesion:     clampUnitInterval(sum.InternalCohesion / count),
		RecencyScore:         clampUnitInterval(sum.RecencyScore / count),
		HealthScore:          clampScore(sum.HealthScore / count),
	}
}

func structuralSimilarity(current CustomerRelationshipHealth, baseline CustomerRelationshipHealth) float64 {
	distances := []float64{
		absScaled(float64(current.TouchpointCount), float64(baseline.TouchpointCount), math.Max(1, math.Max(float64(current.TouchpointCount), float64(baseline.TouchpointCount)))),
		math.Abs(current.RoleDiversity - baseline.RoleDiversity),
		math.Abs(current.InteractionFrequency - baseline.InteractionFrequency),
		math.Abs(current.InternalCohesion - baseline.InternalCohesion),
		math.Abs(current.RecencyScore - baseline.RecencyScore),
		math.Abs((current.HealthScore - baseline.HealthScore) / 100.0),
	}

	distance := 0.0
	for _, value := range distances {
		distance += clampUnitInterval(value)
	}
	distance = distance / float64(len(distances))

	if current.TouchpointTrend != "" && baseline.TouchpointTrend != "" && current.TouchpointTrend != baseline.TouchpointTrend {
		distance += 0.05
	}
	if current.FrequencyTrend != "" && baseline.FrequencyTrend != "" && current.FrequencyTrend != baseline.FrequencyTrend {
		distance += 0.05
	}
	distance = clampUnitInterval(distance)

	return clampUnitInterval(1 - distance)
}

func absScaled(left, right, scale float64) float64 {
	if scale <= 0 {
		scale = 1
	}
	return math.Abs(left-right) / scale
}
