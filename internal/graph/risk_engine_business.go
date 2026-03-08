package graph

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RiskProfile configures how composite posture scoring weighs signal families.
type RiskProfile struct {
	Name    string             `json:"name"`
	Weights map[string]float64 `json:"weights"`
}

func (p RiskProfile) Weight(signal string) float64 {
	if p.Weights == nil {
		return 1
	}
	if w, ok := p.Weights[signal]; ok {
		return w
	}
	return 1
}

// DefaultRiskProfiles returns built-in profile presets.
func DefaultRiskProfiles() map[string]RiskProfile {
	return map[string]RiskProfile{
		"default": {
			Name: "default",
			Weights: map[string]float64{
				"security": 1,
				"business": 1,
				"stripe":   1,
				"support":  1,
				"crm":      1,
				"topology": 1,
				"github":   1,
				"ensemble": 1,
			},
		},
		"security-heavy": {
			Name: "security-heavy",
			Weights: map[string]float64{
				"security": 2.5,
				"business": 0.8,
				"stripe":   0.7,
				"support":  0.8,
				"crm":      0.8,
				"topology": 0.9,
				"github":   1.2,
				"ensemble": 0.8,
			},
		},
		"revenue-heavy": {
			Name: "revenue-heavy",
			Weights: map[string]float64{
				"security": 0.8,
				"business": 1.8,
				"stripe":   2.4,
				"support":  1.4,
				"crm":      2.2,
				"topology": 1.7,
				"github":   0.8,
				"ensemble": 1.3,
			},
		},
		"customer-health": {
			Name: "customer-health",
			Weights: map[string]float64{
				"security": 1.1,
				"business": 1.7,
				"stripe":   1.6,
				"support":  2.1,
				"crm":      1.8,
				"topology": 2.4,
				"github":   0.9,
				"ensemble": 1.8,
			},
		},
	}
}

// DefaultRiskProfile returns the named profile or the default profile.
func DefaultRiskProfile(name string) RiskProfile {
	profiles := DefaultRiskProfiles()
	if p, ok := profiles[strings.TrimSpace(strings.ToLower(name))]; ok {
		return p
	}
	return profiles["default"]
}

// EntityRisk explains why an account/customer/entity is risky.
type EntityRisk struct {
	EntityID   string             `json:"entity_id"`
	EntityName string             `json:"entity_name"`
	EntityKind NodeKind           `json:"entity_kind"`
	Score      float64            `json:"score"`
	Trend      string             `json:"trend"`
	Delta      float64            `json:"delta"`
	Factors    []EntityRiskFactor `json:"factors,omitempty"`
}

// EntityRiskFactor is a weighted signal contributing to entity risk.
type EntityRiskFactor struct {
	Type      string  `json:"type"`
	Source    string  `json:"source"`
	Title     string  `json:"title"`
	Score     float64 `json:"score"`
	Weight    float64 `json:"weight"`
	Evidence  string  `json:"evidence,omitempty"`
	Remedy    string  `json:"remedy,omitempty"`
	MetricKey string  `json:"metric_key,omitempty"`
}

// RiskScoreChangedEvent captures threshold crossings for posture score changes.
type RiskScoreChangedEvent struct {
	EventType     string    `json:"event_type"`
	Scope         string    `json:"scope"`
	EntityID      string    `json:"entity_id,omitempty"`
	PreviousScore float64   `json:"previous_score"`
	CurrentScore  float64   `json:"current_score"`
	Threshold     float64   `json:"threshold"`
	Direction     string    `json:"direction"`
	ChangedAt     time.Time `json:"changed_at"`
}

// SetRiskProfile configures a named composite scoring profile.
func (r *RiskEngine) SetRiskProfile(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	profile := DefaultRiskProfile(name)
	if profile.Name == "default" && strings.TrimSpace(strings.ToLower(name)) != "default" {
		return fmt.Errorf("unknown risk profile %q", name)
	}
	r.riskProfile = profile
	return nil
}

// SetRiskScoreChangedHandler sets a callback for threshold crossing events.
func (r *RiskEngine) SetRiskScoreChangedHandler(handler func(RiskScoreChangedEvent)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onScoreChange = handler
}

// ScoreEntity returns a composite risk explanation for one entity.
func (r *RiskEngine) ScoreEntity(nodeID string) *EntityRisk {
	r.mu.RLock()
	node, ok := r.graph.GetNode(nodeID)
	previous := r.entityScores[nodeID]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	scored := r.scoreEntity(node, previous)
	return &scored
}

func (r *RiskEngine) collectEntityRisks(previous map[string]float64) map[string]EntityRisk {
	scored := make(map[string]EntityRisk)
	for _, node := range r.graph.GetAllNodes() {
		if !node.IsBusinessEntity() {
			continue
		}
		risk := r.scoreEntity(node, previous[node.ID])
		if risk.Score <= 0 && len(risk.Factors) == 0 {
			continue
		}
		scored[node.ID] = risk
	}
	return scored
}

func (r *RiskEngine) scoreEntity(node *Node, previous float64) EntityRisk {
	stripe := r.scoreStripeSignals(node)
	support := r.scoreSupportSignals(node)
	crm := r.scoreCRMSignals(node)
	topology := r.scoreCustomerTopology(node)
	github := r.scoreGitHubSignals(node)
	ensemble := r.scoreEnsembleSignals(node)
	security := r.scoreEntitySecuritySignals(node)

	type factorInput struct {
		source string
		typeID string
		title  string
		score  float64
		reason string
		metric string
		remedy string
	}

	factorInputs := []factorInput{
		{source: "security", typeID: "operational_risk", title: "Security pressure", score: security, reason: "Critical/high security findings attached to entity context", metric: "security_findings", remedy: "Reduce critical findings and isolate exposed resources"},
		{source: "stripe", typeID: "revenue_risk", title: "Billing instability", score: stripe, reason: "Payment failures, chargebacks, or past_due state detected", metric: "billing_failures", remedy: "Resolve payment failures and review account billing controls"},
		{source: "support", typeID: "sla_breach", title: "Support pressure", score: support, reason: "P1 ticket velocity / backlog indicates SLA risk", metric: "p1_ticket_pressure", remedy: "Staff critical support cases and execute SLA escalation path"},
		{source: "crm", typeID: "pipeline_risk", title: "Pipeline stagnation", score: crm, reason: "Stale opportunities/deals or low engagement", metric: "crm_staleness", remedy: "Advance next-step commitments and refresh champion coverage"},
		{source: "topology", typeID: "churn_signal", title: "Relationship topology decay", score: topology, reason: "Relationship structure resembles churn-prone customer topology", metric: "customer_topology_health", remedy: "Add touchpoints, sponsor coverage, and restore interaction cadence"},
		{source: "github", typeID: "operational_risk", title: "Engineering drag", score: github, reason: "Deploy cadence drop or incident PR spikes detected", metric: "deploy_health", remedy: "Stabilize delivery and reduce incident-driven changes"},
		{source: "ensemble", typeID: "churn_signal", title: "Investigation churn signal", score: ensemble, reason: "High investigation volume suggests customer health volatility", metric: "investigation_frequency", remedy: "Run focused customer risk review and ownership escalation"},
	}

	factors := make([]EntityRiskFactor, 0, len(factorInputs))
	totalWeight := 0.0
	weighted := 0.0
	for _, in := range factorInputs {
		if in.score <= 0 {
			continue
		}
		weight := r.riskProfile.Weight(in.source)
		factors = append(factors, EntityRiskFactor{
			Type:      in.typeID,
			Source:    in.source,
			Title:     in.title,
			Score:     clampScore(in.score),
			Weight:    weight,
			Evidence:  in.reason,
			MetricKey: in.metric,
			Remedy:    in.remedy,
		})
		weighted += clampScore(in.score) * weight
		totalWeight += weight
	}

	score := 0.0
	if totalWeight > 0 {
		score = weighted / totalWeight
	}
	delta := score - previous
	trend := "stable"
	if delta > 5 {
		trend = "degrading"
	} else if delta < -5 {
		trend = "improving"
	}

	return EntityRisk{
		EntityID:   node.ID,
		EntityName: node.Name,
		EntityKind: node.Kind,
		Score:      clampScore(score),
		Trend:      trend,
		Delta:      delta,
		Factors:    factors,
	}
}

func (r *RiskEngine) scoreEntitySecuritySignals(node *Node) float64 {
	score := 0.0
	score += float64(readInt(node.Properties, "critical_findings", "critical_finding_count")) * 18
	score += float64(readInt(node.Properties, "high_findings", "high_finding_count")) * 9

	for _, neighbor := range r.entityNeighbors(node.ID) {
		if !neighbor.IsResource() {
			continue
		}
		switch neighbor.Risk {
		case RiskCritical:
			score += 16
		case RiskHigh:
			score += 8
		}
	}

	return clampScore(score)
}

func (r *RiskEngine) scoreStripeSignals(node *Node) float64 {
	score := 0.0
	failed := readInt(node.Properties, "failed_payment_count", "payment_failed_count")
	chargebacks := readInt(node.Properties, "chargeback_count")
	if failed > 0 {
		score += float64(failed) * 20
	}
	if chargebacks > 0 {
		score += float64(chargebacks) * 25
	}
	if status := strings.ToLower(readString(node.Properties, "payment_status", "status")); status == "past_due" || status == "unpaid" {
		score += 35
	}
	for _, neighbor := range r.entityNeighbors(node.ID) {
		if neighbor.Kind != NodeKindSubscription && neighbor.Kind != NodeKindInvoice {
			continue
		}
		score += float64(readInt(neighbor.Properties, "failed_payment_count", "payment_failed_count")) * 12
		if status := strings.ToLower(readString(neighbor.Properties, "status", "collection_status")); status == "past_due" || status == "unpaid" {
			score += 18
		}
	}
	return clampScore(score)
}

func (r *RiskEngine) scoreSupportSignals(node *Node) float64 {
	score := 0.0
	score += float64(readInt(node.Properties, "open_p1_tickets", "p1_ticket_count")) * 18
	score += float64(readInt(node.Properties, "p1_ticket_velocity")) * 9
	if drop := readFloat(node.Properties, "csat_drop", "csat_drop_pct"); drop > 0 {
		score += drop * 0.6
	}
	for _, neighbor := range r.entityNeighbors(node.ID) {
		if neighbor.Kind != NodeKindTicket {
			continue
		}
		priority := strings.ToLower(readString(neighbor.Properties, "priority", "severity"))
		status := strings.ToLower(readString(neighbor.Properties, "status"))
		if (priority == "p1" || priority == "critical" || priority == "sev1") && status != "resolved" && status != "closed" {
			score += 20
		}
		if readBool(neighbor.Properties, "competitor_mentioned") {
			score += 8
		}
	}
	return clampScore(score)
}

func (r *RiskEngine) scoreCRMSignals(node *Node) float64 {
	score := 0.0
	staleActivity := readInt(node.Properties, "days_since_last_activity")
	staleModified := readInt(node.Properties, "days_since_last_modified")
	if staleActivity > 21 {
		score += math.Min(float64(staleActivity-21), 40)
	}
	if staleModified > 21 {
		score += math.Min(float64(staleModified-21), 40)
	}
	if readBool(node.Properties, "no_next_step") {
		score += 18
	}
	if readBool(node.Properties, "champion_departed") {
		score += 25
	}
	if pushCount := readInt(node.Properties, "close_date_push_count"); pushCount > 0 {
		score += float64(pushCount) * 6
	}
	for _, neighbor := range r.entityNeighbors(node.ID) {
		if neighbor.Kind != NodeKindDeal && neighbor.Kind != NodeKindOpportunity {
			continue
		}
		if amount := readFloat(neighbor.Properties, "amount", "arr", "deal_value"); amount >= 100000 {
			score += 12
		}
		if days := readInt(neighbor.Properties, "days_since_last_activity", "days_since_last_modified"); days > 21 {
			score += math.Min(float64(days-21), 25)
		}
	}
	return clampScore(score)
}

func (r *RiskEngine) scoreCustomerTopology(node *Node) float64 {
	if node == nil {
		return 0
	}
	if node.Kind != NodeKindCustomer && node.Kind != NodeKindCompany {
		return 0
	}

	health, ok := r.customerHealth[node.ID]
	if !ok {
		return 0
	}

	score := 100 - clampScore(health.HealthScore)
	if health.TouchpointCount < 2 {
		score += 15
	}
	if health.TouchpointTrend == "declining" {
		score += 10
	}
	if health.FrequencyTrend == "decreasing" {
		score += 10
	}

	churnSimilarity := ChurnRiskFromTopology(r.graph, node.ID)
	if churnSimilarity > 0 {
		score += churnSimilarity * 35
	}

	return clampScore(score)
}

func (r *RiskEngine) scoreGitHubSignals(node *Node) float64 {
	score := 0.0
	if dropPct := readFloat(node.Properties, "deploy_frequency_drop_pct", "deploy_drop_pct"); dropPct > 0 {
		score += dropPct * 0.6
	}
	score += float64(readInt(node.Properties, "incident_pr_count", "incident_pull_request_count")) * 15
	for _, neighbor := range r.entityNeighbors(node.ID) {
		if strings.ToLower(neighbor.Provider) != "github" && neighbor.Kind != NodeKindRepository {
			continue
		}
		if dropPct := readFloat(neighbor.Properties, "deploy_frequency_drop_pct", "deploy_drop_pct"); dropPct > 0 {
			score += dropPct * 0.5
		}
		score += float64(readInt(neighbor.Properties, "incident_pr_count")) * 12
	}
	return clampScore(score)
}

func (r *RiskEngine) scoreEnsembleSignals(node *Node) float64 {
	score := float64(readInt(node.Properties, "investigation_count", "investigation_frequency")) * 9
	if score > 0 {
		score += 10
	}
	return clampScore(score)
}

func (r *RiskEngine) entityNeighbors(nodeID string) []*Node {
	seen := map[string]bool{nodeID: true}
	neighbors := make([]*Node, 0)

	for _, edge := range r.graph.GetOutEdges(nodeID) {
		node, ok := r.graph.GetNode(edge.Target)
		if !ok || seen[node.ID] {
			continue
		}
		seen[node.ID] = true
		neighbors = append(neighbors, node)
	}
	for _, edge := range r.graph.GetInEdges(nodeID) {
		node, ok := r.graph.GetNode(edge.Source)
		if !ok || seen[node.ID] {
			continue
		}
		seen[node.ID] = true
		neighbors = append(neighbors, node)
	}
	return neighbors
}

func (r *RiskEngine) rankEntityRisks(entityRisks map[string]EntityRisk) []*RankedRisk {
	if len(entityRisks) == 0 {
		return nil
	}
	ranked := make([]*RankedRisk, 0)
	for _, risk := range entityRisks {
		for _, factor := range risk.Factors {
			if factor.Score < 35 {
				continue
			}
			ranked = append(ranked, &RankedRisk{
				Type:            factor.Type,
				ID:              fmt.Sprintf("entity-risk:%s:%s", risk.EntityID, factor.Source),
				Title:           fmt.Sprintf("%s on %s", factor.Title, risk.EntityName),
				Description:     factor.Evidence,
				Score:           factor.Score,
				Severity:        scoreToSeverity(factor.Score),
				AffectedAssets:  []string{risk.EntityID},
				Remediation:     factor.Remedy,
				EstimatedEffort: "moderate",
			})
		}
	}
	return ranked
}

func (r *RiskEngine) calculateBusinessRiskScore(entityRisks map[string]EntityRisk) float64 {
	if len(entityRisks) == 0 {
		return 0
	}
	scores := make([]float64, 0, len(entityRisks))
	for _, entity := range entityRisks {
		scores = append(scores, entity.Score)
	}
	sort.Slice(scores, func(i, j int) bool { return scores[i] > scores[j] })
	limit := 5
	if len(scores) < limit {
		limit = len(scores)
	}
	total := 0.0
	for i := 0; i < limit; i++ {
		total += scores[i]
	}
	return total / float64(limit)
}

func (r *RiskEngine) calculateTrendAnalysis(previous, current *SecurityReport) *TrendAnalysis {
	if current == nil {
		return nil
	}
	trend := &TrendAnalysis{
		CurrentScore: current.RiskScore,
		TrendPeriod:  "analysis_window",
	}
	if previous == nil {
		trend.PreviousScore = current.RiskScore
		trend.ScoreChange = 0
		trend.Trend = "stable"
		return trend
	}

	trend.PreviousScore = previous.RiskScore
	trend.ScoreChange = current.RiskScore - previous.RiskScore
	switch {
	case trend.ScoreChange > 3:
		trend.Trend = "degrading"
	case trend.ScoreChange < -3:
		trend.Trend = "improving"
	default:
		trend.Trend = "stable"
	}

	prevTop := make(map[string]bool, len(previous.TopRisks))
	for _, risk := range previous.TopRisks {
		prevTop[risk.ID] = true
	}
	currTop := make(map[string]bool, len(current.TopRisks))
	for _, risk := range current.TopRisks {
		currTop[risk.ID] = true
		if !prevTop[risk.ID] {
			trend.NewIssues++
		}
	}
	for id := range prevTop {
		if !currTop[id] {
			trend.ResolvedIssues++
		}
	}

	return trend
}

func (r *RiskEngine) calculateRiskScoreChanges(previous, current *SecurityReport, now time.Time) []RiskScoreChangedEvent {
	thresholds := []float64{50, 70, 80}
	changes := make([]RiskScoreChangedEvent, 0)

	if previous != nil {
		changes = append(changes, thresholdCrossings("overall", "", previous.RiskScore, current.RiskScore, thresholds, now)...)
	}

	if previous == nil {
		return changes
	}

	for entityID, curr := range current.EntityRisks {
		prevScore, ok := r.entityScores[entityID]
		if !ok {
			continue
		}
		changes = append(changes, thresholdCrossings("entity", entityID, prevScore, curr.Score, thresholds, now)...)
	}

	return changes
}

func thresholdCrossings(scope, entityID string, previous, current float64, thresholds []float64, now time.Time) []RiskScoreChangedEvent {
	if len(thresholds) == 0 || previous == current {
		return nil
	}
	events := make([]RiskScoreChangedEvent, 0)
	for _, threshold := range thresholds {
		if previous < threshold && current >= threshold {
			events = append(events, RiskScoreChangedEvent{
				EventType:     "cerebro.events.risk_score_changed",
				Scope:         scope,
				EntityID:      entityID,
				PreviousScore: previous,
				CurrentScore:  current,
				Threshold:     threshold,
				Direction:     "up",
				ChangedAt:     now,
			})
		}
		if previous >= threshold && current < threshold {
			events = append(events, RiskScoreChangedEvent{
				EventType:     "cerebro.events.risk_score_changed",
				Scope:         scope,
				EntityID:      entityID,
				PreviousScore: previous,
				CurrentScore:  current,
				Threshold:     threshold,
				Direction:     "down",
				ChangedAt:     now,
			})
		}
	}
	return events
}

func clampScore(score float64) float64 {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func readString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if m == nil {
			return ""
		}
		if value, ok := m[key]; ok {
			switch typed := value.(type) {
			case string:
				if strings.TrimSpace(typed) != "" {
					return strings.TrimSpace(typed)
				}
			case fmt.Stringer:
				return strings.TrimSpace(typed.String())
			default:
				return strings.TrimSpace(fmt.Sprintf("%v", typed))
			}
		}
	}
	return ""
}

func readInt(m map[string]any, keys ...string) int {
	for _, key := range keys {
		if m == nil {
			return 0
		}
		value, ok := m[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed
		case int64:
			return int(typed)
		case float64:
			return int(typed)
		case float32:
			return int(typed)
		case string:
			parsed, err := strconv.Atoi(strings.TrimSpace(typed))
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func readFloat(m map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if m == nil {
			return 0
		}
		value, ok := m[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return typed
		case float32:
			return float64(typed)
		case int:
			return float64(typed)
		case int64:
			return float64(typed)
		case string:
			parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func readBool(m map[string]any, keys ...string) bool {
	for _, key := range keys {
		if m == nil {
			return false
		}
		value, ok := m[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed
		case string:
			normalized := strings.TrimSpace(strings.ToLower(typed))
			return normalized == "true" || normalized == "1" || normalized == "yes"
		}
	}
	return false
}
