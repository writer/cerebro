package graph

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	RuleCandidateTypeToxicCombination = "toxic_combination"
	RuleCandidateTypePolicy           = "policy"

	RuleCandidateStatusPendingApproval = "pending_approval"
	RuleCandidateStatusApproved        = "approved"
	RuleCandidateStatusRejected        = "rejected"
)

// RuleDiscoveryRequest configures AI-assisted rule discovery.
type RuleDiscoveryRequest struct {
	WindowDays               int    `json:"window_days,omitempty"`
	MinDetections            int    `json:"min_detections,omitempty"`
	MaxCandidates            int    `json:"max_candidates,omitempty"`
	Profile                  string `json:"profile,omitempty"`
	IncludePolicies          bool   `json:"include_policies,omitempty"`
	IncludeToxicCombinations bool   `json:"include_toxic_combinations,omitempty"`
}

// RuleDecisionRequest records human-in-the-loop approval/rejection.
type RuleDecisionRequest struct {
	Approve  bool   `json:"approve"`
	Reviewer string `json:"reviewer,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// DiscoveredRuleCandidate is an AI-generated rule proposal.
type DiscoveredRuleCandidate struct {
	ID                string         `json:"id"`
	Type              string         `json:"type"`
	Title             string         `json:"title"`
	Description       string         `json:"description"`
	Status            string         `json:"status"`
	Activated         bool           `json:"activated"`
	SignalFamily      string         `json:"signal_family,omitempty"`
	SourceRuleID      string         `json:"source_rule_id,omitempty"`
	SuggestedSeverity Severity       `json:"suggested_severity,omitempty"`
	Precision         float64        `json:"precision"`
	Recall            float64        `json:"recall"`
	AvgLeadTimeDays   float64        `json:"avg_lead_time_days"`
	Support           int            `json:"support"`
	Prompt            string         `json:"prompt,omitempty"`
	CedarPolicy       string         `json:"cedar_policy,omitempty"`
	Definition        map[string]any `json:"definition,omitempty"`
	ProposedAt        time.Time      `json:"proposed_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	ReviewedBy        string         `json:"reviewed_by,omitempty"`
	ReviewedAt        *time.Time     `json:"reviewed_at,omitempty"`
	ReviewNotes       string         `json:"review_notes,omitempty"`
	PromotionStatus   string         `json:"promotion_status,omitempty"`
	PromotionDetails  string         `json:"promotion_details,omitempty"`
	PromotedAt        *time.Time     `json:"promoted_at,omitempty"`
}

// DiscoverRules generates candidate toxic-combination and policy rules from outcome feedback.
func (r *RiskEngine) DiscoverRules(req RuleDiscoveryRequest) []DiscoveredRuleCandidate {
	windowDays := req.WindowDays
	if windowDays <= 0 {
		windowDays = 90
	}
	minDetections := req.MinDetections
	if minDetections <= 0 {
		minDetections = 3
	}
	maxCandidates := req.MaxCandidates
	if maxCandidates <= 0 {
		maxCandidates = 20
	}

	includePolicies := req.IncludePolicies
	includeToxic := req.IncludeToxicCombinations
	if !includePolicies && !includeToxic {
		includePolicies = true
		includeToxic = true
	}

	feedback := r.OutcomeFeedback(time.Duration(windowDays)*24*time.Hour, req.Profile)
	candidates := make([]DiscoveredRuleCandidate, 0)

	if includeToxic {
		for _, metric := range feedback.RuleEffectiveness {
			if metric.Detections < minDetections || metric.Precision < 0.45 {
				continue
			}
			candidates = append(candidates, discoveredToxicCandidate(metric, feedback.ObservationWindowDays))
		}
	}
	if includePolicies {
		for _, adjustment := range feedback.SignalWeightAdjustments {
			if adjustment.Observations < minDetections {
				continue
			}
			if adjustment.Direction != "increase" {
				continue
			}
			candidates = append(candidates, discoveredPolicyCandidate(adjustment, feedback.Profile, feedback.ObservationWindowDays))
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Support == candidates[j].Support {
			if candidates[i].Precision == candidates[j].Precision {
				return candidates[i].ID < candidates[j].ID
			}
			return candidates[i].Precision > candidates[j].Precision
		}
		return candidates[i].Support > candidates[j].Support
	})
	if len(candidates) > maxCandidates {
		candidates = candidates[:maxCandidates]
	}

	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	resolved := make([]DiscoveredRuleCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		existing, ok := r.discoveredRules[candidate.ID]
		if ok {
			candidate.Status = existing.Status
			candidate.Activated = existing.Activated
			candidate.ReviewedBy = existing.ReviewedBy
			candidate.ReviewedAt = existing.ReviewedAt
			candidate.ReviewNotes = existing.ReviewNotes
			candidate.PromotionStatus = existing.PromotionStatus
			candidate.PromotionDetails = existing.PromotionDetails
			candidate.PromotedAt = existing.PromotedAt
			candidate.ProposedAt = existing.ProposedAt
		}
		if candidate.ProposedAt.IsZero() {
			candidate.ProposedAt = now
		}
		candidate.UpdatedAt = now
		if candidate.Status == "" {
			candidate.Status = RuleCandidateStatusPendingApproval
		}
		r.discoveredRules[candidate.ID] = candidate
		resolved = append(resolved, candidate)
	}

	return resolved
}

// ListDiscoveredRules returns candidate rules filtered by optional status.
func (r *RiskEngine) ListDiscoveredRules(status string) []DiscoveredRuleCandidate {
	if r == nil {
		return nil
	}

	normalizedStatus := strings.TrimSpace(strings.ToLower(status))
	r.mu.RLock()
	defer r.mu.RUnlock()

	candidates := make([]DiscoveredRuleCandidate, 0, len(r.discoveredRules))
	for _, candidate := range r.discoveredRules {
		if normalizedStatus != "" && strings.ToLower(candidate.Status) != normalizedStatus {
			continue
		}
		candidates = append(candidates, candidate)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ProposedAt.Equal(candidates[j].ProposedAt) {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].ProposedAt.After(candidates[j].ProposedAt)
	})
	return candidates
}

// DecideDiscoveredRule applies human approval or rejection for a candidate.
func (r *RiskEngine) DecideDiscoveredRule(id string, decision RuleDecisionRequest) (*DiscoveredRuleCandidate, error) {
	if r == nil {
		return nil, fmt.Errorf("risk engine is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("candidate id is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	candidate, ok := r.discoveredRules[id]
	if !ok {
		return nil, fmt.Errorf("candidate %q not found", id)
	}

	now := time.Now().UTC()
	candidate.ReviewedAt = &now
	candidate.ReviewedBy = strings.TrimSpace(decision.Reviewer)
	candidate.ReviewNotes = strings.TrimSpace(decision.Notes)
	if candidate.ReviewedBy == "" {
		candidate.ReviewedBy = "manual-reviewer"
	}

	if decision.Approve {
		candidate.Status = RuleCandidateStatusApproved
		candidate.Activated = true
		r.applyDiscoveredRulePromotionLocked(&candidate, now)
	} else {
		candidate.Status = RuleCandidateStatusRejected
		candidate.Activated = false
		candidate.PromotionStatus = "rejected"
		candidate.PromotionDetails = "candidate rejected during human review"
		candidate.PromotedAt = nil
	}
	candidate.UpdatedAt = now
	r.discoveredRules[id] = candidate

	copy := candidate
	return &copy, nil
}

func discoveredToxicCandidate(metric RuleEffectiveness, windowDays int) DiscoveredRuleCandidate {
	signalFamily := normalizeSignalFamily(metric.SignalFamily)
	if signalFamily == "" {
		signalFamily = "security"
	}
	threshold := 75.0
	if metric.Precision >= 0.80 && metric.AvgLeadTimeDays >= 7 {
		threshold = 70
	}
	id := buildDiscoveredRuleID(RuleCandidateTypeToxicCombination, metric.RuleID)
	title := fmt.Sprintf("Predictive toxic pattern: %s", metric.RuleID)
	description := fmt.Sprintf("Predicts outcomes with precision %.2f and recall %.2f over %d detections", metric.Precision, metric.Recall, metric.Detections)

	return DiscoveredRuleCandidate{
		ID:                id,
		Type:              RuleCandidateTypeToxicCombination,
		Title:             title,
		Description:       description,
		Status:            RuleCandidateStatusPendingApproval,
		SignalFamily:      signalFamily,
		SourceRuleID:      metric.RuleID,
		SuggestedSeverity: metric.Severity,
		Precision:         metric.Precision,
		Recall:            metric.Recall,
		AvgLeadTimeDays:   metric.AvgLeadTimeDays,
		Support:           metric.Detections,
		Prompt:            buildDiscoveryPrompt(signalFamily, windowDays, metric.Precision, metric.Recall),
		Definition: map[string]any{
			"kind":             "toxic_combination",
			"source_rule_id":   metric.RuleID,
			"signal_family":    signalFamily,
			"minimum_score":    threshold,
			"lead_time_days":   metric.AvgLeadTimeDays,
			"required_support": metric.Detections,
		},
	}
}

func discoveredPolicyCandidate(adjustment SignalWeightRecommendation, profile string, windowDays int) DiscoveredRuleCandidate {
	signal := normalizeSignalFamily(adjustment.Signal)
	if signal == "" {
		signal = "security"
	}
	id := buildDiscoveredRuleID(RuleCandidateTypePolicy, signal+":"+profile)
	title := fmt.Sprintf("Policy guardrail for %s risk pattern", signal)
	description := fmt.Sprintf("Signal %s correlates with outcomes (hit rate %.2f across %d observations)", signal, adjustment.OutcomeHitRate, adjustment.Observations)

	return DiscoveredRuleCandidate{
		ID:              id,
		Type:            RuleCandidateTypePolicy,
		Title:           title,
		Description:     description,
		Status:          RuleCandidateStatusPendingApproval,
		SignalFamily:    signal,
		Precision:       adjustment.OutcomeHitRate,
		Recall:          adjustment.OutcomeHitRate,
		AvgLeadTimeDays: 14,
		Support:         adjustment.Observations,
		Prompt:          buildDiscoveryPrompt(signal, windowDays, adjustment.OutcomeHitRate, adjustment.OutcomeHitRate),
		CedarPolicy: fmt.Sprintf(
			"forbid(principal, action, resource) when { context.signal_family == \"%s\" && context.risk_score >= 70 };",
			signal,
		),
		Definition: map[string]any{
			"kind":             "policy",
			"profile":          profile,
			"signal_family":    signal,
			"current_weight":   adjustment.CurrentWeight,
			"suggested_weight": adjustment.SuggestedWeight,
			"hit_rate":         adjustment.OutcomeHitRate,
		},
	}
}

func buildDiscoveredRuleID(kind, seed string) string {
	normalizedKind := strings.TrimSpace(strings.ToLower(kind))
	if normalizedKind == "" {
		normalizedKind = "candidate"
	}
	return fmt.Sprintf("discover:%s:%s", normalizedKind, slugForRuleID(seed))
}

func slugForRuleID(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return "unnamed"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unnamed"
	}
	return out
}

func buildDiscoveryPrompt(signalFamily string, windowDays int, precision, recall float64) string {
	return fmt.Sprintf(
		"Analyze graph snapshots from the %d-day window before negative outcomes. Focus on %s signals and derive a structured detector with precision %.2f / recall %.2f. Return machine-readable rule JSON plus human rationale.",
		windowDays,
		signalFamily,
		precision,
		recall,
	)
}

func (r *RiskEngine) applyDiscoveredRulePromotionLocked(candidate *DiscoveredRuleCandidate, promotedAt time.Time) {
	if candidate == nil {
		return
	}

	status := "approved_noop"
	details := "candidate approved; no automatic activation step available"
	ruleType := strings.TrimSpace(strings.ToLower(candidate.Type))
	switch ruleType {
	case RuleCandidateTypePolicy:
		signal := normalizeSignalFamily(stringFromAny(candidate.Definition["signal_family"]))
		weight, ok := floatFromAny(candidate.Definition["suggested_weight"])
		if !ok || weight <= 0 || signal == "" {
			status = "approved_manual_review"
			details = "policy candidate approved but missing suggested_weight/signal_family fields"
			break
		}
		if r.riskProfile.Weights == nil {
			r.riskProfile.Weights = make(map[string]float64)
		}
		before := r.riskProfile.Weight(signal)
		r.riskProfile.Weights[signal] = weight
		status = "applied_profile_weight"
		details = fmt.Sprintf("updated risk profile %q weight for %s from %.2f to %.2f", r.riskProfile.Name, signal, before, weight)
	case RuleCandidateTypeToxicCombination:
		status = "queued_manual_rule_rollout"
		details = "toxic combination candidate approved; requires detector code registration before runtime activation"
	}

	candidate.PromotionStatus = status
	candidate.PromotionDetails = details
	candidate.PromotedAt = &promotedAt
	r.rulePromotions = append(r.rulePromotions, RulePromotionEvent{
		CandidateID: candidate.ID,
		RuleType:    candidate.Type,
		Status:      status,
		Details:     details,
		AppliedAt:   promotedAt,
	})
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}

func floatFromAny(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	default:
		return 0, false
	}
}
