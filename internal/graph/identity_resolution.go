package graph

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const (
	defaultIdentityAutoLinkThreshold = 0.85
	defaultIdentitySuggestThreshold  = 0.55
)

// IdentityAliasAssertion captures one external identity observation.
type IdentityAliasAssertion struct {
	AliasID       string    `json:"alias_id,omitempty"`
	SourceSystem  string    `json:"source_system"`
	SourceEventID string    `json:"source_event_id,omitempty"`
	ExternalID    string    `json:"external_id"`
	AliasType     string    `json:"alias_type,omitempty"`
	CanonicalHint string    `json:"canonical_hint,omitempty"`
	Email         string    `json:"email,omitempty"`
	Name          string    `json:"name,omitempty"`
	ObservedAt    time.Time `json:"observed_at,omitempty"`
	Confidence    float64   `json:"confidence,omitempty"`
}

// IdentityResolutionOptions controls alias matching and linking behavior.
type IdentityResolutionOptions struct {
	AutoLinkThreshold float64 `json:"auto_link_threshold,omitempty"`
	SuggestThreshold  float64 `json:"suggest_threshold,omitempty"`
}

// IdentityResolutionCandidate represents one canonical entity candidate.
type IdentityResolutionCandidate struct {
	AliasNodeID     string   `json:"alias_node_id"`
	CanonicalNodeID string   `json:"canonical_node_id"`
	Score           float64  `json:"score"`
	Deterministic   bool     `json:"deterministic"`
	Reasons         []string `json:"reasons,omitempty"`
}

// IdentityResolutionResult captures one alias resolution attempt.
type IdentityResolutionResult struct {
	AliasNodeID     string                        `json:"alias_node_id"`
	Applied         bool                          `json:"applied"`
	AppliedTargetID string                        `json:"applied_target_id,omitempty"`
	AppliedScore    float64                       `json:"applied_score,omitempty"`
	Candidates      []IdentityResolutionCandidate `json:"candidates,omitempty"`
}

// ResolveIdentityAlias upserts one alias node, scores candidates, and optionally links the best match.
func ResolveIdentityAlias(g *Graph, assertion IdentityAliasAssertion, opts IdentityResolutionOptions) (IdentityResolutionResult, error) {
	if g == nil {
		return IdentityResolutionResult{}, fmt.Errorf("graph is required")
	}

	normalized, err := normalizeIdentityAssertion(assertion)
	if err != nil {
		return IdentityResolutionResult{}, err
	}
	options := normalizeIdentityResolutionOptions(opts)

	aliasNodeID := upsertIdentityAliasNode(g, normalized)
	candidates := identityResolutionCandidates(g, aliasNodeID, normalized)

	result := IdentityResolutionResult{
		AliasNodeID: aliasNodeID,
		Candidates:  candidatesAboveThreshold(candidates, options.SuggestThreshold),
	}

	if len(candidates) == 0 {
		return result, nil
	}
	best := candidates[0]
	if best.Score < options.AutoLinkThreshold && !best.Deterministic {
		return result, nil
	}

	if err := ConfirmIdentityAlias(g, aliasNodeID, best.CanonicalNodeID, normalized.SourceSystem, normalized.SourceEventID, normalized.ObservedAt, best.Score); err != nil {
		return result, err
	}
	result.Applied = true
	result.AppliedTargetID = best.CanonicalNodeID
	result.AppliedScore = best.Score
	return result, nil
}

// ConfirmIdentityAlias force-links one alias to one canonical node.
func ConfirmIdentityAlias(g *Graph, aliasNodeID, canonicalNodeID, sourceSystem, sourceEventID string, observedAt time.Time, confidence float64) error {
	if g == nil {
		return fmt.Errorf("graph is required")
	}
	aliasNodeID = strings.TrimSpace(aliasNodeID)
	canonicalNodeID = strings.TrimSpace(canonicalNodeID)
	sourceSystem = normalizeIdentitySystem(sourceSystem)
	sourceEventID = strings.TrimSpace(sourceEventID)
	if aliasNodeID == "" || canonicalNodeID == "" {
		return fmt.Errorf("alias_node_id and canonical_node_id are required")
	}
	aliasNode, ok := g.GetNode(aliasNodeID)
	if !ok || aliasNode == nil {
		return fmt.Errorf("alias node not found: %s", aliasNodeID)
	}
	if aliasNode.Kind != NodeKindIdentityAlias {
		return fmt.Errorf("node %s is not an identity_alias", aliasNodeID)
	}
	canonicalNode, ok := g.GetNode(canonicalNodeID)
	if !ok || canonicalNode == nil {
		return fmt.Errorf("canonical node not found: %s", canonicalNodeID)
	}

	if observedAt.IsZero() {
		observedAt = temporalNowUTC()
	}
	if confidence <= 0 {
		confidence = 1
	}
	confidence = clampUnit(confidence)

	canonicalLinkCount := 0
	for _, edge := range g.GetOutEdges(aliasNodeID) {
		if edge == nil || edge.Kind != EdgeKindAliasOf {
			continue
		}
		if edge.Target == canonicalNodeID {
			canonicalLinkCount++
			continue
		}
		_ = g.RemoveEdge(aliasNodeID, edge.Target, EdgeKindAliasOf)
	}
	if canonicalLinkCount > 1 {
		_ = g.RemoveEdge(aliasNodeID, canonicalNodeID, EdgeKindAliasOf)
		canonicalLinkCount = 0
	}
	if canonicalLinkCount == 1 {
		return nil
	}

	g.AddEdge(&Edge{
		ID:     fmt.Sprintf("alias_of:%s->%s", aliasNodeID, canonicalNodeID),
		Source: aliasNodeID,
		Target: canonicalNodeID,
		Kind:   EdgeKindAliasOf,
		Effect: EdgeEffectAllow,
		Properties: map[string]any{
			"source_system":   sourceSystem,
			"source_event_id": sourceEventID,
			"confidence":      confidence,
			"observed_at":     observedAt.UTC().Format(time.RFC3339),
			"valid_from":      observedAt.UTC().Format(time.RFC3339),
		},
		Risk: RiskNone,
	})
	return nil
}

// SplitIdentityAlias removes one alias_of link so the alias can be re-resolved.
func SplitIdentityAlias(g *Graph, aliasNodeID, canonicalNodeID, reason, sourceSystem, sourceEventID string, observedAt time.Time) (bool, error) {
	if g == nil {
		return false, fmt.Errorf("graph is required")
	}
	aliasNodeID = strings.TrimSpace(aliasNodeID)
	canonicalNodeID = strings.TrimSpace(canonicalNodeID)
	reason = strings.TrimSpace(reason)
	sourceSystem = normalizeIdentitySystem(sourceSystem)
	sourceEventID = strings.TrimSpace(sourceEventID)
	if aliasNodeID == "" || canonicalNodeID == "" {
		return false, fmt.Errorf("alias_node_id and canonical_node_id are required")
	}

	if observedAt.IsZero() {
		observedAt = temporalNowUTC()
	}
	removed := g.RemoveEdge(aliasNodeID, canonicalNodeID, EdgeKindAliasOf)
	if !removed {
		return false, nil
	}

	aliasNode, ok := g.GetNode(aliasNodeID)
	if ok && aliasNode != nil {
		props := cloneAnyMap(aliasNode.Properties)
		if props == nil {
			props = make(map[string]any)
		}
		props["split_reason"] = reason
		props["split_source_system"] = sourceSystem
		props["split_source_event_id"] = sourceEventID
		props["split_at"] = observedAt.UTC().Format(time.RFC3339)
		aliasNode.Properties = props
		g.AddNode(aliasNode)
	}
	return true, nil
}

func normalizeIdentityAssertion(assertion IdentityAliasAssertion) (IdentityAliasAssertion, error) {
	out := assertion
	out.SourceSystem = normalizeIdentitySystem(assertion.SourceSystem)
	out.SourceEventID = strings.TrimSpace(assertion.SourceEventID)
	out.ExternalID = normalizeIdentityToken(assertion.ExternalID)
	out.AliasID = normalizeIdentityToken(assertion.AliasID)
	out.CanonicalHint = strings.TrimSpace(assertion.CanonicalHint)
	out.Email = normalizePersonEmail(assertion.Email)
	out.Name = strings.TrimSpace(assertion.Name)
	out.AliasType = strings.ToLower(strings.TrimSpace(assertion.AliasType))
	if out.ObservedAt.IsZero() {
		out.ObservedAt = temporalNowUTC()
	}
	out.ObservedAt = out.ObservedAt.UTC()
	if out.Confidence <= 0 {
		out.Confidence = 0.95
	}
	out.Confidence = clampUnit(out.Confidence)

	if out.SourceSystem == "" {
		return IdentityAliasAssertion{}, fmt.Errorf("source_system is required")
	}
	if out.ExternalID == "" {
		return IdentityAliasAssertion{}, fmt.Errorf("external_id is required")
	}
	return out, nil
}

func normalizeIdentityResolutionOptions(opts IdentityResolutionOptions) IdentityResolutionOptions {
	out := opts
	if out.AutoLinkThreshold <= 0 {
		out.AutoLinkThreshold = defaultIdentityAutoLinkThreshold
	}
	if out.SuggestThreshold <= 0 {
		out.SuggestThreshold = defaultIdentitySuggestThreshold
	}
	if out.AutoLinkThreshold < 0 {
		out.AutoLinkThreshold = 0
	}
	if out.AutoLinkThreshold > 1 {
		out.AutoLinkThreshold = 1
	}
	if out.SuggestThreshold < 0 {
		out.SuggestThreshold = 0
	}
	if out.SuggestThreshold > 1 {
		out.SuggestThreshold = 1
	}
	if out.SuggestThreshold > out.AutoLinkThreshold {
		out.SuggestThreshold = out.AutoLinkThreshold
	}
	return out
}

func upsertIdentityAliasNode(g *Graph, assertion IdentityAliasAssertion) string {
	aliasID := assertion.AliasID
	if aliasID == "" {
		aliasID = fmt.Sprintf("alias:%s:%s", normalizeIdentitySystem(assertion.SourceSystem), normalizeIdentityToken(assertion.ExternalID))
	}

	props := map[string]any{
		"source_system":   assertion.SourceSystem,
		"source_event_id": assertion.SourceEventID,
		"external_id":     assertion.ExternalID,
		"alias_type":      assertion.AliasType,
		"canonical_hint":  assertion.CanonicalHint,
		"email":           assertion.Email,
		"name":            assertion.Name,
		"confidence":      assertion.Confidence,
		"observed_at":     assertion.ObservedAt.Format(time.RFC3339),
		"valid_from":      assertion.ObservedAt.Format(time.RFC3339),
	}
	g.AddNode(&Node{
		ID:         aliasID,
		Kind:       NodeKindIdentityAlias,
		Name:       firstNonEmpty(assertion.Email, assertion.Name, assertion.ExternalID, aliasID),
		Provider:   assertion.SourceSystem,
		Properties: props,
		Risk:       RiskNone,
	})
	return aliasID
}

func identityResolutionCandidates(g *Graph, aliasNodeID string, assertion IdentityAliasAssertion) []IdentityResolutionCandidate {
	candidates := make([]IdentityResolutionCandidate, 0)
	for _, node := range g.GetAllNodes() {
		if node == nil || node.ID == aliasNodeID {
			continue
		}
		if node.Kind != NodeKindPerson && node.Kind != NodeKindUser {
			continue
		}

		score, reasons, deterministic := identityMatchScore(assertion, node)
		if score <= 0 {
			continue
		}
		candidates = append(candidates, IdentityResolutionCandidate{
			AliasNodeID:     aliasNodeID,
			CanonicalNodeID: node.ID,
			Score:           clampUnit(score),
			Deterministic:   deterministic,
			Reasons:         uniqueSortedStrings(reasons),
		})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Score == candidates[j].Score {
			return candidates[i].CanonicalNodeID < candidates[j].CanonicalNodeID
		}
		return candidates[i].Score > candidates[j].Score
	})
	return candidates
}

func identityMatchScore(assertion IdentityAliasAssertion, node *Node) (float64, []string, bool) {
	if node == nil {
		return 0, nil, false
	}

	reasons := make([]string, 0, 4)
	score := 0.0
	deterministic := false

	canonicalHint := strings.TrimSpace(assertion.CanonicalHint)
	if canonicalHint != "" && canonicalHint == node.ID {
		score += 1.0
		deterministic = true
		reasons = append(reasons, "canonical_hint_match")
	}

	aliasEmail := normalizePersonEmail(assertion.Email)
	if aliasEmail != "" {
		emails := identityEmailsFromNode(node)
		for _, email := range emails {
			if aliasEmail == email {
				score += 0.85
				deterministic = true
				reasons = append(reasons, "email_exact_match")
				break
			}
		}
	}

	if assertion.ExternalID != "" {
		for _, value := range identityStringValues(node) {
			if normalizeIdentityToken(value) == assertion.ExternalID {
				score += 0.55
				reasons = append(reasons, "external_id_property_match")
				break
			}
		}
	}

	aliasName := normalizeIdentityDisplay(assertion.Name)
	nodeName := normalizeIdentityDisplay(node.Name)
	if aliasName != "" && nodeName != "" {
		similarity := identityNameSimilarity(aliasName, nodeName)
		if similarity >= 0.95 {
			score += 0.55
			deterministic = true
			reasons = append(reasons, "name_exact_match")
		} else if similarity >= 0.80 {
			score += 0.35
			reasons = append(reasons, "name_similarity_high")
		} else if similarity >= 0.65 {
			score += 0.20
			reasons = append(reasons, "name_similarity_medium")
		}
	}

	return math.Min(score, 1.0), reasons, deterministic
}

func candidatesAboveThreshold(candidates []IdentityResolutionCandidate, threshold float64) []IdentityResolutionCandidate {
	if len(candidates) == 0 {
		return nil
	}
	out := make([]IdentityResolutionCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Score < threshold {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func identityEmailsFromNode(node *Node) []string {
	if node == nil {
		return nil
	}
	seen := make(map[string]struct{})
	add := func(value string) {
		email := normalizePersonEmail(value)
		if email == "" {
			return
		}
		seen[email] = struct{}{}
	}

	add(node.ID)
	add(node.Name)
	if node.Properties != nil {
		for _, key := range []string{"email", "primary_email", "mail", "upn"} {
			add(identityAnyToString(node.Properties[key]))
		}
		if raw := node.Properties["emails"]; raw != nil {
			switch typed := raw.(type) {
			case []string:
				for _, value := range typed {
					add(value)
				}
			case []any:
				for _, value := range typed {
					add(identityAnyToString(value))
				}
			}
		}
	}

	out := make([]string, 0, len(seen))
	for email := range seen {
		out = append(out, email)
	}
	sort.Strings(out)
	return out
}

func identityStringValues(node *Node) []string {
	if node == nil || node.Properties == nil {
		return nil
	}
	values := make([]string, 0, len(node.Properties))
	for _, value := range node.Properties {
		s := strings.TrimSpace(identityAnyToString(value))
		if s == "" {
			continue
		}
		values = append(values, s)
	}
	sort.Strings(values)
	return values
}

func normalizeIdentitySystem(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	return strings.NewReplacer(" ", "_", ":", "_", "/", "_").Replace(value)
}

func normalizeIdentityToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	return strings.NewReplacer(" ", "_", ":", "_", "/", "_", "|", "_").Replace(value)
}

func normalizeIdentityDisplay(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	value = strings.NewReplacer(".", " ", "_", " ", "-", " ", ",", " ").Replace(value)
	return strings.Join(strings.Fields(value), " ")
}

func identityNameSimilarity(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}
	if a == b {
		return 1
	}
	tokensA := strings.Fields(a)
	tokensB := strings.Fields(b)
	if len(tokensA) == 0 || len(tokensB) == 0 {
		return 0
	}

	setA := make(map[string]struct{}, len(tokensA))
	setB := make(map[string]struct{}, len(tokensB))
	for _, token := range tokensA {
		setA[token] = struct{}{}
	}
	for _, token := range tokensB {
		setB[token] = struct{}{}
	}

	intersection := 0
	for token := range setA {
		if _, ok := setB[token]; ok {
			intersection++
		}
	}
	if intersection == 0 {
		return 0
	}
	union := len(setA) + len(setB) - intersection
	if union <= 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func identityAnyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	case fmt.Stringer:
		return typed.String()
	case []byte:
		return string(typed)
	case int:
		return fmt.Sprintf("%d", typed)
	case int8:
		return fmt.Sprintf("%d", typed)
	case int16:
		return fmt.Sprintf("%d", typed)
	case int32:
		return fmt.Sprintf("%d", typed)
	case int64:
		return fmt.Sprintf("%d", typed)
	case uint:
		return fmt.Sprintf("%d", typed)
	case uint8:
		return fmt.Sprintf("%d", typed)
	case uint16:
		return fmt.Sprintf("%d", typed)
	case uint32:
		return fmt.Sprintf("%d", typed)
	case uint64:
		return fmt.Sprintf("%d", typed)
	case float32:
		return fmt.Sprintf("%g", typed)
	case float64:
		return fmt.Sprintf("%g", typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
