package graph

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

const defaultKeyPersonRiskLimit = 10

// KeyPersonRiskSummary captures one ranked single-person-failure risk.
type KeyPersonRiskSummary struct {
	PersonID               string    `json:"person_id"`
	PersonName             string    `json:"person_name,omitempty"`
	Department             string    `json:"department,omitempty"`
	Score                  float64   `json:"score"`
	Risk                   RiskLevel `json:"risk"`
	SystemsBusFactor0      int       `json:"systems_bus_factor_0"`
	SystemsBusFactor1      int       `json:"systems_bus_factor_1"`
	CustomersNoContact     int       `json:"customers_no_contact"`
	AffectedARR            float64   `json:"affected_arr"`
	BrokenBridgeCount      int       `json:"broken_bridge_count"`
	SecretsKnownCount      int       `json:"secrets_known_count"`
	AccessToRevokeCount    int       `json:"access_to_revoke_count"`
	KnowledgeRecoveryWeeks int       `json:"knowledge_recovery_weeks"`
	SuggestedSuccessors    []string  `json:"suggested_successors,omitempty"`
	Summary                string    `json:"summary,omitempty"`
}

// KeyPersonRiskReport is the ranked report surface for key-person risk.
type KeyPersonRiskReport struct {
	GeneratedAt time.Time              `json:"generated_at"`
	PersonID    string                 `json:"person_id,omitempty"`
	Count       int                    `json:"count"`
	Items       []KeyPersonRiskSummary `json:"items,omitempty"`
}

// BuildKeyPersonRiskReport ranks person departures by downstream business and knowledge impact.
func BuildKeyPersonRiskReport(g *Graph, now time.Time, personID string, limit int) KeyPersonRiskReport {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if limit <= 0 {
		limit = defaultKeyPersonRiskLimit
	}
	personID = strings.TrimSpace(personID)
	report := KeyPersonRiskReport{
		GeneratedAt: now,
		PersonID:    personID,
	}
	if g == nil {
		return report
	}

	summaries := make([]KeyPersonRiskSummary, 0)
	if personID != "" {
		if summary, ok := keyPersonRiskSummary(g, personID); ok {
			summaries = append(summaries, summary)
		}
		report.Items = summaries
		report.Count = len(summaries)
		return report
	}

	people := g.GetNodesByKind(NodeKindPerson)
	sort.Slice(people, func(i, j int) bool {
		if people[i] == nil {
			return false
		}
		if people[j] == nil {
			return true
		}
		return people[i].ID < people[j].ID
	})
	for _, person := range people {
		if person == nil {
			continue
		}
		summary, ok := keyPersonRiskSummary(g, person.ID)
		if !ok {
			continue
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].Score == summaries[j].Score {
			if summaries[i].AffectedARR == summaries[j].AffectedARR {
				return summaries[i].PersonID < summaries[j].PersonID
			}
			return summaries[i].AffectedARR > summaries[j].AffectedARR
		}
		return summaries[i].Score > summaries[j].Score
	})
	if len(summaries) > limit {
		summaries = summaries[:limit]
	}
	report.Items = summaries
	report.Count = len(summaries)
	return report
}

func keyPersonRiskSummary(g *Graph, personID string) (KeyPersonRiskSummary, bool) {
	if g == nil {
		return KeyPersonRiskSummary{}, false
	}
	personID = strings.TrimSpace(personID)
	person, ok := g.GetNode(personID)
	if !ok || person == nil || person.Kind != NodeKindPerson {
		return KeyPersonRiskSummary{}, false
	}

	hypothetical := g.Fork()
	hypothetical.RemoveNode(personID)
	hypothetical.BuildIndex()

	impact := buildPersonDepartureImpact(g, hypothetical, personID)
	if impact == nil {
		return KeyPersonRiskSummary{}, false
	}
	summary := KeyPersonRiskSummary{
		PersonID:               personID,
		PersonName:             firstNonEmpty(strings.TrimSpace(person.Name), personID),
		Department:             keyPersonDepartment(g, person),
		SystemsBusFactor0:      len(impact.SystemsBusFactor0),
		SystemsBusFactor1:      len(impact.SystemsBusFactor1),
		CustomersNoContact:     len(impact.CustomersNoContact),
		AffectedARR:            impact.AffectedARR,
		BrokenBridgeCount:      len(impact.BrokenBridges),
		SecretsKnownCount:      len(impact.SecretsKnown),
		AccessToRevokeCount:    len(impact.AccessToRevoke),
		KnowledgeRecoveryWeeks: impact.KnowledgeRecoveryWeeks,
		SuggestedSuccessors:    keyPersonSuggestedSuccessors(impact),
	}
	summary.Score = keyPersonRiskScore(summary)
	summary.Risk = keyPersonRiskLevel(summary.Score)
	summary.Summary = keyPersonRiskNarrative(summary)
	return summary, true
}

func keyPersonDepartment(g *Graph, person *Node) string {
	if person == nil {
		return ""
	}
	if department := strings.TrimSpace(readString(person.Properties, "department", "team", "owner_team")); department != "" {
		return department
	}
	if g == nil {
		return ""
	}
	for _, edge := range g.GetOutEdges(person.ID) {
		if edge == nil || edge.Kind != EdgeKindMemberOf {
			continue
		}
		if department, ok := g.GetNode(edge.Target); ok && department != nil && department.Kind == NodeKindDepartment {
			return firstNonEmpty(strings.TrimSpace(department.Name), department.ID)
		}
	}
	return ""
}

func keyPersonSuggestedSuccessors(impact *PersonDepartureImpact) []string {
	if impact == nil || len(impact.SuggestedSuccessors) == 0 {
		return nil
	}
	seen := make(map[string]string)
	for _, candidates := range impact.SuggestedSuccessors {
		for _, candidate := range candidates {
			if candidate == nil || strings.TrimSpace(candidate.ID) == "" {
				continue
			}
			if _, ok := seen[candidate.ID]; ok {
				continue
			}
			seen[candidate.ID] = firstNonEmpty(strings.TrimSpace(candidate.Name), candidate.ID)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	names := make([]string, 0, minInt(len(ids), 3))
	for _, id := range ids {
		names = append(names, seen[id])
		if len(names) == 3 {
			break
		}
	}
	return names
}

func keyPersonRiskScore(summary KeyPersonRiskSummary) float64 {
	score := 0.0
	score += math.Min(45, float64(summary.SystemsBusFactor0)*15)
	score += math.Min(20, float64(summary.SystemsBusFactor1)*8)
	score += math.Min(20, float64(summary.CustomersNoContact)*10)
	if summary.AffectedARR > 0 {
		score += math.Min(20, math.Log10(summary.AffectedARR+1)*4)
	}
	score += math.Min(10, float64(summary.BrokenBridgeCount)*4)
	score += math.Min(10, float64(summary.SecretsKnownCount)*2+float64(summary.AccessToRevokeCount))
	if summary.KnowledgeRecoveryWeeks > 0 {
		score += math.Min(10, float64(summary.KnowledgeRecoveryWeeks)*1.5)
	}
	if score > 100 {
		score = 100
	}
	return score
}

func keyPersonRiskLevel(score float64) RiskLevel {
	switch {
	case score >= 75:
		return RiskCritical
	case score >= 50:
		return RiskHigh
	case score >= 25:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskNone
	}
}

func keyPersonRiskNarrative(summary KeyPersonRiskSummary) string {
	parts := make([]string, 0, 4)
	if summary.SystemsBusFactor0 > 0 {
		parts = append(parts, fmt.Sprintf("%d systems would be orphaned", summary.SystemsBusFactor0))
	}
	if summary.CustomersNoContact > 0 {
		parts = append(parts, fmt.Sprintf("%d customers would lose a direct owner", summary.CustomersNoContact))
	}
	if summary.AffectedARR > 0 {
		parts = append(parts, fmt.Sprintf("$%.0f ARR is tied to this departure", summary.AffectedARR))
	}
	if summary.BrokenBridgeCount > 0 {
		parts = append(parts, fmt.Sprintf("%d cross-team bridges would break", summary.BrokenBridgeCount))
	}
	if len(parts) == 0 {
		return "No material single-person failure detected."
	}
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, "; ")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
