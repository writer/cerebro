package graph

import (
	"math"
	"strings"
	"time"
)

// WorkloadRuntimeRiskSummary captures runtime-derived risk signals for one workload-like subject.
type WorkloadRuntimeRiskSummary struct {
	SubjectID           string    `json:"subject_id"`
	ObservationCount    int       `json:"observation_count"`
	FindingCount        int       `json:"finding_count"`
	MITRETechniqueCount int       `json:"mitre_technique_count"`
	Dark                bool      `json:"dark"`
	Multiplier          float64   `json:"multiplier"`
	LastObservedAt      time.Time `json:"last_observed_at,omitempty"`
}

// WorkloadRuntimeRiskSummaryAt computes runtime-derived risk signals for one workload-like subject.
func WorkloadRuntimeRiskSummaryAt(g *Graph, subjectID string, validAt, recordedAt time.Time) WorkloadRuntimeRiskSummary {
	summary := WorkloadRuntimeRiskSummary{
		SubjectID:  strings.TrimSpace(subjectID),
		Multiplier: 1.0,
	}
	if g == nil || summary.SubjectID == "" {
		return summary
	}

	if validAt.IsZero() {
		validAt = time.Now().UTC()
	}
	if recordedAt.IsZero() {
		recordedAt = validAt
	}

	techniques := make(map[string]struct{})
	findings := make(map[string]struct{})

	for _, edge := range g.GetOutEdgesBitemporal(summary.SubjectID, validAt, recordedAt) {
		if edge == nil || edge.Kind != EdgeKindTargets {
			continue
		}
		observation, ok := g.GetNodeBitemporal(edge.Target, validAt, recordedAt)
		if !ok || observation == nil || observation.Kind != NodeKindObservation {
			continue
		}

		summary.ObservationCount++
		if observedAt, ok := graphObservedAt(observation); ok && observedAt.After(summary.LastObservedAt) {
			summary.LastObservedAt = observedAt
		}

		for _, inEdge := range g.GetInEdgesBitemporal(observation.ID, validAt, recordedAt) {
			if inEdge == nil || inEdge.Kind != EdgeKindBasedOn {
				continue
			}
			evidence, ok := g.GetNodeBitemporal(inEdge.Source, validAt, recordedAt)
			if !ok || evidence == nil || evidence.Kind != NodeKindEvidence {
				continue
			}
			if readString(evidence.Properties, "evidence_type") != "runtime_finding" {
				continue
			}
			if readBool(evidence.Properties, "suppressed") {
				continue
			}

			findings[evidence.ID] = struct{}{}
			for _, technique := range runtimeRiskStringSlice(evidence.Properties["mitre_attack"]) {
				techniques[technique] = struct{}{}
			}
		}
	}

	summary.FindingCount = len(findings)
	summary.MITRETechniqueCount = len(techniques)
	if summary.ObservationCount == 0 {
		summary.Dark = true
		summary.Multiplier *= 1.2
	}
	if summary.FindingCount > 0 {
		summary.Multiplier *= 2.0
	}
	if summary.MITRETechniqueCount > 1 {
		summary.Multiplier *= math.Pow(1.5, float64(summary.MITRETechniqueCount-1))
	}

	return summary
}

func runtimeRiskStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if trimmed := strings.TrimSpace(entry); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(typed))
		for _, entry := range typed {
			if trimmed := strings.TrimSpace(readString(map[string]any{"value": entry}, "value")); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	default:
		return nil
	}
}
