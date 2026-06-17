package compliance

import (
	"sort"
	"strings"
	"time"
)

const ControlEvidencePacketVersion = "2026-06-17"

type ControlEvidenceExpectationStatus string

const (
	ControlEvidenceExpectationSatisfied ControlEvidenceExpectationStatus = "satisfied"
	ControlEvidenceExpectationMissing   ControlEvidenceExpectationStatus = "missing"
	ControlEvidenceExpectationStale     ControlEvidenceExpectationStatus = "stale"
	ControlEvidenceExpectationOptional  ControlEvidenceExpectationStatus = "optional"
)

type ControlEvidencePacket struct {
	Version     string                         `json:"version"`
	SelectionID string                         `json:"selection_id,omitempty"`
	GeneratedAt time.Time                      `json:"generated_at"`
	Summary     ControlPostureSummary          `json:"summary"`
	Controls    []ControlEvidencePacketControl `json:"controls"`
}

type ControlEvidencePacketControl struct {
	SelectionID string                         `json:"selection_id,omitempty"`
	Control     ControlPostureControl          `json:"control"`
	Status      ControlPostureStatus           `json:"status"`
	Reasons     []string                       `json:"reasons,omitempty"`
	Tags        []string                       `json:"tags,omitempty"`
	MappedRules []string                       `json:"mapped_rules,omitempty"`
	Findings    []ControlEvidencePacketFinding `json:"findings,omitempty"`
	Evidence    ControlEvidencePacketEvidence  `json:"evidence"`
	Overrides   ControlPostureOverrides        `json:"overrides,omitempty"`
}

type ControlEvidencePacketEvidence struct {
	Summary      ControlPostureEvidence              `json:"summary,omitempty"`
	Expectations []ControlEvidenceExpectationPosture `json:"expectations,omitempty"`
	Items        []ControlEvidencePacketEvidenceItem `json:"items,omitempty"`
}

type ControlEvidenceExpectationPosture struct {
	ID               string                           `json:"id"`
	Title            string                           `json:"title,omitempty"`
	Type             string                           `json:"type,omitempty"`
	Required         bool                             `json:"required"`
	Status           ControlEvidenceExpectationStatus `json:"status"`
	EvidenceIDs      []string                         `json:"evidence_ids,omitempty"`
	StaleEvidenceIDs []string                         `json:"stale_evidence_ids,omitempty"`
	FreshnessSLA     string                           `json:"freshness_sla,omitempty"`
}

type ControlEvidencePacketEvidenceItem struct {
	ID           string    `json:"id,omitempty"`
	RuleID       string    `json:"rule_id,omitempty"`
	EvidenceType string    `json:"evidence_type,omitempty"`
	Status       string    `json:"status,omitempty"`
	Source       string    `json:"source,omitempty"`
	ObservedAt   time.Time `json:"observed_at,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Manual       bool      `json:"manual,omitempty"`
}

type ControlEvidencePacketFinding struct {
	ID              string    `json:"id,omitempty"`
	RuleID          string    `json:"rule_id,omitempty"`
	Title           string    `json:"title,omitempty"`
	Status          string    `json:"status,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	FirstObservedAt time.Time `json:"first_observed_at,omitempty"`
	LastObservedAt  time.Time `json:"last_observed_at,omitempty"`
}

func BuildControlEvidencePacket(input ControlPostureInput) ControlEvidencePacket {
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	input.Now = now
	postures := EvaluateControlPosture(input)
	buckets := buildControlPostureBuckets(input, now)
	packet := ControlEvidencePacket{
		Version:     ControlEvidencePacketVersion,
		SelectionID: strings.TrimSpace(input.Selection.SelectionID),
		GeneratedAt: now,
		Summary:     SummarizeControlPosture(input.Selection.SelectionID, postures),
		Controls:    make([]ControlEvidencePacketControl, 0, len(postures)),
	}
	for _, posture := range postures {
		key := ControlKey(ControlRef{FrameworkName: posture.Control.FrameworkName, ControlID: posture.Control.ControlID})
		bucket := buckets[key]
		control := ControlEvidencePacketControl{
			SelectionID: posture.SelectionID,
			Control:     posture.Control,
			Status:      posture.Status,
			Reasons:     append([]string(nil), posture.Reasons...),
			Tags:        append([]string(nil), posture.Tags...),
			MappedRules: append([]string(nil), posture.MappedRules...),
			Evidence:    ControlEvidencePacketEvidence{Summary: posture.Evidence},
			Overrides:   posture.Overrides,
		}
		if bucket != nil {
			control.Findings = controlPacketFindings(bucket.openFindings)
			control.Evidence.Expectations = controlPacketExpectations(bucket.control, bucket.evidence, now)
			control.Evidence.Items = controlPacketEvidenceItems(bucket.evidence)
		}
		packet.Controls = append(packet.Controls, control)
	}
	return packet
}

func controlPacketExpectations(control ResolvedControl, evidence []ControlEvidenceSignal, now time.Time) []ControlEvidenceExpectationPosture {
	if len(control.Evidence) == 0 {
		return []ControlEvidenceExpectationPosture{defaultControlEvidenceExpectationPosture(control, evidence, now)}
	}
	expectations := make([]ControlEvidenceExpectationPosture, 0, len(control.Evidence))
	for _, expectation := range control.Evidence {
		expectation = expectationWithControlFreshness(expectation, control.Control.FreshnessSLA)
		matches := evidenceForExpectation(expectation, evidence)
		staleIDs := staleEvidenceIDsForExpectation(expectation, matches, now)
		expectations = append(expectations, ControlEvidenceExpectationPosture{
			ID:               strings.TrimSpace(expectation.ID),
			Title:            strings.TrimSpace(expectation.Title),
			Type:             strings.TrimSpace(expectation.Type),
			Required:         evidenceExpectationRequired(expectation),
			Status:           controlExpectationStatus(expectation, matches, staleIDs),
			EvidenceIDs:      sortedUniqueStrings(controlEvidenceIDs(matches)),
			StaleEvidenceIDs: sortedUniqueStrings(staleIDs),
			FreshnessSLA:     strings.TrimSpace(expectation.FreshnessSLA),
		})
	}
	return expectations
}

func defaultControlEvidenceExpectationPosture(control ResolvedControl, evidence []ControlEvidenceSignal, now time.Time) ControlEvidenceExpectationPosture {
	expectation := EvidenceExpectation{
		ID:           "control-evidence",
		Title:        "Control evidence",
		FreshnessSLA: strings.TrimSpace(control.Control.FreshnessSLA),
	}
	staleIDs := staleEvidenceIDsForExpectation(expectation, evidence, now)
	return ControlEvidenceExpectationPosture{
		ID:               expectation.ID,
		Title:            expectation.Title,
		Required:         true,
		Status:           controlExpectationStatus(expectation, evidence, staleIDs),
		EvidenceIDs:      sortedUniqueStrings(controlEvidenceIDs(evidence)),
		StaleEvidenceIDs: sortedUniqueStrings(staleIDs),
		FreshnessSLA:     expectation.FreshnessSLA,
	}
}

func controlExpectationStatus(expectation EvidenceExpectation, evidence []ControlEvidenceSignal, staleIDs []string) ControlEvidenceExpectationStatus {
	if len(evidence) == 0 {
		if evidenceExpectationRequired(expectation) {
			return ControlEvidenceExpectationMissing
		}
		return ControlEvidenceExpectationOptional
	}
	if len(staleIDs) != 0 {
		return ControlEvidenceExpectationStale
	}
	return ControlEvidenceExpectationSatisfied
}

func controlPacketEvidenceItems(evidence []ControlEvidenceSignal) []ControlEvidencePacketEvidenceItem {
	items := make([]ControlEvidencePacketEvidenceItem, 0, len(evidence))
	for _, item := range evidence {
		items = append(items, ControlEvidencePacketEvidenceItem{
			ID:           strings.TrimSpace(item.ID),
			RuleID:       strings.TrimSpace(item.RuleID),
			EvidenceType: strings.TrimSpace(item.EvidenceType),
			Status:       strings.TrimSpace(item.Status),
			Source:       strings.TrimSpace(item.Source),
			ObservedAt:   item.ObservedAt,
			ExpiresAt:    item.ExpiresAt,
			Manual:       item.Manual,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		if items[i].RuleID != items[j].RuleID {
			return items[i].RuleID < items[j].RuleID
		}
		return items[i].EvidenceType < items[j].EvidenceType
	})
	return items
}

func controlPacketFindings(findings []ControlFindingSignal) []ControlEvidencePacketFinding {
	items := make([]ControlEvidencePacketFinding, 0, len(findings))
	for _, finding := range findings {
		items = append(items, ControlEvidencePacketFinding{
			ID:              strings.TrimSpace(finding.ID),
			RuleID:          strings.TrimSpace(finding.RuleID),
			Title:           strings.TrimSpace(finding.Title),
			Status:          strings.TrimSpace(finding.Status),
			Severity:        strings.TrimSpace(finding.Severity),
			FirstObservedAt: finding.FirstObservedAt,
			LastObservedAt:  finding.LastObservedAt,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		if items[i].RuleID != items[j].RuleID {
			return items[i].RuleID < items[j].RuleID
		}
		return items[i].Title < items[j].Title
	})
	return items
}
