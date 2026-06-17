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

type ControlEvidenceQuality string

const (
	ControlEvidenceQualityStrong   ControlEvidenceQuality = "strong"
	ControlEvidenceQualityPartial  ControlEvidenceQuality = "partial"
	ControlEvidenceQualityStale    ControlEvidenceQuality = "stale"
	ControlEvidenceQualityManual   ControlEvidenceQuality = "manual"
	ControlEvidenceQualityMissing  ControlEvidenceQuality = "missing"
	ControlEvidenceQualityOptional ControlEvidenceQuality = "optional"
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
	Readiness   ControlEvidencePacketReadiness `json:"audit_readiness"`
	Overrides   ControlPostureOverrides        `json:"overrides,omitempty"`
}

type ControlEvidencePacketEvidence struct {
	Summary      ControlPostureEvidence              `json:"summary,omitempty"`
	Expectations []ControlEvidenceExpectationPosture `json:"expectations,omitempty"`
	Items        []ControlEvidencePacketEvidenceItem `json:"items,omitempty"`
}

type ControlEvidenceExpectationPosture struct {
	ID                string                           `json:"id"`
	Title             string                           `json:"title,omitempty"`
	Type              string                           `json:"type,omitempty"`
	Description       string                           `json:"description,omitempty"`
	Required          bool                             `json:"required"`
	Status            ControlEvidenceExpectationStatus `json:"status"`
	Quality           ControlEvidenceQuality           `json:"quality"`
	Reason            string                           `json:"reason,omitempty"`
	EvidenceIDs       []string                         `json:"evidence_ids,omitempty"`
	StaleEvidenceIDs  []string                         `json:"stale_evidence_ids,omitempty"`
	FreshnessSLA      string                           `json:"freshness_sla,omitempty"`
	AcceptedFrom      []string                         `json:"accepted_from,omitempty"`
	AssessmentMethods []string                         `json:"assessment_methods,omitempty"`
}

type ControlEvidencePacketEvidenceItem struct {
	ID           string                 `json:"id,omitempty"`
	RuleID       string                 `json:"rule_id,omitempty"`
	EvidenceType string                 `json:"evidence_type,omitempty"`
	Status       string                 `json:"status,omitempty"`
	Quality      ControlEvidenceQuality `json:"quality,omitempty"`
	Reason       string                 `json:"reason,omitempty"`
	Source       string                 `json:"source,omitempty"`
	ObservedAt   time.Time              `json:"observed_at,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at,omitempty"`
	Manual       bool                   `json:"manual,omitempty"`
}

type ControlEvidencePacketReadiness struct {
	Score                int                    `json:"score"`
	Rating               ControlEvidenceQuality `json:"rating"`
	Summary              string                 `json:"summary,omitempty"`
	OpenFindings         int                    `json:"open_findings,omitempty"`
	EvidenceItems        int                    `json:"evidence_items,omitempty"`
	RequiredExpectations int                    `json:"required_expectations,omitempty"`
	MissingEvidence      int                    `json:"missing_evidence,omitempty"`
	StaleEvidence        int                    `json:"stale_evidence,omitempty"`
	ManualEvidence       int                    `json:"manual_evidence,omitempty"`
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
			control.Evidence.Items = controlPacketEvidenceItems(bucket.evidence, now)
		}
		control.Readiness = controlPacketReadiness(control)
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
		status := controlExpectationStatus(expectation, matches, staleIDs)
		quality, reason := controlExpectationQuality(expectation, matches, status)
		expectations = append(expectations, ControlEvidenceExpectationPosture{
			ID:                strings.TrimSpace(expectation.ID),
			Title:             strings.TrimSpace(expectation.Title),
			Type:              strings.TrimSpace(expectation.Type),
			Description:       strings.TrimSpace(expectation.Description),
			Required:          evidenceExpectationRequired(expectation),
			Status:            status,
			Quality:           quality,
			Reason:            reason,
			EvidenceIDs:       sortedUniqueStrings(controlEvidenceIDs(matches)),
			StaleEvidenceIDs:  sortedUniqueStrings(staleIDs),
			FreshnessSLA:      strings.TrimSpace(expectation.FreshnessSLA),
			AcceptedFrom:      sortedUniqueStrings(expectation.AcceptedFrom),
			AssessmentMethods: sortedUniqueStrings(expectation.AssessmentMethods),
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
	status := controlExpectationStatus(expectation, evidence, staleIDs)
	quality, reason := controlExpectationQuality(expectation, evidence, status)
	return ControlEvidenceExpectationPosture{
		ID:               expectation.ID,
		Title:            expectation.Title,
		Required:         true,
		Status:           status,
		Quality:          quality,
		Reason:           reason,
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

func controlExpectationQuality(expectation EvidenceExpectation, evidence []ControlEvidenceSignal, status ControlEvidenceExpectationStatus) (ControlEvidenceQuality, string) {
	switch status {
	case ControlEvidenceExpectationMissing:
		return ControlEvidenceQualityMissing, "Required evidence has not been collected for this expectation."
	case ControlEvidenceExpectationOptional:
		return ControlEvidenceQualityOptional, "This optional expectation is not required for the current packet."
	case ControlEvidenceExpectationStale:
		return ControlEvidenceQualityStale, "Evidence is present, but at least one item is outside the freshness window."
	}
	if len(expectation.AcceptedFrom) != 0 && !evidenceHasAcceptedSource(expectation.AcceptedFrom, evidence) {
		return ControlEvidenceQualityPartial, "Evidence matches the expected type, but not a declared accepted collection source."
	}
	if len(evidence) != 0 && allEvidenceManual(evidence) {
		return ControlEvidenceQualityManual, "Only manually supplied evidence is available; auditor review is required before relying on it."
	}
	return ControlEvidenceQualityStrong, "Evidence is present, fresh, and matches the expectation."
}

func controlPacketEvidenceItems(evidence []ControlEvidenceSignal, now time.Time) []ControlEvidencePacketEvidenceItem {
	items := make([]ControlEvidencePacketEvidenceItem, 0, len(evidence))
	for _, item := range evidence {
		quality, reason := evidenceItemQuality(item, now)
		items = append(items, ControlEvidencePacketEvidenceItem{
			ID:           strings.TrimSpace(item.ID),
			RuleID:       strings.TrimSpace(item.RuleID),
			EvidenceType: strings.TrimSpace(item.EvidenceType),
			Status:       strings.TrimSpace(item.Status),
			Quality:      quality,
			Reason:       reason,
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

func evidenceItemQuality(item ControlEvidenceSignal, now time.Time) (ControlEvidenceQuality, string) {
	if !item.ExpiresAt.IsZero() && !item.ExpiresAt.After(now) {
		return ControlEvidenceQualityStale, "Evidence item has expired."
	}
	if item.Manual {
		return ControlEvidenceQualityManual, "Evidence item was supplied manually and should be reviewed before audit reliance."
	}
	switch strings.ToLower(strings.TrimSpace(item.Status)) {
	case "", "valid", "passing", "pass", "ok", "accepted", "collected", "observed":
		return ControlEvidenceQualityStrong, "Evidence item is collected and usable."
	default:
		return ControlEvidenceQualityPartial, "Evidence item is usable but has a non-standard status."
	}
}

func controlPacketReadiness(control ControlEvidencePacketControl) ControlEvidencePacketReadiness {
	readiness := ControlEvidencePacketReadiness{
		Score:                100,
		Rating:               ControlEvidenceQualityStrong,
		OpenFindings:         len(control.Findings),
		EvidenceItems:        len(control.Evidence.Items),
		RequiredExpectations: requiredExpectationCount(control.Evidence.Expectations),
		MissingEvidence:      len(control.Evidence.Summary.MissingEvidenceIDs),
		StaleEvidence:        len(control.Evidence.Summary.StaleEvidenceIDs),
		ManualEvidence:       len(control.Evidence.Summary.ManualEvidenceIDs),
	}
	switch {
	case readiness.MissingEvidence > 0:
		readiness.Score = 25
		readiness.Rating = ControlEvidenceQualityMissing
		readiness.Summary = "Required evidence is missing; collect the listed expectations before audit review."
	case readiness.StaleEvidence > 0:
		readiness.Score = 55
		readiness.Rating = ControlEvidenceQualityStale
		readiness.Summary = "Evidence exists but is outside the required freshness window."
	case readiness.ManualEvidence > 0 || control.Status == ControlPostureManualReview:
		readiness.Score = 70
		readiness.Rating = ControlEvidenceQualityManual
		readiness.Summary = "Evidence exists but includes manual proof that requires human assessment."
	case readiness.EvidenceItems == 0 && readiness.RequiredExpectations > 0:
		readiness.Score = 25
		readiness.Rating = ControlEvidenceQualityMissing
		readiness.Summary = "No required evidence has been attached to this control."
	default:
		readiness.Summary = "Required evidence is present and fresh for this control."
	}
	if readiness.OpenFindings > 0 && readiness.Score > 40 {
		readiness.Score = 40
		readiness.Rating = ControlEvidenceQualityPartial
		readiness.Summary = "Evidence may be present, but open findings must be remediated before control reliance."
	}
	if control.Status == ControlPostureException && readiness.Score > 50 {
		readiness.Score = 50
		readiness.Rating = ControlEvidenceQualityPartial
		readiness.Summary = "An active exception limits auditor reliance for this control."
	}
	return readiness
}

func requiredExpectationCount(expectations []ControlEvidenceExpectationPosture) int {
	count := 0
	for _, expectation := range expectations {
		if expectation.Required {
			count++
		}
	}
	return count
}

func evidenceHasAcceptedSource(accepted []string, evidence []ControlEvidenceSignal) bool {
	for _, item := range evidence {
		for _, value := range accepted {
			if strings.EqualFold(strings.TrimSpace(item.Source), strings.TrimSpace(value)) {
				return true
			}
		}
	}
	return false
}

func allEvidenceManual(evidence []ControlEvidenceSignal) bool {
	if len(evidence) == 0 {
		return false
	}
	for _, item := range evidence {
		if !item.Manual {
			return false
		}
	}
	return true
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
