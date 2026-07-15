package complianceassessment

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/sourcecoverage"
)

var ErrInvalidSourceCheck = errors.New("invalid compliance source check")

// SourceSupportState is the declared collection support for one source dimension.
type SourceSupportState string

const (
	SourceSupportSupported    SourceSupportState = "supported"
	SourceSupportPartial      SourceSupportState = "partial"
	SourceSupportUnsupported  SourceSupportState = "unsupported"
	SourceSupportUnconfigured SourceSupportState = "unconfigured"
)

// SourceHealthState is the observed runtime condition at the assessment cutoff.
type SourceHealthState string

const (
	SourceHealthHealthy     SourceHealthState = "healthy"
	SourceHealthStale       SourceHealthState = "stale"
	SourceHealthFailed      SourceHealthState = "failed"
	SourceHealthConflicting SourceHealthState = "conflicting"
	SourceHealthUnknown     SourceHealthState = "unknown"
)

// SourceCheckSnapshot is an immutable assessment-time statement about one source dimension.
// Evidence and receipts remain visible even when health or trust is insufficient.
type SourceCheckSnapshot struct {
	ID                     string                           `json:"id"`
	TenantID               string                           `json:"tenant_id"`
	SourceID               string                           `json:"source_id"`
	RuntimeID              string                           `json:"runtime_id,omitempty"`
	DimensionID            string                           `json:"dimension_id"`
	Support                SourceSupportState               `json:"support"`
	Health                 SourceHealthState                `json:"health"`
	State                  SourceState                      `json:"state"`
	Certification          sourcecoverage.CertificationTier `json:"certification"`
	CertificationReceiptID string                           `json:"certification_receipt_id,omitempty"`
	UnsupportedFields      []string                         `json:"unsupported_fields,omitempty"`
	Watermark              string                           `json:"watermark,omitempty"`
	CollectionReceiptID    string                           `json:"collection_receipt_id,omitempty"`
	CollectionReceiptHash  string                           `json:"collection_receipt_hash,omitempty"`
	LastSuccessfulAt       time.Time                        `json:"last_successful_at,omitempty"`
	FreshUntil             time.Time                        `json:"fresh_until,omitempty"`
	AffectedObjectiveIDs   []string                         `json:"affected_objective_ids"`
	EvidenceIDs            []string                         `json:"evidence_ids,omitempty"`
	ReasonCodes            []ReasonCode                     `json:"reason_codes,omitempty"`
	NextActions            []NextAction                     `json:"next_actions"`
	CheckedAt              time.Time                        `json:"checked_at"`
	SnapshotHash           string                           `json:"snapshot_hash"`
}

// SourceCheckInput contains the bounded runtime and collection facts for a snapshot.
type SourceCheckInput struct {
	TenantID               string
	SourceID               string
	RuntimeID              string
	DimensionID            string
	Support                SourceSupportState
	Health                 SourceHealthState
	Certification          sourcecoverage.CertificationTier
	CertificationReceiptID string
	UnsupportedFields      []string
	Watermark              string
	CollectionReceiptID    string
	CollectionReceiptHash  string
	LastSuccessfulAt       time.Time
	FreshUntil             time.Time
	AffectedObjectiveIDs   []string
	EvidenceIDs            []string
	CheckedAt              time.Time
}

// SourceCheckRequirement is one objective's minimum source and field contract.
type SourceCheckRequirement struct {
	SourceID             string                           `json:"source_id"`
	DimensionID          string                           `json:"dimension_id"`
	MinimumCertification sourcecoverage.CertificationTier `json:"minimum_certification"`
	RequiredFields       []string                         `json:"required_fields,omitempty"`
}

// ObjectiveSourceRequirement groups the source checks required by one objective.
type ObjectiveSourceRequirement struct {
	ObjectiveID string                   `json:"objective_id"`
	Sources     []SourceCheckRequirement `json:"sources,omitempty"`
}

// CertificationGap explains why a visible source could not meet an objective minimum.
type CertificationGap struct {
	SourceID string                           `json:"source_id"`
	Actual   sourcecoverage.CertificationTier `json:"actual"`
	Minimum  sourcecoverage.CertificationTier `json:"minimum"`
}

// ObjectiveSourceAssessment is the source-trust input for one objective result.
type ObjectiveSourceAssessment struct {
	ObjectiveID        string             `json:"objective_id"`
	Affected           bool               `json:"affected"`
	State              SourceState        `json:"state"`
	SourceCheckIDs     []string           `json:"source_check_ids,omitempty"`
	SourceRuntimeIDs   []string           `json:"source_runtime_ids,omitempty"`
	EvidenceIDs        []string           `json:"evidence_ids,omitempty"`
	CollectionReceipts []string           `json:"collection_receipts,omitempty"`
	UnsupportedFields  []string           `json:"unsupported_fields,omitempty"`
	CertificationGaps  []CertificationGap `json:"certification_gaps,omitempty"`
	ReasonCodes        []ReasonCode       `json:"reason_codes,omitempty"`
	NextActions        []NextAction       `json:"next_actions"`
}

// BuildSourceCheckSnapshot validates, normalizes, and hashes an immutable source check.
func BuildSourceCheckSnapshot(input SourceCheckInput) (SourceCheckSnapshot, error) {
	input = normalizeSourceCheckInput(input)
	if input.TenantID == "" || input.SourceID == "" || input.DimensionID == "" || input.CheckedAt.IsZero() {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: tenant, source, dimension, and checked_at are required", ErrInvalidSourceCheck)
	}
	if !knownSourceSupport(input.Support) || !knownSourceHealth(input.Health) {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: support or health state is unknown", ErrInvalidSourceCheck)
	}
	certification, certificationKnown := sourcecoverage.ParseCertificationTier(string(input.Certification))
	if !certificationKnown {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: certification tier %q is unknown", ErrInvalidSourceCheck, input.Certification)
	}
	input.Certification = certification
	if certification != sourcecoverage.CertificationUnknown && input.CertificationReceiptID == "" {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: known certification requires a receipt", ErrInvalidSourceCheck)
	}
	configured := input.Support == SourceSupportSupported || input.Support == SourceSupportPartial
	if configured && input.RuntimeID == "" {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: configured support requires a runtime id", ErrInvalidSourceCheck)
	}
	collected := configured && input.Health != SourceHealthFailed && input.Health != SourceHealthUnknown
	if collected && (input.Watermark == "" || input.CollectionReceiptID == "" || input.CollectionReceiptHash == "") {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: collected source checks require watermark and collection receipt", ErrInvalidSourceCheck)
	}
	if input.CollectionReceiptHash != "" {
		if err := compliance.ValidateContentDigest(compliance.ContentDigest(input.CollectionReceiptHash)); err != nil {
			return SourceCheckSnapshot{}, fmt.Errorf("%w: collection receipt hash: %w", ErrInvalidSourceCheck, err)
		}
	}
	if input.Health == SourceHealthHealthy && (input.LastSuccessfulAt.IsZero() || input.FreshUntil.IsZero()) {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: healthy source checks require freshness bounds", ErrInvalidSourceCheck)
	}
	if !input.LastSuccessfulAt.IsZero() && input.LastSuccessfulAt.After(input.CheckedAt) {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: last success cannot postdate the check", ErrInvalidSourceCheck)
	}
	if !input.FreshUntil.IsZero() && input.FreshUntil.Before(input.LastSuccessfulAt) {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: fresh_until cannot precede the last success", ErrInvalidSourceCheck)
	}
	if len(input.AffectedObjectiveIDs) == 0 {
		return SourceCheckSnapshot{}, fmt.Errorf("%w: affected objectives are required", ErrInvalidSourceCheck)
	}
	state := sourceCheckBaseState(input)
	reasons, actions := sourceStateReasons(state)
	snapshot := SourceCheckSnapshot{
		TenantID:               input.TenantID,
		SourceID:               input.SourceID,
		RuntimeID:              input.RuntimeID,
		DimensionID:            input.DimensionID,
		Support:                input.Support,
		Health:                 input.Health,
		State:                  state,
		Certification:          certification,
		CertificationReceiptID: input.CertificationReceiptID,
		UnsupportedFields:      input.UnsupportedFields,
		Watermark:              input.Watermark,
		CollectionReceiptID:    input.CollectionReceiptID,
		CollectionReceiptHash:  input.CollectionReceiptHash,
		LastSuccessfulAt:       input.LastSuccessfulAt,
		FreshUntil:             input.FreshUntil,
		AffectedObjectiveIDs:   input.AffectedObjectiveIDs,
		EvidenceIDs:            input.EvidenceIDs,
		ReasonCodes:            reasons,
		NextActions:            actions,
		CheckedAt:              input.CheckedAt,
	}
	hash, err := hashSourceCheckValue(snapshot)
	if err != nil {
		return SourceCheckSnapshot{}, err
	}
	snapshot.SnapshotHash = hash
	snapshot.ID = "compliance-source-check-" + strings.TrimPrefix(hash, "sha256:")
	return snapshot, nil
}

// VerifySourceCheckSnapshot rejects altered or manually promoted source trust.
func VerifySourceCheckSnapshot(snapshot SourceCheckSnapshot) error {
	candidate := snapshot
	candidate.ID = ""
	candidate.SnapshotHash = ""
	contentHash, err := hashSourceCheckValue(candidate)
	if err != nil {
		return err
	}
	rebuilt, err := BuildSourceCheckSnapshot(SourceCheckInput{
		TenantID:               snapshot.TenantID,
		SourceID:               snapshot.SourceID,
		RuntimeID:              snapshot.RuntimeID,
		DimensionID:            snapshot.DimensionID,
		Support:                snapshot.Support,
		Health:                 snapshot.Health,
		Certification:          snapshot.Certification,
		CertificationReceiptID: snapshot.CertificationReceiptID,
		UnsupportedFields:      snapshot.UnsupportedFields,
		Watermark:              snapshot.Watermark,
		CollectionReceiptID:    snapshot.CollectionReceiptID,
		CollectionReceiptHash:  snapshot.CollectionReceiptHash,
		LastSuccessfulAt:       snapshot.LastSuccessfulAt,
		FreshUntil:             snapshot.FreshUntil,
		AffectedObjectiveIDs:   snapshot.AffectedObjectiveIDs,
		EvidenceIDs:            snapshot.EvidenceIDs,
		CheckedAt:              snapshot.CheckedAt,
	})
	if err != nil {
		return err
	}
	if snapshot.ID != rebuilt.ID || snapshot.SnapshotHash != rebuilt.SnapshotHash || snapshot.SnapshotHash != contentHash || snapshot.State != rebuilt.State {
		return fmt.Errorf("%w: source check snapshot hash does not match content", ErrInvalidSourceCheck)
	}
	return nil
}

// AssessObjectiveSourceChecks evaluates only the checks required by one objective.
// Unrelated source failures are excluded, while evidence from insufficient checks remains visible.
func AssessObjectiveSourceChecks(requirement ObjectiveSourceRequirement, snapshots []SourceCheckSnapshot) (ObjectiveSourceAssessment, error) {
	requirement.ObjectiveID = strings.TrimSpace(requirement.ObjectiveID)
	if requirement.ObjectiveID == "" {
		return ObjectiveSourceAssessment{}, fmt.Errorf("%w: objective id is required", ErrInvalidSourceCheck)
	}
	assessment := ObjectiveSourceAssessment{
		ObjectiveID: requirement.ObjectiveID,
		Affected:    len(requirement.Sources) != 0,
		State:       SourceSupported,
		NextActions: []NextAction{ActionNone},
	}
	for index, sourceRequirement := range requirement.Sources {
		sourceRequirement = normalizeSourceRequirement(sourceRequirement)
		if sourceRequirement.SourceID == "" || sourceRequirement.DimensionID == "" {
			return ObjectiveSourceAssessment{}, fmt.Errorf("%w: sources[%d] is incomplete", ErrInvalidSourceCheck, index)
		}
		minimum, ok := sourcecoverage.ParseCertificationTier(string(sourceRequirement.MinimumCertification))
		if !ok {
			return ObjectiveSourceAssessment{}, fmt.Errorf("%w: sources[%d] has unknown certification minimum", ErrInvalidSourceCheck, index)
		}
		sourceRequirement.MinimumCertification = minimum
		matches := matchingSourceChecks(requirement.ObjectiveID, sourceRequirement, snapshots)
		if len(matches) == 0 {
			assessment.State = moreLimitingSourceState(assessment.State, SourceUnconfigured)
			assessment.ReasonCodes = append(assessment.ReasonCodes, ReasonSourceUnconfigured)
			assessment.NextActions = append(assessment.NextActions, ActionRestoreSource)
			continue
		}
		for _, snapshot := range matches {
			if err := VerifySourceCheckSnapshot(snapshot); err != nil {
				return ObjectiveSourceAssessment{}, err
			}
			assessment.SourceCheckIDs = append(assessment.SourceCheckIDs, snapshot.ID)
			assessment.SourceRuntimeIDs = append(assessment.SourceRuntimeIDs, snapshot.RuntimeID)
			assessment.EvidenceIDs = append(assessment.EvidenceIDs, snapshot.EvidenceIDs...)
			assessment.CollectionReceipts = append(assessment.CollectionReceipts, snapshot.CollectionReceiptID)
			state := snapshot.State
			unsupported := intersectStrings(sourceRequirement.RequiredFields, snapshot.UnsupportedFields)
			if len(unsupported) != 0 {
				assessment.UnsupportedFields = append(assessment.UnsupportedFields, unsupported...)
				state = moreLimitingSourceState(state, SourcePartial)
				assessment.ReasonCodes = append(assessment.ReasonCodes, ReasonSourcePartial)
				assessment.NextActions = append(assessment.NextActions, ActionRestoreSource)
			}
			if !sourcecoverage.CertificationMeetsMinimum(snapshot.Certification, minimum) {
				gapState := SourceUnverified
				if snapshot.Certification == sourcecoverage.CertificationUnknown {
					gapState = SourceUnknown
				}
				state = moreLimitingSourceState(state, gapState)
				assessment.CertificationGaps = append(assessment.CertificationGaps, CertificationGap{
					SourceID: snapshot.SourceID, Actual: snapshot.Certification, Minimum: minimum,
				})
				reasons, actions := sourceStateReasons(state)
				assessment.ReasonCodes = append(assessment.ReasonCodes, reasons...)
				assessment.NextActions = append(assessment.NextActions, actions...)
			}
			assessment.State = moreLimitingSourceState(assessment.State, state)
			assessment.ReasonCodes = append(assessment.ReasonCodes, snapshot.ReasonCodes...)
			assessment.NextActions = append(assessment.NextActions, snapshot.NextActions...)
		}
	}
	assessment.SourceCheckIDs = normalizedStrings(assessment.SourceCheckIDs)
	assessment.SourceRuntimeIDs = normalizedStrings(assessment.SourceRuntimeIDs)
	assessment.EvidenceIDs = normalizedStrings(assessment.EvidenceIDs)
	assessment.CollectionReceipts = normalizedStrings(assessment.CollectionReceipts)
	assessment.UnsupportedFields = normalizedStrings(assessment.UnsupportedFields)
	assessment.ReasonCodes = normalizedEnums(assessment.ReasonCodes)
	assessment.NextActions = normalizedEnums(assessment.NextActions)
	if assessment.State != SourceSupported {
		assessment.NextActions = withoutNextAction(assessment.NextActions, ActionNone)
	}
	sort.Slice(assessment.CertificationGaps, func(i, j int) bool {
		left, right := assessment.CertificationGaps[i], assessment.CertificationGaps[j]
		return left.SourceID+"\x00"+string(left.Minimum) < right.SourceID+"\x00"+string(right.Minimum)
	})
	return assessment, nil
}

// EvaluateObjectiveWithSourceChecks applies objective-scoped source trust to the
// existing Phase 1 evaluator without hiding source evidence from the caller.
func EvaluateObjectiveWithSourceChecks(input EvaluateInput, requirement ObjectiveSourceRequirement, snapshots []SourceCheckSnapshot) (ObjectiveResult, ObjectiveSourceAssessment, error) {
	assessment, err := AssessObjectiveSourceChecks(requirement, snapshots)
	if err != nil {
		return ObjectiveResult{}, ObjectiveSourceAssessment{}, err
	}
	if strings.TrimSpace(input.ObjectiveID) != strings.TrimSpace(requirement.ObjectiveID) {
		return ObjectiveResult{}, ObjectiveSourceAssessment{}, fmt.Errorf("%w: evaluator and source requirement objective ids differ", ErrInvalidSourceCheck)
	}
	input.SourceState = assessment.State
	input.SourceRuntimeIDs = normalizedStrings(append(input.SourceRuntimeIDs, assessment.SourceRuntimeIDs...))
	result, err := EvaluateObjective(input)
	if err != nil {
		return ObjectiveResult{}, ObjectiveSourceAssessment{}, err
	}
	return result, assessment, nil
}

func normalizeSourceCheckInput(input SourceCheckInput) SourceCheckInput {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.SourceID = strings.TrimSpace(input.SourceID)
	input.RuntimeID = strings.TrimSpace(input.RuntimeID)
	input.DimensionID = strings.TrimSpace(input.DimensionID)
	input.CertificationReceiptID = strings.TrimSpace(input.CertificationReceiptID)
	input.UnsupportedFields = normalizedStrings(input.UnsupportedFields)
	input.Watermark = strings.TrimSpace(input.Watermark)
	input.CollectionReceiptID = strings.TrimSpace(input.CollectionReceiptID)
	input.CollectionReceiptHash = strings.TrimSpace(input.CollectionReceiptHash)
	input.LastSuccessfulAt = CanonicalTime(input.LastSuccessfulAt)
	input.FreshUntil = CanonicalTime(input.FreshUntil)
	input.AffectedObjectiveIDs = normalizedStrings(input.AffectedObjectiveIDs)
	input.EvidenceIDs = normalizedStrings(input.EvidenceIDs)
	input.CheckedAt = CanonicalTime(input.CheckedAt)
	return input
}

func normalizeSourceRequirement(value SourceCheckRequirement) SourceCheckRequirement {
	value.SourceID = strings.TrimSpace(value.SourceID)
	value.DimensionID = strings.TrimSpace(value.DimensionID)
	value.RequiredFields = normalizedStrings(value.RequiredFields)
	return value
}

func sourceCheckBaseState(input SourceCheckInput) SourceState {
	switch input.Support {
	case SourceSupportUnsupported:
		return SourceUnsupported
	case SourceSupportUnconfigured:
		return SourceUnconfigured
	}
	switch input.Health {
	case SourceHealthFailed:
		return SourceFailed
	case SourceHealthConflicting:
		return SourceConflicting
	case SourceHealthStale:
		return SourceStale
	case SourceHealthUnknown:
		return SourceUnknown
	}
	if !input.FreshUntil.IsZero() && input.CheckedAt.After(input.FreshUntil) {
		return SourceStale
	}
	if input.Support == SourceSupportPartial {
		return SourcePartial
	}
	if input.Certification == sourcecoverage.CertificationUnknown {
		return SourceUnknown
	}
	return SourceSupported
}

func matchingSourceChecks(objectiveID string, requirement SourceCheckRequirement, snapshots []SourceCheckSnapshot) []SourceCheckSnapshot {
	result := make([]SourceCheckSnapshot, 0)
	for _, snapshot := range snapshots {
		if snapshot.SourceID != requirement.SourceID || snapshot.DimensionID != requirement.DimensionID || !containsString(snapshot.AffectedObjectiveIDs, objectiveID) {
			continue
		}
		result = append(result, snapshot)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func sourceStateReasons(state SourceState) ([]ReasonCode, []NextAction) {
	switch state {
	case SourcePartial:
		return []ReasonCode{ReasonSourcePartial}, []NextAction{ActionRestoreSource}
	case SourceStale:
		return []ReasonCode{ReasonSourceStale}, []NextAction{ActionRefreshEvidence}
	case SourceFailed:
		return []ReasonCode{ReasonSourceFailed}, []NextAction{ActionRestoreSource}
	case SourceUnconfigured:
		return []ReasonCode{ReasonSourceUnconfigured}, []NextAction{ActionRestoreSource}
	case SourceUnsupported:
		return []ReasonCode{ReasonSourceUnsupported}, []NextAction{ActionRestoreSource}
	case SourceUnverified:
		return []ReasonCode{ReasonSourceUntrusted}, []NextAction{ActionReview}
	case SourceConflicting:
		return []ReasonCode{ReasonEvidenceConflicting}, []NextAction{ActionReview}
	case SourceUnknown:
		return []ReasonCode{ReasonSourceUnknown}, []NextAction{ActionRestoreSource}
	default:
		return nil, []NextAction{ActionNone}
	}
}

func moreLimitingSourceState(left, right SourceState) SourceState {
	if sourceStateLimitRank(right) < sourceStateLimitRank(left) {
		return right
	}
	return left
}

func sourceStateLimitRank(value SourceState) int {
	switch value {
	case SourceConflicting:
		return 0
	case SourceFailed:
		return 1
	case SourceUnsupported:
		return 2
	case SourceUnconfigured:
		return 3
	case SourceStale:
		return 4
	case SourceUnverified:
		return 5
	case SourceUnknown:
		return 6
	case SourcePartial:
		return 7
	case SourceSupported:
		return 8
	default:
		return -1
	}
}

func knownSourceSupport(value SourceSupportState) bool {
	switch value {
	case SourceSupportSupported, SourceSupportPartial, SourceSupportUnsupported, SourceSupportUnconfigured:
		return true
	default:
		return false
	}
}

func knownSourceHealth(value SourceHealthState) bool {
	switch value {
	case SourceHealthHealthy, SourceHealthStale, SourceHealthFailed, SourceHealthConflicting, SourceHealthUnknown:
		return true
	default:
		return false
	}
}

func intersectStrings(required, unsupported []string) []string {
	unsupportedSet := make(map[string]struct{}, len(unsupported))
	for _, value := range unsupported {
		unsupportedSet[value] = struct{}{}
	}
	result := make([]string, 0)
	for _, value := range required {
		if _, ok := unsupportedSet[value]; ok {
			result = append(result, value)
		}
	}
	return normalizedStrings(result)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func withoutNextAction(values []NextAction, excluded NextAction) []NextAction {
	result := make([]NextAction, 0, len(values))
	for _, value := range values {
		if value != excluded {
			result = append(result, value)
		}
	}
	return result
}

func hashSourceCheckValue(value any) (string, error) {
	data, err := canonicalBytes(value)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}
