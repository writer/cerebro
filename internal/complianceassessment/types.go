package complianceassessment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
)

var (
	ErrInvalidCanonicalValue = errors.New("invalid canonical compliance value")
	ErrInvalidManifest       = errors.New("invalid compliance input manifest")
	ErrInvalidResult         = errors.New("invalid compliance objective result")
)

const (
	CanonicalModelVersion = "compliance-assessment/v1"
	ReasonRegistryVersion = "compliance-reasons/v1"
	LegacyAdapterVersion  = "compliance-legacy-status/v1"
)

type ScopeState string

const (
	ScopeInScope       ScopeState = "in_scope"
	ScopeNotApplicable ScopeState = "not_applicable"
	ScopeUnresolved    ScopeState = "unresolved"
)

type AutomatedOutcome string

const (
	OutcomeSatisfied     AutomatedOutcome = "satisfied"
	OutcomeNotSatisfied  AutomatedOutcome = "not_satisfied"
	OutcomeIndeterminate AutomatedOutcome = "indeterminate"
	OutcomeNotAssessed   AutomatedOutcome = "not_assessed"
)

type DesignState string

const (
	DesignEffective   DesignState = "effective"
	DesignIneffective DesignState = "ineffective"
	DesignUnknown     DesignState = "unknown"
	DesignNotAssessed DesignState = "not_assessed"
)

type OperatingEffectivenessState string

const (
	OperatingEffective   OperatingEffectivenessState = "effective"
	OperatingIneffective OperatingEffectivenessState = "ineffective"
	OperatingUnknown     OperatingEffectivenessState = "unknown"
	OperatingNotTested   OperatingEffectivenessState = "not_tested"
)

type EvidenceState string

const (
	EvidenceSufficient   EvidenceState = "sufficient"
	EvidenceMissing      EvidenceState = "missing"
	EvidenceStale        EvidenceState = "stale"
	EvidenceConflicting  EvidenceState = "conflicting"
	EvidenceUntrusted    EvidenceState = "untrusted"
	EvidenceIncomplete   EvidenceState = "incomplete"
	EvidenceManualReview EvidenceState = "manual_review"
)

type DispositionState string

const (
	DispositionNone              DispositionState = "none"
	DispositionAcceptedException DispositionState = "accepted_exception"
	DispositionAcceptedRisk      DispositionState = "accepted_risk"
	DispositionReviewOverride    DispositionState = "review_override"
)

type Assurance string

const (
	AssuranceHigh   Assurance = "high"
	AssuranceMedium Assurance = "medium"
	AssuranceLow    Assurance = "low"
	AssuranceNone   Assurance = "none"
)

type AuditorState string

const (
	AuditorNotReviewed      AuditorState = "not_reviewed"
	AuditorAccepted         AuditorState = "accepted"
	AuditorChangesRequested AuditorState = "changes_requested"
	AuditorRejected         AuditorState = "rejected"
)

type CoverageState string

const (
	CoverageComplete CoverageState = "complete"
	CoveragePartial  CoverageState = "partial"
	CoverageEmpty    CoverageState = "empty"
	CoverageUnknown  CoverageState = "unknown"
)

type SourceState string

const (
	SourceSupported    SourceState = "supported"
	SourcePartial      SourceState = "partial"
	SourceStale        SourceState = "stale"
	SourceFailed       SourceState = "failed"
	SourceUnconfigured SourceState = "unconfigured"
	SourceUnsupported  SourceState = "unsupported"
	SourceUnverified   SourceState = "unverified"
	SourceConflicting  SourceState = "conflicting"
	SourceUnknown      SourceState = "unknown"
)

type ReasonCode string

const (
	ReasonSatisfied               ReasonCode = "assessment_satisfied"
	ReasonActiveFinding           ReasonCode = "active_finding"
	ReasonEvidenceMissing         ReasonCode = "evidence_missing"
	ReasonEvidenceInvalid         ReasonCode = "evidence_invalid"
	ReasonEvidenceStale           ReasonCode = "evidence_stale"
	ReasonEvidenceConflicting     ReasonCode = "evidence_conflicting"
	ReasonCoverageIncomplete      ReasonCode = "coverage_incomplete"
	ReasonSourceUntrusted         ReasonCode = "source_untrusted"
	ReasonSourceUnknown           ReasonCode = "source_trust_unknown"
	ReasonManualEvidence          ReasonCode = "manual_evidence_review"
	ReasonAcceptedException       ReasonCode = "accepted_exception"
	ReasonAcceptedRisk            ReasonCode = "accepted_risk"
	ReasonNotApplicable           ReasonCode = "not_applicable"
	ReasonInheritedResponsibility ReasonCode = "inherited_responsibility"
	ReasonSampledTesting          ReasonCode = "sampled_testing"
	ReasonSourceUnconfigured      ReasonCode = "source_unconfigured"
	ReasonSourceUnsupported       ReasonCode = "source_unsupported"
	ReasonSourcePartial           ReasonCode = "source_partial"
	ReasonSourceFailed            ReasonCode = "source_failed"
	ReasonSourceStale             ReasonCode = "source_stale"
	ReasonScopeUnresolved         ReasonCode = "scope_unresolved"
	ReasonPopulationEmpty         ReasonCode = "population_empty"
)

type NextAction string

const (
	ActionNone            NextAction = "none"
	ActionReview          NextAction = "review"
	ActionCollectEvidence NextAction = "collect_evidence"
	ActionRefreshEvidence NextAction = "refresh_evidence"
	ActionRestoreSource   NextAction = "restore_source"
	ActionResolveScope    NextAction = "resolve_scope"
	ActionRemediate       NextAction = "remediate"
	ActionRetest          NextAction = "retest"
)

type CollectionCompleteness string

const (
	CollectionComplete          CollectionCompleteness = "complete"
	CollectionPartial           CollectionCompleteness = "partial"
	CollectionTruncated         CollectionCompleteness = "truncated"
	CollectionChangedDuringScan CollectionCompleteness = "changed_during_scan"
	CollectionUnknown           CollectionCompleteness = "unknown"
)

// ManifestRevision pins one semantic input used by an assessment run.
type ManifestRevision struct {
	Kind       string `json:"kind"`
	ID         string `json:"id"`
	RevisionID string `json:"revision_id"`
	Version    uint64 `json:"version"`
	Digest     string `json:"digest"`
}

type CollectionReceipt struct {
	Kind          string                 `json:"kind"`
	RuntimeID     string                 `json:"runtime_id,omitempty"`
	QueryDigest   string                 `json:"query_digest"`
	PageIndex     uint32                 `json:"page_index"`
	Cursor        string                 `json:"cursor,omitempty"`
	NextCursor    string                 `json:"next_cursor,omitempty"`
	RawCount      uint64                 `json:"raw_count"`
	Deduplicated  uint64                 `json:"deduplicated_count"`
	Included      uint64                 `json:"included_count"`
	Excluded      uint64                 `json:"excluded_count"`
	ExpectedTotal *uint64                `json:"expected_total,omitempty"`
	FirstKey      string                 `json:"first_key,omitempty"`
	LastKey       string                 `json:"last_key,omitempty"`
	Watermark     time.Time              `json:"watermark"`
	Cutoff        time.Time              `json:"cutoff"`
	Completeness  CollectionCompleteness `json:"completeness"`
	PageDigest    string                 `json:"page_digest"`
}

// InputManifest pins every revision and collection receipt needed to reproduce
// one automated assessment result.
type InputManifest struct {
	ModelVersion               string              `json:"model_version"`
	ProgramID                  string              `json:"program_id"`
	ScopeRevisionID            string              `json:"scope_revision_id"`
	PlanRevisionID             string              `json:"plan_revision_id"`
	PeriodStart                time.Time           `json:"period_start"`
	PeriodEnd                  time.Time           `json:"period_end"`
	CollectionCutoff           time.Time           `json:"collection_cutoff"`
	RequestedScopeDigest       string              `json:"requested_scope_digest"`
	ResolvedObjectiveSetDigest string              `json:"resolved_objective_set_digest"`
	MappingSetDigest           string              `json:"mapping_set_digest"`
	Revisions                  []ManifestRevision  `json:"revisions"`
	Receipts                   []CollectionReceipt `json:"receipts"`
	EvaluationRunIDs           []string            `json:"evaluation_run_ids,omitempty"`
	ReasonRegistry             string              `json:"reason_registry"`
	AdapterVersion             string              `json:"adapter_version"`
}

type ObjectiveResult struct {
	ID                          string                      `json:"id"`
	ControlRef                  compliance.ControlRef       `json:"control_ref"`
	ObjectiveID                 string                      `json:"objective_id"`
	ScopeState                  ScopeState                  `json:"scope_state"`
	AutomatedOutcome            AutomatedOutcome            `json:"automated_outcome"`
	DesignState                 DesignState                 `json:"design_state"`
	OperatingEffectivenessState OperatingEffectivenessState `json:"operating_effectiveness_state"`
	EvidenceState               EvidenceState               `json:"evidence_state"`
	DispositionState            DispositionState            `json:"disposition_state"`
	Assurance                   Assurance                   `json:"assurance"`
	AuditorState                AuditorState                `json:"auditor_state"`
	ReasonCodes                 []ReasonCode                `json:"reason_codes"`
	NextActions                 []NextAction                `json:"next_actions"`
	EvidenceIDs                 []string                    `json:"evidence_ids,omitempty"`
	FindingIDs                  []string                    `json:"finding_ids,omitempty"`
	SourceRuntimeIDs            []string                    `json:"source_runtime_ids,omitempty"`
	EvaluatorRevision           string                      `json:"evaluator_revision"`
	EvaluatedAt                 time.Time                   `json:"evaluated_at"`
}

func NormalizeManifest(value InputManifest) InputManifest {
	if strings.TrimSpace(value.ModelVersion) == "" {
		value.ModelVersion = CanonicalModelVersion
	}
	if strings.TrimSpace(value.ReasonRegistry) == "" {
		value.ReasonRegistry = ReasonRegistryVersion
	}
	if strings.TrimSpace(value.AdapterVersion) == "" {
		value.AdapterVersion = LegacyAdapterVersion
	}
	value.ModelVersion = strings.TrimSpace(value.ModelVersion)
	value.ProgramID = strings.TrimSpace(value.ProgramID)
	value.ScopeRevisionID = strings.TrimSpace(value.ScopeRevisionID)
	value.PlanRevisionID = strings.TrimSpace(value.PlanRevisionID)
	value.RequestedScopeDigest = strings.TrimSpace(value.RequestedScopeDigest)
	value.ResolvedObjectiveSetDigest = strings.TrimSpace(value.ResolvedObjectiveSetDigest)
	value.MappingSetDigest = strings.TrimSpace(value.MappingSetDigest)
	value.ReasonRegistry = strings.TrimSpace(value.ReasonRegistry)
	value.AdapterVersion = strings.TrimSpace(value.AdapterVersion)
	value.PeriodStart = CanonicalTime(value.PeriodStart)
	value.PeriodEnd = CanonicalTime(value.PeriodEnd)
	value.CollectionCutoff = CanonicalTime(value.CollectionCutoff)
	value.Revisions = append([]ManifestRevision(nil), value.Revisions...)
	for index := range value.Revisions {
		value.Revisions[index].Kind = strings.TrimSpace(value.Revisions[index].Kind)
		value.Revisions[index].ID = strings.TrimSpace(value.Revisions[index].ID)
		value.Revisions[index].RevisionID = strings.TrimSpace(value.Revisions[index].RevisionID)
		value.Revisions[index].Digest = strings.TrimSpace(value.Revisions[index].Digest)
	}
	sort.Slice(value.Revisions, func(i, j int) bool {
		left, right := value.Revisions[i], value.Revisions[j]
		return left.Kind+"\x00"+left.ID+"\x00"+left.RevisionID < right.Kind+"\x00"+right.ID+"\x00"+right.RevisionID
	})
	value.Revisions = deduplicateManifestRevisions(value.Revisions)
	value.Receipts = append([]CollectionReceipt(nil), value.Receipts...)
	for index := range value.Receipts {
		receipt := &value.Receipts[index]
		receipt.Kind = strings.TrimSpace(receipt.Kind)
		receipt.RuntimeID = strings.TrimSpace(receipt.RuntimeID)
		receipt.QueryDigest = strings.TrimSpace(receipt.QueryDigest)
		receipt.Cursor = strings.TrimSpace(receipt.Cursor)
		receipt.NextCursor = strings.TrimSpace(receipt.NextCursor)
		receipt.FirstKey = strings.TrimSpace(receipt.FirstKey)
		receipt.LastKey = strings.TrimSpace(receipt.LastKey)
		receipt.PageDigest = strings.TrimSpace(receipt.PageDigest)
		receipt.Watermark = CanonicalTime(receipt.Watermark)
		receipt.Cutoff = CanonicalTime(receipt.Cutoff)
	}
	sort.Slice(value.Receipts, func(i, j int) bool {
		left, right := value.Receipts[i], value.Receipts[j]
		if left.Kind+"\x00"+left.RuntimeID != right.Kind+"\x00"+right.RuntimeID {
			return left.Kind+"\x00"+left.RuntimeID < right.Kind+"\x00"+right.RuntimeID
		}
		if left.PageIndex != right.PageIndex {
			return left.PageIndex < right.PageIndex
		}
		return left.PageDigest < right.PageDigest
	})
	value.Receipts = deduplicateCollectionReceipts(value.Receipts)
	value.EvaluationRunIDs = normalizedStrings(value.EvaluationRunIDs)
	return value
}

func NormalizeResult(value ObjectiveResult) ObjectiveResult {
	value.ID = strings.TrimSpace(value.ID)
	value.ControlRef = compliance.NormalizeControlRef(value.ControlRef)
	value.ObjectiveID = strings.TrimSpace(value.ObjectiveID)
	value.EvaluatorRevision = strings.TrimSpace(value.EvaluatorRevision)
	value.ReasonCodes = normalizedEnums(value.ReasonCodes)
	value.NextActions = normalizedEnums(value.NextActions)
	value.EvidenceIDs = normalizedStrings(value.EvidenceIDs)
	value.FindingIDs = normalizedStrings(value.FindingIDs)
	value.SourceRuntimeIDs = normalizedStrings(value.SourceRuntimeIDs)
	value.EvaluatedAt = CanonicalTime(value.EvaluatedAt)
	return value
}

func ValidateInputManifest(value InputManifest) error {
	value = NormalizeManifest(value)
	if value.ModelVersion != CanonicalModelVersion {
		return fmt.Errorf("%w: unsupported model_version %q", ErrInvalidManifest, value.ModelVersion)
	}
	if value.ProgramID == "" || value.ScopeRevisionID == "" || value.PlanRevisionID == "" {
		return fmt.Errorf("%w: program, scope revision, and plan revision are required", ErrInvalidManifest)
	}
	if value.PeriodStart.IsZero() || value.PeriodEnd.IsZero() || value.CollectionCutoff.IsZero() || value.PeriodEnd.Before(value.PeriodStart) {
		return fmt.Errorf("%w: valid period and collection cutoff are required", ErrInvalidManifest)
	}
	for _, digest := range []string{value.RequestedScopeDigest, value.ResolvedObjectiveSetDigest, value.MappingSetDigest} {
		if err := compliance.ValidateContentDigest(compliance.ContentDigest(digest)); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidManifest, err)
		}
	}
	if len(value.Revisions) == 0 || len(value.Receipts) == 0 {
		return fmt.Errorf("%w: revisions and collection receipts are required", ErrInvalidManifest)
	}
	for index, revision := range value.Revisions {
		if revision.Kind == "" || revision.ID == "" || revision.RevisionID == "" || revision.Version == 0 {
			return fmt.Errorf("%w: revisions[%d] is incomplete", ErrInvalidManifest, index)
		}
		if err := compliance.ValidateContentDigest(compliance.ContentDigest(revision.Digest)); err != nil {
			return fmt.Errorf("%w: revisions[%d]: %w", ErrInvalidManifest, index, err)
		}
		if index > 0 {
			previous := value.Revisions[index-1]
			if previous.Kind == revision.Kind && previous.ID == revision.ID && previous.RevisionID == revision.RevisionID {
				return fmt.Errorf("%w: conflicting duplicate revision %q", ErrInvalidManifest, revision.RevisionID)
			}
		}
	}
	for index, receipt := range value.Receipts {
		if err := validateCollectionReceipt(receipt); err != nil {
			return fmt.Errorf("%w: receipts[%d]: %w", ErrInvalidManifest, index, err)
		}
		if index > 0 {
			previous := value.Receipts[index-1]
			if previous.Kind == receipt.Kind && previous.RuntimeID == receipt.RuntimeID && previous.PageIndex == receipt.PageIndex {
				return fmt.Errorf("%w: conflicting duplicate collection page %d", ErrInvalidManifest, receipt.PageIndex)
			}
		}
	}
	if err := validateCollectionReceiptChains(value.Receipts); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	return nil
}

func ValidateObjectiveResult(value ObjectiveResult) error {
	value = NormalizeResult(value)
	if value.ID == "" || value.ObjectiveID == "" || strings.TrimSpace(value.ControlRef.ControlID) == "" || value.EvaluatorRevision == "" || value.EvaluatedAt.IsZero() {
		return fmt.Errorf("%w: identity, control, evaluator revision, and evaluated_at are required", ErrInvalidResult)
	}
	if !knownScopeState(value.ScopeState) || !knownOutcome(value.AutomatedOutcome) || !knownDesignState(value.DesignState) ||
		!knownOperatingState(value.OperatingEffectivenessState) || !knownEvidenceState(value.EvidenceState) ||
		!knownDispositionState(value.DispositionState) || !knownAssurance(value.Assurance) || !knownAuditorState(value.AuditorState) {
		return fmt.Errorf("%w: one or more required states are unknown", ErrInvalidResult)
	}
	if len(value.ReasonCodes) == 0 || len(value.NextActions) == 0 {
		return fmt.Errorf("%w: reason_codes and next_actions are required", ErrInvalidResult)
	}
	for _, reason := range value.ReasonCodes {
		if !knownReasonCode(reason) {
			return fmt.Errorf("%w: unknown reason_code %q", ErrInvalidResult, reason)
		}
	}
	for _, action := range value.NextActions {
		if !knownNextAction(action) {
			return fmt.Errorf("%w: unknown next_action %q", ErrInvalidResult, action)
		}
	}
	if value.AutomatedOutcome == OutcomeSatisfied && value.EvidenceState != EvidenceSufficient {
		return fmt.Errorf("%w: satisfied outcome requires sufficient evidence", ErrInvalidResult)
	}
	if value.ScopeState == ScopeNotApplicable && (value.AutomatedOutcome != OutcomeNotAssessed || value.DesignState != DesignNotAssessed || value.OperatingEffectivenessState != OperatingNotTested) {
		return fmt.Errorf("%w: not-applicable scope requires not-assessed axes", ErrInvalidResult)
	}
	return nil
}

// CanonicalTime uses UTC millisecond precision, matching workflow event
// timestamps and preventing event/database round trips from changing hashes.
func CanonicalTime(value time.Time) time.Time {
	return compliance.CanonicalRevisionTime(value)
}

func canonicalBytes(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCanonicalValue, err)
	}
	var decoded any
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCanonicalValue, err)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCanonicalValue, err)
	}
	return canonical, nil
}

func CanonicalManifestBytes(value InputManifest) ([]byte, error) {
	value = NormalizeManifest(value)
	if err := ValidateInputManifest(value); err != nil {
		return nil, err
	}
	return canonicalBytes(value)
}

func CanonicalManifestDigest(value InputManifest) (string, error) {
	data, err := CanonicalManifestBytes(value)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

func CanonicalResultBytes(value ObjectiveResult) ([]byte, error) {
	value = NormalizeResult(value)
	if err := ValidateObjectiveResult(value); err != nil {
		return nil, err
	}
	return canonicalBytes(value)
}

func CanonicalResultDigest(value ObjectiveResult) (string, error) {
	data, err := CanonicalResultBytes(value)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

// CanonicalResultSetDigest hashes one canonical array of normalized results.
// Persisted chunk boundaries do not change the result-set identity.
func CanonicalResultSetDigest(values []ObjectiveResult) (string, error) {
	if len(values) == 0 {
		return "", errors.New("at least one objective result is required")
	}
	values, err := canonicalResultSet(values)
	if err != nil {
		return "", err
	}
	payload, err := canonicalBytes(values)
	if err != nil {
		return "", err
	}
	return digestBytes(payload), nil
}

func canonicalResultSet(values []ObjectiveResult) ([]ObjectiveResult, error) {
	type sortableResult struct {
		value   ObjectiveResult
		key     string
		encoded string
	}
	results := make([]sortableResult, len(values))
	for index := range values {
		value := NormalizeResult(values[index])
		if err := ValidateObjectiveResult(value); err != nil {
			return nil, fmt.Errorf("results[%d]: %w", index, err)
		}
		encoded, err := canonicalBytes(value)
		if err != nil {
			return nil, fmt.Errorf("results[%d]: %w", index, err)
		}
		results[index] = sortableResult{
			value:   value,
			key:     value.ControlRef.FrameworkID + "\x00" + value.ControlRef.ControlID + "\x00" + value.ObjectiveID + "\x00" + value.ID,
			encoded: string(encoded),
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].key != results[j].key {
			return results[i].key < results[j].key
		}
		return results[i].encoded < results[j].encoded
	})
	canonical := make([]ObjectiveResult, len(results))
	for index := range results {
		canonical[index] = results[index].value
	}
	return canonical, nil
}
func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func normalizedStrings(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizedEnums[T ~string](values []T) []T {
	stringsIn := make([]string, 0, len(values))
	for _, value := range values {
		stringsIn = append(stringsIn, string(value))
	}
	normalized := normalizedStrings(stringsIn)
	result := make([]T, 0, len(normalized))
	for _, value := range normalized {
		result = append(result, T(value))
	}
	return result
}

func deduplicateManifestRevisions(values []ManifestRevision) []ManifestRevision {
	result := make([]ManifestRevision, 0, len(values))
	for _, value := range values {
		if len(result) != 0 {
			previous := result[len(result)-1]
			if previous.Kind == value.Kind && previous.ID == value.ID && previous.RevisionID == value.RevisionID && previous.Digest == value.Digest && previous.Version == value.Version {
				continue
			}
		}
		result = append(result, value)
	}
	return result
}

func deduplicateCollectionReceipts(values []CollectionReceipt) []CollectionReceipt {
	result := make([]CollectionReceipt, 0, len(values))
	for _, value := range values {
		if len(result) != 0 {
			previous := result[len(result)-1]
			if previous.Kind == value.Kind && previous.RuntimeID == value.RuntimeID && previous.PageIndex == value.PageIndex && previous.PageDigest == value.PageDigest {
				continue
			}
		}
		result = append(result, value)
	}
	return result
}

func validateCollectionReceipt(receipt CollectionReceipt) error {
	if receipt.Kind == "" || receipt.QueryDigest == "" || receipt.PageDigest == "" || receipt.Cutoff.IsZero() {
		return errors.New("kind, digests, and cutoff are required")
	}
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(receipt.QueryDigest)); err != nil {
		return err
	}
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(receipt.PageDigest)); err != nil {
		return err
	}
	if !knownCompleteness(receipt.Completeness) {
		return fmt.Errorf("unknown completeness %q", receipt.Completeness)
	}
	if receipt.Included > receipt.Deduplicated ||
		receipt.Excluded != receipt.Deduplicated-receipt.Included ||
		receipt.Deduplicated > receipt.RawCount {
		return errors.New("collection counts are inconsistent")
	}
	if receipt.Watermark.IsZero() && !emptyCollectionReceipt(receipt) {
		return errors.New("watermark is required for a non-empty collection")
	}
	return nil
}

func validateCollectionReceiptChains(receipts []CollectionReceipt) error {
	for start := 0; start < len(receipts); {
		end := start + 1
		for end < len(receipts) && receipts[end].Kind == receipts[start].Kind && receipts[end].RuntimeID == receipts[start].RuntimeID {
			end++
		}
		chain := receipts[start:end]
		if chain[0].PageIndex != 0 || chain[0].Cursor != "" {
			return fmt.Errorf("collection %q/%q must begin at page zero without a cursor", chain[0].Kind, chain[0].RuntimeID)
		}
		var collected uint64
		for index, receipt := range chain {
			if receipt.QueryDigest != chain[0].QueryDigest || receipt.Cutoff != chain[0].Cutoff || receipt.Watermark != chain[0].Watermark {
				return fmt.Errorf("collection %q/%q changed query, cutoff, or watermark between pages", receipt.Kind, receipt.RuntimeID)
			}
			if !equalExpectedTotal(receipt.ExpectedTotal, chain[0].ExpectedTotal) {
				return fmt.Errorf("collection %q/%q changed expected total between pages", receipt.Kind, receipt.RuntimeID)
			}
			if collected > math.MaxUint64-receipt.Deduplicated {
				return fmt.Errorf("collection %q/%q record count overflows uint64", receipt.Kind, receipt.RuntimeID)
			}
			collected += receipt.Deduplicated
			if index == 0 {
				continue
			}
			previous := chain[index-1]
			if receipt.PageIndex != previous.PageIndex+1 || previous.NextCursor == "" || receipt.Cursor != previous.NextCursor {
				return fmt.Errorf("collection %q/%q has a missing or disconnected page at index %d", receipt.Kind, receipt.RuntimeID, receipt.PageIndex)
			}
		}
		terminal := chain[len(chain)-1]
		if terminal.NextCursor != "" {
			return fmt.Errorf("collection %q/%q has no terminal page", terminal.Kind, terminal.RuntimeID)
		}
		if terminal.Completeness == CollectionComplete && terminal.ExpectedTotal != nil && collected != *terminal.ExpectedTotal {
			return fmt.Errorf("collection %q/%q completed with %d records; expected %d", terminal.Kind, terminal.RuntimeID, collected, *terminal.ExpectedTotal)
		}
		start = end
	}
	return nil
}

func emptyCollectionReceipt(receipt CollectionReceipt) bool {
	return receipt.PageIndex == 0 && receipt.Cursor == "" && receipt.NextCursor == "" &&
		receipt.RawCount == 0 && receipt.Deduplicated == 0 && receipt.Included == 0 && receipt.Excluded == 0 &&
		receipt.ExpectedTotal != nil && *receipt.ExpectedTotal == 0 && receipt.FirstKey == "" && receipt.LastKey == ""
}

func equalExpectedTotal(left, right *uint64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
