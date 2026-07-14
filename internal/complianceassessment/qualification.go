package complianceassessment

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/observability"
)

var (
	ErrDecisionNotQualified = errors.New("assurance decision is not qualified")
	ErrCanaryProductionUse  = errors.New("assurance canary cannot be used for production")
)

const QualifiedDecisionVersion = "qualified-decision/v1"

type QualificationReason string

const (
	QualificationManifestInvalid       QualificationReason = "manifest_invalid"
	QualificationScopeUnpinned         QualificationReason = "scope_unpinned"
	QualificationPopulationIncomplete  QualificationReason = "population_incomplete"
	QualificationResultInvalid         QualificationReason = "result_invalid"
	QualificationSourceProofMissing    QualificationReason = "source_proof_missing"
	QualificationSourceUnhealthy       QualificationReason = "source_unhealthy"
	QualificationSourceStale           QualificationReason = "source_stale"
	QualificationEvidenceProofMissing  QualificationReason = "evidence_proof_missing"
	QualificationEvidenceNotCurrent    QualificationReason = "evidence_not_current"
	QualificationEvidenceConflicting   QualificationReason = "evidence_conflicting"
	QualificationLimitationsUndeclared QualificationReason = "limitations_not_declared"
	QualificationBlockingLimitation    QualificationReason = "blocking_limitation"
	QualificationReviewsUndeclared     QualificationReason = "review_requirements_not_declared"
	QualificationReviewIncomplete      QualificationReason = "review_incomplete"
	QualificationExceptionExpired      QualificationReason = "exception_expired"
	QualificationVerificationFailed    QualificationReason = "verification_failed"
)

type SourceProof struct {
	RuntimeID  string      `json:"runtime_id"`
	State      SourceState `json:"state"`
	ObservedAt time.Time   `json:"observed_at"`
	FreshUntil time.Time   `json:"fresh_until"`
}

type EvidenceProof struct {
	EvidenceID  string        `json:"evidence_id"`
	State       EvidenceState `json:"state"`
	CollectedAt time.Time     `json:"collected_at"`
	ValidUntil  time.Time     `json:"valid_until"`
}

type Limitation struct {
	Code     string `json:"code"`
	Detail   string `json:"detail"`
	Blocking bool   `json:"blocking"`
}

type ReviewStatus string

const (
	ReviewPending  ReviewStatus = "pending"
	ReviewApproved ReviewStatus = "approved"
	ReviewRejected ReviewStatus = "rejected"
)

type ReviewRequirement struct {
	Kind        string       `json:"kind"`
	Required    bool         `json:"required"`
	Status      ReviewStatus `json:"status"`
	CompletedAt time.Time    `json:"completed_at,omitempty"`
	ValidUntil  time.Time    `json:"valid_until,omitempty"`
}

type ExceptionProof struct {
	ExceptionID string    `json:"exception_id"`
	Active      bool      `json:"active"`
	ValidUntil  time.Time `json:"valid_until"`
}

type VerificationState string

const (
	VerificationNotRequired VerificationState = "not_required"
	VerificationPending     VerificationState = "pending"
	VerificationPassed      VerificationState = "passed"
	VerificationFailed      VerificationState = "failed"
)

type VerificationProof struct {
	Required   bool              `json:"required"`
	State      VerificationState `json:"state"`
	VerifiedAt time.Time         `json:"verified_at,omitempty"`
	ValidUntil time.Time         `json:"valid_until,omitempty"`
}

type QualificationInput struct {
	Manifest        InputManifest       `json:"input_manifest"`
	Result          ObjectiveResult     `json:"result"`
	AsOf            time.Time           `json:"as_of"`
	SourceProofs    []SourceProof       `json:"source_proofs"`
	EvidenceProofs  []EvidenceProof     `json:"evidence_proofs"`
	Limitations     []Limitation        `json:"limitations"`
	RequiredReviews []ReviewRequirement `json:"required_reviews"`
	Exceptions      []ExceptionProof    `json:"exceptions,omitempty"`
	Verification    VerificationProof   `json:"verification"`
}

// QualifiedDecision binds a decision to the exact assessment inputs and result.
// Qualification is fail closed: callers must use AuthorizeProductionUse before
// placing a decision in an audit packet or using it to authorize an action.
type QualifiedDecision struct {
	Version         string                `json:"version"`
	Qualified       bool                  `json:"qualified"`
	ManifestHash    string                `json:"manifest_hash,omitempty"`
	ResultHash      string                `json:"result_hash,omitempty"`
	ProofDigest     string                `json:"proof_digest,omitempty"`
	AsOf            time.Time             `json:"as_of"`
	Reasons         []QualificationReason `json:"reasons,omitempty"`
	Limitations     []Limitation          `json:"limitations"`
	RequiredReviews []ReviewRequirement   `json:"required_reviews"`
	DecisionDigest  string                `json:"decision_digest"`
}

func (decision QualifiedDecision) AuthorizeProductionUse() error {
	if !decision.Qualified || len(decision.Reasons) != 0 || strings.TrimSpace(decision.ProofDigest) == "" || strings.TrimSpace(decision.DecisionDigest) == "" {
		return ErrDecisionNotQualified
	}
	return nil
}

// QualifyDecision evaluates the evidence boundary for one assessment result.
// It records every rejected gate as a reason instead of collapsing incomplete
// evidence into a successful result.
func QualifyDecision(ctx context.Context, input QualificationInput) QualifiedDecision {
	decision := evaluateQualification(input)
	status := "unqualified"
	if decision.Qualified {
		status = "qualified"
	}
	observability.Default.Inc("cerebro_assurance_decisions_total", map[string]string{"status": status})
	if NormalizeResult(input.Result).ScopeState == ScopeInScope {
		observability.Default.Inc("cerebro_assurance_qualified_coverage_total", map[string]string{"measure": "applicable"})
		if decision.Qualified {
			observability.Default.Inc("cerebro_assurance_qualified_coverage_total", map[string]string{"measure": "qualified"})
		}
	}
	_ = ctx
	return decision
}

func evaluateQualification(input QualificationInput) QualifiedDecision {
	input.AsOf = CanonicalTime(input.AsOf)
	decision := QualifiedDecision{
		Version:         QualifiedDecisionVersion,
		AsOf:            input.AsOf,
		Limitations:     normalizeLimitations(input.Limitations),
		RequiredReviews: normalizeReviews(input.RequiredReviews),
	}
	addReason := func(reason QualificationReason) {
		decision.Reasons = append(decision.Reasons, reason)
	}

	manifest := NormalizeManifest(input.Manifest)
	if err := ValidateInputManifest(manifest); err != nil {
		addReason(QualificationManifestInvalid)
	} else {
		decision.ManifestHash, _ = CanonicalManifestDigest(manifest)
		if manifest.ScopeRevisionID == "" || manifest.RequestedScopeDigest == "" || manifest.ResolvedObjectiveSetDigest == "" {
			addReason(QualificationScopeUnpinned)
		}
		for _, receipt := range manifest.Receipts {
			if receipt.Completeness != CollectionComplete {
				addReason(QualificationPopulationIncomplete)
				break
			}
		}
	}

	result := NormalizeResult(input.Result)
	if err := ValidateObjectiveResult(result); err != nil {
		addReason(QualificationResultInvalid)
	} else {
		decision.ResultHash, _ = CanonicalResultDigest(result)
		if result.ScopeState == ScopeUnresolved || result.EvidenceState == EvidenceIncomplete || result.EvidenceState == EvidenceMissing {
			addReason(QualificationPopulationIncomplete)
		}
		if result.EvidenceState == EvidenceConflicting {
			addReason(QualificationEvidenceConflicting)
		}
		if result.EvidenceState != EvidenceSufficient {
			addReason(QualificationEvidenceNotCurrent)
		}
	}

	if input.AsOf.IsZero() {
		addReason(QualificationEvidenceNotCurrent)
	}
	checkSourceProofs(input, manifest, result, addReason)
	checkEvidenceProofs(input, result, addReason)
	if input.Limitations == nil {
		addReason(QualificationLimitationsUndeclared)
	}
	for _, limitation := range input.Limitations {
		if limitation.Blocking || strings.TrimSpace(limitation.Code) == "" || strings.TrimSpace(limitation.Detail) == "" {
			addReason(QualificationBlockingLimitation)
		}
	}
	if input.RequiredReviews == nil {
		addReason(QualificationReviewsUndeclared)
	}
	for _, review := range input.RequiredReviews {
		if !review.Required {
			continue
		}
		if review.Status != ReviewApproved || review.CompletedAt.IsZero() || review.CompletedAt.After(input.AsOf) || (!review.ValidUntil.IsZero() && review.ValidUntil.Before(input.AsOf)) {
			addReason(QualificationReviewIncomplete)
		}
	}
	for _, exception := range input.Exceptions {
		if exception.Active && (exception.ValidUntil.IsZero() || exception.ValidUntil.Before(input.AsOf)) {
			addReason(QualificationExceptionExpired)
		}
	}
	if input.Verification.Required && (input.Verification.State != VerificationPassed || input.Verification.VerifiedAt.IsZero() || input.Verification.VerifiedAt.After(input.AsOf) || (!input.Verification.ValidUntil.IsZero() && input.Verification.ValidUntil.Before(input.AsOf))) {
		addReason(QualificationVerificationFailed)
	}
	decision.ProofDigest = qualificationProofDigest(input)

	decision.Reasons = normalizeQualificationReasons(decision.Reasons)
	decision.Qualified = len(decision.Reasons) == 0
	digestInput := struct {
		Version         string                `json:"version"`
		Qualified       bool                  `json:"qualified"`
		ManifestHash    string                `json:"manifest_hash"`
		ResultHash      string                `json:"result_hash"`
		ProofDigest     string                `json:"proof_digest"`
		AsOf            time.Time             `json:"as_of"`
		Reasons         []QualificationReason `json:"reasons"`
		Limitations     []Limitation          `json:"limitations"`
		RequiredReviews []ReviewRequirement   `json:"required_reviews"`
	}{decision.Version, decision.Qualified, decision.ManifestHash, decision.ResultHash, decision.ProofDigest, decision.AsOf, decision.Reasons, decision.Limitations, decision.RequiredReviews}
	if data, err := canonicalBytes(digestInput); err == nil {
		decision.DecisionDigest = digestBytes(data)
	}
	return decision
}

func checkSourceProofs(input QualificationInput, manifest InputManifest, result ObjectiveResult, addReason func(QualificationReason)) {
	proofs := make(map[string]SourceProof, len(input.SourceProofs))
	for _, proof := range input.SourceProofs {
		proof.RuntimeID = strings.TrimSpace(proof.RuntimeID)
		proof.ObservedAt = CanonicalTime(proof.ObservedAt)
		proof.FreshUntil = CanonicalTime(proof.FreshUntil)
		proofs[proof.RuntimeID] = proof
	}
	required := append([]string(nil), result.SourceRuntimeIDs...)
	for _, receipt := range manifest.Receipts {
		if receipt.RuntimeID != "" {
			required = append(required, receipt.RuntimeID)
		}
	}
	for _, runtimeID := range normalizedStrings(required) {
		proof, ok := proofs[runtimeID]
		if !ok {
			addReason(QualificationSourceProofMissing)
			continue
		}
		if proof.State != SourceSupported {
			addReason(QualificationSourceUnhealthy)
		}
		if proof.ObservedAt.IsZero() || proof.ObservedAt.After(input.AsOf) || proof.FreshUntil.Before(input.AsOf) {
			addReason(QualificationSourceStale)
		}
	}
}

func checkEvidenceProofs(input QualificationInput, result ObjectiveResult, addReason func(QualificationReason)) {
	proofs := make(map[string]EvidenceProof, len(input.EvidenceProofs))
	for _, proof := range input.EvidenceProofs {
		proof.EvidenceID = strings.TrimSpace(proof.EvidenceID)
		proof.CollectedAt = CanonicalTime(proof.CollectedAt)
		proof.ValidUntil = CanonicalTime(proof.ValidUntil)
		proofs[proof.EvidenceID] = proof
	}
	if len(result.EvidenceIDs) == 0 {
		addReason(QualificationEvidenceProofMissing)
	}
	for _, evidenceID := range result.EvidenceIDs {
		proof, ok := proofs[evidenceID]
		if !ok {
			addReason(QualificationEvidenceProofMissing)
			continue
		}
		if proof.State == EvidenceConflicting {
			addReason(QualificationEvidenceConflicting)
		}
		if proof.State != EvidenceSufficient || proof.CollectedAt.IsZero() || proof.CollectedAt.After(input.AsOf) || proof.ValidUntil.Before(input.AsOf) {
			addReason(QualificationEvidenceNotCurrent)
		}
	}
}

func normalizeQualificationReasons(values []QualificationReason) []QualificationReason {
	values = normalizedEnums(values)
	return values
}

func normalizeLimitations(values []Limitation) []Limitation {
	if values == nil {
		return nil
	}
	result := append([]Limitation(nil), values...)
	for index := range result {
		result[index].Code = strings.TrimSpace(result[index].Code)
		result[index].Detail = strings.TrimSpace(result[index].Detail)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Code+"\x00"+result[i].Detail < result[j].Code+"\x00"+result[j].Detail
	})
	return result
}

func normalizeReviews(values []ReviewRequirement) []ReviewRequirement {
	if values == nil {
		return nil
	}
	result := append([]ReviewRequirement(nil), values...)
	for index := range result {
		result[index].Kind = strings.TrimSpace(result[index].Kind)
		result[index].CompletedAt = CanonicalTime(result[index].CompletedAt)
		result[index].ValidUntil = CanonicalTime(result[index].ValidUntil)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Kind < result[j].Kind })
	return result
}

func qualificationProofDigest(input QualificationInput) string {
	sources := append([]SourceProof(nil), input.SourceProofs...)
	for index := range sources {
		sources[index].RuntimeID = strings.TrimSpace(sources[index].RuntimeID)
		sources[index].ObservedAt = CanonicalTime(sources[index].ObservedAt)
		sources[index].FreshUntil = CanonicalTime(sources[index].FreshUntil)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].RuntimeID < sources[j].RuntimeID })
	evidence := append([]EvidenceProof(nil), input.EvidenceProofs...)
	for index := range evidence {
		evidence[index].EvidenceID = strings.TrimSpace(evidence[index].EvidenceID)
		evidence[index].CollectedAt = CanonicalTime(evidence[index].CollectedAt)
		evidence[index].ValidUntil = CanonicalTime(evidence[index].ValidUntil)
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].EvidenceID < evidence[j].EvidenceID })
	exceptions := append([]ExceptionProof(nil), input.Exceptions...)
	for index := range exceptions {
		exceptions[index].ExceptionID = strings.TrimSpace(exceptions[index].ExceptionID)
		exceptions[index].ValidUntil = CanonicalTime(exceptions[index].ValidUntil)
	}
	sort.Slice(exceptions, func(i, j int) bool { return exceptions[i].ExceptionID < exceptions[j].ExceptionID })
	verification := input.Verification
	verification.VerifiedAt = CanonicalTime(verification.VerifiedAt)
	verification.ValidUntil = CanonicalTime(verification.ValidUntil)
	data, err := canonicalBytes(struct {
		Sources      []SourceProof     `json:"source_proofs"`
		Evidence     []EvidenceProof   `json:"evidence_proofs"`
		Exceptions   []ExceptionProof  `json:"exceptions"`
		Verification VerificationProof `json:"verification"`
	}{sources, evidence, exceptions, verification})
	if err != nil {
		return ""
	}
	return digestBytes(data)
}

func (reason QualificationReason) String() string { return string(reason) }

func (decision QualifiedDecision) String() string {
	return fmt.Sprintf("qualified=%t manifest=%s result=%s", decision.Qualified, decision.ManifestHash, decision.ResultHash)
}
