package evidenceledger

import (
	"context"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

const (
	reasonApproved           = "evidence_claim_approved"
	reasonClaimPending       = "evidence_claim_pending"
	reasonClaimRejected      = "evidence_claim_rejected"
	reasonClaimInvalidated   = "evidence_claim_invalidated"
	reasonVersionQuarantined = "evidence_version_quarantined"
	reasonVersionRevoked     = "evidence_version_revoked"
	reasonVersionExpired     = "evidence_version_expired"
	reasonPeriodGap          = "evidence_period_gap"
	reasonSubjectMismatch    = "evidence_subject_mismatch"
)

type ValidateClaimRequest struct {
	TenantID    string
	ClaimID     string
	Subjects    []ports.EvidenceSubjectRef
	PeriodStart time.Time
	PeriodEnd   time.Time
	At          time.Time
}

func (s *Service) ValidateClaim(ctx context.Context, request ValidateClaimRequest) (ports.EvidenceClaimValidation, error) {
	claim, err := s.store.GetEvidenceClaim(ctx, strings.TrimSpace(request.TenantID), strings.TrimSpace(request.ClaimID))
	if err != nil {
		return ports.EvidenceClaimValidation{}, err
	}
	version, err := s.store.GetEvidenceVersion(ctx, claim.TenantID, claim.ArtifactVersionID)
	if err != nil {
		return ports.EvidenceClaimValidation{}, err
	}
	result := ports.EvidenceClaimValidation{Valid: true, ReasonCodes: []string{reasonApproved}, NextActions: []string{"none"}}
	addInvalid := func(reason, action string) {
		if result.Valid {
			result.ReasonCodes = nil
			result.NextActions = nil
		}
		result.Valid = false
		result.ReasonCodes = append(result.ReasonCodes, reason)
		result.NextActions = append(result.NextActions, action)
	}
	if !claim.Decision.InvalidatedAt.IsZero() {
		addInvalid(reasonClaimInvalidated, "replace_claim")
	}
	switch claim.Decision.ReviewState {
	case ports.EvidenceReviewApproved:
	case ports.EvidenceReviewRejected:
		addInvalid(reasonClaimRejected, "replace_claim")
	default:
		addInvalid(reasonClaimPending, "review")
	}
	if version.State == ports.EvidenceStateValidationFailed || strings.TrimSpace(version.QuarantineReason) != "" {
		addInvalid(reasonVersionQuarantined, "repair_source")
	}
	if version.State == ports.EvidenceStateRevoked || version.State == ports.EvidenceStateSuperseded {
		addInvalid(reasonVersionRevoked, "collect_evidence")
	}
	at := request.At.UTC()
	if at.IsZero() {
		at = s.now().UTC()
	}
	if !version.ValidUntil.IsZero() && !at.Before(version.ValidUntil) {
		addInvalid(reasonVersionExpired, "refresh_evidence")
	}
	if request.PeriodStart.Before(claim.Scope.PeriodStart) || request.PeriodEnd.After(claim.Scope.PeriodEnd) {
		addInvalid(reasonPeriodGap, "collect_evidence")
	}
	if !version.Provenance.PeriodStart.IsZero() && !version.Provenance.PeriodEnd.IsZero() &&
		(request.PeriodStart.Before(version.Provenance.PeriodStart) || request.PeriodEnd.After(version.Provenance.PeriodEnd)) {
		addInvalid(reasonPeriodGap, "collect_evidence")
	}
	if !subjectsCover(claim.Scope.Subjects, normalizeSubjects(request.Subjects)) || !subjectsCover(version.Subjects, normalizeSubjects(request.Subjects)) {
		addInvalid(reasonSubjectMismatch, "collect_evidence")
	}
	result.ReasonCodes = normalizedStrings(result.ReasonCodes)
	result.NextActions = normalizedStrings(result.NextActions)
	return result, nil
}

func (s *Service) ReadVersion(ctx context.Context, access ports.EvidenceAccessRequest, versionID string) (ports.EvidenceVersion, error) {
	version, err := s.store.GetEvidenceVersion(ctx, strings.TrimSpace(access.TenantID), strings.TrimSpace(versionID))
	if err != nil {
		return ports.EvidenceVersion{}, err
	}
	maximumRank, maximumOK := sensitivityRank(access.MaximumSensitivity)
	versionRank, versionOK := sensitivityRank(version.Governance.Sensitivity)
	if strings.TrimSpace(access.ActorID) == "" || !allowedPurpose(access.Purpose) || !maximumOK || !versionOK || maximumRank < versionRank {
		return ports.EvidenceVersion{}, ports.ErrEvidenceAccessDenied
	}
	return version, nil
}

// ReuseClaim creates a separate scoped claim over the same immutable version.
// It never copies approval or invalidation state from the source claim.
func (s *Service) ReuseClaim(ctx context.Context, sourceTenantID, sourceClaimID, actorID string, replacement ports.EvidenceClaim) (ports.EvidenceClaim, error) {
	source, err := s.store.GetEvidenceClaim(ctx, strings.TrimSpace(sourceTenantID), strings.TrimSpace(sourceClaimID))
	if err != nil {
		return ports.EvidenceClaim{}, err
	}
	replacement.ID = ""
	replacement.TenantID = source.TenantID
	replacement.ArtifactVersionID = source.ArtifactVersionID
	replacement.Decision = ports.EvidenceClaimDecision{ReviewState: ports.EvidenceReviewPending}
	replacement.Version = 1
	return s.CreateClaim(ctx, CreateClaimRequest{Claim: replacement, ActorID: actorID})
}

func subjectsCover(available, required []ports.EvidenceSubjectRef) bool {
	set := make(map[ports.EvidenceSubjectRef]struct{}, len(available))
	for _, subject := range available {
		set[subject] = struct{}{}
	}
	for _, subject := range required {
		if _, ok := set[subject]; !ok {
			return false
		}
	}
	return true
}

func allowedPurpose(value string) bool {
	switch strings.TrimSpace(value) {
	case "assessment", "review", "audit", "export":
		return true
	default:
		return false
	}
}

func sensitivityRank(value string) (int, bool) {
	switch strings.TrimSpace(value) {
	case ports.EvidenceSensitivityPublic:
		return 1, true
	case ports.EvidenceSensitivityInternal:
		return 2, true
	case ports.EvidenceSensitivityConfidential:
		return 3, true
	case ports.EvidenceSensitivityRestricted:
		return 4, true
	default:
		return 0, false
	}
}
