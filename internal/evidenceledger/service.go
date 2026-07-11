package evidenceledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

var ErrInvalidEvidence = errors.New("invalid evidence ledger request")

type Service struct {
	store ports.EvidenceLedgerStore
	log   ports.AppendLog
	now   func() time.Time
}

func New(store ports.EvidenceLedgerStore, log ports.AppendLog) *Service {
	return &Service{store: store, log: log, now: func() time.Time { return time.Now().UTC() }}
}

type RegisterVersionRequest struct {
	Artifact ports.EvidenceArtifact
	Version  ports.EvidenceVersion
	ActorID  string
}

func (s *Service) RegisterVersion(ctx context.Context, request RegisterVersionRequest) (ports.EvidenceVersion, error) {
	if s == nil || s.store == nil || s.log == nil {
		return ports.EvidenceVersion{}, fmt.Errorf("%w: ledger capability unavailable", ErrInvalidEvidence)
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	artifact := request.Artifact
	version := request.Version
	actorID := strings.TrimSpace(request.ActorID)
	artifact.TenantID = strings.TrimSpace(artifact.TenantID)
	version.TenantID = artifact.TenantID
	if artifact.ID == "" {
		id, err := compliance.NewIdentifier(compliance.IdentifierArtifact)
		if err != nil {
			return ports.EvidenceVersion{}, err
		}
		artifact.ID = id
	}
	if version.ID == "" {
		id, err := compliance.NewRevisionIdentifier(compliance.IdentifierArtifact)
		if err != nil {
			return ports.EvidenceVersion{}, err
		}
		version.ID = id
	}
	version.ArtifactID = artifact.ID
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = now
	}
	if artifact.CreatedBy == "" {
		artifact.CreatedBy = actorID
	}
	version.RecordedAt = now
	if version.ValidFrom.IsZero() {
		version.ValidFrom = version.Provenance.CollectedAt
	}
	version = normalizeVersion(version)
	artifact = normalizeArtifact(artifact)
	if strings.TrimSpace(version.Provenance.SourceProofRevisionID) == "" {
		version.State = ports.EvidenceStateValidationFailed
		version.QuarantineReason = "source_proof_unverified"
	} else if version.State == "" {
		version.State = ports.EvidenceStateCollected
	}
	if version.Revision.Version == 0 {
		version.Revision.Version = 1
	}
	version.Revision.ID = artifact.ID
	version.Revision.RevisionID = version.ID
	version.Revision.LastModified = now
	version.Revision.ContentDigest = ""
	recordDigest, err := semanticDigest(version)
	if err != nil {
		return ports.EvidenceVersion{}, err
	}
	version.Revision.ContentDigest = recordDigest
	if err := validateArtifactVersion(artifact, version, actorID); err != nil {
		return ports.EvidenceVersion{}, err
	}
	payload, err := json.Marshal(struct {
		Artifact ports.EvidenceArtifact `json:"artifact"`
		Version  ports.EvidenceVersion  `json:"version"`
	}{artifact, version})
	if err != nil {
		return ports.EvidenceVersion{}, fmt.Errorf("marshal evidence version event: %w", err)
	}
	aggregateVersion, err := eventAggregateVersion(version.Revision.Version)
	if err != nil {
		return ports.EvidenceVersion{}, err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: workflowevents.EventKindComplianceEvidenceVersionRecorded, TenantID: artifact.TenantID,
		AggregateType: "evidence_artifact", AggregateID: artifact.ID, RevisionID: version.ID,
		AggregateVersion: aggregateVersion, Operation: "version_recorded",
		ContentDigest: recordDigest, PayloadJSON: string(payload), ActorID: actorID, RecordedAt: now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return ports.EvidenceVersion{}, err
	}
	if err := s.log.Append(ctx, event); err != nil {
		return ports.EvidenceVersion{}, fmt.Errorf("append evidence version: %w", err)
	}
	if err := s.store.ApplyEvidenceVersion(ctx, event.GetId(), artifact, version); err != nil {
		return ports.EvidenceVersion{}, fmt.Errorf("project evidence version: %w", err)
	}
	return version, nil
}

type CreateClaimRequest struct {
	Claim   ports.EvidenceClaim
	ActorID string
}

func (s *Service) CreateClaim(ctx context.Context, request CreateClaimRequest) (ports.EvidenceClaim, error) {
	if s == nil || s.store == nil || s.log == nil {
		return ports.EvidenceClaim{}, fmt.Errorf("%w: ledger capability unavailable", ErrInvalidEvidence)
	}
	claim := normalizeClaim(request.Claim)
	actorID := strings.TrimSpace(request.ActorID)
	if claim.ID == "" {
		id, err := compliance.NewIdentifier(compliance.IdentifierClaim)
		if err != nil {
			return ports.EvidenceClaim{}, err
		}
		claim.ID = id
	}
	if claim.Version == 0 {
		claim.Version = 1
	}
	if claim.CreatedAt.IsZero() {
		claim.CreatedAt = s.now().UTC().Truncate(time.Millisecond)
	}
	if claim.CreatedBy == "" {
		claim.CreatedBy = actorID
	}
	if claim.Decision.ReviewState == "" {
		claim.Decision.ReviewState = ports.EvidenceReviewPending
	}
	version, err := s.store.GetEvidenceVersion(ctx, claim.TenantID, claim.ArtifactVersionID)
	if err != nil {
		return ports.EvidenceClaim{}, err
	}
	if err := validateClaimRecord(claim, version, actorID); err != nil {
		return ports.EvidenceClaim{}, err
	}
	return s.appendClaim(ctx, workflowevents.EventKindComplianceEvidenceClaimRecorded, "claim_recorded", claim, 0, actorID)
}

func (s *Service) ReviewClaim(ctx context.Context, tenantID, claimID, reviewerID, state, reason string, expectedVersion uint64) (ports.EvidenceClaim, error) {
	claim, err := s.store.GetEvidenceClaim(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(claimID))
	if err != nil {
		return ports.EvidenceClaim{}, err
	}
	if claim.Version != expectedVersion {
		return ports.EvidenceClaim{}, ports.ErrEvidenceLedgerConflict
	}
	state = strings.TrimSpace(state)
	if state != ports.EvidenceReviewApproved && state != ports.EvidenceReviewRejected {
		return ports.EvidenceClaim{}, fmt.Errorf("%w: review state is invalid", ErrInvalidEvidence)
	}
	if strings.TrimSpace(reviewerID) == "" || strings.TrimSpace(reason) == "" {
		return ports.EvidenceClaim{}, fmt.Errorf("%w: reviewer and reason are required", ErrInvalidEvidence)
	}
	claim.Decision.ReviewState = state
	claim.Decision.ReviewerID = strings.TrimSpace(reviewerID)
	claim.Decision.ReviewReason = strings.TrimSpace(reason)
	claim.Decision.ReviewedAt = s.now().UTC().Truncate(time.Millisecond)
	claim.Version++
	return s.appendClaim(ctx, workflowevents.EventKindComplianceEvidenceClaimReviewed, "claim_reviewed", claim, expectedVersion, reviewerID)
}

func (s *Service) InvalidateClaim(ctx context.Context, tenantID, claimID, actorID, reason string, expectedVersion uint64) (ports.EvidenceClaim, error) {
	claim, err := s.store.GetEvidenceClaim(ctx, strings.TrimSpace(tenantID), strings.TrimSpace(claimID))
	if err != nil {
		return ports.EvidenceClaim{}, err
	}
	if claim.Version != expectedVersion {
		return ports.EvidenceClaim{}, ports.ErrEvidenceLedgerConflict
	}
	if strings.TrimSpace(actorID) == "" || strings.TrimSpace(reason) == "" {
		return ports.EvidenceClaim{}, fmt.Errorf("%w: actor and invalidation reason are required", ErrInvalidEvidence)
	}
	claim.Decision.InvalidatedAt = s.now().UTC().Truncate(time.Millisecond)
	claim.Decision.InvalidationReason = strings.TrimSpace(reason)
	claim.Version++
	return s.appendClaim(ctx, workflowevents.EventKindComplianceEvidenceClaimInvalidated, "claim_invalidated", claim, expectedVersion, actorID)
}

func (s *Service) appendClaim(ctx context.Context, kind, operation string, claim ports.EvidenceClaim, expectedVersion uint64, actorID string) (ports.EvidenceClaim, error) {
	payload, err := json.Marshal(claim)
	if err != nil {
		return ports.EvidenceClaim{}, fmt.Errorf("marshal evidence claim event: %w", err)
	}
	digest, err := semanticDigest(claim)
	if err != nil {
		return ports.EvidenceClaim{}, err
	}
	aggregateVersion, err := eventAggregateVersion(claim.Version)
	if err != nil {
		return ports.EvidenceClaim{}, err
	}
	event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
		Kind: kind, TenantID: claim.TenantID, AggregateType: "evidence_claim", AggregateID: claim.ID,
		RevisionID: fmt.Sprintf("%s-v%d", claim.ID, claim.Version), AggregateVersion: aggregateVersion,
		Operation: operation, ContentDigest: digest, PayloadJSON: string(payload), ActorID: strings.TrimSpace(actorID),
		RecordedAt: s.now().UTC().Truncate(time.Millisecond).Format(time.RFC3339Nano),
	})
	if err != nil {
		return ports.EvidenceClaim{}, err
	}
	if err := s.log.Append(ctx, event); err != nil {
		return ports.EvidenceClaim{}, fmt.Errorf("append evidence claim: %w", err)
	}
	if err := s.store.ApplyEvidenceClaim(ctx, event.GetId(), claim, expectedVersion); err != nil {
		return ports.EvidenceClaim{}, fmt.Errorf("project evidence claim: %w", err)
	}
	return claim, nil
}

func normalizeArtifact(value ports.EvidenceArtifact) ports.EvidenceArtifact {
	value.ID = strings.TrimSpace(value.ID)
	value.TenantID = strings.TrimSpace(value.TenantID)
	value.Title = strings.TrimSpace(value.Title)
	value.Description = strings.TrimSpace(value.Description)
	value.Type = strings.TrimSpace(value.Type)
	value.CreatedBy = strings.TrimSpace(value.CreatedBy)
	value.CreatedAt = value.CreatedAt.UTC().Truncate(time.Millisecond)
	return value
}

func normalizeVersion(value ports.EvidenceVersion) ports.EvidenceVersion {
	value.ID = strings.TrimSpace(value.ID)
	value.TenantID = strings.TrimSpace(value.TenantID)
	value.ArtifactID = strings.TrimSpace(value.ArtifactID)
	value.Content.MediaType = strings.TrimSpace(value.Content.MediaType)
	value.Content.URI = strings.TrimSpace(value.Content.URI)
	value.Content.ContentDigest = strings.TrimSpace(value.Content.ContentDigest)
	value.Provenance.Producer = strings.TrimSpace(value.Provenance.Producer)
	value.Provenance.ProducerVersion = strings.TrimSpace(value.Provenance.ProducerVersion)
	value.Provenance.SourceRuntimeID = strings.TrimSpace(value.Provenance.SourceRuntimeID)
	value.Provenance.SourceEventID = strings.TrimSpace(value.Provenance.SourceEventID)
	value.Provenance.SourceProofRevisionID = strings.TrimSpace(value.Provenance.SourceProofRevisionID)
	value.Governance.Sensitivity = strings.TrimSpace(value.Governance.Sensitivity)
	value.Governance.AccessPolicy = strings.TrimSpace(value.Governance.AccessPolicy)
	value.Governance.RedactionState = strings.TrimSpace(value.Governance.RedactionState)
	value.Governance.ParserQuality = strings.TrimSpace(value.Governance.ParserQuality)
	value.State = strings.TrimSpace(value.State)
	value.QuarantineReason = strings.TrimSpace(value.QuarantineReason)
	value.PredecessorID = strings.TrimSpace(value.PredecessorID)
	value.Provenance.CollectedAt = value.Provenance.CollectedAt.UTC().Truncate(time.Millisecond)
	value.Provenance.PeriodStart = value.Provenance.PeriodStart.UTC().Truncate(time.Millisecond)
	value.Provenance.PeriodEnd = value.Provenance.PeriodEnd.UTC().Truncate(time.Millisecond)
	value.ValidFrom = value.ValidFrom.UTC().Truncate(time.Millisecond)
	value.ValidUntil = value.ValidUntil.UTC().Truncate(time.Millisecond)
	value.Governance.RetentionUntil = value.Governance.RetentionUntil.UTC().Truncate(time.Millisecond)
	value.RecordedAt = value.RecordedAt.UTC().Truncate(time.Millisecond)
	value.Subjects = normalizeSubjects(value.Subjects)
	value.Provenance.DerivationIDs = normalizedStrings(value.Provenance.DerivationIDs)
	return value
}

func normalizeClaim(value ports.EvidenceClaim) ports.EvidenceClaim {
	value.ID = strings.TrimSpace(value.ID)
	value.TenantID = strings.TrimSpace(value.TenantID)
	value.ArtifactVersionID = strings.TrimSpace(value.ArtifactVersionID)
	value.Scope.ObjectiveID = strings.TrimSpace(value.Scope.ObjectiveID)
	value.Scope.ImplementationRevisionID = strings.TrimSpace(value.Scope.ImplementationRevisionID)
	value.Scope.RequirementID = strings.TrimSpace(value.Scope.RequirementID)
	value.Linkage = strings.TrimSpace(value.Linkage)
	value.Strength = strings.TrimSpace(value.Strength)
	value.Limitation = strings.TrimSpace(value.Limitation)
	value.MappingRationale = strings.TrimSpace(value.MappingRationale)
	value.Decision.ReviewState = strings.TrimSpace(value.Decision.ReviewState)
	value.Scope.Subjects = normalizeSubjects(value.Scope.Subjects)
	value.Scope.PeriodStart = value.Scope.PeriodStart.UTC().Truncate(time.Millisecond)
	value.Scope.PeriodEnd = value.Scope.PeriodEnd.UTC().Truncate(time.Millisecond)
	return value
}

func normalizeSubjects(values []ports.EvidenceSubjectRef) []ports.EvidenceSubjectRef {
	values = append([]ports.EvidenceSubjectRef(nil), values...)
	for index := range values {
		values[index].Type = strings.TrimSpace(values[index].Type)
		values[index].ID = strings.TrimSpace(values[index].ID)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Type+"\x00"+values[i].ID < values[j].Type+"\x00"+values[j].ID })
	result := values[:0]
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}

func normalizedStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func semanticDigest(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal evidence semantic content: %w", err)
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func eventAggregateVersion(value uint64) (int64, error) {
	if value == 0 || value > math.MaxInt64 {
		return 0, fmt.Errorf("%w: aggregate version is out of range", ErrInvalidEvidence)
	}
	return int64(value), nil
}

func validateArtifactVersion(artifact ports.EvidenceArtifact, version ports.EvidenceVersion, actorID string) error {
	if artifact.ID == "" || artifact.TenantID == "" || artifact.Title == "" || artifact.Type == "" || actorID == "" {
		return fmt.Errorf("%w: artifact identity, tenant, title, type, and actor are required", ErrInvalidEvidence)
	}
	if err := compliance.ValidateIdentifier(compliance.IdentifierArtifact, artifact.ID); err != nil {
		return err
	}
	if err := compliance.ValidateRevisionIdentifier(compliance.IdentifierArtifact, version.ID); err != nil {
		return err
	}
	if err := compliance.ValidateContentDigest(compliance.ContentDigest(version.Content.ContentDigest)); err != nil {
		return err
	}
	if version.Content.MediaType == "" || version.Content.URI == "" || version.Provenance.Producer == "" || version.Provenance.CollectedAt.IsZero() || version.ValidFrom.IsZero() || len(version.Subjects) == 0 || version.Governance.AccessPolicy == "" {
		return fmt.Errorf("%w: version metadata is incomplete", ErrInvalidEvidence)
	}
	parsed, err := url.Parse(version.Content.URI)
	if err != nil || parsed.Scheme == "" || parsed.Scheme == "file" || parsed.Scheme == "data" {
		return fmt.Errorf("%w: evidence URI must be an approved immutable reference", ErrInvalidEvidence)
	}
	for _, subject := range version.Subjects {
		if strings.TrimSpace(subject.Type) == "" || strings.TrimSpace(subject.ID) == "" {
			return fmt.Errorf("%w: evidence subject type and id are required", ErrInvalidEvidence)
		}
	}
	if version.Revision.ID == "" || version.Revision.RevisionID == "" || version.Revision.Version == 0 || version.Revision.LastModified.IsZero() {
		return fmt.Errorf("%w: evidence revision metadata is incomplete", ErrInvalidEvidence)
	}
	return compliance.ValidateContentDigest(compliance.ContentDigest(version.Revision.ContentDigest))
}

func validateClaimRecord(claim ports.EvidenceClaim, version ports.EvidenceVersion, actorID string) error {
	if claim.TenantID == "" || claim.ArtifactVersionID == "" || claim.Scope.ObjectiveID == "" || claim.Scope.ImplementationRevisionID == "" || claim.Scope.RequirementID == "" || actorID == "" {
		return fmt.Errorf("%w: claim identity, scope, requirement, and actor are required", ErrInvalidEvidence)
	}
	if version.TenantID != claim.TenantID {
		return ports.ErrEvidenceVersionNotFound
	}
	if claim.Linkage != ports.EvidenceLinkDirect && claim.Linkage != ports.EvidenceLinkInherited && claim.Linkage != ports.EvidenceLinkInferred {
		return fmt.Errorf("%w: claim linkage is invalid", ErrInvalidEvidence)
	}
	if claim.Strength == "" || claim.MappingRationale == "" || claim.Scope.PeriodStart.IsZero() || claim.Scope.PeriodEnd.IsZero() || claim.Scope.PeriodEnd.Before(claim.Scope.PeriodStart) || len(claim.Scope.Subjects) == 0 {
		return fmt.Errorf("%w: claim basis is incomplete", ErrInvalidEvidence)
	}
	return nil
}
