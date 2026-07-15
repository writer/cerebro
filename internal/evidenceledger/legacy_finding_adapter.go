package evidenceledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/ports"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

var ErrInvalidLegacyEvidenceBinding = errors.New("invalid legacy finding evidence binding")

// LegacyFindingEvidenceBinding supplies the canonical scope that the legacy
// record cannot prove by itself. The adapter never guesses an objective,
// implementation revision, requirement, review decision, or evidence period.
type LegacyFindingEvidenceBinding struct {
	TenantID                 string
	ActorID                  string
	SourceProofRevisionID    string
	ObjectiveID              string
	ImplementationRevisionID string
	RequirementID            string
	Subjects                 []ports.EvidenceSubjectRef
	PeriodStart              time.Time
	PeriodEnd                time.Time
	Strength                 string
	MappingRationale         string
	Sensitivity              string
	AccessPolicy             string
	RetentionUntil           time.Time
}

// LegacyFindingEvidenceProjection is ready for the evidence ledger service.
// Register the version before creating the claim. Both identities are stable,
// so retries address the same immutable records.
type LegacyFindingEvidenceProjection struct {
	Version RegisterVersionRequest
	Claim   CreateClaimRequest
}

func AdaptLegacyFindingEvidence(source *cerebrov1.FindingEvidence, binding LegacyFindingEvidenceBinding) (LegacyFindingEvidenceProjection, error) {
	if err := validateLegacyBinding(source, binding); err != nil {
		return LegacyFindingEvidenceProjection{}, err
	}
	normalized := normalizeLegacyFindingEvidence(source)
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return LegacyFindingEvidenceProjection{}, fmt.Errorf("marshal legacy finding evidence: %w", err)
	}
	contentDigest := digestBytes(payload)
	artifactID := stableIdentifier(compliance.IdentifierArtifact, binding.TenantID, normalized.GetId())
	versionID := stableRevisionIdentifier(compliance.IdentifierArtifact, binding.TenantID, normalized.GetId(), contentDigest)
	subjects := legacySubjects(normalized, binding.Subjects)
	collectedAt := legacyObservedAt(normalized)
	if collectedAt.IsZero() {
		collectedAt = binding.PeriodEnd.UTC().Truncate(time.Millisecond)
	}
	createdAt := timestampTime(normalized.GetCreatedAt())
	if createdAt.IsZero() {
		createdAt = collectedAt
	}
	firstEventID := ""
	if len(normalized.GetEventIds()) != 0 {
		firstEventID = normalized.GetEventIds()[0]
	}
	derivations := normalizedStrings(append(append(append([]string{}, normalized.GetClaimIds()...), normalized.GetEventIds()...), normalized.GetRunIds()...))
	if normalized.GetFindingId() != "" {
		derivations = normalizedStrings(append(derivations, normalized.GetFindingId()))
	}
	artifact := ports.EvidenceArtifact{
		ID: artifactID, TenantID: strings.TrimSpace(binding.TenantID),
		Title: "Finding evidence " + normalized.GetId(), Type: "finding_evidence",
		CreatedAt: createdAt, CreatedBy: strings.TrimSpace(binding.ActorID),
	}
	version := ports.EvidenceVersion{
		ID: versionID, TenantID: artifact.TenantID, ArtifactID: artifactID,
		Content: ports.EvidenceContentRef{
			MediaType: "application/x-protobuf", URI: "cerebro+finding-evidence:" + url.PathEscape(normalized.GetId()),
			ContentDigest: contentDigest, SizeBytes: uint64(len(payload)),
		},
		Provenance: ports.EvidenceProvenance{
			Producer: "finding-evidence-adapter", CollectedAt: collectedAt,
			PeriodStart: binding.PeriodStart, PeriodEnd: binding.PeriodEnd,
			SourceRuntimeID: normalized.GetRuntimeId(), SourceEventID: firstEventID,
			SourceProofRevisionID: strings.TrimSpace(binding.SourceProofRevisionID), DerivationIDs: derivations,
		},
		Governance: ports.EvidenceGovernance{
			Sensitivity: strings.TrimSpace(binding.Sensitivity), AccessPolicy: strings.TrimSpace(binding.AccessPolicy),
			RetentionUntil: binding.RetentionUntil, ParserQuality: "legacy_normalized",
		},
		ValidFrom: binding.PeriodStart, Subjects: subjects, State: ports.EvidenceStateCollected,
	}
	claimID := stableIdentifier(compliance.IdentifierClaim, artifact.TenantID, versionID,
		binding.ObjectiveID, binding.ImplementationRevisionID, binding.RequirementID,
		binding.PeriodStart.UTC().Format(time.RFC3339Nano), binding.PeriodEnd.UTC().Format(time.RFC3339Nano))
	claim := ports.EvidenceClaim{
		ID: claimID, TenantID: artifact.TenantID, ArtifactVersionID: versionID,
		Scope: ports.EvidenceClaimScope{
			ObjectiveID:              strings.TrimSpace(binding.ObjectiveID),
			ImplementationRevisionID: strings.TrimSpace(binding.ImplementationRevisionID),
			RequirementID:            strings.TrimSpace(binding.RequirementID), Subjects: subjects,
			PeriodStart: binding.PeriodStart, PeriodEnd: binding.PeriodEnd,
		},
		Linkage: ports.EvidenceLinkDirect, Strength: strings.TrimSpace(binding.Strength),
		Limitation: "legacy_record_requires_canonical_review", MappingRationale: strings.TrimSpace(binding.MappingRationale),
		Decision: ports.EvidenceClaimDecision{ReviewState: ports.EvidenceReviewPending},
		Version:  1, CreatedAt: collectedAt, CreatedBy: strings.TrimSpace(binding.ActorID),
	}
	return LegacyFindingEvidenceProjection{
		Version: RegisterVersionRequest{Artifact: artifact, Version: version, ActorID: binding.ActorID},
		Claim:   CreateClaimRequest{Claim: claim, ActorID: binding.ActorID},
	}, nil
}

func validateLegacyBinding(source *cerebrov1.FindingEvidence, binding LegacyFindingEvidenceBinding) error {
	if source == nil || strings.TrimSpace(source.GetId()) == "" {
		return fmt.Errorf("%w: finding evidence id is required", ErrInvalidLegacyEvidenceBinding)
	}
	required := []string{binding.TenantID, binding.ActorID, binding.SourceProofRevisionID, binding.ObjectiveID,
		binding.ImplementationRevisionID, binding.RequirementID, binding.Strength, binding.MappingRationale,
		binding.Sensitivity, binding.AccessPolicy}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: canonical scope, proof, governance, and actor fields are required", ErrInvalidLegacyEvidenceBinding)
		}
	}
	if binding.PeriodStart.IsZero() || binding.PeriodEnd.IsZero() || binding.PeriodEnd.Before(binding.PeriodStart) {
		return fmt.Errorf("%w: a valid evidence period is required", ErrInvalidLegacyEvidenceBinding)
	}
	if len(legacySubjects(source, binding.Subjects)) == 0 {
		return fmt.Errorf("%w: at least one canonical subject is required", ErrInvalidLegacyEvidenceBinding)
	}
	return nil
}

func normalizeLegacyFindingEvidence(source *cerebrov1.FindingEvidence) *cerebrov1.FindingEvidence {
	value := proto.Clone(source).(*cerebrov1.FindingEvidence)
	value.ClaimIds = normalizedStrings(value.GetClaimIds())
	value.EventIds = normalizedStrings(value.GetEventIds())
	value.GraphRootUrns = normalizedStrings(value.GetGraphRootUrns())
	value.GraphPathUrns = normalizedStrings(value.GetGraphPathUrns())
	value.RunIds = normalizedStrings(value.GetRunIds())
	value.GraphRows = sortedGraphRows(value.GetGraphRows())
	for _, observation := range value.GetObservations() {
		observation.ClaimIds = normalizedStrings(observation.GetClaimIds())
		observation.EventIds = normalizedStrings(observation.GetEventIds())
		observation.GraphRootUrns = normalizedStrings(observation.GetGraphRootUrns())
		observation.GraphPathUrns = normalizedStrings(observation.GetGraphPathUrns())
		observation.GraphRows = sortedGraphRows(observation.GetGraphRows())
	}
	sort.Slice(value.Observations, func(i, j int) bool {
		left, _ := proto.MarshalOptions{Deterministic: true}.Marshal(value.Observations[i])
		right, _ := proto.MarshalOptions{Deterministic: true}.Marshal(value.Observations[j])
		return bytes.Compare(left, right) < 0
	})
	return value
}

func sortedGraphRows(values []*cerebrov1.GraphEvidenceRow) []*cerebrov1.GraphEvidenceRow {
	result := append([]*cerebrov1.GraphEvidenceRow(nil), values...)
	sort.Slice(result, func(i, j int) bool {
		left, _ := proto.MarshalOptions{Deterministic: true}.Marshal(result[i])
		right, _ := proto.MarshalOptions{Deterministic: true}.Marshal(result[j])
		return bytes.Compare(left, right) < 0
	})
	return result
}

func legacySubjects(source *cerebrov1.FindingEvidence, explicit []ports.EvidenceSubjectRef) []ports.EvidenceSubjectRef {
	result := append([]ports.EvidenceSubjectRef(nil), explicit...)
	for _, id := range append(append([]string{}, source.GetGraphRootUrns()...), source.GetGraphPathUrns()...) {
		if value := strings.TrimSpace(id); value != "" {
			result = append(result, ports.EvidenceSubjectRef{Type: "resource", ID: value})
		}
	}
	return normalizeSubjects(result)
}

func legacyObservedAt(source *cerebrov1.FindingEvidence) time.Time {
	if value := timestampTime(source.GetLastObservedAt()); !value.IsZero() {
		return value
	}
	return timestampTime(source.GetCreatedAt())
}

func timestampTime(value *timestamppb.Timestamp) time.Time {
	if value == nil || !value.IsValid() {
		return time.Time{}
	}
	return value.AsTime().UTC().Truncate(time.Millisecond)
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func stableIdentifier(kind compliance.IdentifierKind, parts ...string) string {
	digest := stableDigest(parts...)
	return string(kind) + "-" + hex.EncodeToString(digest[:16])
}

func stableRevisionIdentifier(kind compliance.IdentifierKind, parts ...string) string {
	digest := stableDigest(parts...)
	return string(kind) + "-revision-" + hex.EncodeToString(digest[:16])
}

func stableDigest(parts ...string) [32]byte {
	return sha256.Sum256([]byte(strings.Join(parts, "\x00")))
}
