package evidenceledger

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestAdaptLegacyFindingEvidenceIsDeterministicAndReviewPending(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	source := legacyFixture(now)
	first, err := AdaptLegacyFindingEvidence(source, legacyBinding(now, "tenant-1"))
	if err != nil {
		t.Fatalf("AdaptLegacyFindingEvidence() error = %v", err)
	}
	reordered := proto.Clone(source).(*cerebrov1.FindingEvidence)
	reordered.ClaimIds = []string{"claim-2", "claim-1", "claim-1"}
	reordered.EventIds = []string{"event-2", "event-1"}
	reordered.GraphRootUrns = []string{"urn:asset:2", "urn:asset:1"}
	reordered.RunIds = []string{"run-2", "run-1"}
	second, err := AdaptLegacyFindingEvidence(reordered, legacyBinding(now, "tenant-1"))
	if err != nil {
		t.Fatalf("reordered AdaptLegacyFindingEvidence() error = %v", err)
	}
	if first.Version.Artifact.ID != second.Version.Artifact.ID ||
		first.Version.Version.ID != second.Version.Version.ID ||
		first.Version.Version.Content.ContentDigest != second.Version.Version.Content.ContentDigest ||
		first.Claim.Claim.ID != second.Claim.Claim.ID {
		t.Fatalf("reordered source changed stable projection:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if first.Claim.Claim.Decision.ReviewState != ports.EvidenceReviewPending || first.Claim.Claim.Decision.ReviewerID != "" {
		t.Fatalf("legacy claim inherited a decision: %#v", first.Claim.Claim.Decision)
	}
	if strings.Contains(first.Version.Version.Content.URI, "tenant-1") || strings.HasPrefix(first.Version.Version.Content.URI, "file:") || strings.HasPrefix(first.Version.Version.Content.URI, "data:") {
		t.Fatalf("unsafe or tenant-bearing content URI = %q", first.Version.Version.Content.URI)
	}
}

func TestAdaptLegacyFindingEvidenceRequiresExplicitCanonicalBinding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	tests := map[string]func(*cerebrov1.FindingEvidence, *LegacyFindingEvidenceBinding){
		"source": func(source *cerebrov1.FindingEvidence, _ *LegacyFindingEvidenceBinding) { source.Id = "" },
		"tenant": func(_ *cerebrov1.FindingEvidence, binding *LegacyFindingEvidenceBinding) { binding.TenantID = "" },
		"proof": func(_ *cerebrov1.FindingEvidence, binding *LegacyFindingEvidenceBinding) {
			binding.SourceProofRevisionID = ""
		},
		"objective":   func(_ *cerebrov1.FindingEvidence, binding *LegacyFindingEvidenceBinding) { binding.ObjectiveID = "" },
		"requirement": func(_ *cerebrov1.FindingEvidence, binding *LegacyFindingEvidenceBinding) { binding.RequirementID = "" },
		"period": func(_ *cerebrov1.FindingEvidence, binding *LegacyFindingEvidenceBinding) {
			binding.PeriodEnd = binding.PeriodStart.Add(-time.Second)
		},
		"subjects": func(source *cerebrov1.FindingEvidence, binding *LegacyFindingEvidenceBinding) {
			source.GraphRootUrns = nil
			source.GraphPathUrns = nil
			binding.Subjects = nil
		},
		"access policy": func(_ *cerebrov1.FindingEvidence, binding *LegacyFindingEvidenceBinding) { binding.AccessPolicy = "" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			source := legacyFixture(now)
			binding := legacyBinding(now, "tenant-1")
			mutate(source, &binding)
			if _, err := AdaptLegacyFindingEvidence(source, binding); !errors.Is(err, ErrInvalidLegacyEvidenceBinding) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestAdaptLegacyFindingEvidenceSeparatesTenantsAndRegistersThroughLedger(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC)
	source := legacyFixture(now)
	first, err := AdaptLegacyFindingEvidence(source, legacyBinding(now, "tenant-1"))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := AdaptLegacyFindingEvidence(source, legacyBinding(now, "tenant-2"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Version.Artifact.ID == foreign.Version.Artifact.ID || first.Claim.Claim.ID == foreign.Claim.Claim.ID {
		t.Fatal("tenant-scoped adapter identities collided")
	}
	store := newMemoryStore()
	service := newTestService(store, &memoryLog{}, now)
	version, err := service.RegisterVersion(context.Background(), first.Version)
	if err != nil {
		t.Fatalf("RegisterVersion() error = %v", err)
	}
	claim, err := service.CreateClaim(context.Background(), first.Claim)
	if err != nil {
		t.Fatalf("CreateClaim() error = %v", err)
	}
	if version.ID != first.Version.Version.ID || claim.ArtifactVersionID != version.ID || !reflect.DeepEqual(claim.Scope.Subjects, version.Subjects) {
		t.Fatalf("registered projection mismatch: version=%#v claim=%#v", version, claim)
	}
}

func legacyFixture(now time.Time) *cerebrov1.FindingEvidence {
	return &cerebrov1.FindingEvidence{
		Id: "finding-evidence-1", RuntimeId: "runtime-1", RuleId: "rule-1", FindingId: "finding-1", RunId: "run-2",
		ClaimIds: []string{"claim-1", "claim-2"}, EventIds: []string{"event-1", "event-2"},
		GraphRootUrns: []string{"urn:asset:1", "urn:asset:2"}, GraphPathUrns: []string{"urn:path:1"},
		CreatedAt: timestamppb.New(now.Add(-time.Hour)), LastObservedAt: timestamppb.New(now),
		RunIds: []string{"run-1", "run-2"}, ObservationCount: 2,
	}
}

func legacyBinding(now time.Time, tenantID string) LegacyFindingEvidenceBinding {
	return LegacyFindingEvidenceBinding{
		TenantID: tenantID, ActorID: "migration-owner", SourceProofRevisionID: "source-proof-revision-1",
		ObjectiveID: "objective-1", ImplementationRevisionID: "implementation-revision-1", RequirementID: "requirement-1",
		PeriodStart: now.Add(-24 * time.Hour), PeriodEnd: now, Strength: "moderate",
		MappingRationale: "The existing finding evidence record is explicitly bound to this requirement.",
		Sensitivity:      ports.EvidenceSensitivityInternal, AccessPolicy: "compliance-evidence-readers",
	}
}
