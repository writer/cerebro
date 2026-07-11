package evidenceledger

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestArtifactVersionSupportsIndependentClaims(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	service := newTestService(store, &memoryLog{}, now)
	version := registerTestVersion(t, service, now, true)
	first := createTestClaim(t, service, version, "objective-1")
	second, err := service.ReuseClaim(context.Background(), first.TenantID, first.ID, "owner-2", ports.EvidenceClaim{
		Scope: ports.EvidenceClaimScope{ObjectiveID: "objective-2", ImplementationRevisionID: "implementation-revision-2",
			RequirementID: "requirement-2", Subjects: first.Scope.Subjects, PeriodStart: first.Scope.PeriodStart,
			PeriodEnd: first.Scope.PeriodEnd}, Linkage: ports.EvidenceLinkDirect, Strength: "strong",
		MappingRationale: "Same artifact supports a separate scoped objective.",
	})
	if err != nil {
		t.Fatalf("ReuseClaim() error = %v", err)
	}
	approved, err := service.ReviewClaim(context.Background(), first.TenantID, first.ID, "reviewer-1", ports.EvidenceReviewApproved, "Verified against the requirement.", first.Version)
	if err != nil {
		t.Fatalf("ReviewClaim() error = %v", err)
	}
	if approved.Decision.ReviewState != ports.EvidenceReviewApproved {
		t.Fatalf("first review state = %q", approved.Decision.ReviewState)
	}
	storedSecond, err := store.GetEvidenceClaim(context.Background(), second.TenantID, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedSecond.Decision.ReviewState != ports.EvidenceReviewPending || storedSecond.Decision.ReviewerID != "" {
		t.Fatalf("second claim inherited approval: %#v", storedSecond)
	}
}

func TestQuarantinedVersionCannotSatisfyClaim(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	service := newTestService(store, &memoryLog{}, now)
	version := registerTestVersion(t, service, now, false)
	claim := createTestClaim(t, service, version, "objective-1")
	claim, err := service.ReviewClaim(context.Background(), claim.TenantID, claim.ID, "reviewer-1", ports.EvidenceReviewApproved, "Metadata reviewed.", claim.Version)
	if err != nil {
		t.Fatal(err)
	}
	validation, err := service.ValidateClaim(context.Background(), ValidateClaimRequest{
		TenantID: claim.TenantID, ClaimID: claim.ID, Subjects: claim.Scope.Subjects,
		PeriodStart: claim.Scope.PeriodStart, PeriodEnd: claim.Scope.PeriodEnd, At: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if validation.Valid || !contains(validation.ReasonCodes, reasonVersionQuarantined) {
		t.Fatalf("validation = %#v", validation)
	}
}

func TestInvalidationAndScopePeriodChecks(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	service := newTestService(store, &memoryLog{}, now)
	version := registerTestVersion(t, service, now, true)
	claim := createTestClaim(t, service, version, "objective-1")
	claim, err := service.ReviewClaim(context.Background(), claim.TenantID, claim.ID, "reviewer-1", ports.EvidenceReviewApproved, "Verified.", claim.Version)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := service.ValidateClaim(context.Background(), ValidateClaimRequest{TenantID: claim.TenantID, ClaimID: claim.ID, Subjects: claim.Scope.Subjects, PeriodStart: claim.Scope.PeriodStart, PeriodEnd: claim.Scope.PeriodEnd, At: now})
	if err != nil || !valid.Valid {
		t.Fatalf("ValidateClaim() = (%#v, %v)", valid, err)
	}
	invalidated, err := service.InvalidateClaim(context.Background(), claim.TenantID, claim.ID, "owner-1", "Source record was revoked.", claim.Version)
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := service.ValidateClaim(context.Background(), ValidateClaimRequest{TenantID: claim.TenantID, ClaimID: invalidated.ID, Subjects: []ports.EvidenceSubjectRef{{Type: "asset", ID: "different"}}, PeriodStart: now.Add(-48 * time.Hour), PeriodEnd: now, At: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{reasonClaimInvalidated, reasonPeriodGap, reasonSubjectMismatch} {
		if !contains(invalid.ReasonCodes, reason) {
			t.Fatalf("validation reasons %v missing %q", invalid.ReasonCodes, reason)
		}
	}
}

func TestEvidenceReadEnforcesPurposeSensitivityAndTenant(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	service := newTestService(store, &memoryLog{}, now)
	version := registerTestVersion(t, service, now, true)
	if _, err := service.ReadVersion(context.Background(), ports.EvidenceAccessRequest{TenantID: version.TenantID, ActorID: "reader", Purpose: "assessment", MaximumSensitivity: ports.EvidenceSensitivityInternal}, version.ID); !errors.Is(err, ports.ErrEvidenceAccessDenied) {
		t.Fatalf("restricted read error = %v", err)
	}
	if _, err := service.ReadVersion(context.Background(), ports.EvidenceAccessRequest{TenantID: "foreign", ActorID: "reader", Purpose: "audit", MaximumSensitivity: ports.EvidenceSensitivityRestricted}, version.ID); !errors.Is(err, ports.ErrEvidenceVersionNotFound) {
		t.Fatalf("foreign tenant read error = %v", err)
	}
	if _, err := service.ReadVersion(context.Background(), ports.EvidenceAccessRequest{TenantID: version.TenantID, ActorID: "reader", Purpose: "audit", MaximumSensitivity: ports.EvidenceSensitivityRestricted}, version.ID); err != nil {
		t.Fatalf("authorized read error = %v", err)
	}
}

func TestAppendFailurePreventsProjection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	service := newTestService(store, &memoryLog{err: errors.New("append unavailable")}, now)
	request := testVersionRequest(now, true)
	if _, err := service.RegisterVersion(context.Background(), request); err == nil {
		t.Fatal("RegisterVersion() unexpectedly succeeded")
	}
	if len(store.versions) != 0 {
		t.Fatalf("projection changed after append failure: %#v", store.versions)
	}
}

func newTestService(store *memoryStore, log *memoryLog, now time.Time) *Service {
	service := New(store, log)
	service.now = func() time.Time { return now }
	return service
}

func registerTestVersion(t *testing.T, service *Service, now time.Time, trusted bool) ports.EvidenceVersion {
	t.Helper()
	version, err := service.RegisterVersion(context.Background(), testVersionRequest(now, trusted))
	if err != nil {
		t.Fatalf("RegisterVersion() error = %v", err)
	}
	return version
}

func testVersionRequest(now time.Time, trusted bool) RegisterVersionRequest {
	proof := ""
	if trusted {
		proof = "source-proof-revision-1"
	}
	return RegisterVersionRequest{
		Artifact: ports.EvidenceArtifact{TenantID: "tenant-1", Title: "Access review export", Type: "record", CreatedBy: "owner-1"},
		Version: ports.EvidenceVersion{
			Content: ports.EvidenceContentRef{MediaType: "application/json", URI: "cas://evidence/sha256-abc",
				ContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 10},
			Provenance: ports.EvidenceProvenance{Producer: "source-runtime", CollectedAt: now,
				PeriodStart: now.Add(-24 * time.Hour), PeriodEnd: now, SourceProofRevisionID: proof},
			ValidFrom: now.Add(-24 * time.Hour), ValidUntil: now.Add(24 * time.Hour),
			Subjects:   []ports.EvidenceSubjectRef{{Type: "asset", ID: "asset-1"}},
			Governance: ports.EvidenceGovernance{Sensitivity: ports.EvidenceSensitivityRestricted, AccessPolicy: "evidence-owner-or-engagement"},
		},
		ActorID: "owner-1",
	}
}

func createTestClaim(t *testing.T, service *Service, version ports.EvidenceVersion, objectiveID string) ports.EvidenceClaim {
	t.Helper()
	claim, err := service.CreateClaim(context.Background(), CreateClaimRequest{Claim: ports.EvidenceClaim{
		TenantID: version.TenantID, ArtifactVersionID: version.ID,
		Scope: ports.EvidenceClaimScope{ObjectiveID: objectiveID, ImplementationRevisionID: "implementation-revision-1", RequirementID: "requirement-1",
			Subjects: version.Subjects, PeriodStart: version.Provenance.PeriodStart, PeriodEnd: version.Provenance.PeriodEnd},
		Linkage: ports.EvidenceLinkDirect, Strength: "strong", MappingRationale: "Direct source record for the objective.",
	}, ActorID: "owner-1"})
	if err != nil {
		t.Fatalf("CreateClaim() error = %v", err)
	}
	return claim
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type memoryLog struct {
	mu     sync.Mutex
	events []*cerebrov1.EventEnvelope
	err    error
}

func (l *memoryLog) Ping(context.Context) error { return nil }
func (l *memoryLog) Append(_ context.Context, event *cerebrov1.EventEnvelope) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	l.events = append(l.events, event)
	return nil
}

type memoryStore struct {
	mu        sync.Mutex
	artifacts map[string]ports.EvidenceArtifact
	versions  map[string]ports.EvidenceVersion
	claims    map[string]ports.EvidenceClaim
	events    map[string]struct{}
}

func newMemoryStore() *memoryStore {
	return &memoryStore{artifacts: map[string]ports.EvidenceArtifact{}, versions: map[string]ports.EvidenceVersion{}, claims: map[string]ports.EvidenceClaim{}, events: map[string]struct{}{}}
}

func tenantKey(tenantID, id string) string { return tenantID + "\x00" + id }

func (s *memoryStore) ApplyEvidenceVersion(_ context.Context, eventID string, artifact ports.EvidenceArtifact, version ports.EvidenceVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[eventID]; ok {
		return nil
	}
	s.events[eventID] = struct{}{}
	s.artifacts[tenantKey(artifact.TenantID, artifact.ID)] = artifact
	s.versions[tenantKey(version.TenantID, version.ID)] = version
	return nil
}

func (s *memoryStore) ApplyEvidenceClaim(_ context.Context, eventID string, claim ports.EvidenceClaim, expectedVersion uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[eventID]; ok {
		return nil
	}
	key := tenantKey(claim.TenantID, claim.ID)
	existing, ok := s.claims[key]
	if ok && existing.Version != expectedVersion {
		return ports.ErrEvidenceLedgerConflict
	}
	if !ok && expectedVersion != 0 {
		return ports.ErrEvidenceLedgerConflict
	}
	s.events[eventID] = struct{}{}
	s.claims[key] = claim
	return nil
}

func (s *memoryStore) GetEvidenceArtifact(_ context.Context, tenantID, id string) (ports.EvidenceArtifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.artifacts[tenantKey(tenantID, id)]
	if !ok {
		return ports.EvidenceArtifact{}, ports.ErrEvidenceArtifactNotFound
	}
	return value, nil
}
func (s *memoryStore) GetEvidenceVersion(_ context.Context, tenantID, id string) (ports.EvidenceVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.versions[tenantKey(tenantID, id)]
	if !ok {
		return ports.EvidenceVersion{}, ports.ErrEvidenceVersionNotFound
	}
	return value, nil
}
func (s *memoryStore) GetEvidenceClaim(_ context.Context, tenantID, id string) (ports.EvidenceClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.claims[tenantKey(tenantID, id)]
	if !ok {
		return ports.EvidenceClaim{}, ports.ErrEvidenceClaimNotFound
	}
	return value, nil
}
func (s *memoryStore) ListEvidenceClaimsByVersion(_ context.Context, tenantID, versionID string) ([]ports.EvidenceClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []ports.EvidenceClaim
	for _, claim := range s.claims {
		if claim.TenantID == tenantID && claim.ArtifactVersionID == versionID {
			result = append(result, claim)
		}
	}
	return result, nil
}
