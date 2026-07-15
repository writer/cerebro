package evidenceledgerhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/evidenceledger"
	"github.com/writer/cerebro/internal/ports"
)

func TestEvidenceLedgerHTTPJourney(t *testing.T) {
	t.Parallel()
	errTenantForbidden := errors.New("tenant forbidden")
	store := newHTTPStore()
	service := evidenceledger.New(store, &httpLog{})
	handler := NewHandler(service, func(_ context.Context, tenantID string) (string, error) {
		if tenantID != "tenant-1" {
			return "", errTenantForbidden
		}
		return tenantID, nil
	}, func(context.Context) string { return "operator-1" }, func(err error) bool {
		return errors.Is(err, errTenantForbidden)
	}, 0).WithMaximumSensitivity(func(context.Context) string { return ports.EvidenceSensitivityInternal })
	mux := http.NewServeMux()
	mux.HandleFunc("POST /grc/evidence-artifacts/{artifactID}/versions", handler.RegisterVersion)
	mux.HandleFunc("GET /grc/evidence-versions/{versionID}", handler.GetVersion)
	mux.HandleFunc("POST /grc/evidence-claims", handler.CreateClaim)
	mux.HandleFunc("POST /grc/evidence-claims/compatibility", handler.EvaluateCompatibility)
	mux.HandleFunc("GET /grc/evidence-claims/{claimID}", handler.GetClaim)
	mux.HandleFunc("POST /grc/evidence-claims/{claimID}/reviews", handler.ReviewClaim)
	mux.HandleFunc("POST /grc/evidence-claims/{claimID}/validate", handler.ValidateClaim)
	mux.HandleFunc("POST /grc/evidence-claims/{claimID}/reuse", handler.ReuseClaim)
	mux.HandleFunc("POST /grc/evidence-claims/{claimID}/invalidate", handler.InvalidateClaim)
	server := httptest.NewServer(mux)
	defer server.Close()

	artifactID := mustIdentifier(t, compliance.IdentifierArtifact)
	periodStart := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)
	validUntil := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	register := registerEvidenceVersionRequest{
		Artifact: ports.EvidenceArtifact{TenantID: "tenant-1", Title: "Access review export", Type: "access_review"},
		Version: ports.EvidenceVersion{
			Content:    ports.EvidenceContentRef{MediaType: "application/json", URI: "evidencecas://access-reviews/july", ContentDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 512},
			Provenance: ports.EvidenceProvenance{Producer: "identity-source", CollectedAt: periodEnd, PeriodStart: periodStart, PeriodEnd: periodEnd, SourceProofRevisionID: "proof-revision-1"},
			Governance: ports.EvidenceGovernance{Sensitivity: ports.EvidenceSensitivityInternal, AccessPolicy: "security-assurance"},
			ValidUntil: validUntil,
			Subjects:   []ports.EvidenceSubjectRef{{Type: "account", ID: "account-1"}},
		},
	}
	var versionResponse evidenceVersionRegisterResponse
	doJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/evidence-artifacts/"+artifactID+"/versions", register, http.StatusCreated, &versionResponse)
	if versionResponse.Version.ArtifactID != artifactID || versionResponse.Version.State != ports.EvidenceStateCollected {
		t.Fatalf("registered version = %#v", versionResponse.Version)
	}
	if versionResponse.Artifact.ID != artifactID || versionResponse.Artifact.CreatedBy != "operator-1" {
		t.Fatalf("registered artifact = %#v", versionResponse.Artifact)
	}

	claimInput := ports.EvidenceClaim{
		TenantID: "tenant-1", ArtifactVersionID: versionResponse.Version.ID,
		Scope:   ports.EvidenceClaimScope{ObjectiveID: "objective-1", ImplementationRevisionID: "implementation-revision-1", RequirementID: "requirement-1", Subjects: register.Version.Subjects, PeriodStart: periodStart, PeriodEnd: periodEnd},
		Linkage: ports.EvidenceLinkDirect, Strength: "authoritative", MappingRationale: "The export is produced by the system of record.",
	}
	var created evidenceClaimResponse
	doJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/evidence-claims", createEvidenceClaimRequest{Claim: claimInput}, http.StatusCreated, &created)
	if created.Claim.Decision.ReviewState != ports.EvidenceReviewPending || !created.Claim.ValidUntil.Equal(validUntil) {
		t.Fatalf("created claim = %#v", created.Claim)
	}

	var reviewed evidenceClaimResponse
	doJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/evidence-claims/"+created.Claim.ID+"/reviews", reviewEvidenceClaimRequest{
		TenantID: "tenant-1", ExpectedVersion: 1, State: ports.EvidenceReviewApproved, Reason: "Scope and provenance verified.",
	}, http.StatusOK, &reviewed)
	if reviewed.Claim.Version != 2 || reviewed.Claim.Decision.ReviewerID != "operator-1" {
		t.Fatalf("reviewed claim = %#v", reviewed.Claim)
	}

	var validation validateEvidenceClaimResponse
	doJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/evidence-claims/"+created.Claim.ID+"/validate", validateEvidenceClaimRequest{
		TenantID: "tenant-1", Subjects: register.Version.Subjects, PeriodStart: periodStart, PeriodEnd: periodEnd, At: periodEnd,
	}, http.StatusOK, &validation)
	if !validation.Validation.Valid {
		t.Fatalf("validation = %#v", validation.Validation)
	}
	obligation := compliance.ProofObligation{
		RequirementID: "requirement-1", ControlID: "control-1", FrameworkID: "framework-1", FrameworkVersion: "2026",
		ImplementationRevision: "implementation-revision-1", ScopeRevision: "scope-revision-1", SubjectKinds: []string{"account"},
		PopulationDigest: "sha256:" + strings.Repeat("b", 64), PeriodStart: periodStart, PeriodEnd: periodEnd,
		Method: compliance.ProofMethodAutomated, Strength: compliance.AssuranceTested, Frequency: "continuous", ReviewerRequired: true,
	}
	var compatibility evidenceClaimCompatibilityResponse
	doJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/evidence-claims/compatibility", evidenceClaimCompatibilityRequest{
		TenantID: "tenant-1", ClaimID: created.Claim.ID, Source: obligation, Target: obligation, At: periodEnd,
	}, http.StatusOK, &compatibility)
	if !compatibility.Decision.Reusable || compatibility.Decision.Reuse.State != compliance.ReuseExact {
		t.Fatalf("compatibility = %#v", compatibility.Decision)
	}

	reuseInput := claimInput
	reuseInput.Scope.RequirementID = "requirement-2"
	var reused evidenceClaimResponse
	doJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/evidence-claims/"+created.Claim.ID+"/reuse", reuseEvidenceClaimRequest{TenantID: "tenant-1", Claim: reuseInput}, http.StatusCreated, &reused)
	if reused.Claim.ID == created.Claim.ID || reused.Claim.ArtifactVersionID != created.Claim.ArtifactVersionID || reused.Claim.Decision.ReviewState != ports.EvidenceReviewPending {
		t.Fatalf("reused claim = %#v", reused.Claim)
	}

	var invalidated evidenceClaimResponse
	doJSON(t, server.Client(), http.MethodPost, server.URL+"/grc/evidence-claims/"+created.Claim.ID+"/invalidate", invalidateEvidenceClaimRequest{
		TenantID: "tenant-1", ExpectedVersion: 2, Reason: "Source data was withdrawn.",
	}, http.StatusOK, &invalidated)
	if invalidated.Claim.Version != 3 || invalidated.Claim.Decision.InvalidatedAt.IsZero() {
		t.Fatalf("invalidated claim = %#v", invalidated.Claim)
	}

	var readClaim evidenceClaimResponse
	doJSON(t, server.Client(), http.MethodGet, server.URL+"/grc/evidence-claims/"+created.Claim.ID+"?tenant_id=tenant-1", nil, http.StatusOK, &readClaim)
	if readClaim.Claim.Version != 3 {
		t.Fatalf("read claim version = %d", readClaim.Claim.Version)
	}
	var readVersion evidenceVersionResponse
	doJSON(t, server.Client(), http.MethodGet, server.URL+"/grc/evidence-versions/"+versionResponse.Version.ID+"?tenant_id=tenant-1&purpose=assessment&maximum_sensitivity=internal", nil, http.StatusOK, &readVersion)
	if readVersion.Version.ID != versionResponse.Version.ID {
		t.Fatalf("read version id = %q", readVersion.Version.ID)
	}
}

func TestGetVersionUsesAuthenticatedSensitivity(t *testing.T) {
	t.Parallel()
	store := newHTTPStore()
	store.versions[storeKey("tenant-1", "version-1")] = ports.EvidenceVersion{
		ID: "version-1", TenantID: "tenant-1",
		Governance: ports.EvidenceGovernance{Sensitivity: ports.EvidenceSensitivityRestricted},
	}
	service := evidenceledger.New(store, &httpLog{})
	newServer := func(maximumSensitivity string) *httptest.Server {
		handler := NewHandler(service, func(_ context.Context, tenantID string) (string, error) {
			return tenantID, nil
		}, func(context.Context) string { return "reader-1" }, nil, 0).
			WithMaximumSensitivity(func(context.Context) string { return maximumSensitivity })
		mux := http.NewServeMux()
		mux.HandleFunc("GET /grc/evidence-versions/{versionID}", handler.GetVersion)
		return httptest.NewServer(mux)
	}

	reader := newServer(ports.EvidenceSensitivityInternal)
	defer reader.Close()
	doJSON(t, reader.Client(), http.MethodGet, reader.URL+"/grc/evidence-versions/version-1?tenant_id=tenant-1&purpose=assessment&maximum_sensitivity=restricted", nil, http.StatusForbidden, nil)

	operator := newServer(ports.EvidenceSensitivityRestricted)
	defer operator.Close()
	var response evidenceVersionResponse
	doJSON(t, operator.Client(), http.MethodGet, operator.URL+"/grc/evidence-versions/version-1?tenant_id=tenant-1&purpose=assessment&maximum_sensitivity=public", nil, http.StatusOK, &response)
	if response.Version.ID != "version-1" {
		t.Fatalf("version id = %q", response.Version.ID)
	}
}

func TestUnavailableReturnsServiceUnavailable(t *testing.T) {
	t.Parallel()
	handler := NewHandler(nil, func(_ context.Context, tenantID string) (string, error) {
		return tenantID, nil
	}, func(context.Context) string { return "reader-1" }, nil, 0)
	request := httptest.NewRequest(http.MethodGet, "/grc/evidence-versions/version-1?tenant_id=tenant-1&purpose=assessment", nil)
	request.SetPathValue("versionID", "version-1")
	response := httptest.NewRecorder()
	handler.GetVersion(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusServiceUnavailable, response.Body.String())
	}
}

func doJSON(t *testing.T, client *http.Client, method, url string, input any, wantStatus int, output any) {
	t.Helper()
	var body bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&body).Encode(input); err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequestWithContext(context.Background(), method, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != wantStatus {
		var problem bytes.Buffer
		_, _ = problem.ReadFrom(response.Body)
		t.Fatalf("%s %s status = %d, want %d: %s", method, url, response.StatusCode, wantStatus, problem.String())
	}
	if output != nil {
		if err := json.NewDecoder(response.Body).Decode(output); err != nil {
			t.Fatal(err)
		}
	}
}

func mustIdentifier(t *testing.T, kind compliance.IdentifierKind) string {
	t.Helper()
	id, err := compliance.NewIdentifier(kind)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type httpLog struct{}

func (*httpLog) Ping(context.Context) error                             { return nil }
func (*httpLog) Append(context.Context, *cerebrov1.EventEnvelope) error { return nil }

type httpStore struct {
	artifacts map[string]ports.EvidenceArtifact
	versions  map[string]ports.EvidenceVersion
	claims    map[string]ports.EvidenceClaim
}

func newHTTPStore() *httpStore {
	return &httpStore{artifacts: map[string]ports.EvidenceArtifact{}, versions: map[string]ports.EvidenceVersion{}, claims: map[string]ports.EvidenceClaim{}}
}

func storeKey(tenantID, id string) string { return tenantID + "\x00" + id }

func (s *httpStore) ApplyEvidenceVersion(_ context.Context, _ string, artifact ports.EvidenceArtifact, version ports.EvidenceVersion) error {
	s.artifacts[storeKey(artifact.TenantID, artifact.ID)] = artifact
	s.versions[storeKey(version.TenantID, version.ID)] = version
	return nil
}

func (s *httpStore) ApplyEvidenceClaim(_ context.Context, _ string, claim ports.EvidenceClaim, expectedVersion uint64) error {
	key := storeKey(claim.TenantID, claim.ID)
	current, found := s.claims[key]
	if (!found && expectedVersion != 0) || (found && current.Version != expectedVersion) {
		return ports.ErrEvidenceLedgerConflict
	}
	s.claims[key] = claim
	return nil
}

func (s *httpStore) GetEvidenceArtifact(_ context.Context, tenantID, id string) (ports.EvidenceArtifact, error) {
	value, ok := s.artifacts[storeKey(tenantID, id)]
	if !ok {
		return ports.EvidenceArtifact{}, ports.ErrEvidenceArtifactNotFound
	}
	return value, nil
}

func (s *httpStore) GetEvidenceVersion(_ context.Context, tenantID, id string) (ports.EvidenceVersion, error) {
	value, ok := s.versions[storeKey(tenantID, id)]
	if !ok {
		return ports.EvidenceVersion{}, ports.ErrEvidenceVersionNotFound
	}
	return value, nil
}

func (s *httpStore) GetEvidenceClaim(_ context.Context, tenantID, id string) (ports.EvidenceClaim, error) {
	value, ok := s.claims[storeKey(tenantID, id)]
	if !ok {
		return ports.EvidenceClaim{}, ports.ErrEvidenceClaimNotFound
	}
	return value, nil
}

func (s *httpStore) ListEvidenceClaimsByVersion(_ context.Context, tenantID, versionID string) ([]ports.EvidenceClaim, error) {
	values := make([]ports.EvidenceClaim, 0)
	for _, claim := range s.claims {
		if claim.TenantID == tenantID && claim.ArtifactVersionID == versionID {
			values = append(values, claim)
		}
	}
	return values, nil
}
