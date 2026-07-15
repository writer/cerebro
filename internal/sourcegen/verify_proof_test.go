package sourcegen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/providercontractlock"
)

func TestVerifyProofBundleChecksOutputsAndProviderContract(t *testing.T) {
	outputDir := t.TempDir()
	lock := providercontractlock.Lock{
		SchemaVersion:        providercontractlock.SchemaVersion,
		NormalizationVersion: providercontractlock.NormalizationVersion,
		SourceID:             "proof_source",
		DocumentDigest:       "document-digest",
		AuthDigest:           "auth-digest",
	}
	lockDigest, err := providercontractlock.Digest(lock)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	lockPath := filepath.Join(outputDir, "sources", "proof_source", ".provider-contract-lock.json")
	if err := providercontractlock.Write(lockPath, lock); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := GenerateDefinition(DefinitionRequest{
		Definition: proofVerificationDefinition(),
		ProviderContract: &ProviderContractEvidence{
			LockDigest:  lockDigest,
			DriftStatus: "unchanged",
			Reviewed:    true,
		},
		OutputDir: outputDir,
	}); err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	result, err := VerifyProofBundle(ProofVerificationRequest{SourceID: "proof_source", OutputDir: outputDir})
	if err != nil {
		t.Fatalf("VerifyProofBundle() error = %v", err)
	}
	if result.Status != VerificationStatusPending || result.PromotionReady {
		t.Fatalf("verification result = %#v", result)
	}
	if !hasVerificationCheck(result.Checks, "output.digests", VerificationCheckPassed) || !hasVerificationCheck(result.Checks, "provider_contract.digest", VerificationCheckPassed) {
		t.Fatalf("verification checks = %#v", result.Checks)
	}
	if len(result.PendingObligations) != 1 || result.PendingObligations[0] != "runtime.semantic_replay" {
		t.Fatalf("pending obligations = %v", result.PendingObligations)
	}
}

func TestVerifyProofBundleDetectsGeneratedOutputMutation(t *testing.T) {
	outputDir := t.TempDir()
	if _, err := Generate(Request{SourceID: "proof_source", AssetSchemas: []string{"host"}, OutputDir: outputDir}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	path := filepath.Join(outputDir, "sources", "proof_source", "source.go")
	if err := os.WriteFile(path, []byte("package proofsource\n\n// mutation\n"), 0o600); err != nil {
		t.Fatalf("write mutation: %v", err)
	}
	result, err := VerifyProofBundle(ProofVerificationRequest{SourceID: "proof_source", OutputDir: outputDir})
	if err != nil {
		t.Fatalf("VerifyProofBundle() error = %v", err)
	}
	if result.Status != VerificationStatusBlocked || !hasVerificationCheck(result.Checks, "output.digest", VerificationCheckFailed) {
		t.Fatalf("verification result = %#v", result)
	}
}

func TestVerifyProofBundleDetectsProofMutation(t *testing.T) {
	outputDir := t.TempDir()
	generated, err := Generate(Request{SourceID: "proof_source", AssetSchemas: []string{"host"}, OutputDir: outputDir})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	payload, err := os.ReadFile(generated.ProofBundle) // #nosec G304 -- test-owned generated path.
	if err != nil {
		t.Fatalf("read proof bundle: %v", err)
	}
	payload = append(payload, ' ')
	if err := os.WriteFile(generated.ProofBundle, payload, 0o600); err != nil { // #nosec G703 -- test-owned generated path.
		t.Fatalf("write proof mutation: %v", err)
	}
	result, err := VerifyProofBundle(ProofVerificationRequest{SourceID: "proof_source", OutputDir: outputDir})
	if err != nil {
		t.Fatalf("VerifyProofBundle() error = %v", err)
	}
	if result.Status != VerificationStatusBlocked || !hasVerificationCheck(result.Checks, "proof.digest", VerificationCheckFailed) {
		t.Fatalf("verification result = %#v", result)
	}
}

func TestVerifyProofBundleReportsMissingManifest(t *testing.T) {
	result, err := VerifyProofBundle(ProofVerificationRequest{SourceID: "missing", OutputDir: t.TempDir()})
	if err != nil {
		t.Fatalf("VerifyProofBundle() error = %v", err)
	}
	if result.Status != VerificationStatusBlocked || !hasVerificationCheck(result.Checks, "manifest.load", VerificationCheckFailed) {
		t.Fatalf("verification result = %#v", result)
	}
}

func proofVerificationDefinition() connectordefinitions.Definition {
	return connectordefinitions.Definition{
		SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
		ID:            "builtin-proof_source",
		TenantID:      "builtin",
		SourceID:      "proof_source",
		DisplayName:   "Proof source",
		Runtime:       connectordefinitions.RuntimeJSONAPI,
		Stage:         connectordefinitions.StageDraft,
		Auth:          connectordefinitions.AuthSpec{Model: "none"},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL:      "https://api.example.test",
			Verification: &connectordefinitions.VerificationSpec{Path: "/v1/resources"},
		},
		ProviderAPI: &connectordefinitions.ProviderAPISpec{
			Status:     "verified",
			Basis:      "detected",
			Transport:  "rest",
			Auth:       "none",
			BaseURL:    "https://api.example.test",
			SpecURL:    "https://api.example.test/openapi.json",
			SpecKind:   "openapi",
			References: []string{"https://api.example.test/openapi.json"},
			Families: []connectordefinitions.ProviderAPIFamilySpec{{
				ID: "resources", Method: "GET", Path: "/v1/resources",
			}},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "resources",
			Path:           "/v1/resources",
			Method:         "GET",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			NameField:      "name",
			Event: connectordefinitions.EventMappingSpec{
				Kind: "proof_source.resources", SchemaRef: "proof_source/resources/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				ID: "resources", Type: "entity_family", Families: []string{"resources"}, Support: "supported",
			}},
		}},
	}
}

func hasVerificationCheck(checks []ProofVerificationCheck, id string, status string) bool {
	for _, check := range checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}
