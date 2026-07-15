package sourcegen

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/providercontractlock"
)

const (
	VerificationStatusVerified = "verified"
	VerificationStatusPending  = "verified_with_pending_obligations"
	VerificationStatusBlocked  = "blocked"

	VerificationCheckPassed = "passed"
	VerificationCheckFailed = "failed"
)

// ProofVerificationRequest selects one generated source and its provider lock.
type ProofVerificationRequest struct {
	SourceID             string
	OutputDir            string
	ProviderContractLock string
}

// ProofVerificationResult reports current artifact integrity and promotion
// obligations for one generated source.
type ProofVerificationResult struct {
	SourceID           string                   `json:"source_id"`
	Status             string                   `json:"status"`
	PromotionReady     bool                     `json:"promotion_ready"`
	Checks             []ProofVerificationCheck `json:"checks"`
	PendingObligations []string                 `json:"pending_obligations,omitempty"`
}

// ProofVerificationCheck is one artifact or receipt integrity decision.
type ProofVerificationCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail"`
}

// VerifyProofBundle verifies the generation manifest, proof receipt, current
// output contents, and provider contract lock without regenerating files.
func VerifyProofBundle(request ProofVerificationRequest) (*ProofVerificationResult, error) {
	sourceID := strings.TrimSpace(request.SourceID)
	if sourceID == "" {
		return nil, fmt.Errorf("source_id is required")
	}
	outputDir := strings.TrimSpace(request.OutputDir)
	if outputDir == "" {
		outputDir = "."
	}
	result := &ProofVerificationResult{SourceID: sourceID, Status: VerificationStatusVerified}
	add := func(check ProofVerificationCheck) {
		result.Checks = append(result.Checks, check)
		if check.Status == VerificationCheckFailed {
			result.Status = VerificationStatusBlocked
		}
	}
	sourceDir := filepath.Join(outputDir, "sources", sourceID)
	manifestPath := filepath.Join(sourceDir, manifestName)
	manifest, err := loadGenerationManifest(outputDir, manifestPath)
	if err != nil {
		add(failedVerification("manifest.load", manifestPath, err.Error()))
		return finalizeProofVerification(result, nil), nil
	}
	if manifest == nil {
		add(failedVerification("manifest.load", manifestPath, "Generation manifest is missing."))
		return finalizeProofVerification(result, nil), nil
	}
	add(passedVerification("manifest.load", manifestPath, "Generation manifest loaded."))

	proofPath := filepath.Join(sourceDir, proofBundleName)
	proofPayload, err := os.ReadFile(proofPath) // #nosec G304 -- proof path is constrained to OutputDir.
	if err != nil {
		add(failedVerification("proof.load", proofPath, err.Error()))
		return finalizeProofVerification(result, nil), nil
	}
	var proof ProofBundle
	if err := json.Unmarshal(proofPayload, &proof); err != nil {
		add(failedVerification("proof.load", proofPath, "Proof bundle is not valid JSON: "+err.Error()))
		return finalizeProofVerification(result, nil), nil //nolint:nilerr // Malformed proof content is a reported verification failure.
	}
	add(passedVerification("proof.load", proofPath, "Proof bundle loaded."))
	if digestMatches(proofPayload, manifest.ProofDigest) {
		add(passedVerification("proof.digest", proofPath, "Proof bundle digest matches the generation manifest."))
	} else {
		add(failedVerification("proof.digest", proofPath, "Proof bundle digest does not match the generation manifest."))
	}
	if proof.SchemaVersion == ProofBundleSchemaVersion && proof.GeneratorVersion == manifest.GeneratorVersion && proof.SourceID == manifest.SourceID && proof.SourceID == sourceID && proof.InputDigest == manifest.InputDigest {
		add(passedVerification("proof.identity", proofPath, "Proof identity and normalized input match the generation manifest."))
	} else {
		add(failedVerification("proof.identity", proofPath, "Proof identity or normalized input does not match the generation manifest."))
	}

	proofOutputs := make(map[string]string, len(proof.Outputs))
	for _, output := range proof.Outputs {
		proofOutputs[output.Path] = output.Digest
	}
	if equalOutputDigests(manifest.Outputs, proofOutputs) {
		add(passedVerification("proof.outputs", proofPath, fmt.Sprintf("Proof receipt binds %d generated outputs.", len(proofOutputs))))
	} else {
		add(failedVerification("proof.outputs", proofPath, "Proof output paths or digests do not match the generation manifest."))
	}
	verifyCurrentOutputs(add, outputDir, manifest.Outputs)
	verifyProviderContract(add, request, outputDir, sourceID, proof.ProviderContract)
	return finalizeProofVerification(result, proof.Obligations), nil
}

func verifyCurrentOutputs(add func(ProofVerificationCheck), outputDir string, outputs map[string]string) {
	paths := make([]string, 0, len(outputs))
	for path := range outputs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	failed := false
	for _, relativePath := range paths {
		path := filepath.Join(outputDir, filepath.FromSlash(relativePath))
		normalized, err := manifestRelativePath(outputDir, path)
		if err != nil || normalized != relativePath {
			add(failedVerification("output.path", relativePath, "Generated output path escapes the output directory."))
			failed = true
			continue
		}
		payload, err := os.ReadFile(path) // #nosec G304 -- path is constrained to OutputDir above.
		if err != nil {
			add(failedVerification("output.read", relativePath, err.Error()))
			failed = true
			continue
		}
		if !digestMatches(payload, outputs[relativePath]) {
			add(failedVerification("output.digest", relativePath, "Generated output content does not match the recorded digest."))
			failed = true
		}
	}
	if !failed {
		add(passedVerification("output.digests", "", fmt.Sprintf("All %d generated outputs match their recorded digests.", len(paths))))
	}
}

func verifyProviderContract(add func(ProofVerificationCheck), request ProofVerificationRequest, outputDir string, sourceID string, evidence *ProviderContractEvidence) {
	if evidence == nil {
		return
	}
	lockPath := strings.TrimSpace(request.ProviderContractLock)
	if lockPath == "" {
		lockPath = filepath.Join(outputDir, "sources", sourceID, ".provider-contract-lock.json")
	}
	lock, err := providercontractlock.Read(lockPath)
	if err != nil {
		add(failedVerification("provider_contract.load", lockPath, err.Error()))
		return
	}
	digest, err := providercontractlock.Digest(lock)
	if err != nil {
		add(failedVerification("provider_contract.digest", lockPath, err.Error()))
		return
	}
	if lock.SourceID != sourceID {
		add(failedVerification("provider_contract.identity", lockPath, "Provider contract lock source id does not match the proof bundle source."))
		return
	}
	if digest != evidence.LockDigest {
		add(failedVerification("provider_contract.digest", lockPath, "Provider contract lock does not match the proof bundle digest."))
		return
	}
	add(passedVerification("provider_contract.digest", lockPath, "Provider contract lock matches the proof bundle digest."))
}

func finalizeProofVerification(result *ProofVerificationResult, obligations []ProofObligation) *ProofVerificationResult {
	for _, obligation := range obligations {
		if obligation.Status == ProofStatusPending {
			result.PendingObligations = append(result.PendingObligations, obligation.ID)
		}
	}
	sort.Strings(result.PendingObligations)
	if result.Status != VerificationStatusBlocked && len(result.PendingObligations) != 0 {
		result.Status = VerificationStatusPending
	}
	result.PromotionReady = result.Status == VerificationStatusVerified
	return result
}

func equalOutputDigests(first map[string]string, second map[string]string) bool {
	if len(first) != len(second) {
		return false
	}
	for path, digest := range first {
		if second[path] != digest {
			return false
		}
	}
	return true
}

func passedVerification(id string, path string, detail string) ProofVerificationCheck {
	return ProofVerificationCheck{ID: id, Status: VerificationCheckPassed, Path: path, Detail: detail}
}

func failedVerification(id string, path string, detail string) ProofVerificationCheck {
	return ProofVerificationCheck{ID: id, Status: VerificationCheckFailed, Path: path, Detail: detail}
}
