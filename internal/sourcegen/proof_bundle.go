package sourcegen

import (
	"encoding/json"
	"sort"
	"strings"
)

const (
	ProofBundleSchemaVersion = "cerebro.sourcegen.proof/v1"

	ProofStatusPassed        = "passed"
	ProofStatusPending       = "pending"
	ProofStatusNotApplicable = "not_applicable"

	proofBundleName = ".sourcegen-proof.json"
)

// ProofBundle records the deterministic inputs, outputs, ownership, capability
// claims, and remaining obligations for one sourcegen run.
type ProofBundle struct {
	SchemaVersion    string            `json:"schema_version"`
	GeneratorVersion string            `json:"generator_version"`
	SourceID         string            `json:"source_id"`
	InputDigest      string            `json:"input_digest"`
	GrammarFeatures  []string          `json:"grammar_features"`
	Outputs          []ProofOutput     `json:"outputs"`
	Obligations      []ProofObligation `json:"obligations"`
}

// ProofOutput identifies one sourcegen-owned artifact by content digest.
type ProofOutput struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	Ownership string `json:"ownership"`
}

// ProofObligation records evidence already produced and evidence still needed
// before a generated source can be promoted.
type ProofObligation struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Action string `json:"action,omitempty"`
}

func buildProofBundle(request normalizedRequest, manifest generationManifest) ProofBundle {
	outputs := make([]ProofOutput, 0, len(manifest.Outputs))
	for path, digest := range manifest.Outputs {
		outputs = append(outputs, ProofOutput{Path: path, Digest: digest, Ownership: "sourcegen"})
	}
	sort.Slice(outputs, func(left, right int) bool { return outputs[left].Path < outputs[right].Path })

	providerStatus := ProofStatusNotApplicable
	providerDetail := "This source was generated without provider API metadata."
	providerAction := ""
	if request.ProviderAPI != nil {
		providerStatus = ProofStatusPending
		providerDetail = "Provider API metadata is recorded, but no reviewed contract lock is attached."
		providerAction = "Generate and review a provider contract lock before promotion."
	}

	return ProofBundle{
		SchemaVersion:    ProofBundleSchemaVersion,
		GeneratorVersion: manifest.GeneratorVersion,
		SourceID:         manifest.SourceID,
		InputDigest:      manifest.InputDigest,
		GrammarFeatures:  grammarFeatures(request),
		Outputs:          outputs,
		Obligations: []ProofObligation{
			{ID: "sourcegen.input_digest", Status: ProofStatusPassed, Detail: "Normalized generator inputs have a deterministic content digest."},
			{ID: "sourcegen.output_digests", Status: ProofStatusPassed, Detail: "Every generated output has a deterministic content digest."},
			{ID: "sourcegen.output_ownership", Status: ProofStatusPassed, Detail: "Every listed output is owned by sourcegen and guarded against unreviewed edits."},
			{ID: "provider.contract_lock", Status: providerStatus, Detail: providerDetail, Action: providerAction},
			{ID: "runtime.semantic_replay", Status: ProofStatusPending, Detail: "Runtime output has not been compared with provider-shaped replay evidence.", Action: "Run differential or provider-fixture replay before promotion."},
		},
	}
}

func marshalProofBundle(bundle ProofBundle) ([]byte, error) {
	payload, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func grammarFeatures(request normalizedRequest) []string {
	features := map[string]struct{}{
		"auth." + firstNonEmptyString(request.AuthModel, AuthModelBearerToken):  {},
		"runtime." + firstNonEmptyString(request.SourceType, SourceTypeJSONAPI): {},
	}
	for _, family := range request.Families {
		method := strings.ToUpper(strings.TrimSpace(family.Method))
		if method == "" {
			method = "GET"
		}
		features["method."+method] = struct{}{}
		features["pagination."+firstNonEmptyString(family.PaginationType, "none")] = struct{}{}
		features["incremental."+firstNonEmptyString(family.IncrementalState, "none")] = struct{}{}
		projection := firstNonEmptyString(family.ProjectionTemplate, family.Class)
		if projection != "" {
			features["projection."+projection] = struct{}{}
		}
	}
	result := make([]string, 0, len(features))
	for feature := range features {
		result = append(result, feature)
	}
	sort.Strings(result)
	return result
}
