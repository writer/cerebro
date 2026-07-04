package connectorcatalog

import (
	"strings"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

type ProviderAPIView struct {
	ProviderAPIContractViewFields
	ProviderAPIProofViewFields
	ProviderAPIDisproofViewFields
}

type ProviderAPIContractViewFields struct {
	HasProviderAPIContract     bool     `json:"has_provider_api_contract,omitempty"`
	HasProviderAPIMapping      bool     `json:"has_provider_api_mapping,omitempty"`
	ProviderAPIStatus          string   `json:"provider_api_status,omitempty"`
	ProviderAPIBasis           string   `json:"provider_api_basis,omitempty"`
	ProviderAPIVerifiedAt      string   `json:"provider_api_verified_at,omitempty"`
	ProviderAPITransport       string   `json:"provider_api_transport,omitempty"`
	ProviderAPIAuth            string   `json:"provider_api_auth,omitempty"`
	ProviderAPIAuthMechanics   string   `json:"provider_api_auth_mechanics,omitempty"`
	ProviderAPIBaseURL         string   `json:"provider_api_base_url,omitempty"`
	ProviderAPIEndpoint        string   `json:"provider_api_endpoint,omitempty"`
	ProviderAPISpecURL         string   `json:"provider_api_spec_url,omitempty"`
	ProviderAPISpecKind        string   `json:"provider_api_spec_kind,omitempty"`
	ProviderAPIReferences      []string `json:"provider_api_references,omitempty"`
	ProviderAPIAuthEvidence    []string `json:"provider_api_auth_evidence,omitempty"`
	ProviderAPIScopeEvidence   []string `json:"provider_api_scope_evidence,omitempty"`
	ProviderAPIMappedFamilies  []string `json:"provider_api_mapped_families,omitempty"`
	ProviderAPIMissingFamilies []string `json:"provider_api_missing_families,omitempty"`
}

type ProviderAPIProofViewFields struct {
	HasProviderAPIProof   bool     `json:"has_provider_api_proof,omitempty"`
	ProviderAPIProofScore int      `json:"provider_api_proof_score,omitempty"`
	ProviderAPIProofLevel string   `json:"provider_api_proof_level,omitempty"`
	ProviderAPIProofGaps  []string `json:"provider_api_proof_gaps,omitempty"`
}

type ProviderAPIDisproofViewFields struct {
	HasProviderAPIDisproof          bool     `json:"has_provider_api_disproof,omitempty"`
	ProviderAPIDisproofStatus       string   `json:"provider_api_disproof_status,omitempty"`
	ProviderAPIDisproofReason       string   `json:"provider_api_disproof_reason,omitempty"`
	ProviderAPIDisproofCheckedAt    string   `json:"provider_api_disproof_checked_at,omitempty"`
	ProviderAPIDisproofReferences   []string `json:"provider_api_disproof_references,omitempty"`
	ProviderAPIDisproofFamilies     []string `json:"provider_api_disproof_families,omitempty"`
	ProviderAPIDisproofMissingPaths []string `json:"provider_api_disproof_missing_paths,omitempty"`
	ProviderAPIDisproofNotes        []string `json:"provider_api_disproof_notes,omitempty"`
}

func ProviderAPIViewForDefinition(definition connectordefinitions.Definition) (ProviderAPIView, bool) {
	return ProviderAPIViewForDepth(ProviderAPIDepthForDefinition(definition))
}

func ProviderAPIViewForSource(sourceID string, definition connectordefinitions.Definition) ProviderAPIView {
	if api, runtimeFamilies, ok := sourcecdk.CatalogProviderAPIForSource(sourceID); ok {
		if view, present := ProviderAPIViewForDepth(ProviderAPIDepthForSourceCatalog(api, runtimeFamilies)); present {
			return view
		}
	}
	view, _ := ProviderAPIViewForDefinition(definition)
	return view
}

func ProviderAPIViewForDepth(depth RuntimeProviderAPIDepth) (ProviderAPIView, bool) {
	if !ProviderAPIViewPresent(depth) {
		return ProviderAPIView{}, false
	}
	return ProviderAPIView{
		ProviderAPIContractViewFields: ProviderAPIContractViewFields{
			HasProviderAPIContract:     depth.HasContract,
			HasProviderAPIMapping:      depth.HasMapping,
			ProviderAPIStatus:          depth.Status,
			ProviderAPIBasis:           depth.Basis,
			ProviderAPIVerifiedAt:      depth.VerifiedAt,
			ProviderAPITransport:       depth.Transport,
			ProviderAPIAuth:            depth.Auth,
			ProviderAPIAuthMechanics:   depth.AuthMechanics,
			ProviderAPIBaseURL:         depth.BaseURL,
			ProviderAPIEndpoint:        depth.Endpoint,
			ProviderAPISpecURL:         depth.SpecURL,
			ProviderAPISpecKind:        depth.SpecKind,
			ProviderAPIReferences:      append([]string(nil), depth.References...),
			ProviderAPIAuthEvidence:    append([]string(nil), depth.AuthEvidence...),
			ProviderAPIScopeEvidence:   append([]string(nil), depth.ScopeEvidence...),
			ProviderAPIMappedFamilies:  append([]string(nil), depth.MappedFamilies...),
			ProviderAPIMissingFamilies: append([]string(nil), depth.MissingFamilyMappings...),
		},
		ProviderAPIProofViewFields: ProviderAPIProofViewFields{
			HasProviderAPIProof:   depth.HasProof,
			ProviderAPIProofScore: depth.ProofScore,
			ProviderAPIProofLevel: depth.ProofLevel,
			ProviderAPIProofGaps:  append([]string(nil), depth.ProofGaps...),
		},
		ProviderAPIDisproofViewFields: ProviderAPIDisproofViewFields{
			HasProviderAPIDisproof:          depth.HasDisproof,
			ProviderAPIDisproofStatus:       depth.DisproofStatus,
			ProviderAPIDisproofReason:       depth.DisproofReason,
			ProviderAPIDisproofCheckedAt:    depth.DisproofCheckedAt,
			ProviderAPIDisproofReferences:   append([]string(nil), depth.DisproofReferences...),
			ProviderAPIDisproofFamilies:     append([]string(nil), depth.DisproofFamilies...),
			ProviderAPIDisproofMissingPaths: append([]string(nil), depth.DisproofMissingPaths...),
			ProviderAPIDisproofNotes:        append([]string(nil), depth.DisproofNotes...),
		},
	}, true
}

func ProviderAPIViewPresent(depth RuntimeProviderAPIDepth) bool {
	return depth.HasContract ||
		depth.HasMapping ||
		depth.HasProof ||
		depth.HasDisproof ||
		strings.TrimSpace(depth.Status) != "" ||
		strings.TrimSpace(depth.Basis) != "" ||
		strings.TrimSpace(depth.VerifiedAt) != "" ||
		strings.TrimSpace(depth.Transport) != "" ||
		strings.TrimSpace(depth.Auth) != "" ||
		strings.TrimSpace(depth.AuthMechanics) != "" ||
		strings.TrimSpace(depth.BaseURL) != "" ||
		strings.TrimSpace(depth.Endpoint) != "" ||
		strings.TrimSpace(depth.SpecURL) != "" ||
		strings.TrimSpace(depth.SpecKind) != "" ||
		len(depth.References) > 0 ||
		len(depth.AuthEvidence) > 0 ||
		len(depth.ScopeEvidence) > 0 ||
		len(depth.MappedFamilies) > 0 ||
		len(depth.MissingFamilyMappings) > 0 ||
		strings.TrimSpace(depth.DisproofStatus) != "" ||
		strings.TrimSpace(depth.DisproofReason) != "" ||
		strings.TrimSpace(depth.DisproofCheckedAt) != "" ||
		len(depth.DisproofReferences) > 0 ||
		len(depth.DisproofFamilies) > 0 ||
		len(depth.DisproofMissingPaths) > 0 ||
		len(depth.DisproofNotes) > 0
}
