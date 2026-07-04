package connectorcatalog

import (
	"sort"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
)

// ProviderAPIDepthForDefinition summarizes the provider-owned API proof
// declared on a connector definition without reading repository runtime files.
func ProviderAPIDepthForDefinition(definition connectordefinitions.Definition) RuntimeProviderAPIDepth {
	return ProviderAPIDepthForSpec(definition.ProviderAPI, definitionProviderFamilies(definition))
}

// ProviderAPIDepthForSourceCatalog summarizes provider-owned API proof declared
// by a compiled source catalog.
func ProviderAPIDepthForSourceCatalog(api sourcecdk.CatalogProviderAPI, runtimeFamilies []string) RuntimeProviderAPIDepth {
	fields := runtimeProviderAPIFields{
		Status:        api.Status,
		Basis:         api.Basis,
		VerifiedAt:    api.VerifiedAt,
		Transport:     api.Transport,
		Auth:          api.Auth,
		AuthMechanics: api.AuthMechanics,
		BaseURL:       api.BaseURL,
		Endpoint:      api.Endpoint,
		SpecURL:       api.SpecURL,
		SpecKind:      api.SpecKind,
		References:    normalizedList(api.References),
		AuthEvidence:  normalizedList(api.AuthEvidence),
		ScopeEvidence: normalizedList(api.ScopeEvidence),
		Families: make([]struct {
			ID        string `yaml:"id"`
			Method    string `yaml:"method"`
			Path      string `yaml:"path"`
			Operation string `yaml:"operation"`
		}, 0, len(api.Families)),
	}
	for _, family := range api.Families {
		fields.Families = append(fields.Families, struct {
			ID        string `yaml:"id"`
			Method    string `yaml:"method"`
			Path      string `yaml:"path"`
			Operation string `yaml:"operation"`
		}{
			ID:        family.ID,
			Method:    family.Method,
			Path:      family.Path,
			Operation: family.Operation,
		})
	}
	return providerAPIDepthForFields(fields, runtimeFamilies)
}

// ProviderAPIDepthForSpec applies the catalog provider API proof rules to an
// already-normalized provider API spec and the runtime families it should cover.
func ProviderAPIDepthForSpec(api *connectordefinitions.ProviderAPISpec, runtimeFamilies []string) RuntimeProviderAPIDepth {
	if api == nil {
		return RuntimeProviderAPIDepth{}
	}
	fields := runtimeProviderAPIFields{
		Status:        api.Status,
		Basis:         api.Basis,
		VerifiedAt:    api.VerifiedAt,
		Transport:     api.Transport,
		Auth:          api.Auth,
		AuthMechanics: api.AuthMechanics,
		BaseURL:       api.BaseURL,
		Endpoint:      api.Endpoint,
		SpecURL:       api.SpecURL,
		SpecKind:      api.SpecKind,
		References:    normalizedList(api.References),
		AuthEvidence:  normalizedList(api.AuthEvidence),
		ScopeEvidence: normalizedList(api.ScopeEvidence),
		Families: make([]struct {
			ID        string `yaml:"id"`
			Method    string `yaml:"method"`
			Path      string `yaml:"path"`
			Operation string `yaml:"operation"`
		}, 0, len(api.Families)),
	}
	for _, family := range api.Families {
		fields.Families = append(fields.Families, struct {
			ID        string `yaml:"id"`
			Method    string `yaml:"method"`
			Path      string `yaml:"path"`
			Operation string `yaml:"operation"`
		}{
			ID:        family.ID,
			Method:    family.Method,
			Path:      family.Path,
			Operation: family.Operation,
		})
	}
	return providerAPIDepthForFields(fields, runtimeFamilies)
}

func providerAPIDepthForFields(fields runtimeProviderAPIFields, runtimeFamilies []string) RuntimeProviderAPIDepth {
	mappedFamilies := providerAPIFamilies(fields)
	missingFamilies := missingValues(normalizedList(runtimeFamilies), mappedFamilies)
	proof := providerAPIProofScore(fields, missingFamilies)
	depth := RuntimeProviderAPIDepth{
		RuntimeProviderAPIContractDepth: RuntimeProviderAPIContractDepth{
			HasContract:           hasProviderAPIContract(fields),
			HasMapping:            hasProviderAPIContract(fields) && len(missingFamilies) == 0 && len(mappedFamilies) > 0,
			Status:                fields.Status,
			Basis:                 fields.Basis,
			VerifiedAt:            fields.VerifiedAt,
			Transport:             fields.Transport,
			Auth:                  fields.Auth,
			AuthMechanics:         fields.AuthMechanics,
			BaseURL:               fields.BaseURL,
			Endpoint:              fields.Endpoint,
			SpecURL:               fields.SpecURL,
			SpecKind:              fields.SpecKind,
			References:            append([]string(nil), fields.References...),
			AuthEvidence:          append([]string(nil), fields.AuthEvidence...),
			ScopeEvidence:         append([]string(nil), fields.ScopeEvidence...),
			MappedFamilies:        append([]string(nil), mappedFamilies...),
			MissingFamilyMappings: append([]string(nil), missingFamilies...),
		},
		RuntimeProviderAPIProofDepth: RuntimeProviderAPIProofDepth{
			HasProof:   proof.HasProof,
			ProofScore: proof.Score,
			ProofLevel: proof.Level,
			ProofGaps:  append([]string(nil), proof.Gaps...),
		},
	}
	sort.Strings(depth.ProofGaps)
	sort.Strings(depth.References)
	sort.Strings(depth.AuthEvidence)
	sort.Strings(depth.ScopeEvidence)
	sort.Strings(depth.MappedFamilies)
	sort.Strings(depth.MissingFamilyMappings)
	return depth
}

func definitionProviderFamilies(definition connectordefinitions.Definition) []string {
	values := make([]string, 0, len(definition.ResourceFamilies))
	for _, family := range definition.ResourceFamilies {
		values = append(values, family.ID)
	}
	return normalizedList(values)
}
