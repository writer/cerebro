// Package connectorimport industrializes connector-definition authoring. It
// turns a provider OpenAPI document into a classified, catalog-ready connector
// definition and aggregates a measured funnel (yield + blocking reasons) across
// a batch of providers.
//
// This package is pure: it operates on already-loaded OpenAPI documents and
// produces bytes and reports. Spec resolution (file, URL, registry) and file
// writing live in the tools/connectorimport CLI so that this package stays
// hermetically testable and free of network or environment access.
package connectorimport

import (
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/connectordefinitions/openapigen"
	"github.com/writer/cerebro/sources/catalogruntime"
)

// Verdict outcomes used by the funnel. The first three mirror the classifier
// verdicts; VerdictGenerationError captures specs the generic engine could not
// turn into a valid definition at all (the dominant real-world blocker).
const (
	VerdictSupported         = connectordefinitions.SupportVerdictSupported
	VerdictExtensionRequired = connectordefinitions.SupportVerdictExtensionRequired
	VerdictBespokeRequired   = connectordefinitions.SupportVerdictBespokeRequired
	VerdictGenerationError   = "generation_error"
	// VerdictRuntimeUnsupported marks definitions the classifier accepts but the
	// zero-code catalog runtime cannot actually execute (for example a non-GET
	// list method). The classifier verdict alone does not guarantee a connector
	// goes live without bespoke code; this is the gate that does.
	VerdictRuntimeUnsupported = "runtime_unsupported"
	// VerdictProofGate marks definitions that load at runtime but fail the
	// catalog proof gate (family count or high-value coverage) that catalog-check
	// enforces, so they are not promotable as-is.
	VerdictProofGate = "proof_gate"
)

// Target describes one provider to import.
type Target struct {
	SourceID    string   `json:"source_id" yaml:"source_id"`
	DisplayName string   `json:"display_name" yaml:"display_name"`
	Description string   `json:"description" yaml:"description"`
	Domain      string   `json:"domain" yaml:"domain"`
	Categories  []string `json:"categories" yaml:"categories"`
	BaseURL     string   `json:"base_url" yaml:"base_url"`
	AuthModel   string   `json:"auth_model" yaml:"auth_model"`
	MaxFamilies int      `json:"max_families" yaml:"max_families"`
	AllFamilies bool     `json:"all_families" yaml:"all_families"`
}

// Outcome is the per-target result of an import attempt.
type Outcome struct {
	SourceID        string                          `json:"source_id"`
	Domain          string                          `json:"domain"`
	Verdict         string                          `json:"verdict"`
	AuthModel       string                          `json:"auth_model,omitempty"`
	FamilyCount     int                             `json:"family_count,omitempty"`
	EndpointCount   int                             `json:"endpoint_count,omitempty"`
	MissingFeatures []string                        `json:"missing_features,omitempty"`
	Error           string                          `json:"error,omitempty"`
	Definition      connectordefinitions.Definition `json:"-"`
}

// CatalogReady reports whether the outcome can be promoted into the built-in
// catalog and go live with no per-connector Go code.
func (o Outcome) CatalogReady() bool {
	return o.Verdict == VerdictSupported && strings.TrimSpace(o.SourceID) != ""
}

// GenerateTarget runs the generic engine over one loaded OpenAPI document and
// classifies the result against the default grammar.
func GenerateTarget(doc *openapi3.T, target Target) Outcome {
	outcome := Outcome{SourceID: strings.TrimSpace(target.SourceID), Domain: strings.TrimSpace(target.Domain)}
	// The catalog proof gate accepts 2-4 resource families, so cap selection at
	// 4 regardless of the manifest. AllFamilies is ignored for the same reason.
	maxFamilies := target.MaxFamilies
	if maxFamilies <= 0 || maxFamilies > maxCatalogFamilies {
		maxFamilies = maxCatalogFamilies
	}
	definition, report, err := openapigen.Generate(doc, openapigen.Request{
		SourceID:    target.SourceID,
		DisplayName: target.DisplayName,
		Description: target.Description,
		Categories:  target.Categories,
		BaseURL:     target.BaseURL,
		AuthModel:   target.AuthModel,
		MaxFamilies: maxFamilies,
		AllFamilies: false,
		ListGETOnly: true,
	})
	if err != nil {
		outcome.Verdict = VerdictGenerationError
		outcome.Error = err.Error()
		return outcome
	}
	if outcome.SourceID == "" {
		outcome.SourceID = definition.SourceID
	}
	support, err := connectordefinitions.Classify(definition, connectordefinitions.DefaultGrammar())
	if err != nil {
		outcome.Verdict = VerdictGenerationError
		outcome.Error = "classify: " + err.Error()
		return outcome
	}
	outcome.Verdict = support.Verdict
	outcome.AuthModel = definition.Auth.Model
	outcome.FamilyCount = len(definition.ResourceFamilies)
	outcome.EndpointCount = report.EndpointCount
	outcome.MissingFeatures = support.MissingFeatures
	outcome.Definition = definition
	// A "supported" verdict is necessary but not sufficient for a zero-code live
	// connector: confirm the catalog runtime can actually construct it, then that
	// it clears the catalog proof gate that catalog-check enforces.
	if outcome.Verdict == VerdictSupported {
		if _, err := catalogruntime.NewDefinition(definition); err != nil {
			outcome.Verdict = VerdictRuntimeUnsupported
			outcome.Error = err.Error()
		} else if reason := proofGateReason(definition); reason != "" {
			outcome.Verdict = VerdictProofGate
			outcome.Error = reason
		}
	}
	return outcome
}

// maxCatalogFamilies is the upper bound the catalog proof gate accepts.
const maxCatalogFamilies = 4

// proofGateReason mirrors connectorcatalog.proofGateIssues: a catalog entry needs
// a verification endpoint, 2-4 resource families, and at least one high-value
// coverage dimension. It returns an empty string when the definition passes.
func proofGateReason(definition connectordefinitions.Definition) string {
	if definition.Transport == nil || definition.Transport.Verification == nil ||
		strings.TrimSpace(definition.Transport.Verification.Path) == "" {
		return "missing_verification"
	}
	if n := len(definition.ResourceFamilies); n < 2 || n > maxCatalogFamilies {
		return "family_count_out_of_range"
	}
	for _, family := range definition.ResourceFamilies {
		for _, dimension := range family.Coverage {
			if dimension.HighValue {
				return ""
			}
		}
	}
	return "no_high_value_coverage"
}
