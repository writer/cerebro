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
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/connectordefinitions/openapigen"
	"github.com/writer/cerebro/internal/sourceregistry"
	"gopkg.in/yaml.v3"
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

// computed definition keys that the catalog fills in at load time via
// connectordefinitions.Normalize. They are stripped from emitted entries so the
// committed catalog stays minimal and matches existing hand-authored entries.
var computedDefinitionKeys = []string{
	"validation",
	"promotion",
	"current_version",
	"runtime",
	"stage",
	"maturity",
	"created_at",
	"updated_at",
}

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
		if _, err := sourceregistry.DynamicDefinitionSource(definition); err != nil {
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

// Summary aggregates a batch funnel for CI artifacts and roadmap input.
type Summary struct {
	Targets            int            `json:"targets"`
	Supported          int            `json:"supported"`
	ExtensionNeeded    int            `json:"extension_required"`
	BespokeNeeded      int            `json:"bespoke_required"`
	RuntimeUnsupported int            `json:"runtime_unsupported"`
	ProofGateFailed    int            `json:"proof_gate_failed"`
	GenerationError    int            `json:"generation_error"`
	YieldPercent       float64        `json:"yield_percent"`
	ByAuthModel        map[string]int `json:"by_auth_model,omitempty"`
	ByDomain           map[string]int `json:"by_domain,omitempty"`
	BlockingReasons    map[string]int `json:"blocking_reasons,omitempty"`
}

// Summarize folds outcomes into a funnel. BlockingReasons combines classifier
// missing-feature identifiers with a coarse bucket for generation failures, so
// the histogram answers one question: what unblocks the most connectors next.
func Summarize(outcomes []Outcome) Summary {
	summary := Summary{
		ByAuthModel:     map[string]int{},
		ByDomain:        map[string]int{},
		BlockingReasons: map[string]int{},
	}
	for _, outcome := range outcomes {
		summary.Targets++
		if model := strings.TrimSpace(outcome.AuthModel); model != "" {
			summary.ByAuthModel[model]++
		}
		switch outcome.Verdict {
		case VerdictSupported:
			summary.Supported++
			if domain := strings.TrimSpace(outcome.Domain); domain != "" {
				summary.ByDomain[domain]++
			}
		case VerdictExtensionRequired:
			summary.ExtensionNeeded++
		case VerdictBespokeRequired:
			summary.BespokeNeeded++
		case VerdictRuntimeUnsupported:
			summary.RuntimeUnsupported++
			summary.BlockingReasons["runtime."+runtimeReasonBucket(outcome.Error)]++
		case VerdictProofGate:
			summary.ProofGateFailed++
			summary.BlockingReasons["proofgate."+strings.TrimSpace(outcome.Error)]++
		case VerdictGenerationError:
			summary.GenerationError++
			summary.BlockingReasons["generation."+generationReasonBucket(outcome.Error)]++
		}
		for _, feature := range outcome.MissingFeatures {
			summary.BlockingReasons[feature]++
		}
	}
	if summary.Targets > 0 {
		summary.YieldPercent = round1(float64(summary.Supported) * 100 / float64(summary.Targets))
	}
	if len(summary.ByAuthModel) == 0 {
		summary.ByAuthModel = nil
	}
	if len(summary.ByDomain) == 0 {
		summary.ByDomain = nil
	}
	if len(summary.BlockingReasons) == 0 {
		summary.BlockingReasons = nil
	}
	return summary
}

// catalogEntry mirrors the connectorcatalog.RawEntry shape for emission.
type catalogEntry struct {
	ClassifierOutput string         `json:"classifier_output"`
	Definition       map[string]any `json:"definition"`
}

type catalogFile struct {
	Entries []catalogEntry `json:"entries"`
}

// RenderCatalogEntries renders the catalog-ready (supported) outcomes as a YAML
// entries document compatible with the built-in catalog loader. Entries are
// sorted by source_id to match catalog review conventions.
func RenderCatalogEntries(header string, outcomes []Outcome) ([]byte, error) {
	ready := make([]Outcome, 0, len(outcomes))
	for _, outcome := range outcomes {
		if outcome.CatalogReady() {
			ready = append(ready, outcome)
		}
	}
	sort.SliceStable(ready, func(i, j int) bool { return ready[i].SourceID < ready[j].SourceID })
	file := catalogFile{Entries: make([]catalogEntry, 0, len(ready))}
	for _, outcome := range ready {
		definitionMap, err := minimalDefinitionMap(outcome.Definition)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", outcome.SourceID, err)
		}
		file.Entries = append(file.Entries, catalogEntry{
			ClassifierOutput: outcome.Verdict,
			Definition:       definitionMap,
		})
	}
	body, err := marshalYAMLWithJSONTags(file)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(header) == "" {
		return body, nil
	}
	return append([]byte(commentHeader(header)), body...), nil
}

// RenderCatalogEntryBlocks renders each supported outcome as a standalone YAML
// list item suitable for appending under an existing catalog file's `entries:`
// key, keyed by source_id for stable append order.
func RenderCatalogEntryBlocks(outcomes []Outcome) (map[string]string, error) {
	blocks := map[string]string{}
	for _, outcome := range outcomes {
		if !outcome.CatalogReady() {
			continue
		}
		definitionMap, err := minimalDefinitionMap(outcome.Definition)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", outcome.SourceID, err)
		}
		body, err := marshalYAMLWithJSONTags(catalogFile{Entries: []catalogEntry{{
			ClassifierOutput: outcome.Verdict,
			Definition:       definitionMap,
		}}})
		if err != nil {
			return nil, err
		}
		blocks[outcome.SourceID] = stripEntriesKey(string(body))
	}
	return blocks, nil
}

func minimalDefinitionMap(definition connectordefinitions.Definition) (map[string]any, error) {
	encoded, err := json.Marshal(definition)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		return nil, err
	}
	for _, key := range computedDefinitionKeys {
		delete(generic, key)
	}
	return generic, nil
}

func runtimeReasonBucket(message string) string {
	message = strings.ToLower(message)
	switch {
	case strings.Contains(message, "method") && strings.Contains(message, "not supported"):
		return "non_get_list_method"
	case strings.Contains(message, "runtime") && strings.Contains(message, "not supported"):
		return "non_jsonapi_runtime"
	case strings.Contains(message, "auth"):
		return "auth_not_executable"
	case strings.Contains(message, "transport"):
		return "transport_missing"
	default:
		return "other"
	}
}

func generationReasonBucket(message string) string {
	message = strings.ToLower(message)
	switch {
	case strings.Contains(message, "no sourcegen-ready") || strings.Contains(message, "get list"):
		return "no_list_endpoint"
	case strings.Contains(message, "openapi document is required") || strings.Contains(message, "load") || strings.Contains(message, "parse") || strings.Contains(message, "unmarshal"):
		return "spec_parse"
	case strings.Contains(message, "not valid") || strings.Contains(message, "blocked"):
		return "definition_invalid"
	default:
		return "other"
	}
}

func commentHeader(header string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
		b.WriteString("# ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func round1(value float64) float64 {
	return float64(int(value*10+0.5)) / 10
}

// marshalYAMLWithJSONTags emits YAML whose keys are JSON tag names, at the
// 2-space indentation the built-in catalog files use. It is the inverse of the
// catalog loader's YAML->JSON-tag decode path, so emitted entries round-trip.
func marshalYAMLWithJSONTags(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := yaml.Unmarshal(encoded, &generic); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(generic); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// stripEntriesKey removes the leading `entries:` line from a single-entry
// catalog render, leaving an indented list item that can be appended under an
// existing catalog file's `entries:` key.
func stripEntriesKey(body string) string {
	lines := strings.SplitN(body, "\n", 2)
	if len(lines) == 2 && strings.TrimSpace(lines[0]) == "entries:" {
		return lines[1]
	}
	return body
}
