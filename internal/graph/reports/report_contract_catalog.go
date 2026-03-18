package reports

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	defaultReportContractCatalogAPIVersion = "cerebro.report.contracts/v1alpha1"
	defaultReportContractCatalogKind       = "ReportContractCatalog"
)

// ReportContractCatalog captures the machine-readable contract surface for the report runtime.
type ReportContractCatalog struct {
	APIVersion       string                            `json:"apiVersion"`
	Kind             string                            `json:"kind"`
	GeneratedAt      time.Time                         `json:"generated_at,omitempty"`
	Reports          []ReportDefinition                `json:"reports,omitempty"`
	Measures         []ReportMeasure                   `json:"measures,omitempty"`
	Checks           []ReportCheck                     `json:"checks,omitempty"`
	SectionEnvelopes []ReportSectionEnvelopeDefinition `json:"section_envelopes,omitempty"`
	SectionFragments []ReportSectionFragmentDefinition `json:"section_fragments,omitempty"`
	BenchmarkPacks   []BenchmarkPack                   `json:"benchmark_packs,omitempty"`
}

// ReportContractCompatibilityIssue captures one compatibility-affecting change.
type ReportContractCompatibilityIssue struct {
	ContractType    string `json:"contract_type,omitempty"`
	ContractID      string `json:"contract_id,omitempty"`
	ChangeType      string `json:"change_type"`
	Detail          string `json:"detail"`
	PreviousVersion string `json:"previous_version,omitempty"`
	CurrentVersion  string `json:"current_version,omitempty"`
}

// ReportContractDiffSummary captures field-level diff paths for one changed contract.
type ReportContractDiffSummary struct {
	ContractType    string   `json:"contract_type,omitempty"`
	ContractID      string   `json:"contract_id,omitempty"`
	PreviousVersion string   `json:"previous_version,omitempty"`
	CurrentVersion  string   `json:"current_version,omitempty"`
	AddedPaths      []string `json:"added_paths,omitempty"`
	RemovedPaths    []string `json:"removed_paths,omitempty"`
	ChangedPaths    []string `json:"changed_paths,omitempty"`
}

// ReportContractCompatibilityReport summarizes compatibility drift between baseline and current report catalogs.
type ReportContractCompatibilityReport struct {
	GeneratedAt              time.Time                          `json:"generated_at"`
	BaselineSectionEnvelopes int                                `json:"baseline_section_envelopes"`
	CurrentSectionEnvelopes  int                                `json:"current_section_envelopes"`
	BaselineSectionFragments int                                `json:"baseline_section_fragments"`
	CurrentSectionFragments  int                                `json:"current_section_fragments"`
	BaselineBenchmarkPacks   int                                `json:"baseline_benchmark_packs"`
	CurrentBenchmarkPacks    int                                `json:"current_benchmark_packs"`
	AddedSectionEnvelopes    []string                           `json:"added_section_envelopes,omitempty"`
	RemovedSectionEnvelopes  []string                           `json:"removed_section_envelopes,omitempty"`
	AddedSectionFragments    []string                           `json:"added_section_fragments,omitempty"`
	RemovedSectionFragments  []string                           `json:"removed_section_fragments,omitempty"`
	AddedBenchmarkPacks      []string                           `json:"added_benchmark_packs,omitempty"`
	RemovedBenchmarkPacks    []string                           `json:"removed_benchmark_packs,omitempty"`
	BreakingChanges          []ReportContractCompatibilityIssue `json:"breaking_changes,omitempty"`
	VersioningViolations     []ReportContractCompatibilityIssue `json:"versioning_violations,omitempty"`
	DiffSummaries            []ReportContractDiffSummary        `json:"diff_summaries,omitempty"`
	Compatible               bool                               `json:"compatible"`
}

// BuildReportContractCatalog constructs the current report contract catalog from built-in registries.
func BuildReportContractCatalog(now time.Time) ReportContractCatalog {
	if !now.IsZero() {
		now = now.UTC()
	}
	return ReportContractCatalog{
		APIVersion:       defaultReportContractCatalogAPIVersion,
		Kind:             defaultReportContractCatalogKind,
		GeneratedAt:      now,
		Reports:          ReportCatalogSnapshot(time.Time{}).Reports,
		Measures:         ReportMeasureCatalogSnapshot(time.Time{}).Measures,
		Checks:           ReportCheckCatalogSnapshot(time.Time{}).Checks,
		SectionEnvelopes: ListReportSectionEnvelopeDefinitions(),
		SectionFragments: ListReportSectionFragmentDefinitions(),
		BenchmarkPacks:   ListBenchmarkPacks(),
	}
}

// CompareReportContractCatalogs evaluates compatibility drift between two report contract catalogs.
func CompareReportContractCatalogs(baseline, current ReportContractCatalog, now time.Time) ReportContractCompatibilityReport {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	report := ReportContractCompatibilityReport{
		GeneratedAt:              now,
		BaselineSectionEnvelopes: len(baseline.SectionEnvelopes),
		CurrentSectionEnvelopes:  len(current.SectionEnvelopes),
		BaselineSectionFragments: len(baseline.SectionFragments),
		CurrentSectionFragments:  len(current.SectionFragments),
		BaselineBenchmarkPacks:   len(baseline.BenchmarkPacks),
		CurrentBenchmarkPacks:    len(current.BenchmarkPacks),
		Compatible:               true,
	}

	baselineEnvelopes := make(map[string]ReportSectionEnvelopeDefinition, len(baseline.SectionEnvelopes))
	for _, envelope := range baseline.SectionEnvelopes {
		baselineEnvelopes[strings.TrimSpace(envelope.ID)] = envelope
	}
	currentEnvelopes := make(map[string]ReportSectionEnvelopeDefinition, len(current.SectionEnvelopes))
	for _, envelope := range current.SectionEnvelopes {
		currentEnvelopes[strings.TrimSpace(envelope.ID)] = envelope
	}
	compareReportContractMaps("section_envelope", baselineEnvelopes, currentEnvelopes, envelopeFingerprint, &report)

	baselineFragments := make(map[string]ReportSectionFragmentDefinition, len(baseline.SectionFragments))
	for _, fragment := range baseline.SectionFragments {
		baselineFragments[strings.TrimSpace(fragment.ID)] = fragment
	}
	currentFragments := make(map[string]ReportSectionFragmentDefinition, len(current.SectionFragments))
	for _, fragment := range current.SectionFragments {
		currentFragments[strings.TrimSpace(fragment.ID)] = fragment
	}
	compareReportContractMaps("section_fragment", baselineFragments, currentFragments, fragmentFingerprint, &report)

	baselinePacks := make(map[string]BenchmarkPack, len(baseline.BenchmarkPacks))
	for _, pack := range baseline.BenchmarkPacks {
		baselinePacks[strings.TrimSpace(pack.ID)] = pack
	}
	currentPacks := make(map[string]BenchmarkPack, len(current.BenchmarkPacks))
	for _, pack := range current.BenchmarkPacks {
		currentPacks[strings.TrimSpace(pack.ID)] = pack
	}
	compareReportContractMaps("benchmark_pack", baselinePacks, currentPacks, benchmarkPackFingerprint, &report)

	report.Compatible = len(report.VersioningViolations) == 0
	sort.Strings(report.AddedSectionEnvelopes)
	sort.Strings(report.RemovedSectionEnvelopes)
	sort.Strings(report.AddedSectionFragments)
	sort.Strings(report.RemovedSectionFragments)
	sort.Strings(report.AddedBenchmarkPacks)
	sort.Strings(report.RemovedBenchmarkPacks)
	return report
}

func compareReportContractMaps[T any](contractType string, baseline, current map[string]T, fingerprint func(T) string, report *ReportContractCompatibilityReport) {
	ids := make(map[string]struct{}, len(baseline)+len(current))
	for id := range baseline {
		ids[id] = struct{}{}
	}
	for id := range current {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)

	for _, id := range ordered {
		before, hadBefore := baseline[id]
		after, hasAfter := current[id]
		switch {
		case hadBefore && !hasAfter:
			issue := ReportContractCompatibilityIssue{
				ContractType:    contractType,
				ContractID:      id,
				ChangeType:      "removed",
				Detail:          fmt.Sprintf("%s %q was removed", contractType, id),
				PreviousVersion: contractVersion(before),
			}
			appendReportContractIssue(report, issue, true)
		case !hadBefore && hasAfter:
			switch contractType {
			case "section_envelope":
				report.AddedSectionEnvelopes = append(report.AddedSectionEnvelopes, id)
			case "section_fragment":
				report.AddedSectionFragments = append(report.AddedSectionFragments, id)
			case "benchmark_pack":
				report.AddedBenchmarkPacks = append(report.AddedBenchmarkPacks, id)
			}
		case hadBefore && hasAfter:
			beforeFingerprint := fingerprint(before)
			afterFingerprint := fingerprint(after)
			if beforeFingerprint == afterFingerprint {
				continue
			}
			issue := ReportContractCompatibilityIssue{
				ContractType:    contractType,
				ContractID:      id,
				ChangeType:      "changed",
				Detail:          fmt.Sprintf("%s %q contract changed", contractType, id),
				PreviousVersion: contractVersion(before),
				CurrentVersion:  contractVersion(after),
			}
			appendReportContractIssue(report, issue, issue.PreviousVersion == issue.CurrentVersion)
			appendReportContractDiffSummary(report, buildReportContractDiffSummary(issue, before, after))
		}
	}
}

func appendReportContractIssue(report *ReportContractCompatibilityReport, issue ReportContractCompatibilityIssue, failVersioning bool) {
	if report == nil {
		return
	}
	report.BreakingChanges = append(report.BreakingChanges, issue)
	switch issue.ContractType {
	case "section_envelope":
		if issue.ChangeType == "removed" {
			report.RemovedSectionEnvelopes = append(report.RemovedSectionEnvelopes, issue.ContractID)
		}
	case "section_fragment":
		if issue.ChangeType == "removed" {
			report.RemovedSectionFragments = append(report.RemovedSectionFragments, issue.ContractID)
		}
	case "benchmark_pack":
		if issue.ChangeType == "removed" {
			report.RemovedBenchmarkPacks = append(report.RemovedBenchmarkPacks, issue.ContractID)
		}
	}
	if failVersioning {
		report.VersioningViolations = append(report.VersioningViolations, issue)
	}
}

func contractVersion(value any) string {
	switch typed := value.(type) {
	case ReportSectionEnvelopeDefinition:
		return strings.TrimSpace(typed.Version)
	case ReportSectionFragmentDefinition:
		return strings.TrimSpace(typed.Version)
	case BenchmarkPack:
		return strings.TrimSpace(typed.Version)
	default:
		return ""
	}
}

func envelopeFingerprint(value ReportSectionEnvelopeDefinition) string {
	normalized := value
	normalized.Version = ""
	payload, _ := json.Marshal(normalized)
	return string(payload)
}

func fragmentFingerprint(value ReportSectionFragmentDefinition) string {
	normalized := value
	normalized.Version = ""
	payload, _ := json.Marshal(normalized)
	return string(payload)
}

func benchmarkPackFingerprint(value BenchmarkPack) string {
	normalized := value
	normalized.Version = ""
	payload, _ := json.Marshal(normalized)
	return string(payload)
}

func appendReportContractDiffSummary(report *ReportContractCompatibilityReport, diff ReportContractDiffSummary) {
	if report == nil {
		return
	}
	if len(diff.AddedPaths) == 0 && len(diff.RemovedPaths) == 0 && len(diff.ChangedPaths) == 0 {
		return
	}
	report.DiffSummaries = append(report.DiffSummaries, diff)
}

func buildReportContractDiffSummary(issue ReportContractCompatibilityIssue, before, after any) ReportContractDiffSummary {
	diff := ReportContractDiffSummary{
		ContractType:    issue.ContractType,
		ContractID:      issue.ContractID,
		PreviousVersion: issue.PreviousVersion,
		CurrentVersion:  issue.CurrentVersion,
	}
	diff.AddedPaths, diff.RemovedPaths, diff.ChangedPaths = reportContractDiffPaths(before, after)
	return diff
}

func reportContractDiffPaths(before, after any) ([]string, []string, []string) {
	left := reportContractValueTree(before)
	right := reportContractValueTree(after)
	added := make([]string, 0)
	removed := make([]string, 0)
	changed := make([]string, 0)
	collectReportContractDiffPaths("$", left, right, &added, &removed, &changed)
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

func reportContractValueTree(value any) any {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil
	}
	return decoded
}

func collectReportContractDiffPaths(path string, before, after any, added, removed, changed *[]string) {
	switch beforeTyped := before.(type) {
	case map[string]any:
		afterTyped, ok := after.(map[string]any)
		if !ok {
			*changed = append(*changed, path)
			return
		}
		keys := make(map[string]struct{}, len(beforeTyped)+len(afterTyped))
		for key := range beforeTyped {
			keys[key] = struct{}{}
		}
		for key := range afterTyped {
			keys[key] = struct{}{}
		}
		ordered := make([]string, 0, len(keys))
		for key := range keys {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		for _, key := range ordered {
			nextPath := path + "." + key
			beforeValue, hadBefore := beforeTyped[key]
			afterValue, hasAfter := afterTyped[key]
			switch {
			case hadBefore && !hasAfter:
				*removed = append(*removed, nextPath)
			case !hadBefore && hasAfter:
				*added = append(*added, nextPath)
			default:
				collectReportContractDiffPaths(nextPath, beforeValue, afterValue, added, removed, changed)
			}
		}
	case []any:
		afterTyped, ok := after.([]any)
		if !ok || !reflect.DeepEqual(beforeTyped, afterTyped) {
			*changed = append(*changed, path)
		}
	default:
		if !reflect.DeepEqual(before, after) {
			*changed = append(*changed, path)
		}
	}
}
