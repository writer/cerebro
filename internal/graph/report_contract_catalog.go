package graph

import (
	"encoding/json"
	"fmt"
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

// ReportContractCompatibilityReport summarizes compatibility drift between baseline and current report catalogs.
type ReportContractCompatibilityReport struct {
	GeneratedAt              time.Time                          `json:"generated_at"`
	BaselineSectionEnvelopes int                                `json:"baseline_section_envelopes"`
	CurrentSectionEnvelopes  int                                `json:"current_section_envelopes"`
	BaselineBenchmarkPacks   int                                `json:"baseline_benchmark_packs"`
	CurrentBenchmarkPacks    int                                `json:"current_benchmark_packs"`
	AddedSectionEnvelopes    []string                           `json:"added_section_envelopes,omitempty"`
	RemovedSectionEnvelopes  []string                           `json:"removed_section_envelopes,omitempty"`
	AddedBenchmarkPacks      []string                           `json:"added_benchmark_packs,omitempty"`
	RemovedBenchmarkPacks    []string                           `json:"removed_benchmark_packs,omitempty"`
	BreakingChanges          []ReportContractCompatibilityIssue `json:"breaking_changes,omitempty"`
	VersioningViolations     []ReportContractCompatibilityIssue `json:"versioning_violations,omitempty"`
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

func benchmarkPackFingerprint(value BenchmarkPack) string {
	normalized := value
	normalized.Version = ""
	payload, _ := json.Marshal(normalized)
	return string(payload)
}
