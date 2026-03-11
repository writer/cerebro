package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	defaultEntityFacetContractCatalogAPIVersion = "cerebro.entity-facets/v1alpha1"
	defaultEntityFacetContractCatalogKind       = "EntityFacetContractCatalog"
)

// EntityFacetContractCatalog captures the machine-readable contract surface for entity facets.
type EntityFacetContractCatalog struct {
	APIVersion  string                  `json:"apiVersion"`
	Kind        string                  `json:"kind"`
	GeneratedAt time.Time               `json:"generated_at,omitempty"`
	Facets      []EntityFacetDefinition `json:"facets,omitempty"`
}

// EntityFacetCompatibilityIssue captures one compatibility-affecting change.
type EntityFacetCompatibilityIssue struct {
	FacetID         string `json:"facet_id,omitempty"`
	ChangeType      string `json:"change_type"`
	Detail          string `json:"detail"`
	PreviousVersion string `json:"previous_version,omitempty"`
	CurrentVersion  string `json:"current_version,omitempty"`
}

// EntityFacetDiffSummary captures field-level diff paths for one changed facet contract.
type EntityFacetDiffSummary struct {
	FacetID         string   `json:"facet_id,omitempty"`
	PreviousVersion string   `json:"previous_version,omitempty"`
	CurrentVersion  string   `json:"current_version,omitempty"`
	AddedPaths      []string `json:"added_paths,omitempty"`
	RemovedPaths    []string `json:"removed_paths,omitempty"`
	ChangedPaths    []string `json:"changed_paths,omitempty"`
}

// EntityFacetCompatibilityReport summarizes compatibility drift between baseline and current facet catalogs.
type EntityFacetCompatibilityReport struct {
	GeneratedAt          time.Time                       `json:"generated_at"`
	BaselineFacets       int                             `json:"baseline_facets"`
	CurrentFacets        int                             `json:"current_facets"`
	AddedFacets          []string                        `json:"added_facets,omitempty"`
	RemovedFacets        []string                        `json:"removed_facets,omitempty"`
	BreakingChanges      []EntityFacetCompatibilityIssue `json:"breaking_changes,omitempty"`
	VersioningViolations []EntityFacetCompatibilityIssue `json:"versioning_violations,omitempty"`
	DiffSummaries        []EntityFacetDiffSummary        `json:"diff_summaries,omitempty"`
	Compatible           bool                            `json:"compatible"`
}

func BuildEntityFacetContractCatalog(now time.Time) EntityFacetContractCatalog {
	// Zero time is preserved intentionally so generated artifacts can omit
	// generated_at and remain deterministic across runs. API callers that need a
	// timestamp should pass an explicit time.
	if !now.IsZero() {
		now = now.UTC()
	}
	return EntityFacetContractCatalog{
		APIVersion:  defaultEntityFacetContractCatalogAPIVersion,
		Kind:        defaultEntityFacetContractCatalogKind,
		GeneratedAt: now,
		Facets:      ListEntityFacetDefinitions(),
	}
}

func CompareEntityFacetContractCatalogs(baseline, current EntityFacetContractCatalog, now time.Time) EntityFacetCompatibilityReport {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	report := EntityFacetCompatibilityReport{
		GeneratedAt:    now,
		BaselineFacets: len(baseline.Facets),
		CurrentFacets:  len(current.Facets),
		Compatible:     true,
	}
	baselineByID := make(map[string]EntityFacetDefinition, len(baseline.Facets))
	for _, facet := range baseline.Facets {
		baselineByID[strings.TrimSpace(facet.ID)] = facet
	}
	currentByID := make(map[string]EntityFacetDefinition, len(current.Facets))
	for _, facet := range current.Facets {
		currentByID[strings.TrimSpace(facet.ID)] = facet
	}
	ids := make(map[string]struct{}, len(baselineByID)+len(currentByID))
	for id := range baselineByID {
		ids[id] = struct{}{}
	}
	for id := range currentByID {
		ids[id] = struct{}{}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		before, hadBefore := baselineByID[id]
		after, hasAfter := currentByID[id]
		switch {
		case hadBefore && !hasAfter:
			issue := EntityFacetCompatibilityIssue{
				FacetID:         id,
				ChangeType:      "removed",
				Detail:          fmt.Sprintf("facet %q was removed", id),
				PreviousVersion: strings.TrimSpace(before.Version),
			}
			report.RemovedFacets = append(report.RemovedFacets, id)
			report.BreakingChanges = append(report.BreakingChanges, issue)
		case !hadBefore && hasAfter:
			report.AddedFacets = append(report.AddedFacets, id)
		case hadBefore && hasAfter:
			if entityFacetFingerprint(before) == entityFacetFingerprint(after) {
				continue
			}
			diffSummary := buildEntityFacetDiffSummary(id, before, after)
			issue := EntityFacetCompatibilityIssue{
				FacetID:         id,
				ChangeType:      "changed",
				Detail:          fmt.Sprintf("facet %q contract changed", id),
				PreviousVersion: strings.TrimSpace(before.Version),
				CurrentVersion:  strings.TrimSpace(after.Version),
			}
			if entityFacetDiffIsBreaking(diffSummary) {
				report.BreakingChanges = append(report.BreakingChanges, issue)
			}
			if issue.PreviousVersion == issue.CurrentVersion {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
			report.DiffSummaries = append(report.DiffSummaries, diffSummary.withVersions(issue.PreviousVersion, issue.CurrentVersion))
		}
	}
	sort.Strings(report.AddedFacets)
	sort.Strings(report.RemovedFacets)
	report.Compatible = len(report.BreakingChanges) == 0 && len(report.VersioningViolations) == 0
	return report
}

func entityFacetFingerprint(value EntityFacetDefinition) string {
	normalized := buildEntityFacetContractSurface(value)
	payload, _ := json.Marshal(normalized)
	return string(payload)
}

type entityFacetFieldContractSurface struct {
	Key       string `json:"key"`
	ValueType string `json:"value_type"`
}

type entityFacetContractSurface struct {
	ID              string                            `json:"id"`
	SchemaName      string                            `json:"schema_name"`
	SchemaURL       string                            `json:"schema_url"`
	ApplicableKinds []NodeKind                        `json:"applicable_kinds,omitempty"`
	SourceKeys      []string                          `json:"source_keys,omitempty"`
	ClaimPredicates []string                          `json:"claim_predicates,omitempty"`
	Fields          []entityFacetFieldContractSurface `json:"fields,omitempty"`
}

func buildEntityFacetContractSurface(value EntityFacetDefinition) entityFacetContractSurface {
	fields := make([]entityFacetFieldContractSurface, 0, len(value.Fields))
	for _, field := range value.Fields {
		fields = append(fields, entityFacetFieldContractSurface{
			Key:       field.Key,
			ValueType: field.ValueType,
		})
	}
	return entityFacetContractSurface{
		ID:              value.ID,
		SchemaName:      value.SchemaName,
		SchemaURL:       value.SchemaURL,
		ApplicableKinds: append([]NodeKind(nil), value.ApplicableKinds...),
		SourceKeys:      append([]string(nil), value.SourceKeys...),
		ClaimPredicates: append([]string(nil), value.ClaimPredicates...),
		Fields:          fields,
	}
}

func buildEntityFacetDiffSummary(facetID string, before, after EntityFacetDefinition) EntityFacetDiffSummary {
	summary := EntityFacetDiffSummary{FacetID: facetID}
	if before.SchemaName != after.SchemaName {
		summary.ChangedPaths = append(summary.ChangedPaths, "$.schema_name")
	}
	if before.SchemaURL != after.SchemaURL {
		summary.ChangedPaths = append(summary.ChangedPaths, "$.schema_url")
	}
	summary.AddedPaths = append(summary.AddedPaths, diffAddedStrings("$.applicable_kinds", nodeKindsToStrings(before.ApplicableKinds), nodeKindsToStrings(after.ApplicableKinds))...)
	summary.RemovedPaths = append(summary.RemovedPaths, diffRemovedStrings("$.applicable_kinds", nodeKindsToStrings(before.ApplicableKinds), nodeKindsToStrings(after.ApplicableKinds))...)
	summary.AddedPaths = append(summary.AddedPaths, diffAddedStrings("$.source_keys", before.SourceKeys, after.SourceKeys)...)
	summary.RemovedPaths = append(summary.RemovedPaths, diffRemovedStrings("$.source_keys", before.SourceKeys, after.SourceKeys)...)
	summary.AddedPaths = append(summary.AddedPaths, diffAddedStrings("$.claim_predicates", before.ClaimPredicates, after.ClaimPredicates)...)
	summary.RemovedPaths = append(summary.RemovedPaths, diffRemovedStrings("$.claim_predicates", before.ClaimPredicates, after.ClaimPredicates)...)
	addedFields, removedFields, changedFields := diffFacetFields(before.Fields, after.Fields)
	summary.AddedPaths = append(summary.AddedPaths, addedFields...)
	summary.RemovedPaths = append(summary.RemovedPaths, removedFields...)
	summary.ChangedPaths = append(summary.ChangedPaths, changedFields...)
	sort.Strings(summary.AddedPaths)
	sort.Strings(summary.RemovedPaths)
	sort.Strings(summary.ChangedPaths)
	return summary
}

func entityFacetDiffIsBreaking(summary EntityFacetDiffSummary) bool {
	return len(summary.RemovedPaths) > 0 || len(summary.ChangedPaths) > 0
}

func (s EntityFacetDiffSummary) withVersions(previousVersion, currentVersion string) EntityFacetDiffSummary {
	s.PreviousVersion = previousVersion
	s.CurrentVersion = currentVersion
	return s
}

func nodeKindsToStrings(values []NodeKind) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func diffAddedStrings(basePath string, before, after []string) []string {
	beforeSet := make(map[string]struct{}, len(before))
	for _, value := range before {
		beforeSet[value] = struct{}{}
	}
	added := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range after {
		if _, ok := beforeSet[value]; ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		added = append(added, fmt.Sprintf("%s[%q]", basePath, value))
	}
	return added
}

func diffRemovedStrings(basePath string, before, after []string) []string {
	afterSet := make(map[string]struct{}, len(after))
	for _, value := range after {
		afterSet[value] = struct{}{}
	}
	removed := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range before {
		if _, ok := afterSet[value]; ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		removed = append(removed, fmt.Sprintf("%s[%q]", basePath, value))
	}
	return removed
}

func diffFacetFields(before, after []EntityFacetFieldDefinition) (added, removed, changed []string) {
	beforeByKey := make(map[string]EntityFacetFieldDefinition, len(before))
	for _, field := range before {
		beforeByKey[field.Key] = field
	}
	afterByKey := make(map[string]EntityFacetFieldDefinition, len(after))
	for _, field := range after {
		afterByKey[field.Key] = field
	}
	for key := range beforeByKey {
		if _, ok := afterByKey[key]; !ok {
			removed = append(removed, fmt.Sprintf("$.fields[%q]", key))
		}
	}
	for key, afterField := range afterByKey {
		beforeField, ok := beforeByKey[key]
		if !ok {
			added = append(added, fmt.Sprintf("$.fields[%q]", key))
			continue
		}
		if beforeField.ValueType != afterField.ValueType {
			changed = append(changed, fmt.Sprintf("$.fields[%q].value_type", key))
		}
	}
	return added, removed, changed
}
