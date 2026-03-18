package compliance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/graph"
	entities "github.com/writer/cerebro/internal/graph/entities"
)

func newGraphPolicyEvaluation(policyID string) policyEvaluation {
	return policyEvaluation{
		PolicyID:      policyID,
		Supported:     true,
		Source:        ControlEvaluationSourceGraph,
		FailEntityIDs: make(map[string]struct{}),
		PassEntityIDs: make(map[string]struct{}),
	}
}

func (e *graphComplianceEvaluator) entityRecords(provider string, kinds ...graph.NodeKind) []entities.EntityRecord {
	sortKinds := append([]graph.NodeKind(nil), kinds...)
	sort.Slice(sortKinds, func(i, j int) bool { return sortKinds[i] < sortKinds[j] })
	parts := []string{provider}
	for _, kind := range sortKinds {
		parts = append(parts, string(kind))
	}
	cacheKey := strings.Join(parts, "|")
	if cached, ok := e.entityCache[cacheKey]; ok {
		return cached
	}
	kindSet := make(map[graph.NodeKind]struct{}, len(sortKinds))
	for _, kind := range sortKinds {
		kindSet[kind] = struct{}{}
	}
	records := make([]entities.EntityRecord, 0)
	if e.graph != nil {
		for _, node := range e.graph.GetAllNodesBitemporal(e.validAt, e.recordedAt) {
			if node == nil {
				continue
			}
			if provider != "" && !strings.EqualFold(strings.TrimSpace(node.Provider), provider) {
				continue
			}
			if len(kindSet) > 0 {
				if _, ok := kindSet[node.Kind]; !ok {
					continue
				}
			}
			record, ok := entities.GetEntityRecord(e.graph, node.ID, e.validAt, e.recordedAt)
			if !ok {
				continue
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	e.entityCache[cacheKey] = records
	return records
}

func summarizePolicyStatus(result policyEvaluation, unknown, totalRecords int) string {
	switch {
	case result.Failing > 0:
		return ControlStateFailing
	case result.Applicable == 0 && totalRecords == 0:
		return ControlStateNotApplicable
	case result.Applicable == 0 && unknown > 0:
		return ControlStateUnknown
	case result.Applicable == 0:
		return ControlStateNotApplicable
	case unknown > 0:
		if result.Passing > 0 {
			return ControlStatePartial
		}
		return ControlStateUnknown
	case result.Passing > 0:
		return ControlStatePassing
	default:
		return ControlStateUnknown
	}
}

func controlEvidence(record entities.EntityRecord, facetID, policyID, status, reason string) ControlEvidence {
	return ControlEvidence{
		EntityID:   record.ID,
		EntityKind: string(record.Kind),
		EntityName: record.Name,
		FacetID:    facetID,
		PolicyID:   policyID,
		Status:     status,
		Reason:     reason,
	}
}

func entityFacet(record entities.EntityRecord, facetID string) (entities.EntityFacetRecord, bool) {
	for _, facet := range record.Facets {
		if facet.ID == facetID {
			return facet, true
		}
	}
	return entities.EntityFacetRecord{}, false
}

func sensitiveDataState(record entities.EntityRecord) (bool, bool) {
	facet, ok := entityFacet(record, "data_sensitivity")
	if !ok {
		return false, false
	}
	classification := strings.TrimSpace(strings.ToLower(stringField(facet.Fields, "classification")))
	if classification != "" && classification != "none" {
		return true, true
	}
	for _, field := range []string{"contains_pii", "contains_phi", "contains_pci", "contains_secrets"} {
		if value, ok := boolField(facet.Fields, field); ok && value {
			return true, true
		}
	}
	for _, field := range []string{"contains_pii", "contains_phi", "contains_pci", "contains_secrets"} {
		if _, ok := boolField(facet.Fields, field); ok {
			return false, true
		}
	}
	return false, false
}

func encryptionState(record entities.EntityRecord) (bool, bool, string) {
	if facet, ok := entityFacet(record, "bucket_encryption"); ok {
		if value, ok := boolField(facet.Fields, "encrypted"); ok {
			return value, true, facet.ID
		}
	}
	if value, ok := firstBool(record.Properties, "encrypted", "storage_encrypted", "kms_encrypted"); ok {
		return value, true, ""
	}
	return false, false, ""
}

func publicExposureState(record entities.EntityRecord) (bool, bool, string) {
	if facet, ok := entityFacet(record, "bucket_public_access"); ok {
		if value, ok := boolField(facet.Fields, "public_access"); ok {
			return value, true, facet.ID
		}
	}
	if facet, ok := entityFacet(record, "exposure"); ok {
		if value, ok := boolField(facet.Fields, "public_access"); ok {
			return value, true, facet.ID
		}
		if value, ok := boolField(facet.Fields, "internet_exposed"); ok {
			return value, true, facet.ID
		}
	}
	if value, ok := firstBool(record.Properties, "public", "public_access", "publicly_accessible", "internet_accessible"); ok {
		return value, true, ""
	}
	return false, false, ""
}

func boolField(fields map[string]any, key string) (bool, bool) {
	if fields == nil {
		return false, false
	}
	value, ok := fields[key]
	if !ok {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.TrimSpace(strings.ToLower(typed)) {
		case "true", "enabled", "on", "yes":
			return true, true
		case "false", "disabled", "off", "no":
			return false, true
		}
	}
	return false, false
}

func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	if value, ok := fields[key]; ok {
		switch typed := value.(type) {
		case string:
			return typed
		case fmt.Stringer:
			return typed.String()
		}
	}
	return ""
}

func firstBool(fields map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if value, ok := boolField(fields, key); ok {
			return value, true
		}
	}
	return false, false
}

func firstInt(fields map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		value, ok := fields[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case int:
			return typed, true
		case int32:
			return int(typed), true
		case int64:
			return int(typed), true
		case float64:
			return int(typed), true
		case float32:
			return int(typed), true
		}
	}
	return 0, false
}

func unionStringSets(sets ...map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	for _, set := range sets {
		for key := range set {
			out[key] = struct{}{}
		}
	}
	return out
}

func cloneFindingCounts(src map[string]int) map[string]int {
	if len(src) == 0 {
		return map[string]int{}
	}
	dst := make(map[string]int, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func limitControlEvidence(items []ControlEvidence) []ControlEvidence {
	if len(items) <= maxControlEvidence {
		return items
	}
	prioritized := make([]ControlEvidence, 0, len(items))
	for _, item := range items {
		if item.Status != ControlStatePassing {
			prioritized = append(prioritized, item)
		}
	}
	for _, item := range items {
		if item.Status == ControlStatePassing {
			prioritized = append(prioritized, item)
		}
	}
	return prioritized[:maxControlEvidence]
}
