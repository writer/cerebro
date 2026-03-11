package graph

import (
	"fmt"
	"strings"
	"time"
)

// EntitySummaryReportOptions tunes one entity-centric report view.
type EntitySummaryReportOptions struct {
	EntityID         string    `json:"entity_id"`
	ValidAt          time.Time `json:"valid_at,omitempty"`
	RecordedAt       time.Time `json:"recorded_at,omitempty"`
	MaxPostureClaims int       `json:"max_posture_claims,omitempty"`
}

// EntitySummaryMeasureValue is one typed measure emitted by the entity summary report.
type EntitySummaryMeasureValue struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	ValueType string `json:"value_type"`
	Unit      string `json:"unit,omitempty"`
	Value     any    `json:"value,omitempty"`
	Status    string `json:"status,omitempty"`
}

// EntitySummaryOverviewSection captures the identity/context module for one entity.
type EntitySummaryOverviewSection struct {
	Headline   string                      `json:"headline"`
	Highlights []string                    `json:"highlights,omitempty"`
	Measures   []EntitySummaryMeasureValue `json:"measures,omitempty"`
}

// EntitySummaryDistributionItem is one grouped breakdown item.
type EntitySummaryDistributionItem struct {
	Dimension string                      `json:"dimension"`
	Measures  []EntitySummaryMeasureValue `json:"measures,omitempty"`
}

// EntitySummaryTopologySection captures grouped graph relationships around an entity.
type EntitySummaryTopologySection struct {
	Items []EntitySummaryDistributionItem `json:"items,omitempty"`
}

// EntitySummaryRankingItem is one ranked asset module item.
type EntitySummaryRankingItem struct {
	ID            string                      `json:"id"`
	Title         string                      `json:"title"`
	Rank          int                         `json:"rank"`
	Score         float64                     `json:"score,omitempty"`
	Summary       string                      `json:"summary,omitempty"`
	MeasureValues []EntitySummaryMeasureValue `json:"measure_values,omitempty"`
}

// EntitySummaryFacetSection captures high-value entity facets as ranked modules.
type EntitySummaryFacetSection struct {
	Items []EntitySummaryRankingItem `json:"items,omitempty"`
}

// EntitySummarySubresourceSection captures promoted subresources and their support state.
type EntitySummarySubresourceSection struct {
	Items []EntitySummaryRankingItem `json:"items,omitempty"`
}

// EntitySummaryPostureSection captures normalized posture claims attached to the entity.
type EntitySummaryPostureSection struct {
	Headline   string                      `json:"headline"`
	Highlights []string                    `json:"highlights,omitempty"`
	Measures   []EntitySummaryMeasureValue `json:"measures,omitempty"`
	Claims     []EntityPostureClaimRecord  `json:"claims,omitempty"`
}

// EntitySummarySupportSection captures coverage/support quality on the entity.
type EntitySummarySupportSection struct {
	Headline   string                      `json:"headline"`
	Highlights []string                    `json:"highlights,omitempty"`
	Measures   []EntitySummaryMeasureValue `json:"measures,omitempty"`
}

// EntitySummaryReport is the report-level asset summary view built from entity and knowledge primitives.
type EntitySummaryReport struct {
	GeneratedAt  time.Time                       `json:"generated_at"`
	ValidAt      time.Time                       `json:"valid_at"`
	RecordedAt   time.Time                       `json:"recorded_at"`
	Entity       EntityRecord                    `json:"entity"`
	Overview     EntitySummaryOverviewSection    `json:"overview"`
	Topology     EntitySummaryTopologySection    `json:"topology"`
	Facets       EntitySummaryFacetSection       `json:"facets"`
	Subresources EntitySummarySubresourceSection `json:"subresources"`
	Posture      EntitySummaryPostureSection     `json:"posture"`
	Support      EntitySummarySupportSection     `json:"support"`
}

// BuildEntitySummaryReport builds a report-level entity summary without inventing a bespoke asset API tree.
func BuildEntitySummaryReport(g *Graph, opts EntitySummaryReportOptions) (EntitySummaryReport, bool) {
	if g == nil {
		return EntitySummaryReport{}, false
	}
	validAt := opts.ValidAt
	if validAt.IsZero() {
		validAt = temporalNowUTC()
	}
	recordedAt := opts.RecordedAt
	if recordedAt.IsZero() {
		recordedAt = temporalNowUTC()
	}
	entity, ok := GetEntityRecord(g, strings.TrimSpace(opts.EntityID), validAt, recordedAt)
	if !ok {
		return EntitySummaryReport{}, false
	}
	report := EntitySummaryReport{
		GeneratedAt:  temporalNowUTC(),
		ValidAt:      validAt.UTC(),
		RecordedAt:   recordedAt.UTC(),
		Entity:       entity,
		Overview:     buildEntitySummaryOverviewSection(entity),
		Topology:     buildEntitySummaryTopologySection(entity),
		Facets:       buildEntitySummaryFacetSection(entity),
		Subresources: buildEntitySummarySubresourceSection(entity),
		Posture:      buildEntitySummaryPostureSection(entity, opts.MaxPostureClaims),
		Support:      buildEntitySummarySupportSection(entity),
	}
	return report, true
}

func buildEntitySummaryOverviewSection(entity EntityRecord) EntitySummaryOverviewSection {
	var highlights []string
	if entity.CanonicalRef != nil {
		highlights = append(highlights, fmt.Sprintf("Canonical ref %s/%s", entity.CanonicalRef.Namespace, entity.CanonicalRef.Name))
	}
	if len(entity.ExternalRefs) > 0 {
		highlights = append(highlights, fmt.Sprintf("%d external ref(s)", len(entity.ExternalRefs)))
	}
	if len(entity.Facets) > 0 {
		highlights = append(highlights, fmt.Sprintf("%d facet module(s)", len(entity.Facets)))
	}
	if len(entity.Subresources) > 0 {
		highlights = append(highlights, fmt.Sprintf("%d subresource(s)", len(entity.Subresources)))
	}
	if entity.Posture != nil && entity.Posture.ActiveClaimCount > 0 {
		highlights = append(highlights, fmt.Sprintf("%d posture claim(s)", entity.Posture.ActiveClaimCount))
	}
	headline := firstNonEmpty(entity.Name, entity.ID)
	return EntitySummaryOverviewSection{
		Headline:   headline,
		Highlights: compactEntityHighlights(highlights),
		Measures: []EntitySummaryMeasureValue{
			entitySummaryMeasure("risk_score", "Risk Score", "number", "score", entityRiskScore(entity.Risk), strings.ToLower(string(entity.Risk))),
			entitySummaryMeasure("external_refs", "External Refs", "integer", "", len(entity.ExternalRefs), ""),
			entitySummaryMeasure("aliases", "Aliases", "integer", "", len(entity.Aliases), ""),
			entitySummaryMeasure("facet_coverage_percent", "Facet Coverage", "number", "percent", entityFacetCoveragePercent(entity), entityFacetCoverageStatus(entity)),
			entitySummaryMeasure("subresource_count", "Subresources", "integer", "", len(entity.Subresources), ""),
		},
	}
}

func buildEntitySummaryTopologySection(entity EntityRecord) EntitySummaryTopologySection {
	items := make([]EntitySummaryDistributionItem, 0, len(entity.Relationships))
	for _, relationship := range entity.Relationships {
		items = append(items, EntitySummaryDistributionItem{
			Dimension: fmt.Sprintf("%s %s %s", relationship.Direction, relationship.EdgeKind, relationship.RelatedKind),
			Measures: []EntitySummaryMeasureValue{
				entitySummaryMeasure("count", "Count", "integer", "", relationship.Count, ""),
				entitySummaryMeasure("sampled_entities", "Sampled Entities", "integer", "", len(relationship.SampleEntityIDs), ""),
			},
		})
	}
	return EntitySummaryTopologySection{Items: items}
}

func buildEntitySummaryFacetSection(entity EntityRecord) EntitySummaryFacetSection {
	items := make([]EntitySummaryRankingItem, 0, len(entity.Facets))
	for idx, facet := range entity.Facets {
		items = append(items, EntitySummaryRankingItem{
			ID:      facet.ID,
			Title:   facet.Title,
			Rank:    idx + 1,
			Score:   entityFacetSummaryScore(facet.Assessment),
			Summary: facet.Summary,
			MeasureValues: []EntitySummaryMeasureValue{
				entitySummaryMeasure("fields", "Fields", "integer", "", len(facet.Fields), facet.Assessment),
				entitySummaryMeasure("claims", "Claim Predicates", "integer", "", len(facet.ClaimPredicates), ""),
			},
		})
	}
	return EntitySummaryFacetSection{Items: items}
}

func buildEntitySummarySubresourceSection(entity EntityRecord) EntitySummarySubresourceSection {
	items := make([]EntitySummaryRankingItem, 0, len(entity.Subresources))
	for idx, subresource := range entity.Subresources {
		items = append(items, EntitySummaryRankingItem{
			ID:      subresource.ID,
			Title:   firstNonEmpty(subresource.Name, subresource.ID),
			Rank:    idx + 1,
			Score:   entityFacetSummaryScore(subresource.Assessment),
			Summary: subresource.Summary,
			MeasureValues: []EntitySummaryMeasureValue{
				entitySummaryMeasure("claims", "Claims", "integer", "", subresource.Knowledge.ClaimCount, ""),
				entitySummaryMeasure("supported_claims", "Supported Claims", "integer", "", subresource.Knowledge.SupportedClaimCount, ""),
				entitySummaryMeasure("evidence", "Evidence", "integer", "", subresource.Knowledge.EvidenceCount, ""),
				entitySummaryMeasure("related_entities", "Related Entities", "integer", "", len(subresource.RelatedEntityIDs), subresource.Assessment),
			},
		})
	}
	return EntitySummarySubresourceSection{Items: items}
}

func buildEntitySummaryPostureSection(entity EntityRecord, maxClaims int) EntitySummaryPostureSection {
	section := EntitySummaryPostureSection{
		Headline: "No posture claims attached",
	}
	if entity.Posture == nil {
		return section
	}
	claims := append([]EntityPostureClaimRecord(nil), entity.Posture.Claims...)
	if maxClaims > 0 && len(claims) > maxClaims {
		claims = claims[:maxClaims]
	}
	highlights := make([]string, 0, 3)
	if entity.Posture.DisputedClaimCount > 0 {
		highlights = append(highlights, fmt.Sprintf("%d disputed", entity.Posture.DisputedClaimCount))
	}
	if entity.Posture.StaleClaimCount > 0 {
		highlights = append(highlights, fmt.Sprintf("%d stale", entity.Posture.StaleClaimCount))
	}
	if entity.Posture.SupportedClaimCount > 0 {
		highlights = append(highlights, fmt.Sprintf("%d supported", entity.Posture.SupportedClaimCount))
	}
	section.Headline = fmt.Sprintf("%d posture claim(s) attached", entity.Posture.ActiveClaimCount)
	section.Highlights = highlights
	section.Measures = []EntitySummaryMeasureValue{
		entitySummaryMeasure("active_claims", "Active Claims", "integer", "", entity.Posture.ActiveClaimCount, ""),
		entitySummaryMeasure("supported_claims", "Supported Claims", "integer", "", entity.Posture.SupportedClaimCount, ""),
		entitySummaryMeasure("disputed_claims", "Disputed Claims", "integer", "", entity.Posture.DisputedClaimCount, postureSectionStatus(entity.Posture)),
		entitySummaryMeasure("stale_claims", "Stale Claims", "integer", "", entity.Posture.StaleClaimCount, staleSectionStatus(entity.Posture)),
	}
	section.Claims = claims
	return section
}

func buildEntitySummarySupportSection(entity EntityRecord) EntitySummarySupportSection {
	highlights := []string{
		fmt.Sprintf("%d evidence artifact(s)", entity.Knowledge.EvidenceCount),
		fmt.Sprintf("%d observation(s)", entity.Knowledge.ObservationCount),
	}
	if entity.Knowledge.ConflictedClaimCount > 0 {
		highlights = append(highlights, fmt.Sprintf("%d conflicted claim(s)", entity.Knowledge.ConflictedClaimCount))
	}
	return EntitySummarySupportSection{
		Headline:   "Knowledge support attached to entity",
		Highlights: compactEntityHighlights(highlights),
		Measures: []EntitySummaryMeasureValue{
			entitySummaryMeasure("claim_count", "Claims", "integer", "", entity.Knowledge.ClaimCount, ""),
			entitySummaryMeasure("supported_claim_count", "Supported Claims", "integer", "", entity.Knowledge.SupportedClaimCount, ""),
			entitySummaryMeasure("conflicted_claim_count", "Conflicted Claims", "integer", "", entity.Knowledge.ConflictedClaimCount, supportConflictStatus(entity.Knowledge)),
			entitySummaryMeasure("evidence_count", "Evidence", "integer", "", entity.Knowledge.EvidenceCount, ""),
			entitySummaryMeasure("observation_count", "Observations", "integer", "", entity.Knowledge.ObservationCount, ""),
		},
	}
}

func compactEntityHighlights(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func entitySummaryMeasure(id, label, valueType, unit string, value any, status string) EntitySummaryMeasureValue {
	return EntitySummaryMeasureValue{
		ID:        id,
		Label:     label,
		ValueType: valueType,
		Unit:      unit,
		Value:     value,
		Status:    strings.TrimSpace(status),
	}
}

func entityRiskScore(level RiskLevel) int {
	switch level {
	case RiskCritical:
		return 95
	case RiskHigh:
		return 80
	case RiskMedium:
		return 55
	case RiskLow:
		return 25
	default:
		return 0
	}
}

func entityFacetCoveragePercent(entity EntityRecord) float64 {
	applicable := 0
	for _, def := range defaultEntityFacetDefinitions {
		if entityFacetAppliesToNode(def, entity.Kind) {
			applicable++
		}
	}
	if applicable == 0 {
		return 100
	}
	materialized := 0
	for _, facet := range entity.Facets {
		if strings.EqualFold(strings.TrimSpace(facet.Status), "missing") {
			continue
		}
		materialized++
	}
	return float64(materialized) * 100 / float64(applicable)
}

func entityFacetCoverageStatus(entity EntityRecord) string {
	percent := entityFacetCoveragePercent(entity)
	switch {
	case percent >= 80:
		return "pass"
	case percent >= 50:
		return "warn"
	default:
		return "fail"
	}
}

func entityFacetSummaryScore(assessment string) float64 {
	switch assessment {
	case "fail":
		return 100
	case "warn":
		return 75
	case "info":
		return 50
	case "pass":
		return 25
	default:
		return 0
	}
}

func postureSectionStatus(summary *EntityPostureSummary) string {
	if summary == nil || summary.DisputedClaimCount == 0 {
		return "pass"
	}
	return "warn"
}

func staleSectionStatus(summary *EntityPostureSummary) string {
	if summary == nil || summary.StaleClaimCount == 0 {
		return "pass"
	}
	return "warn"
}

func supportConflictStatus(summary EntityKnowledgeSupportSummary) string {
	if summary.ConflictedClaimCount == 0 {
		return "pass"
	}
	return "warn"
}

// SortEntitySummaryRankingItems sorts report ranking items deterministically.
