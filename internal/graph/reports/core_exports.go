package reports

import (
	"fmt"
	"sort"
	"strings"
	"time"

	graph "github.com/evalops/cerebro/internal/graph"
	entities "github.com/evalops/cerebro/internal/graph/entities"
	risk "github.com/evalops/cerebro/internal/graph/risk"
)

type (
	Graph                         = graph.Graph
	Node                          = graph.Node
	Edge                          = graph.Edge
	NodeKind                      = graph.NodeKind
	EdgeKind                      = graph.EdgeKind
	EdgeEffect                    = graph.EdgeEffect
	Metadata                      = graph.Metadata
	RiskLevel                     = graph.RiskLevel
	Severity                      = risk.Severity
	GraphDiff                     = graph.GraphDiff
	GraphDelta                    = graph.GraphDelta
	NodeMutation                  = graph.NodeMutation
	EdgeMutation                  = graph.EdgeMutation
	FreshnessMetrics              = graph.FreshnessMetrics
	SchemaHealthReport            = graph.SchemaHealthReport
	OutcomeFeedbackReport         = graph.OutcomeFeedbackReport
	GraphQueryTemplate            = graph.GraphQueryTemplate
	NodeMetadataProfile           = graph.NodeMetadataProfile
	NodeKindDefinition            = graph.NodeKindDefinition
	NodeKindCategory              = graph.NodeKindCategory
	SchemaValidationMode          = graph.SchemaValidationMode
	IdentityCalibrationOptions    = graph.IdentityCalibrationOptions
	IdentityCalibrationReport     = graph.IdentityCalibrationReport
	IdentityReviewDecision        = graph.IdentityReviewDecision
	OutcomeEvent                  = risk.OutcomeEvent
	GraphSnapshotRecord           = graph.GraphSnapshotRecord
	GraphSnapshotCollection       = graph.GraphSnapshotCollection
	RiskEngine                    = risk.RiskEngine
	SecurityReport                = risk.SecurityReport
	RankedRisk                    = risk.RankedRisk
	Chokepoint                    = risk.Chokepoint
	EntityFacetDefinition         = entities.EntityFacetDefinition
	EntityPostureSummary          = entities.EntityPostureSummary
	SchemaKindCount               = graph.SchemaKindCount
	EntityRecord                  = entities.EntityRecord
	EntityPostureClaimRecord      = entities.EntityPostureClaimRecord
	EntityFacetRecord             = entities.EntityFacetRecord
	EntitySubresourceRecord       = entities.EntitySubresourceRecord
	EntityKnowledgeSupportSummary = entities.EntityKnowledgeSupportSummary
)

const (
	RiskCritical                  = graph.RiskCritical
	RiskHigh                      = graph.RiskHigh
	RiskMedium                    = graph.RiskMedium
	RiskLow                       = graph.RiskLow
	RiskNone                      = graph.RiskNone
	NodeKindUser                  = graph.NodeKindUser
	NodeKindPerson                = graph.NodeKindPerson
	NodeKindIdentityAlias         = graph.NodeKindIdentityAlias
	NodeKindRole                  = graph.NodeKindRole
	NodeKindService               = graph.NodeKindService
	NodeKindWorkload              = graph.NodeKindWorkload
	NodeKindBucket                = graph.NodeKindBucket
	NodeKindDatabase              = graph.NodeKindDatabase
	NodeKindCompany               = graph.NodeKindCompany
	NodeKindVendor                = graph.NodeKindVendor
	NodeKindActivity              = graph.NodeKindActivity
	NodeKindDecision              = graph.NodeKindDecision
	NodeKindOutcome               = graph.NodeKindOutcome
	NodeKindEvidence              = graph.NodeKindEvidence
	NodeKindObservation           = graph.NodeKindObservation
	NodeKindSource                = graph.NodeKindSource
	NodeKindClaim                 = graph.NodeKindClaim
	NodeKindAction                = graph.NodeKindAction
	NodeKindDeploymentRun         = graph.NodeKindDeploymentRun
	NodeCategoryIdentity          = graph.NodeCategoryIdentity
	NodeCategoryResource          = graph.NodeCategoryResource
	NodeCategoryBusiness          = graph.NodeCategoryBusiness
	NodeCategoryKubernetes        = graph.NodeCategoryKubernetes
	EdgeKindAliasOf               = graph.EdgeKindAliasOf
	EdgeKindCanAssume             = graph.EdgeKindCanAssume
	EdgeKindCanRead               = graph.EdgeKindCanRead
	EdgeKindCanWrite              = graph.EdgeKindCanWrite
	EdgeKindTargets               = graph.EdgeKindTargets
	EdgeKindBasedOn               = graph.EdgeKindBasedOn
	EdgeKindExecutedBy            = graph.EdgeKindExecutedBy
	EdgeKindEvaluates             = graph.EdgeKindEvaluates
	EdgeKindAssertedBy            = graph.EdgeKindAssertedBy
	EdgeKindSupports              = graph.EdgeKindSupports
	EdgeKindRefutes               = graph.EdgeKindRefutes
	EdgeKindSupersedes            = graph.EdgeKindSupersedes
	EdgeEffectAllow               = graph.EdgeEffectAllow
	EdgeEffectDeny                = graph.EdgeEffectDeny
	SeverityCritical              = risk.SeverityCritical
	SeverityHigh                  = risk.SeverityHigh
	SeverityMedium                = risk.SeverityMedium
	SeverityLow                   = risk.SeverityLow
	GraphOntologyContractVersion  = graph.GraphOntologyContractVersion
	SchemaValidationEnforce       = graph.SchemaValidationEnforce
	IdentityReviewVerdictAccepted = graph.IdentityReviewVerdictAccepted
)

var (
	GetEntityRecord                    = entities.GetEntityRecord
	AnalyzeSchemaHealth                = graph.AnalyzeSchemaHealth
	BuildIdentityCalibrationReport     = graph.BuildIdentityCalibrationReport
	CurrentGraphSnapshotRecord         = graph.CurrentGraphSnapshotRecord
	DefaultGraphQueryTemplates         = graph.DefaultGraphQueryTemplates
	GlobalSchemaRegistry               = graph.GlobalSchemaRegistry
	GraphSnapshotCollectionFromRecords = graph.GraphSnapshotCollectionFromRecords
	IsNodeKindInCategory               = graph.IsNodeKindInCategory
	NewRiskEngine                      = risk.NewRiskEngine
	New                                = graph.New
	ReviewIdentityAlias                = graph.ReviewIdentityAlias
	SchemaVersion                      = graph.SchemaVersion
	ValidateEdgeAgainstSchema          = graph.ValidateEdgeAgainstSchema
	ValidateNodeAgainstSchema          = graph.ValidateNodeAgainstSchema
)

const defaultFreshnessStaleAfter = 30 * 24 * time.Hour

var (
	defaultEntityFacetDefinitions = entities.DefaultEntityFacetDefinitions()
	entityFacetAppliesToNode      = entities.EntityFacetAppliesToNode
)

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := value.UTC()
	return &copy
}

func clampUnit(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func scoreToSeverity(score float64) Severity {
	if score >= 70 {
		return SeverityCritical
	}
	if score >= 50 {
		return SeverityHigh
	}
	if score >= 25 {
		return SeverityMedium
	}
	return SeverityLow
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func summarizeSchemaKindCounts(values []SchemaKindCount, limit int) string {
	if len(values) == 0 || limit == 0 {
		return ""
	}
	if limit < 0 || limit > len(values) {
		limit = len(values)
	}
	parts := make([]string, 0, limit)
	for _, item := range values[:limit] {
		if item.Kind == "" || item.Count <= 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (%d)", item.Kind, item.Count))
	}
	return strings.Join(parts, ", ")
}

func identityAnyToString(value any) string {
	if value == nil {
		return ""
	}
	if typed, ok := value.(string); ok {
		return strings.TrimSpace(typed)
	}
	return strings.TrimSpace(fmt.Sprintf("%v", value))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func temporalPropertyTime(properties map[string]any, key string) (time.Time, bool) {
	if len(properties) == 0 {
		return time.Time{}, false
	}
	value, ok := properties[strings.TrimSpace(key)]
	if !ok {
		return time.Time{}, false
	}
	return graphValueTime(value)
}

func graphValueTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return typed.UTC(), true
	case string:
		raw := strings.TrimSpace(typed)
		if raw == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
			if parsed, err := time.Parse(layout, raw); err == nil {
				return parsed.UTC(), true
			}
		}
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}

func graphObservedAt(node *Node) (time.Time, bool) {
	if node == nil {
		return time.Time{}, false
	}
	if value, ok := node.PropertyValue("observed_at"); ok {
		if ts, ok := graphValueTime(value); ok {
			return ts, true
		}
	}
	if ts, ok := temporalPropertyTime(node.Properties, "observed_at"); ok {
		return ts, true
	}
	if !node.UpdatedAt.IsZero() {
		return node.UpdatedAt.UTC(), true
	}
	if !node.CreatedAt.IsZero() {
		return node.CreatedAt.UTC(), true
	}
	return time.Time{}, false
}

func graphNodePropertyString(node *Node, key string) string {
	if node == nil {
		return ""
	}
	if value, ok := node.PropertyValue(key); ok {
		return strings.TrimSpace(identityAnyToString(value))
	}
	return strings.TrimSpace(identityAnyToString(node.Properties[key]))
}

func cloneAnyMap(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]any, len(values))
	for key, value := range values {
		cloned[key] = cloneAnyValue(value)
	}
	return cloned
}

func cloneAnyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneAnyMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for i := range typed {
			cloned[i] = cloneAnyValue(typed[i])
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	case []int:
		return append([]int(nil), typed...)
	case []float64:
		return append([]float64(nil), typed...)
	case []bool:
		return append([]bool(nil), typed...)
	default:
		return value
	}
}
