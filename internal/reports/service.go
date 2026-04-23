package reports

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	findingSummaryReportID           = "finding-summary"
	findingSummaryReportName         = "Finding Summary"
	findingSummaryReportStatus       = "completed"
	reportParameterRuntimeID         = "runtime_id"
	reportParameterResourceLimit     = "resource_limit"
	reportParameterGraphLimit        = "graph_limit"
	defaultResourceEvidenceLimit     = 3
	maxResourceEvidenceLimit         = 10
	defaultNeighborhoodEvidenceLimit = 3
	maxNeighborhoodEvidenceLimit     = 10
	graphEvidenceStatusIncluded      = "included"
	graphEvidenceStatusUnconfigured  = "unconfigured"
	graphEvidenceEntryStatusIncluded = "included"
	graphEvidenceEntryStatusNotFound = "not_found"
)

var (
	// ErrRuntimeUnavailable indicates that the report-run dependencies are unavailable.
	ErrRuntimeUnavailable = errors.New("report runtime is unavailable")

	// ErrReportNotFound indicates that a requested built-in report definition does not exist.
	ErrReportNotFound = errors.New("report definition not found")
)

// Service exposes the first durable report-run foundation.
type Service struct {
	findingStore ports.FindingStore
	graphStore   ports.GraphQueryStore
	reportStore  ports.ReportStore
}

// New constructs the report service.
func New(findingStore ports.FindingStore, graphStore ports.GraphQueryStore, reportStore ports.ReportStore) *Service {
	return &Service{
		findingStore: findingStore,
		graphStore:   graphStore,
		reportStore:  reportStore,
	}
}

// List returns the built-in report definition catalog.
func (s *Service) List() *cerebrov1.ListReportDefinitionsResponse {
	return &cerebrov1.ListReportDefinitionsResponse{
		Reports: []*cerebrov1.ReportDefinition{
			findingSummaryDefinition(),
		},
	}
}

// Run evaluates one built-in report and persists the resulting run.
func (s *Service) Run(ctx context.Context, request *cerebrov1.RunReportRequest) (*cerebrov1.RunReportResponse, error) {
	if s == nil || s.findingStore == nil || s.reportStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	if request == nil {
		return nil, errors.New("report request is required")
	}
	reportID := strings.TrimSpace(request.GetReportId())
	if reportID == "" {
		return nil, errors.New("report id is required")
	}
	definition, err := reportDefinition(reportID)
	if err != nil {
		return nil, err
	}
	parameters := normalizeParameters(request.GetParameters())
	generatedAt := time.Now().UTC()

	var result *structpb.Struct
	switch reportID {
	case findingSummaryReportID:
		result, err = s.runFindingSummary(ctx, parameters)
	default:
		err = fmt.Errorf("%w: %s", ErrReportNotFound, reportID)
	}
	if err != nil {
		return nil, err
	}

	run := &cerebrov1.ReportRun{
		Id:          reportRunID(reportID, generatedAt),
		ReportId:    reportID,
		Parameters:  parameters,
		Status:      findingSummaryReportStatus,
		GeneratedAt: timestamppb.New(generatedAt),
		Result:      result,
	}
	if err := s.reportStore.PutReportRun(ctx, run); err != nil {
		return nil, fmt.Errorf("persist report run %q: %w", run.GetId(), err)
	}
	return &cerebrov1.RunReportResponse{
		Report: definition,
		Run:    run,
	}, nil
}

// Get loads one persisted report run.
func (s *Service) Get(ctx context.Context, request *cerebrov1.GetReportRunRequest) (*cerebrov1.GetReportRunResponse, error) {
	if s == nil || s.reportStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	if request == nil {
		return nil, errors.New("get report run request is required")
	}
	reportRunID := strings.TrimSpace(request.GetId())
	if reportRunID == "" {
		return nil, errors.New("report run id is required")
	}
	run, err := s.reportStore.GetReportRun(ctx, reportRunID)
	if err != nil {
		return nil, err
	}
	return &cerebrov1.GetReportRunResponse{Run: run}, nil
}

func (s *Service) runFindingSummary(ctx context.Context, parameters map[string]string) (*structpb.Struct, error) {
	runtimeID := strings.TrimSpace(parameters[reportParameterRuntimeID])
	if runtimeID == "" {
		return nil, fmt.Errorf("report parameter %q is required", reportParameterRuntimeID)
	}
	resourceLimit, err := normalizePositiveLimit(parameters[reportParameterResourceLimit], defaultResourceEvidenceLimit, maxResourceEvidenceLimit, reportParameterResourceLimit)
	if err != nil {
		return nil, err
	}
	graphLimit, err := normalizePositiveLimit(parameters[reportParameterGraphLimit], defaultNeighborhoodEvidenceLimit, maxNeighborhoodEvidenceLimit, reportParameterGraphLimit)
	if err != nil {
		return nil, err
	}
	findings, err := s.findingStore.ListFindings(ctx, ports.ListFindingsRequest{RuntimeID: runtimeID})
	if err != nil {
		return nil, fmt.Errorf("list findings for runtime %q: %w", runtimeID, err)
	}
	severityCounts := make(map[string]int, len(findings))
	statusCounts := make(map[string]int, len(findings))
	ruleCounts := make(map[string]int, len(findings))
	resourceCounts := make(map[string]int, len(findings))
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		severity := strings.TrimSpace(finding.Severity)
		if severity != "" {
			severityCounts[severity]++
		}
		status := strings.TrimSpace(finding.Status)
		if status != "" {
			statusCounts[status]++
		}
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID != "" {
			ruleCounts[ruleID]++
		}
		if resourceURN := primaryResourceURN(finding); resourceURN != "" {
			resourceCounts[resourceURN]++
		}
	}
	graphEvidenceStatus := graphEvidenceStatusUnconfigured
	graphEvidence := []any{}
	if s.graphStore != nil {
		graphEvidenceStatus = graphEvidenceStatusIncluded
		graphEvidence, err = s.graphEvidence(ctx, resourceCounts, resourceLimit, graphLimit)
		if err != nil {
			return nil, err
		}
	}
	result, err := structpb.NewStruct(map[string]any{
		reportParameterRuntimeID: runtimeID,
		"total_findings":         len(findings),
		"severity_counts":        countEntries(severityCounts, "severity"),
		"status_counts":          countEntries(statusCounts, "status"),
		"rule_counts":            countEntries(ruleCounts, "rule_id"),
		"resource_counts":        countEntries(resourceCounts, "resource_urn"),
		"graph_evidence_status":  graphEvidenceStatus,
		"graph_evidence":         graphEvidence,
	})
	if err != nil {
		return nil, fmt.Errorf("build finding summary report result: %w", err)
	}
	return result, nil
}

func (s *Service) graphEvidence(ctx context.Context, resourceCounts map[string]int, resourceLimit int, graphLimit int) ([]any, error) {
	entries := sortedCountEntries(resourceCounts)
	if len(entries) > resourceLimit {
		entries = entries[:resourceLimit]
	}
	evidence := make([]any, 0, len(entries))
	for _, entry := range entries {
		neighborhood, err := s.graphStore.GetEntityNeighborhood(ctx, entry.Key, graphLimit)
		switch {
		case err == nil:
			if neighborhood == nil {
				neighborhood = &ports.EntityNeighborhood{}
			}
			evidence = append(evidence, map[string]any{
				"resource_urn":  entry.Key,
				"finding_count": entry.Count,
				"status":        graphEvidenceEntryStatusIncluded,
				"root":          graphNodePayload(neighborhood.Root),
				"neighbors":     graphNodesPayload(neighborhood.Neighbors),
				"relations":     graphRelationsPayload(neighborhood.Relations),
			})
		case errors.Is(err, ports.ErrGraphEntityNotFound):
			evidence = append(evidence, map[string]any{
				"resource_urn":  entry.Key,
				"finding_count": entry.Count,
				"status":        graphEvidenceEntryStatusNotFound,
			})
		default:
			return nil, fmt.Errorf("load graph evidence for %q: %w", entry.Key, err)
		}
	}
	return evidence, nil
}

func findingSummaryDefinition() *cerebrov1.ReportDefinition {
	return &cerebrov1.ReportDefinition{
		Id:          findingSummaryReportID,
		Name:        findingSummaryReportName,
		Description: "Materialize one runtime-scoped summary of persisted findings, grouped by severity, status, and rule, with bounded graph evidence for top resources when the graph is configured.",
		Parameters: []*cerebrov1.ReportParameter{
			{
				Id:          reportParameterRuntimeID,
				Description: "Stored source runtime identifier whose persisted findings should be summarized.",
				Required:    true,
			},
			{
				Id:          reportParameterResourceLimit,
				Description: "Optional maximum number of resource roots to include in the graph evidence section.",
				Required:    false,
			},
			{
				Id:          reportParameterGraphLimit,
				Description: "Optional maximum neighborhood size to read for each graph evidence root.",
				Required:    false,
			},
		},
	}
}

func reportDefinition(reportID string) (*cerebrov1.ReportDefinition, error) {
	switch strings.TrimSpace(reportID) {
	case findingSummaryReportID:
		return findingSummaryDefinition(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrReportNotFound, reportID)
	}
}

func normalizeParameters(parameters map[string]string) map[string]string {
	if len(parameters) == 0 {
		return map[string]string{}
	}
	normalized := make(map[string]string, len(parameters))
	for key, value := range parameters {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		normalized[trimmedKey] = strings.TrimSpace(value)
	}
	return normalized
}

func reportRunID(reportID string, generatedAt time.Time) string {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-")
	return replacer.Replace(strings.TrimSpace(reportID)) + "-" + fmt.Sprintf("%d", generatedAt.UnixNano())
}

type countEntry struct {
	Key   string
	Count int
}

func countEntries(counts map[string]int, keyName string) []any {
	entries := sortedCountEntries(counts)
	values := make([]any, 0, len(entries))
	for _, entry := range entries {
		values = append(values, map[string]any{
			keyName: entry.Key,
			"count": entry.Count,
		})
	}
	return values
}

func sortedCountEntries(counts map[string]int) []countEntry {
	entries := make([]countEntry, 0, len(counts))
	for key, count := range counts {
		entries = append(entries, countEntry{Key: key, Count: count})
	}
	slices.SortFunc(entries, func(left countEntry, right countEntry) int {
		switch {
		case left.Count > right.Count:
			return -1
		case left.Count < right.Count:
			return 1
		case left.Key < right.Key:
			return -1
		case left.Key > right.Key:
			return 1
		default:
			return 0
		}
	})
	return entries
}

func primaryResourceURN(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	if value := strings.TrimSpace(finding.Attributes["primary_resource_urn"]); value != "" {
		return value
	}
	primaryActorURN := strings.TrimSpace(finding.Attributes["primary_actor_urn"])
	for _, resourceURN := range finding.ResourceURNs {
		trimmed := strings.TrimSpace(resourceURN)
		if trimmed == "" || trimmed == primaryActorURN {
			continue
		}
		return trimmed
	}
	return ""
}

func normalizePositiveLimit(raw string, defaultValue int, maxValue int, parameterID string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("report parameter %q must be a positive integer: %w", parameterID, err)
	}
	switch {
	case parsed <= 0:
		return 0, fmt.Errorf("report parameter %q must be greater than zero", parameterID)
	case parsed > maxValue:
		return maxValue, nil
	default:
		return parsed, nil
	}
}

func graphNodePayload(node *ports.NeighborhoodNode) map[string]any {
	if node == nil {
		return map[string]any{}
	}
	return map[string]any{
		"urn":         node.URN,
		"entity_type": node.EntityType,
		"label":       node.Label,
	}
}

func graphNodesPayload(nodes []*ports.NeighborhoodNode) []any {
	payload := make([]any, 0, len(nodes))
	for _, node := range nodes {
		payload = append(payload, graphNodePayload(node))
	}
	return payload
}

func graphRelationsPayload(relations []*ports.NeighborhoodRelation) []any {
	payload := make([]any, 0, len(relations))
	for _, relation := range relations {
		if relation == nil {
			continue
		}
		payload = append(payload, map[string]any{
			"from_urn": relation.FromURN,
			"relation": relation.Relation,
			"to_urn":   relation.ToURN,
		})
	}
	return payload
}
