package reports

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	reportParameterTenantID          = "tenant_id"
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

	// ErrInvalidRequest indicates that a report request failed validation.
	ErrInvalidRequest = errors.New("invalid report request")
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
		return nil, fmt.Errorf("%w: report request is required", ErrInvalidRequest)
	}
	reportID := strings.TrimSpace(request.GetReportId())
	if reportID == "" {
		return nil, fmt.Errorf("%w: report id is required", ErrInvalidRequest)
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

	runID, err := reportRunID(reportID, generatedAt)
	if err != nil {
		return nil, err
	}
	run := &cerebrov1.ReportRun{
		Id:          runID,
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
		return nil, fmt.Errorf("%w: get report run request is required", ErrInvalidRequest)
	}
	reportRunID := strings.TrimSpace(request.GetId())
	if reportRunID == "" {
		return nil, fmt.Errorf("%w: report run id is required", ErrInvalidRequest)
	}
	run, err := s.reportStore.GetReportRun(ctx, reportRunID)
	if err != nil {
		return nil, err
	}
	return &cerebrov1.GetReportRunResponse{Run: run}, nil
}

func (s *Service) runFindingSummary(ctx context.Context, parameters map[string]string) (*structpb.Struct, error) {
	tenantID := strings.TrimSpace(parameters[reportParameterTenantID])
	if tenantID == "" {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterTenantID)
	}
	runtimeID := strings.TrimSpace(parameters[reportParameterRuntimeID])
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterRuntimeID)
	}
	resourceLimit, err := normalizePositiveLimit(parameters[reportParameterResourceLimit], defaultResourceEvidenceLimit, maxResourceEvidenceLimit, reportParameterResourceLimit)
	if err != nil {
		return nil, err
	}
	graphLimit, err := normalizePositiveLimit(parameters[reportParameterGraphLimit], defaultNeighborhoodEvidenceLimit, maxNeighborhoodEvidenceLimit, reportParameterGraphLimit)
	if err != nil {
		return nil, err
	}
	parameters[reportParameterResourceLimit] = strconv.Itoa(resourceLimit)
	parameters[reportParameterGraphLimit] = strconv.Itoa(graphLimit)
	findings, err := s.findingStore.ListFindings(ctx, ports.ListFindingsRequest{TenantID: tenantID, RuntimeID: runtimeID})
	if err != nil {
		return nil, fmt.Errorf("list findings for tenant %q runtime %q: %w", tenantID, runtimeID, err)
	}
	severityCounts := make(map[string]int, len(findings))
	statusCounts := make(map[string]int, len(findings))
	dueStatusCounts := make(map[string]int, len(findings))
	ruleCounts := make(map[string]int, len(findings))
	policyCounts := make(map[string]int, len(findings))
	checkCounts := make(map[string]*checkCountEntry, len(findings))
	controlCounts := make(map[string]*controlCountEntry, len(findings))
	resourceCounts := make(map[string]int, len(findings))
	noteCount := 0
	notedFindingCount := 0
	ticketCount := 0
	ticketedFindingCount := 0
	now := time.Now().UTC()
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
		dueStatusCounts[dueStatusBucket(finding, now)]++
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID != "" {
			ruleCounts[ruleID]++
		}
		policyID := strings.TrimSpace(finding.PolicyID)
		if policyID != "" {
			policyCounts[policyID]++
		}
		checkID := strings.TrimSpace(finding.CheckID)
		if checkID != "" {
			entry, ok := checkCounts[checkID]
			if !ok {
				entry = &checkCountEntry{
					CheckID:   checkID,
					CheckName: strings.TrimSpace(finding.CheckName),
				}
				checkCounts[checkID] = entry
			}
			entry.Count++
		}
		seenControlRefs := make(map[string]struct{}, len(finding.ControlRefs))
		for _, controlRef := range finding.ControlRefs {
			normalized, key := normalizeControlRef(controlRef)
			if key == "" {
				continue
			}
			if _, seen := seenControlRefs[key]; seen {
				continue
			}
			seenControlRefs[key] = struct{}{}
			entry, ok := controlCounts[key]
			if !ok {
				entry = &controlCountEntry{
					FrameworkName: normalized.FrameworkName,
					ControlID:     normalized.ControlID,
				}
				controlCounts[key] = entry
			}
			entry.Count++
		}
		if resourceURN := primaryResourceURN(finding); resourceURN != "" {
			resourceCounts[resourceURN]++
		}
		if len(finding.Notes) != 0 {
			notedFindingCount++
			noteCount += len(finding.Notes)
		}
		if len(finding.Tickets) != 0 {
			ticketedFindingCount++
			ticketCount += len(finding.Tickets)
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
		reportParameterTenantID:  tenantID,
		reportParameterRuntimeID: runtimeID,
		"total_findings":         len(findings),
		"severity_counts":        countEntries(severityCounts, "severity"),
		"status_counts":          countEntries(statusCounts, "status"),
		"due_status_counts":      countEntries(dueStatusCounts, "due_status"),
		"rule_counts":            countEntries(ruleCounts, "rule_id"),
		"policy_counts":          countEntries(policyCounts, "policy_id"),
		"check_counts":           checkCountEntries(checkCounts),
		"control_counts":         controlCountEntries(controlCounts),
		"noted_finding_count":    notedFindingCount,
		"note_count":             noteCount,
		"ticketed_finding_count": ticketedFindingCount,
		"ticket_count":           ticketCount,
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
		Description: "Materialize one tenant/runtime-scoped summary of persisted findings, grouped by severity, status, due-date posture, rule, policy, check, and control, with note and ticket activity plus bounded graph evidence for top resources when the graph is configured.",
		Parameters: []*cerebrov1.ReportParameter{
			{
				Id:          reportParameterTenantID,
				Description: "Tenant identifier whose persisted findings should be summarized.",
				Required:    true,
			},
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

func reportRunID(reportID string, generatedAt time.Time) (string, error) {
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-")
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate report run id entropy: %w", err)
	}
	return replacer.Replace(strings.TrimSpace(reportID)) + "-" + fmt.Sprintf("%d", generatedAt.UnixNano()) + "-" + hex.EncodeToString(random), nil
}

type countEntry struct {
	Key   string
	Count int
}

type checkCountEntry struct {
	CheckID   string
	CheckName string
	Count     int
}

type controlCountEntry struct {
	FrameworkName string
	ControlID     string
	Count         int
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

func checkCountEntries(counts map[string]*checkCountEntry) []any {
	entries := sortedCheckCountEntries(counts)
	values := make([]any, 0, len(entries))
	for _, entry := range entries {
		values = append(values, map[string]any{
			"check_id":   entry.CheckID,
			"check_name": entry.CheckName,
			"count":      entry.Count,
		})
	}
	return values
}

func controlCountEntries(counts map[string]*controlCountEntry) []any {
	entries := sortedControlCountEntries(counts)
	values := make([]any, 0, len(entries))
	for _, entry := range entries {
		values = append(values, map[string]any{
			"framework_name": entry.FrameworkName,
			"control_id":     entry.ControlID,
			"count":          entry.Count,
		})
	}
	return values
}

func dueStatusBucket(finding *ports.FindingRecord, now time.Time) string {
	if finding == nil || finding.DueAt.IsZero() {
		return "unscheduled"
	}
	if strings.TrimSpace(finding.Status) == "open" && finding.DueAt.UTC().Before(now) {
		return "overdue"
	}
	return "scheduled"
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

func sortedCheckCountEntries(counts map[string]*checkCountEntry) []*checkCountEntry {
	entries := make([]*checkCountEntry, 0, len(counts))
	for _, entry := range counts {
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(left *checkCountEntry, right *checkCountEntry) int {
		switch {
		case left.Count > right.Count:
			return -1
		case left.Count < right.Count:
			return 1
		case left.CheckID < right.CheckID:
			return -1
		case left.CheckID > right.CheckID:
			return 1
		default:
			return 0
		}
	})
	return entries
}

func sortedControlCountEntries(counts map[string]*controlCountEntry) []*controlCountEntry {
	entries := make([]*controlCountEntry, 0, len(counts))
	for _, entry := range counts {
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(left *controlCountEntry, right *controlCountEntry) int {
		switch {
		case left.Count > right.Count:
			return -1
		case left.Count < right.Count:
			return 1
		case left.FrameworkName < right.FrameworkName:
			return -1
		case left.FrameworkName > right.FrameworkName:
			return 1
		case left.ControlID < right.ControlID:
			return -1
		case left.ControlID > right.ControlID:
			return 1
		default:
			return 0
		}
	})
	return entries
}

func normalizeControlRef(value ports.FindingControlRef) (ports.FindingControlRef, string) {
	normalized := ports.FindingControlRef{
		FrameworkName: strings.TrimSpace(value.FrameworkName),
		ControlID:     strings.TrimSpace(value.ControlID),
	}
	if normalized.FrameworkName == "" || normalized.ControlID == "" {
		return ports.FindingControlRef{}, ""
	}
	return normalized, normalized.FrameworkName + "|" + normalized.ControlID
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
		return 0, fmt.Errorf("%w: report parameter %q must be a positive integer: %w", ErrInvalidRequest, parameterID, err)
	}
	switch {
	case parsed <= 0:
		return 0, fmt.Errorf("%w: report parameter %q must be greater than zero", ErrInvalidRequest, parameterID)
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
		relationPayload := map[string]any{
			"from_urn": relation.FromURN,
			"relation": relation.Relation,
			"to_urn":   relation.ToURN,
		}
		if len(relation.Attributes) > 0 {
			relationPayload["attributes"] = relation.Attributes
		}
		payload = append(payload, relationPayload)
	}
	return payload
}
