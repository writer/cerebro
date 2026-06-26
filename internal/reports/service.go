package reports

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	findinganalysis "github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
)

const (
	findingSummaryReportID           = "finding-summary"
	findingSummaryReportName         = "Finding Summary"
	riskDeltaReportID                = "risk-delta"
	riskDeltaReportName              = "Risk Delta"
	riskActionPlanReportID           = "risk-action-plan"
	riskActionPlanReportName         = "Risk Action Plan"
	findingSummaryReportStatus       = "completed"
	reportParameterTenantID          = "tenant_id"
	reportParameterRuntimeIDs        = "runtime_ids"
	reportParameterScenarioType      = "scenario_type"
	reportParameterTargetURN         = "target_urn"
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

type graphNeighborhoodBatchStore interface {
	GetEntityNeighborhoods(context.Context, []string, int) (map[string]*ports.EntityNeighborhood, error)
}

// New constructs the report service.
func New(findingStore ports.FindingStore, graphStore ports.GraphQueryStore, reportStore ports.ReportStore) *Service {
	return &Service{
		findingStore: findingStore,
		graphStore:   graphStore,
		reportStore:  reportStore,
	}
}

func (s *Service) effectiveRiskScoringConfig(ctx context.Context, tenantID string) (*ports.RiskScoringConfig, error) {
	if s == nil || s.findingStore == nil {
		return nil, nil
	}
	store, ok := s.findingStore.(ports.RiskScoringConfigStore)
	if !ok {
		return nil, nil
	}
	config, err := store.GetRiskScoringConfig(ctx, strings.TrimSpace(tenantID))
	if err != nil {
		if errors.Is(err, ports.ErrRiskScoringConfigNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("load risk scoring config: %w", err)
	}
	normalized, err := findinganalysis.NormalizeCompleteRiskScoringConfig(*config)
	if err != nil {
		return nil, fmt.Errorf("normalize risk scoring config: %w", err)
	}
	return &normalized, nil
}

// List returns the built-in report definition catalog.
func (s *Service) List() *cerebrov1.ListReportDefinitionsResponse {
	return &cerebrov1.ListReportDefinitionsResponse{
		Reports: []*cerebrov1.ReportDefinition{
			findingSummaryDefinition(),
			riskDeltaDefinition(),
			riskActionPlanDefinition(),
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
	case riskDeltaReportID:
		result, err = s.runRiskDelta(ctx, parameters)
	case riskActionPlanReportID:
		result, err = s.runRiskActionPlan(ctx, parameters)
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
	runtimeIDs := normalizeRuntimeIDs(parameters[reportParameterRuntimeIDs])
	if len(runtimeIDs) == 0 {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterRuntimeIDs)
	}
	runtimeIDsCSV := strings.Join(runtimeIDs, ",")
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
	parameters[reportParameterRuntimeIDs] = runtimeIDsCSV
	listRequest := ports.ListFindingsRequest{TenantID: tenantID, Order: ports.FindingOrderRiskScore}
	if len(runtimeIDs) == 1 {
		listRequest.RuntimeID = runtimeIDs[0]
	} else {
		listRequest.RuntimeIDs = runtimeIDs
	}
	findings, err := s.findingStore.ListFindings(ctx, listRequest)
	if err != nil {
		return nil, fmt.Errorf("list findings for tenant %q runtimes %q: %w", tenantID, runtimeIDsCSV, err)
	}
	severityCounts := make(map[string]int, len(findings))
	statusCounts := make(map[string]int, len(findings))
	dueStatusCounts := make(map[string]int, len(findings))
	runtimeCounts := make(map[string]int, len(findings))
	sourceCounts := make(map[string]int, len(findings))
	ruleCounts := make(map[string]int, len(findings))
	policyCounts := make(map[string]int, len(findings))
	checkCounts := make(map[string]*checkCountEntry, len(findings))
	controlCounts := make(map[string]*controlCountEntry, len(findings))
	resourceCounts := make(map[string]int, len(findings))
	riskCounts := make(map[string]int, len(findings))
	riskFactorCounts := make(map[string]*riskFactorCountEntry, len(findings))
	noteCount := 0
	notedFindingCount := 0
	ticketCount := 0
	ticketedFindingCount := 0
	ruleSourceIDs := findinganalysis.BuiltinRuleSourceIDs()
	now := time.Now().UTC()
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if findingRuntimeID := strings.TrimSpace(finding.RuntimeID); findingRuntimeID != "" {
			runtimeCounts[findingRuntimeID]++
		}
		if sourceID := findingSourceID(finding, ruleSourceIDs); sourceID != "" {
			sourceCounts[sourceID]++
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
		if finding.RiskScore != 0 {
			riskCounts[reportRiskLevel(finding.RiskScore)]++
		}
		if len(finding.RiskFactors) != 0 {
			for _, factor := range finding.RiskFactors {
				factorID := strings.TrimSpace(factor.FactorID)
				if factorID == "" {
					continue
				}
				entry := riskFactorCounts[factorID]
				if entry == nil {
					entry = &riskFactorCountEntry{
						FactorID:             factorID,
						Category:             strings.TrimSpace(factor.Category),
						SeverityContribution: strings.TrimSpace(factor.SeverityContribution),
					}
					riskFactorCounts[factorID] = entry
				}
				entry.Count++
				entry.WeightTotal += factor.Weight
			}
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
	graphNeighborhoods := map[string]*ports.EntityNeighborhood{}
	if s.graphStore != nil {
		graphEvidenceStatus = graphEvidenceStatusIncluded
		graphEvidence, graphNeighborhoods, err = s.graphEvidence(ctx, resourceCounts, resourceLimit, graphLimit)
		if err != nil {
			return nil, err
		}
	}
	riskConfig, err := s.effectiveRiskScoringConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	exposureReport := findinganalysis.AnalyzeFindingExposure(findings, findinganalysis.FindingExposureAnalysisOptions{
		Limit:              10,
		SampleLimit:        3,
		GraphNeighborhoods: graphNeighborhoods,
		RiskScoringConfig:  riskConfig,
	})
	if graphEvidenceStatus == graphEvidenceStatusUnconfigured {
		exposureReport.AttackPaths = nil
	}
	exposureAnalysis, err := jsonPayload(exposureReport)
	if err != nil {
		return nil, fmt.Errorf("build exposure analysis report payload: %w", err)
	}
	result, err := structpb.NewStruct(map[string]any{
		reportParameterTenantID:   tenantID,
		reportParameterRuntimeIDs: reportStringValues(runtimeIDs),
		"total_findings":          len(findings),
		"runtime_counts":          countEntries(runtimeCounts, "runtime_id"),
		"source_counts":           countEntries(sourceCounts, "source_id"),
		"severity_counts":         countEntries(severityCounts, "severity"),
		"status_counts":           countEntries(statusCounts, "status"),
		"due_status_counts":       countEntries(dueStatusCounts, "due_status"),
		"rule_counts":             countEntries(ruleCounts, "rule_id"),
		"policy_counts":           countEntries(policyCounts, "policy_id"),
		"check_counts":            checkCountEntries(checkCounts),
		"control_counts":          controlCountEntries(controlCounts),
		"noted_finding_count":     notedFindingCount,
		"note_count":              noteCount,
		"ticketed_finding_count":  ticketedFindingCount,
		"ticket_count":            ticketCount,
		"resource_counts":         countEntries(resourceCounts, "resource_urn"),
		"risk_counts":             countEntries(riskCounts, "risk_level"),
		"risk_factor_counts":      riskFactorCountEntries(riskFactorCounts),
		"top_risk_findings":       topRiskFindingEntries(findings, 10),
		"exposure_analysis":       exposureAnalysis,
		"graph_evidence_status":   graphEvidenceStatus,
		"graph_evidence":          graphEvidence,
	})
	if err != nil {
		return nil, fmt.Errorf("build finding summary report result: %w", err)
	}
	return result, nil
}

func (s *Service) runRiskDelta(ctx context.Context, parameters map[string]string) (*structpb.Struct, error) {
	tenantID := strings.TrimSpace(parameters[reportParameterTenantID])
	if tenantID == "" {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterTenantID)
	}
	runtimeIDs := normalizeRuntimeIDs(parameters[reportParameterRuntimeIDs])
	if len(runtimeIDs) == 0 {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterRuntimeIDs)
	}
	scenarioType, err := normalizeRiskDeltaScenario(parameters[reportParameterScenarioType])
	if err != nil {
		return nil, err
	}
	targetURN := strings.TrimSpace(parameters[reportParameterTargetURN])
	if targetURN == "" {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterTargetURN)
	}
	if err := validateRiskDeltaTargetTenant(tenantID, targetURN); err != nil {
		return nil, err
	}
	runtimeIDsCSV := strings.Join(runtimeIDs, ",")
	resourceLimit, err := normalizePositiveLimit(parameters[reportParameterResourceLimit], defaultResourceEvidenceLimit, maxResourceEvidenceLimit, reportParameterResourceLimit)
	if err != nil {
		return nil, err
	}
	graphLimit, err := normalizePositiveLimit(parameters[reportParameterGraphLimit], defaultNeighborhoodEvidenceLimit, maxNeighborhoodEvidenceLimit, reportParameterGraphLimit)
	if err != nil {
		return nil, err
	}
	parameters[reportParameterRuntimeIDs] = runtimeIDsCSV
	parameters[reportParameterScenarioType] = scenarioType
	parameters[reportParameterTargetURN] = targetURN
	parameters[reportParameterResourceLimit] = strconv.Itoa(resourceLimit)
	parameters[reportParameterGraphLimit] = strconv.Itoa(graphLimit)
	listRequest := ports.ListFindingsRequest{TenantID: tenantID, Order: ports.FindingOrderRiskScore}
	if len(runtimeIDs) == 1 {
		listRequest.RuntimeID = runtimeIDs[0]
	} else {
		listRequest.RuntimeIDs = runtimeIDs
	}
	findings, err := s.findingStore.ListFindings(ctx, listRequest)
	if err != nil {
		return nil, fmt.Errorf("list findings for tenant %q runtimes %q: %w", tenantID, runtimeIDsCSV, err)
	}
	graphEvidenceStatus := graphEvidenceStatusUnconfigured
	graphNeighborhoods := map[string]*ports.EntityNeighborhood{}
	if s.graphStore != nil {
		graphEvidenceStatus = graphEvidenceStatusIncluded
		graphNeighborhoods, err = s.riskDeltaGraphNeighborhoods(ctx, targetURN, findings, resourceLimit, graphLimit)
		if err != nil {
			return nil, err
		}
	}
	riskConfig, err := s.effectiveRiskScoringConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	report := findinganalysis.SimulateRiskDelta(findings, findinganalysis.RiskDeltaSimulationOptions{
		ScenarioType:       scenarioType,
		TargetURN:          targetURN,
		Limit:              10,
		GraphNeighborhoods: graphNeighborhoods,
		RiskScoringConfig:  riskConfig,
	})
	riskDelta, err := jsonPayload(report)
	if err != nil {
		return nil, fmt.Errorf("build risk delta report payload: %w", err)
	}
	result, err := structpb.NewStruct(map[string]any{
		reportParameterTenantID:       tenantID,
		reportParameterRuntimeIDs:     reportStringValues(runtimeIDs),
		reportParameterScenarioType:   scenarioType,
		reportParameterTargetURN:      targetURN,
		"total_findings":              len(findings),
		"graph_evidence_status":       graphEvidenceStatus,
		"graph_neighborhood_count":    len(graphNeighborhoods),
		"risk_delta":                  riskDelta,
		"risk_score_change":           report.RiskScoreChange,
		"attack_path_score_change":    report.AttackPathScoreChange,
		"attack_path_count_change":    report.AttackPathCountChange,
		"risk_score_reduction":        report.RiskScoreReduction,
		"attack_path_score_reduction": report.AttackPathScoreReduction,
		"attack_path_count_reduction": report.AttackPathCountReduction,
	})
	if err != nil {
		return nil, fmt.Errorf("build risk delta report result: %w", err)
	}
	return result, nil
}

func jsonPayload(value any) (any, error) {
	content, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := json.Unmarshal(content, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func normalizeRuntimeIDs(runtimeIDs string) []string {
	values := strings.FieldsFunc(runtimeIDs, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t'
	})
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	slices.Sort(normalized)
	return normalized
}

func findingSourceID(finding *ports.FindingRecord, ruleSourceIDs map[string]string) string {
	if finding == nil {
		return ""
	}
	for _, key := range []string{"source_id", "rule_source_id", "source_family"} {
		if value := strings.TrimSpace(finding.Attributes[key]); value != "" {
			return value
		}
	}
	if sourceID := strings.TrimSpace(ruleSourceIDs[strings.TrimSpace(finding.RuleID)]); sourceID != "" {
		return sourceID
	}
	return "unknown"
}

func (s *Service) graphEvidence(ctx context.Context, resourceCounts map[string]int, resourceLimit int, graphLimit int) ([]any, map[string]*ports.EntityNeighborhood, error) {
	entries := sortedCountEntries(resourceCounts)
	if len(entries) > resourceLimit {
		entries = entries[:resourceLimit]
	}
	roots := make([]string, 0, len(entries))
	for _, entry := range entries {
		roots = append(roots, entry.Key)
	}
	if batchNeighborhoods, ok, err := s.batchGraphNeighborhoods(ctx, roots, graphLimit); err != nil {
		return nil, nil, fmt.Errorf("batch load graph evidence: %w", err)
	} else if ok {
		evidence := make([]any, 0, len(entries))
		neighborhoods := make(map[string]*ports.EntityNeighborhood, len(entries))
		for _, entry := range entries {
			neighborhood, found := batchNeighborhoods[entry.Key]
			if !found {
				evidence = append(evidence, missingGraphEvidenceEntry(entry))
				continue
			}
			evidence = appendIncludedGraphEvidence(evidence, neighborhoods, entry, neighborhood)
		}
		return evidence, neighborhoods, nil
	}
	evidence := make([]any, 0, len(entries))
	neighborhoods := make(map[string]*ports.EntityNeighborhood, len(entries))
	for _, entry := range entries {
		neighborhood, err := s.graphStore.GetEntityNeighborhood(ctx, entry.Key, graphLimit)
		switch {
		case err == nil:
			evidence = appendIncludedGraphEvidence(evidence, neighborhoods, entry, neighborhood)
		case errors.Is(err, ports.ErrGraphEntityNotFound):
			evidence = append(evidence, missingGraphEvidenceEntry(entry))
		default:
			return nil, nil, fmt.Errorf("load graph evidence for %q: %w", entry.Key, err)
		}
	}
	return evidence, neighborhoods, nil
}

func (s *Service) riskDeltaGraphNeighborhoods(ctx context.Context, targetURN string, findings []*ports.FindingRecord, resourceLimit int, graphLimit int) (map[string]*ports.EntityNeighborhood, error) {
	roots := []string{strings.TrimSpace(targetURN)}
	resourceCounts := map[string]int{}
	for _, finding := range findings {
		if resourceURN := primaryResourceURN(finding); resourceURN != "" {
			resourceCounts[resourceURN]++
		}
	}
	for _, entry := range sortedCountEntries(resourceCounts) {
		if len(roots) >= resourceLimit {
			break
		}
		roots = append(roots, entry.Key)
	}
	return s.graphNeighborhoods(ctx, roots, resourceLimit, graphLimit, "risk delta")
}

func (s *Service) graphNeighborhoods(ctx context.Context, rawRoots []string, resourceLimit int, graphLimit int, label string) (map[string]*ports.EntityNeighborhood, error) {
	roots := limitedGraphNeighborhoodRoots(rawRoots, resourceLimit)
	if batchNeighborhoods, ok, err := s.batchGraphNeighborhoods(ctx, roots, graphLimit); err != nil {
		return nil, fmt.Errorf("batch load %s graph neighborhoods: %w", label, err)
	} else if ok {
		return batchNeighborhoods, nil
	}
	neighborhoods := make(map[string]*ports.EntityNeighborhood, len(roots))
	for _, rootURN := range roots {
		neighborhood, err := s.graphStore.GetEntityNeighborhood(ctx, rootURN, graphLimit)
		switch {
		case err == nil:
			neighborhoods[rootURN] = normalizedNeighborhood(neighborhood)
		case errors.Is(err, ports.ErrGraphEntityNotFound):
			continue
		default:
			return nil, fmt.Errorf("load %s graph neighborhood for %q: %w", label, rootURN, err)
		}
	}
	return neighborhoods, nil
}

func (s *Service) batchGraphNeighborhoods(ctx context.Context, roots []string, graphLimit int) (map[string]*ports.EntityNeighborhood, bool, error) {
	if len(roots) == 0 {
		return map[string]*ports.EntityNeighborhood{}, true, nil
	}
	batchStore, ok := s.graphStore.(graphNeighborhoodBatchStore)
	if !ok {
		return nil, false, nil
	}
	neighborhoods, err := batchStore.GetEntityNeighborhoods(ctx, roots, graphLimit)
	if err != nil {
		return nil, true, err
	}
	normalized := make(map[string]*ports.EntityNeighborhood, len(neighborhoods))
	for _, rootURN := range roots {
		neighborhood, ok := neighborhoods[rootURN]
		if !ok {
			continue
		}
		normalized[rootURN] = normalizedNeighborhood(neighborhood)
	}
	return normalized, true, nil
}

func limitedGraphNeighborhoodRoots(rawRoots []string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	roots := make([]string, 0, min(len(rawRoots), limit))
	seen := map[string]struct{}{}
	for _, rawRoot := range rawRoots {
		if len(roots) >= limit {
			break
		}
		rootURN := strings.TrimSpace(rawRoot)
		if rootURN == "" {
			continue
		}
		if _, ok := seen[rootURN]; ok {
			continue
		}
		seen[rootURN] = struct{}{}
		roots = append(roots, rootURN)
	}
	return roots
}

func normalizedNeighborhood(neighborhood *ports.EntityNeighborhood) *ports.EntityNeighborhood {
	if neighborhood == nil {
		return &ports.EntityNeighborhood{}
	}
	return neighborhood
}

func appendIncludedGraphEvidence(evidence []any, neighborhoods map[string]*ports.EntityNeighborhood, entry countEntry, neighborhood *ports.EntityNeighborhood) []any {
	neighborhood = normalizedNeighborhood(neighborhood)
	neighborhoods[entry.Key] = neighborhood
	return append(evidence, map[string]any{
		"resource_urn":  entry.Key,
		"finding_count": entry.Count,
		"status":        graphEvidenceEntryStatusIncluded,
		"root":          graphNodePayload(neighborhood.Root),
		"neighbors":     graphNodesPayload(neighborhood.Neighbors),
		"relations":     graphRelationsPayload(neighborhood.Relations),
	})
}

func missingGraphEvidenceEntry(entry countEntry) map[string]any {
	return map[string]any{
		"resource_urn":  entry.Key,
		"finding_count": entry.Count,
		"status":        graphEvidenceEntryStatusNotFound,
	}
}

func findingSummaryDefinition() *cerebrov1.ReportDefinition {
	return &cerebrov1.ReportDefinition{
		Id:          findingSummaryReportID,
		Name:        findingSummaryReportName,
		Description: "Materialize one tenant summary of persisted findings for one or more runtimes, grouped by severity, status, due-date posture, rule, policy, check, source, and control, with note and ticket activity plus bounded graph evidence for top resources when the graph is configured.",
		Parameters: []*cerebrov1.ReportParameter{
			{
				Id:          reportParameterTenantID,
				Description: "Tenant identifier whose persisted findings should be summarized.",
				Required:    true,
			},
			{
				Id:          reportParameterRuntimeIDs,
				Description: "Required comma-separated stored source runtime identifiers for finding summaries.",
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

func riskDeltaDefinition() *cerebrov1.ReportDefinition {
	return &cerebrov1.ReportDefinition{
		Id:          riskDeltaReportID,
		Name:        riskDeltaReportName,
		Description: "Simulate an in-memory remediation scenario against persisted findings and bounded graph neighborhoods, returning before/after risk, attack-path, and affected-finding deltas without mutating stores.",
		Parameters: []*cerebrov1.ReportParameter{
			{
				Id:          reportParameterTenantID,
				Description: "Tenant identifier whose persisted findings should be simulated.",
				Required:    true,
			},
			{
				Id:          reportParameterRuntimeIDs,
				Description: "Required comma-separated stored source runtime identifiers for risk delta simulation.",
				Required:    true,
			},
			{
				Id:          reportParameterScenarioType,
				Description: "Simulation scenario: remove_public_exposure, remove_privilege, patch_vulnerability, or compromise_identity.",
				Required:    true,
			},
			{
				Id:          reportParameterTargetURN,
				Description: "Graph/resource URN targeted by the simulated remediation.",
				Required:    true,
			},
			{
				Id:          reportParameterResourceLimit,
				Description: "Optional maximum number of resource roots to include in simulation graph context.",
				Required:    false,
			},
			{
				Id:          reportParameterGraphLimit,
				Description: "Optional maximum neighborhood size to read for each simulation graph root.",
				Required:    false,
			},
		},
	}
}

func reportDefinition(reportID string) (*cerebrov1.ReportDefinition, error) {
	switch strings.TrimSpace(reportID) {
	case findingSummaryReportID:
		return findingSummaryDefinition(), nil
	case riskDeltaReportID:
		return riskDeltaDefinition(), nil
	case riskActionPlanReportID:
		return riskActionPlanDefinition(), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrReportNotFound, reportID)
	}
}

func normalizeRiskDeltaScenario(value string) (string, error) {
	scenarioType := strings.TrimSpace(value)
	switch scenarioType {
	case findinganalysis.RiskDeltaScenarioCompromiseIdentity,
		findinganalysis.RiskDeltaScenarioPatchVulnerability,
		findinganalysis.RiskDeltaScenarioRemovePrivilege,
		findinganalysis.RiskDeltaScenarioRemovePublicExposure:
		return scenarioType, nil
	default:
		return "", fmt.Errorf("%w: report parameter %q must be one of %s, %s, %s, %s", ErrInvalidRequest, reportParameterScenarioType, findinganalysis.RiskDeltaScenarioRemovePublicExposure, findinganalysis.RiskDeltaScenarioRemovePrivilege, findinganalysis.RiskDeltaScenarioPatchVulnerability, findinganalysis.RiskDeltaScenarioCompromiseIdentity)
	}
}

func validateRiskDeltaTargetTenant(tenantID string, targetURN string) error {
	targetTenantID := tenantIDFromRiskDeltaTargetURN(targetURN)
	if targetTenantID == "" {
		return fmt.Errorf("%w: report parameter %q must be a tenant-scoped cerebro urn", ErrInvalidRequest, reportParameterTargetURN)
	}
	if targetTenantID != strings.TrimSpace(tenantID) {
		return fmt.Errorf("%w: report parameter %q tenant must match %q", ErrInvalidRequest, reportParameterTargetURN, reportParameterTenantID)
	}
	return nil
}

func tenantIDFromRiskDeltaTargetURN(urn string) string {
	parts := strings.SplitN(strings.TrimSpace(urn), ":", 5)
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

var sensitiveReportParameterTokens = []string{
	"token",
	"secret",
	"password",
	"passwd",
	"credential",
	"privatekey",
	"apikey",
	"accesskey",
	"clientsecret",
	"signingkey",
	"session",
	"cookie",
	"authorization",
	"xapikey",
}

func isSensitiveReportParameter(key string) bool {
	lowered := strings.ToLower(key)
	lowered = strings.ReplaceAll(lowered, "-", "")
	lowered = strings.ReplaceAll(lowered, "_", "")
	lowered = strings.ReplaceAll(lowered, " ", "")
	for _, token := range sensitiveReportParameterTokens {
		if strings.Contains(lowered, token) {
			return true
		}
	}
	return false
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
		if isSensitiveReportParameter(trimmedKey) {
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

type riskFactorCountEntry struct {
	FactorID             string
	Category             string
	SeverityContribution string
	Count                int
	WeightTotal          int
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

func topRiskFindingEntries(findings []*ports.FindingRecord, limit int) []any {
	records := append([]*ports.FindingRecord(nil), findings...)
	slices.SortFunc(records, func(left *ports.FindingRecord, right *ports.FindingRecord) int {
		if left == nil || right == nil {
			switch {
			case left == nil && right == nil:
				return 0
			case left == nil:
				return 1
			default:
				return -1
			}
		}
		switch {
		case left.RiskScore > right.RiskScore:
			return -1
		case left.RiskScore < right.RiskScore:
			return 1
		case reportSeverityRank(left.Severity) > reportSeverityRank(right.Severity):
			return -1
		case reportSeverityRank(left.Severity) < reportSeverityRank(right.Severity):
			return 1
		case left.LastObservedAt.After(right.LastObservedAt):
			return -1
		case left.LastObservedAt.Before(right.LastObservedAt):
			return 1
		case left.ID < right.ID:
			return -1
		case left.ID > right.ID:
			return 1
		default:
			return 0
		}
	})
	if len(records) > limit {
		records = records[:limit]
	}
	values := make([]any, 0, len(records))
	for _, finding := range records {
		if finding == nil || finding.RiskScore == 0 {
			continue
		}
		values = append(values, map[string]any{
			"finding_id":       finding.ID,
			"title":            finding.Title,
			"severity":         finding.Severity,
			"risk_score":       finding.RiskScore,
			"likelihood_score": finding.LikelihoodScore,
			"impact_score":     finding.ImpactScore,
			"risk_level":       reportRiskLevel(finding.RiskScore),
			"risk_reasons":     reportStringValues(finding.RiskReasons),
			"risk_factors":     reportRiskFactors(finding.RiskFactors),
		})
	}
	return values
}

func reportSeverityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func reportStringValues(values []string) []any {
	if len(values) == 0 {
		return []any{}
	}
	converted := make([]any, 0, len(values))
	for _, value := range values {
		converted = append(converted, value)
	}
	return converted
}

func reportRiskFactors(factors []ports.FindingRiskFactor) []any {
	if len(factors) == 0 {
		return []any{}
	}
	entries := append([]ports.FindingRiskFactor(nil), factors...)
	slices.SortFunc(entries, func(left ports.FindingRiskFactor, right ports.FindingRiskFactor) int {
		switch {
		case left.Weight > right.Weight:
			return -1
		case left.Weight < right.Weight:
			return 1
		case left.FactorID < right.FactorID:
			return -1
		case left.FactorID > right.FactorID:
			return 1
		default:
			return 0
		}
	})
	values := make([]any, 0, len(entries))
	for _, factor := range entries {
		entry := map[string]any{
			"factor_id":             factor.FactorID,
			"category":              factor.Category,
			"weight":                factor.Weight,
			"severity_contribution": factor.SeverityContribution,
			"evidence_refs":         reportStringValues(factor.EvidenceRefs),
			"suppression_scope":     factor.SuppressionScope,
		}
		if !factor.ObservedAt.IsZero() {
			entry["observed_at"] = factor.ObservedAt.UTC().Format(time.RFC3339Nano)
		}
		values = append(values, entry)
	}
	return values
}

func reportRiskLevel(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
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

func riskFactorCountEntries(counts map[string]*riskFactorCountEntry) []any {
	entries := sortedRiskFactorCountEntries(counts)
	values := make([]any, 0, len(entries))
	for _, entry := range entries {
		values = append(values, map[string]any{
			"factor_id":             entry.FactorID,
			"category":              entry.Category,
			"severity_contribution": entry.SeverityContribution,
			"count":                 entry.Count,
			"weight_total":          entry.WeightTotal,
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

func sortedRiskFactorCountEntries(counts map[string]*riskFactorCountEntry) []*riskFactorCountEntry {
	entries := make([]*riskFactorCountEntry, 0, len(counts))
	for _, entry := range counts {
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(left *riskFactorCountEntry, right *riskFactorCountEntry) int {
		switch {
		case left.Count > right.Count:
			return -1
		case left.Count < right.Count:
			return 1
		case left.WeightTotal > right.WeightTotal:
			return -1
		case left.WeightTotal < right.WeightTotal:
			return 1
		case left.FactorID < right.FactorID:
			return -1
		case left.FactorID > right.FactorID:
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

func normalizePositiveLimit(raw string, defaultValue int, maxValue int, parameterID string) (int, error) { //nolint:unparam // distinct report parameters intentionally carry separate defaults.
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
