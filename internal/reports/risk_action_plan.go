package reports

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/riskplan"
)

const (
	reportParameterCandidateLimit      = "candidate_limit"
	reportParameterIncludeUnscored     = "include_unscored"
	reportParameterPreviousReportRunID = "previous_report_run_id"
)

func (s *Service) runRiskActionPlan(ctx context.Context, parameters map[string]string) (*structpb.Struct, error) {
	tenantID := strings.TrimSpace(parameters[reportParameterTenantID])
	if tenantID == "" {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterTenantID)
	}
	runtimeIDs := normalizeRuntimeIDs(parameters[reportParameterRuntimeIDs])
	if len(runtimeIDs) == 0 {
		return nil, fmt.Errorf("%w: report parameter %q is required", ErrInvalidRequest, reportParameterRuntimeIDs)
	}
	candidateLimit, err := normalizePositiveLimit(parameters[reportParameterCandidateLimit], riskplan.DefaultCandidateLimit, riskplan.MaxCandidateLimit, reportParameterCandidateLimit)
	if err != nil {
		return nil, err
	}
	resourceLimit, err := normalizePositiveLimit(parameters[reportParameterResourceLimit], defaultResourceEvidenceLimit, maxResourceEvidenceLimit, reportParameterResourceLimit)
	if err != nil {
		return nil, err
	}
	graphLimit, err := normalizePositiveLimit(parameters[reportParameterGraphLimit], defaultNeighborhoodEvidenceLimit, maxNeighborhoodEvidenceLimit, reportParameterGraphLimit)
	if err != nil {
		return nil, err
	}
	includeUnscored, err := normalizeBoolParameter(parameters[reportParameterIncludeUnscored], false, reportParameterIncludeUnscored)
	if err != nil {
		return nil, err
	}
	runtimeIDsCSV := strings.Join(runtimeIDs, ",")
	parameters[reportParameterRuntimeIDs] = runtimeIDsCSV
	parameters[reportParameterCandidateLimit] = strconv.Itoa(candidateLimit)
	parameters[reportParameterResourceLimit] = strconv.Itoa(resourceLimit)
	parameters[reportParameterGraphLimit] = strconv.Itoa(graphLimit)
	if includeUnscored {
		parameters[reportParameterIncludeUnscored] = "true"
	}

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
	now := time.Now().UTC()
	previousCandidates, err := s.previousRiskActionCandidates(ctx, tenantID, strings.TrimSpace(parameters[reportParameterPreviousReportRunID]))
	if err != nil {
		return nil, err
	}
	riskConfig, err := s.effectiveRiskScoringConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	graphEvidenceStatus := graphEvidenceStatusUnconfigured
	graphNeighborhoods := map[string]*ports.EntityNeighborhood{}
	if s.graphStore != nil {
		graphEvidenceStatus = graphEvidenceStatusIncluded
		targetURNs := riskplan.TargetURNs(findings, riskplan.Options{
			TenantID:          tenantID,
			RuntimeIDs:        runtimeIDs,
			SeedLimit:         riskplan.MaxSimulationSeedLimit,
			Now:               now,
			IncludeUnscored:   includeUnscored,
			RiskScoringConfig: riskConfig,
		})
		graphNeighborhoods, err = s.riskActionPlanGraphNeighborhoods(ctx, targetURNs, resourceLimit, graphLimit)
		if err != nil {
			return nil, err
		}
	}
	plan := riskplan.Analyze(findings, riskplan.Options{
		TenantID:           tenantID,
		RuntimeIDs:         runtimeIDs,
		CandidateLimit:     candidateLimit,
		SeedLimit:          riskplan.MaxSimulationSeedLimit,
		GraphNeighborhoods: graphNeighborhoods,
		Now:                now,
		PreviousCandidates: previousCandidates,
		IncludeUnscored:    includeUnscored,
		RiskScoringConfig:  riskConfig,
	})
	actionCandidates, err := jsonPayload(plan.ActionCandidates)
	if err != nil {
		return nil, fmt.Errorf("build risk action plan candidate payload: %w", err)
	}
	planPayload, err := jsonPayload(plan)
	if err != nil {
		return nil, fmt.Errorf("build risk action plan payload: %w", err)
	}
	resultValues := map[string]any{
		reportParameterTenantID:        tenantID,
		reportParameterRuntimeIDs:      reportStringValues(runtimeIDs),
		reportParameterCandidateLimit:  candidateLimit,
		reportParameterResourceLimit:   resourceLimit,
		reportParameterGraphLimit:      graphLimit,
		reportParameterIncludeUnscored: includeUnscored,
		"model_version":                plan.ModelVersion,
		"total_findings":               plan.TotalFindings,
		"candidate_seed_count":         plan.CandidateSeedCount,
		"total_candidates":             plan.TotalCandidates,
		"simulated_candidate_count":    plan.SimulatedCandidateCount,
		"unscored_candidate_count":     plan.UnscoredCandidateCount,
		"graph_evidence_status":        graphEvidenceStatus,
		"graph_neighborhood_count":     len(graphNeighborhoods),
		"action_candidates":            actionCandidates,
		"plan":                         planPayload,
	}
	if plan.Diff != nil {
		planDiff, err := jsonPayload(plan.Diff)
		if err != nil {
			return nil, fmt.Errorf("build risk action plan diff payload: %w", err)
		}
		resultValues["plan_diff"] = planDiff
	}
	result, err := structpb.NewStruct(resultValues)
	if err != nil {
		return nil, fmt.Errorf("build risk action plan report result: %w", err)
	}
	return result, nil
}

func (s *Service) previousRiskActionCandidates(ctx context.Context, tenantID string, reportRunID string) ([]riskplan.Candidate, error) {
	if reportRunID == "" {
		return nil, nil
	}
	if s.reportStore == nil {
		return nil, ErrRuntimeUnavailable
	}
	run, err := s.reportStore.GetReportRun(ctx, reportRunID)
	if err != nil {
		return nil, fmt.Errorf("load previous risk action plan report run %q: %w", reportRunID, err)
	}
	if runTenantID := strings.TrimSpace(run.GetParameters()[reportParameterTenantID]); runTenantID != strings.TrimSpace(tenantID) {
		return nil, fmt.Errorf("%w: previous_report_run_id %q does not belong to tenant %q", ErrInvalidRequest, reportRunID, tenantID)
	}
	result := run.GetResult()
	if result == nil {
		return nil, nil
	}
	content, err := json.Marshal(result.AsMap()["action_candidates"])
	if err != nil {
		return nil, fmt.Errorf("encode previous risk action plan candidates from %q: %w", reportRunID, err)
	}
	candidates, err := riskplan.DecodeCandidates(content)
	if err != nil {
		return nil, fmt.Errorf("decode previous risk action plan candidates from %q: %w", reportRunID, err)
	}
	return candidates, nil
}

func normalizeBoolParameter(raw string, defaultValue bool, parameterID string) (bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return defaultValue, nil
	}
	value, err := strconv.ParseBool(trimmed)
	if err != nil {
		return false, fmt.Errorf("%w: report parameter %q must be a boolean", ErrInvalidRequest, parameterID)
	}
	return value, nil
}

func (s *Service) riskActionPlanGraphNeighborhoods(ctx context.Context, targetURNs []string, resourceLimit int, graphLimit int) (map[string]*ports.EntityNeighborhood, error) {
	neighborhoods := map[string]*ports.EntityNeighborhood{}
	seen := map[string]struct{}{}
	for _, targetURN := range targetURNs {
		if len(seen) >= resourceLimit {
			break
		}
		targetURN = strings.TrimSpace(targetURN)
		if targetURN == "" {
			continue
		}
		if _, ok := seen[targetURN]; ok {
			continue
		}
		seen[targetURN] = struct{}{}
		neighborhood, err := s.graphStore.GetEntityNeighborhood(ctx, targetURN, graphLimit)
		switch {
		case err == nil:
			if neighborhood == nil {
				neighborhood = &ports.EntityNeighborhood{}
			}
			neighborhoods[targetURN] = neighborhood
		case errors.Is(err, ports.ErrGraphEntityNotFound):
			continue
		default:
			return nil, fmt.Errorf("load risk action plan graph neighborhood for %q: %w", targetURN, err)
		}
	}
	return neighborhoods, nil
}

func riskActionPlanDefinition() *cerebrov1.ReportDefinition {
	return &cerebrov1.ReportDefinition{
		Id:          riskActionPlanReportID,
		Name:        riskActionPlanReportName,
		Description: "Rank next-best remediation actions with typed score breakdowns, effort, ownership, evidence quality, prior outcome learning, and optional plan diffs without mutating stores.",
		Parameters: []*cerebrov1.ReportParameter{
			{
				Id:          reportParameterTenantID,
				Description: "Tenant identifier whose persisted findings should be planned.",
				Required:    true,
			},
			{
				Id:          reportParameterRuntimeIDs,
				Description: "Required comma-separated stored source runtime identifiers for action planning.",
				Required:    true,
			},
			{
				Id:          reportParameterCandidateLimit,
				Description: "Optional maximum number of ranked remediation candidates to return.",
				Required:    false,
			},
			{
				Id:          reportParameterResourceLimit,
				Description: "Optional maximum number of candidate target roots to include in simulation graph context.",
				Required:    false,
			},
			{
				Id:          reportParameterGraphLimit,
				Description: "Optional maximum neighborhood size to read for each candidate target root.",
				Required:    false,
			},
			{
				Id:          reportParameterIncludeUnscored,
				Description: "Optional boolean that includes planning blockers such as missing ownership or stale evidence even when no direct risk-delta simulation is available.",
				Required:    false,
			},
			{
				Id:          reportParameterPreviousReportRunID,
				Description: "Optional prior risk-action-plan report run id used to return added, removed, and changed candidate diffs.",
				Required:    false,
			},
		},
	}
}
