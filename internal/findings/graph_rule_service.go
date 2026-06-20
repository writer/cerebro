package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
)

// EvaluateGraphRulesRequest scopes one graph-rule evaluation pass over one runtime.
type EvaluateGraphRulesRequest struct {
	RuntimeID string
	RuleIDs   []string
}

// GraphRuleEvaluationResult reports one graph rule's outputs inside a multi-rule pass.
type GraphRuleEvaluationResult struct {
	Rule      *cerebrov1.RuleSpec
	Findings  []*ports.FindingRecord
	Run       *cerebrov1.FindingEvaluationRun
	Evidence  []*cerebrov1.FindingEvidence
	RowsRead  uint32
	Truncated bool
}

// EvaluateGraphRulesResult reports one multi-rule graph evaluation over one runtime.
type EvaluateGraphRulesResult struct {
	Runtime     *cerebrov1.SourceRuntime
	Evaluations []*GraphRuleEvaluationResult
}

// ErrGraphRuntimeUnavailable indicates that the graph query boundary is not configured.
var ErrGraphRuntimeUnavailable = fmt.Errorf("%w: graph query boundary is not configured", ErrRuntimeUnavailable)

// EvaluateSourceRuntimeGraphRules runs every registered GraphRule that supports one runtime.
//
// Each rule is evaluated in its own bounded read transaction; failures of one rule do not
// abort the others. The orchestrator should call this after the graph projection has been
// updated for the runtime so the rule sees the freshest world model.
func (s *Service) EvaluateSourceRuntimeGraphRules(ctx context.Context, request EvaluateGraphRulesRequest) (*EvaluateGraphRulesResult, error) {
	if s == nil || s.runtimeStore == nil || s.store == nil || s.runStore == nil || s.evidenceStore == nil || s.rules == nil {
		return nil, ErrRuntimeUnavailable
	}
	if s.graphQuery == nil {
		return nil, ErrGraphRuntimeUnavailable
	}
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if runtimeID == "" {
		return nil, fmt.Errorf("%w: source runtime id is required", ErrInvalidRequest)
	}
	runtime, err := s.runtimeStore.GetSourceRuntime(ctx, runtimeID)
	if err != nil {
		return nil, err
	}
	candidates, err := s.selectGraphRules(runtime, request.RuleIDs)
	if err != nil {
		return nil, err
	}
	startedAt := time.Now().UTC()
	result := &EvaluateGraphRulesResult{
		Runtime:     runtime,
		Evaluations: make([]*GraphRuleEvaluationResult, 0, len(candidates)),
	}
	var firstErr error
	for _, rule := range candidates {
		evaluation, err := s.evaluateGraphRule(ctx, runtime, rule, startedAt)
		if evaluation != nil {
			result.Evaluations = append(result.Evaluations, evaluation)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return result, firstErr
}

func (s *Service) evaluateGraphRule(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule GraphRule, startedAt time.Time) (result *GraphRuleEvaluationResult, err error) {
	spec := rule.Spec()
	run := newGraphFindingEvaluationRun(strings.TrimSpace(runtime.GetId()), spec.GetId(), startedAt)
	result = &GraphRuleEvaluationResult{
		Rule: spec,
		Run:  run,
	}
	queryPresent := false
	ruleStarted := time.Now()
	defer func() {
		emitGraphRuleEvaluationDetail(ctx, runtime, spec, result, queryPresent, time.Since(ruleStarted), err)
	}()
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return result, fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	queryRequest := rule.QueryFor(runtime)
	if strings.TrimSpace(queryRequest.Query) == "" {
		if retiredGraphRule(rule) {
			if err := s.resolveStaleGraphFindings(ctx, strings.TrimSpace(runtime.GetTenantId()), strings.TrimSpace(runtime.GetId()), spec.GetId(), nil); err != nil {
				evaluationErr := fmt.Errorf("resolve retired graph findings for rule %q: %w", spec.GetId(), err)
				return result, s.finishFailedGraphRun(ctx, run, 0, nil, evaluationErr)
			}
		}
		if err := s.finishCompletedGraphRun(ctx, run, 0, nil); err != nil {
			return result, err
		}
		return result, nil
	}
	queryPresent = true
	rows, err := s.graphQuery.ExecuteReadCypher(ctx, queryRequest)
	if err != nil {
		evaluationErr := fmt.Errorf("execute graph rule %q cypher: %w", spec.GetId(), err)
		return result, s.finishFailedGraphRun(ctx, run, 0, nil, evaluationErr)
	}
	result.RowsRead = boundedUint32(len(rows))
	result.Truncated = cypherRowsTruncated(queryRequest, len(rows))
	emitted, err := rule.EvaluateRows(ctx, runtime, rows)
	if err != nil {
		evaluationErr := fmt.Errorf("evaluate graph rule %q rows: %w", spec.GetId(), err)
		return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, nil, evaluationErr)
	}
	evidenceIDs := map[string]struct{}{}
	emittedFindingIDs := map[string]struct{}{}
	for _, record := range emitted {
		if record == nil {
			continue
		}
		graphRows := cloneGraphEvidenceRows(record.GraphEvidenceRows)
		record, err = s.reconcileLegacyFindingIdentity(ctx, record)
		if err != nil {
			evaluationErr := fmt.Errorf("reconcile finding identity for graph rule %q: %w", spec.GetId(), err)
			return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
		}
		stored, isNewFinding, err := s.upsertFindingWithRiskAndNewness(ctx, record, runtime, startedAt)
		if err != nil {
			evaluationErr := fmt.Errorf("persist finding for graph rule %q: %w", spec.GetId(), err)
			return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
		}
		result.Findings = append(result.Findings, stored)
		emittedFindingIDs[strings.TrimSpace(stored.ID)] = struct{}{}
		evidence, err := s.buildFindingEvidence(ctx, stored, run, graphRows...)
		if err != nil {
			evaluationErr := fmt.Errorf("build evidence for graph rule %q finding %q: %w", spec.GetId(), stored.ID, err)
			return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
		}
		if _, seen := evidenceIDs[evidence.GetId()]; !seen {
			if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
				evaluationErr := fmt.Errorf("persist evidence for graph rule %q finding %q: %w", spec.GetId(), stored.ID, err)
				return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
			}
			evidenceIDs[evidence.GetId()] = struct{}{}
			result.Evidence = append(result.Evidence, evidence)
		}
		if err := s.projectFindingAnchor(ctx, stored); err != nil {
			evaluationErr := fmt.Errorf("project graph rule %q finding %q anchor: %w", spec.GetId(), stored.ID, err)
			return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
		}
		if err := s.projectFindingExternalRefs(ctx, stored); err != nil {
			evaluationErr := fmt.Errorf("project graph rule %q finding %q external refs: %w", spec.GetId(), stored.ID, err)
			return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
		}
		if isNewFinding {
			if err := s.projectFindingNewActionRecommendations(ctx, stored); err != nil {
				evaluationErr := fmt.Errorf("project graph rule %q finding %q action recommendations: %w", spec.GetId(), stored.ID, err)
				return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
			}
		}
	}
	if !result.Truncated {
		if err := s.resolveStaleGraphFindings(ctx, strings.TrimSpace(runtime.GetTenantId()), strings.TrimSpace(runtime.GetId()), spec.GetId(), emittedFindingIDs); err != nil {
			evaluationErr := fmt.Errorf("resolve stale graph findings for rule %q: %w", spec.GetId(), err)
			return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
		}
	}
	if err := s.finishCompletedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings)); err != nil {
		return result, err
	}
	return result, nil
}

func emitGraphRuleEvaluationDetail(ctx context.Context, runtime *cerebrov1.SourceRuntime, spec *cerebrov1.RuleSpec, result *GraphRuleEvaluationResult, queryPresent bool, duration time.Duration, err error) {
	status := "completed"
	if err != nil {
		status = "failed"
	}
	ruleID := ""
	if spec != nil {
		ruleID = strings.TrimSpace(spec.GetId())
	}
	var runID string
	var rowsRead uint32
	var findingsEmitted int
	var evidenceWritten int
	var truncated bool
	if result != nil {
		if result.Run != nil {
			runID = strings.TrimSpace(result.Run.GetId())
		}
		rowsRead = result.RowsRead
		findingsEmitted = len(result.Findings)
		evidenceWritten = len(result.Evidence)
		truncated = result.Truncated
	}
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "component", Value: "findings.graph_rules"},
		telemetry.Field{Key: "status", Value: status},
		telemetry.Field{Key: "runtime_id", Value: runtime.GetId()},
		telemetry.Field{Key: "source_runtime_id", Value: runtime.GetId()},
		telemetry.Field{Key: "source_id", Value: runtime.GetSourceId()},
		telemetry.Field{Key: "tenant_id", Value: runtime.GetTenantId()},
		telemetry.Field{Key: "rule_id", Value: ruleID},
		telemetry.Field{Key: "run_id", Value: runID},
		telemetry.Field{Key: "query_present", Value: queryPresent},
		telemetry.Field{Key: "rows_read", Value: rowsRead},
		telemetry.Field{Key: "rows_truncated", Value: truncated},
		telemetry.Field{Key: "findings_emitted", Value: findingsEmitted},
		telemetry.Field{Key: "evidence_written", Value: evidenceWritten},
		telemetry.Field{Key: "stale_resolution_skipped", Value: truncated},
		telemetry.Field{Key: "duration_ms", Value: duration.Milliseconds()},
	)
	if err != nil {
		attrs = attrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
	}
	telemetry.IncrementMain(ctx, "finding.graph_rule.evaluation.count", 1)
	if status == "failed" {
		telemetry.IncrementMain(ctx, "finding.graph_rule.evaluation.failed.count", 1)
	}
	if truncated {
		telemetry.IncrementMain(ctx, "finding.graph_rule.evaluation.truncated.count", 1)
	}
	telemetry.Event(ctx, "finding.graph_rule.evaluation", attrs)
}

func retiredGraphRule(rule GraphRule) bool {
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return false
	}
	return metadataRule.RuleMetadata().Lifecycle.Kind == LifecycleRetired
}

// cypherRowsTruncated reports whether the cypher result hit the effective row cap. When the
// rule asks for at most N rows and we got back exactly N, we cannot tell the graph apart from
// a graph that had N+1 matching rows, so the rule may have missed offenders. Stale-finding
// auto-resolution must not run in that case or we would close findings whose still-matching
// row simply fell past the cutoff.
func cypherRowsTruncated(request ports.CypherQueryRequest, rowsReturned int) bool {
	cap := request.RowLimit
	if cap <= 0 || cap > ports.MaxCypherQueryRows {
		cap = ports.MaxCypherQueryRows
	}
	return rowsReturned >= cap
}

func (s *Service) selectGraphRules(runtime *cerebrov1.SourceRuntime, ruleIDs []string) ([]GraphRule, error) {
	if len(ruleIDs) == 0 {
		var graphRules []GraphRule
		for _, rule := range s.rules.ForRuntime(runtime) {
			if graphRule, ok := asGraphRule(rule); ok {
				graphRules = append(graphRules, graphRule)
			}
		}
		return graphRules, nil
	}
	graphRules := make([]GraphRule, 0, len(ruleIDs))
	seen := make(map[string]struct{}, len(ruleIDs))
	for _, rawID := range ruleIDs {
		trimmedID := strings.TrimSpace(rawID)
		if trimmedID == "" {
			continue
		}
		if _, ok := seen[trimmedID]; ok {
			continue
		}
		rule, ok := s.rules.Get(trimmedID)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrRuleNotFound, trimmedID)
		}
		graphRule, ok := asGraphRule(rule)
		if !ok {
			return nil, fmt.Errorf("%w: %s is not a graph rule", ErrRuleUnsupported, trimmedID)
		}
		if !rule.SupportsRuntime(runtime) {
			return nil, fmt.Errorf("%w: %s", ErrRuleUnsupported, trimmedID)
		}
		seen[trimmedID] = struct{}{}
		graphRules = append(graphRules, graphRule)
	}
	if len(graphRules) == 0 {
		return nil, fmt.Errorf("%w for runtime %q", ErrRuleSelectionRequired, strings.TrimSpace(runtime.GetId()))
	}
	return graphRules, nil
}

// resolveStaleGraphFindings closes any open finding emitted previously by one graph rule whose
// source rows are no longer present in the latest evaluation. Without this, dormant findings
// would never auto-resolve when an offending principal is finally deprovisioned in both
// systems or the relationship is removed.
//
// The scope is intentionally (tenant, rule) rather than (tenant, runtime, rule). Graph rules
// query a tenant-wide view (the projected graph upserts by tenant+entity, not by runtime),
// so an emit set computed from any okta runtime in the tenant covers every offender that the
// rule would report. Scoping by runtime here would close a finding that runtime A emitted as
// soon as runtime B syncs and finishes its own evaluation (because runtime B's emit set
// doesn't include runtime A's finding under the runtime-keyed query).
func (s *Service) resolveStaleGraphFindings(ctx context.Context, tenantID string, _ string, ruleID string, emittedFindingIDs map[string]struct{}) error {
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID: strings.TrimSpace(tenantID),
		RuleID:   strings.TrimSpace(ruleID),
		Status:   findingStatusOpen,
	})
	if err != nil {
		return fmt.Errorf("list stale graph candidates for rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if _, emitted := emittedFindingIDs[strings.TrimSpace(finding.ID)]; emitted {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    "graph_rule_no_longer_matches",
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("resolve stale graph finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, "graph_rule_evaluation"); err != nil {
			return fmt.Errorf("project stale graph finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
	}
	return nil
}
