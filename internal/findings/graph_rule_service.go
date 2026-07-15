package findings

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/observability"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/telemetry"
	"google.golang.org/protobuf/proto"
)

// EvaluateGraphRulesRequest scopes one graph-rule evaluation pass over one runtime.
type EvaluateGraphRulesRequest struct {
	RuntimeID string
	RuleIDs   []string
	// ExcludeRuleIDs drops the named graph rules from the default
	// (ForRuntime) selection. The orchestrator uses this to run each
	// tenant-scoped graph rule at most once per cycle even when many runtimes
	// in the tenant would otherwise each trigger the same rule. It is ignored
	// when RuleIDs is set explicitly.
	ExcludeRuleIDs []string
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
	candidates, err := s.selectGraphRules(runtime, request.RuleIDs, request.ExcludeRuleIDs)
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

func (s *Service) evaluateGraphRule(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule GraphRule, startedAt time.Time) (evaluation *GraphRuleEvaluationResult, err error) {
	spec := rule.Spec()
	ctx, span := telemetry.Start(ctx, "graph_rule.evaluate", telemetry.Attrs(
		telemetry.Field{Key: "rule_id", Value: strings.TrimSpace(spec.GetId())},
		telemetry.Field{Key: "source_id", Value: strings.TrimSpace(runtime.GetSourceId())},
		telemetry.Field{Key: "tenant_id", Value: strings.TrimSpace(runtime.GetTenantId())},
		telemetry.Field{Key: "runtime_id", Value: strings.TrimSpace(runtime.GetId())},
	))
	metricsStartedAt := time.Now()
	defer func() {
		spanStatus := "completed"
		spanAttrs := telemetry.Attrs()
		if evaluation != nil {
			spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "rows_read", Value: int64(evaluation.RowsRead)})
			spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "findings_emitted", Value: int64(len(evaluation.Findings))})
			spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "truncated", Value: evaluation.Truncated})
		}
		if err != nil {
			spanStatus = "failed"
			spanAttrs = spanAttrs.WithField(telemetry.Field{Key: "error_kind", Value: telemetry.ErrorKind(err)})
		}
		telemetry.End(span, spanStatus, spanAttrs)
	}()
	defer func() {
		status := "completed"
		errorKind := ""
		if err != nil {
			status = "failed"
			errorKind = telemetry.ErrorKind(err)
		}
		metrics := observability.GraphRuleEvaluationMetrics{
			SourceID:  strings.TrimSpace(runtime.GetSourceId()),
			RuleID:    strings.TrimSpace(spec.GetId()),
			Status:    status,
			ErrorKind: errorKind,
			Duration:  time.Since(metricsStartedAt),
		}
		if evaluation != nil {
			metrics.RowsRead = evaluation.RowsRead
			metrics.Findings = len(evaluation.Findings)
			metrics.Truncated = evaluation.Truncated
		}
		observability.RecordGraphRuleEvaluation(ctx, metrics)
	}()
	queryRequest := rule.QueryFor(runtime)
	run := newGraphFindingEvaluationRun(strings.TrimSpace(runtime.GetId()), spec.GetId(), startedAt)
	run.RuleApplicable = proto.Bool(rule.SupportsRuntime(runtime))
	s.bindGraphEvaluationSourceSnapshots(ctx, run, runtime, rule, startedAt)
	if strings.TrimSpace(queryRequest.Query) != "" {
		run.GraphRowLimit = proto.Uint32(uint32(effectiveGraphRowLimit(queryRequest)))
	}
	if err := s.runStore.PutFindingEvaluationRun(ctx, run); err != nil {
		return nil, fmt.Errorf("persist finding evaluation run %q: %w", run.GetId(), err)
	}
	result := &GraphRuleEvaluationResult{
		Rule: spec,
		Run:  run,
	}
	if strings.TrimSpace(queryRequest.Query) == "" {
		if retiredGraphRule(rule) {
			if err := s.resolveStaleGraphFindings(ctx, strings.TrimSpace(runtime.GetTenantId()), strings.TrimSpace(runtime.GetId()), spec.GetId(), nil, nil); err != nil {
				evaluationErr := fmt.Errorf("resolve retired graph findings for rule %q: %w", spec.GetId(), err)
				return result, s.finishFailedGraphRun(ctx, run, 0, nil, evaluationErr)
			}
		}
		if err := s.finishCompletedGraphRun(ctx, run, 0, nil); err != nil {
			return result, err
		}
		return result, nil
	}
	queryCtx := ctx
	if budget := s.graphRuleQueryBudget(); budget > 0 {
		var cancelQuery context.CancelFunc
		queryCtx, cancelQuery = context.WithTimeout(ctx, budget)
		defer cancelQuery()
	}
	rows, err := s.graphQuery.ExecuteReadCypher(queryCtx, queryRequest)
	if err != nil {
		evaluationErr := fmt.Errorf("execute graph rule %q cypher: %w", spec.GetId(), err)
		return result, s.finishFailedGraphRun(ctx, run, 0, nil, evaluationErr)
	}
	s.verifyGraphEvaluationSourceSnapshots(ctx, run)
	result.RowsRead = boundedUint32(len(rows))
	rowLimitTruncated := cypherRowsTruncated(queryRequest, len(rows))
	result.Truncated = rowLimitTruncated || cypherRowsSignalTruncated(rows)
	run.GraphTruncated = proto.Bool(result.Truncated)
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
	resolveStale := !result.Truncated && s.canResolveFromFindingEvaluationRun(run, true)
	var scopeFilter *staleScopeFilter
	if result.Truncated && !rowLimitTruncated && s.canResolveFromFindingEvaluationRun(run, true) {
		// Only an internal per-scope cap fired (not the global row limit). Scopes
		// returned in full can still auto-resolve; scopes that were capped this pass
		// must stay open because a still-matching row may have been dropped. The
		// row-limit case keeps the conservative global skip above.
		if scoped, ok := rule.(ScopedStaleResolver); ok {
			if attribute := strings.TrimSpace(scoped.StaleResolutionScopeAttribute()); attribute != "" {
				scopeFilter = &staleScopeFilter{
					attribute:  attribute,
					incomplete: scoped.IncompleteStaleResolutionScopes(rows),
				}
				resolveStale = true
			}
		}
	}
	if resolveStale {
		if err := s.resolveStaleGraphFindings(ctx, strings.TrimSpace(runtime.GetTenantId()), strings.TrimSpace(runtime.GetId()), spec.GetId(), emittedFindingIDs, scopeFilter); err != nil {
			evaluationErr := fmt.Errorf("resolve stale graph findings for rule %q: %w", spec.GetId(), err)
			return result, s.finishFailedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings), evaluationErr)
		}
	}
	if err := s.finishCompletedGraphRun(ctx, run, result.RowsRead, findingIDs(result.Findings)); err != nil {
		return result, err
	}
	return result, nil
}

const maxGraphEvaluationDependencyRuntimes = uint32(500)

func (s *Service) bindGraphEvaluationSourceSnapshots(ctx context.Context, run *cerebrov1.FindingEvaluationRun, trigger *cerebrov1.SourceRuntime, rule GraphRule, evaluationStartedAt time.Time) {
	if run == nil {
		return
	}
	listStore, ok := s.runtimeStore.(ports.SourceRuntimeListStore)
	if !ok || trigger == nil {
		bindFindingEvaluationSourceSnapshot(run, trigger)
		run.SourceDependencyComplete = proto.Bool(false)
		return
	}
	runtimes, err := listStore.ListSourceRuntimes(ctx, ports.SourceRuntimeFilter{
		TenantID: strings.TrimSpace(trigger.GetTenantId()),
		Limit:    maxGraphEvaluationDependencyRuntimes + 1,
	})
	if err != nil || uint32(len(runtimes)) > maxGraphEvaluationDependencyRuntimes {
		bindFindingEvaluationSourceSnapshot(run, trigger)
		run.SourceDependencyComplete = proto.Bool(false)
		return
	}
	dependencies := graphRuleDependencyKeys(rule)
	resolvedDependencies := make(map[string]struct{}, len(dependencies))
	snapshots := make([]*cerebrov1.FindingEvaluationSourceSnapshot, 0, len(runtimes))
	for _, runtime := range runtimes {
		if runtime == nil || !rule.SupportsRuntime(runtime) {
			continue
		}
		snapshot := findingEvaluationSourceSnapshot(runtime)
		if s.graphRunStore != nil {
			runs, listErr := s.graphRunStore.ListIngestRuns(ctx, graphstore.IngestRunFilter{RuntimeID: snapshot.GetRuntimeId(), Limit: 1})
			if listErr == nil && len(runs) == 1 {
				bindGraphSnapshot(snapshot, runs[0], evaluationStartedAt)
			}
		}
		for _, dependency := range dependencies {
			if runtimeMatchesGraphDependency(runtime, dependency) {
				resolvedDependencies[dependency] = struct{}{}
			}
		}
		snapshots = append(snapshots, snapshot)
	}
	if len(snapshots) == 0 {
		snapshots = append(snapshots, findingEvaluationSourceSnapshot(trigger))
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].GetRuntimeId() < snapshots[j].GetRuntimeId() })
	run.SourceSnapshots = snapshots
	run.SourceDependencyComplete = proto.Bool(len(dependencies) > 0 && len(resolvedDependencies) == len(dependencies))
}

func (s *Service) verifyGraphEvaluationSourceSnapshots(ctx context.Context, run *cerebrov1.FindingEvaluationRun) {
	if run == nil || s.graphRunStore == nil {
		return
	}
	for _, snapshot := range run.GetSourceSnapshots() {
		if snapshot == nil || snapshot.GraphSnapshotComplete == nil || !snapshot.GetGraphSnapshotComplete() {
			continue
		}
		runs, err := s.graphRunStore.ListIngestRuns(ctx, graphstore.IngestRunFilter{RuntimeID: snapshot.GetRuntimeId(), Limit: 1})
		if err != nil || len(runs) != 1 || !graphSnapshotMatchesRun(snapshot, runs[0]) {
			snapshot.GraphSnapshotComplete = proto.Bool(false)
		}
	}
}

func graphSnapshotMatchesRun(snapshot *cerebrov1.FindingEvaluationSourceSnapshot, run graphstore.IngestRun) bool {
	if snapshot == nil || strings.TrimSpace(run.RuntimeID) != snapshot.GetRuntimeId() || strings.TrimSpace(run.ID) != snapshot.GetGraphIngestRunId() ||
		strings.TrimSpace(run.Status) != snapshot.GetGraphIngestStatus() || strings.TrimSpace(run.CheckpointID) != snapshot.GetGraphCheckpointId() ||
		snapshot.GetGraphIngestedAt() == nil || snapshot.GetGraphIngestedAt().CheckValid() != nil {
		return false
	}
	finishedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(run.FinishedAt))
	return err == nil && finishedAt.UTC().Equal(snapshot.GetGraphIngestedAt().AsTime().UTC())
}

func graphRuleDependencyKeys(rule GraphRule) []string {
	metadata, ok := ruleMetadata(rule)
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	for _, eventKind := range metadata.EventKinds {
		parts := strings.SplitN(strings.ToLower(strings.TrimSpace(eventKind)), ".", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		seen[parts[0]+"\x00"+strings.ReplaceAll(parts[1], ".", "_")] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func runtimeMatchesGraphDependency(runtime *cerebrov1.SourceRuntime, dependency string) bool {
	parts := strings.SplitN(dependency, "\x00", 2)
	if runtime == nil || len(parts) != 2 {
		return false
	}
	sourceID := strings.ToLower(strings.TrimSpace(runtime.GetSourceId()))
	family := strings.ToLower(strings.TrimSpace(runtime.GetConfig()["family"]))
	return sourceID == parts[0] && family == parts[1]
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
	return rowsReturned >= effectiveGraphRowLimit(request)
}

func effectiveGraphRowLimit(request ports.CypherQueryRequest) int {
	limit := request.RowLimit
	if limit <= 0 || limit > ports.MaxCypherQueryRows {
		return ports.MaxCypherQueryRows
	}
	return limit
}

// graphRuleTruncationColumn lets a rule's Cypher signal that it dropped matching
// data internally (for example a per-account cap applied before the row limit)
// even when the total row count stayed under the row limit. Without this a rule
// that caps per-group results could return < RowLimit rows yet still be missing
// offenders, and stale-finding auto-resolution would wrongly close the dropped
// findings as no-longer-matching.
const graphRuleTruncationColumn = "graph_rule_truncated"

// cypherRowsSignalTruncated reports whether any row carries a truthy
// graphRuleTruncationColumn, i.e. the rule's query itself signaled that it
// dropped matching data.
func cypherRowsSignalTruncated(rows []ports.CypherRow) bool {
	for _, row := range rows {
		if row.Values == nil {
			continue
		}
		if value, ok := row.Values[graphRuleTruncationColumn]; ok && cypherValueTruthy(value) {
			return true
		}
	}
	return false
}

func cypherValueTruthy(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "t", "yes":
			return true
		}
	}
	return false
}

func (s *Service) selectGraphRules(runtime *cerebrov1.SourceRuntime, ruleIDs []string, excludeRuleIDs []string) ([]GraphRule, error) {
	if len(ruleIDs) == 0 {
		excluded := make(map[string]struct{}, len(excludeRuleIDs))
		for _, id := range excludeRuleIDs {
			if trimmed := strings.TrimSpace(id); trimmed != "" {
				excluded[trimmed] = struct{}{}
			}
		}
		var graphRules []GraphRule
		for _, rule := range s.rules.ForRuntime(runtime) {
			graphRule, ok := asGraphRule(rule)
			if !ok {
				continue
			}
			if _, skip := excluded[strings.TrimSpace(graphRule.Spec().GetId())]; skip {
				continue
			}
			graphRules = append(graphRules, graphRule)
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

// staleScopeFilter narrows stale-finding auto-resolution to scopes that were fully
// represented during a per-scope-capped evaluation. A nil filter resolves every
// non-emitted open finding, which is the default for rules without an internal cap
// and for the row-limit-clean path.
type staleScopeFilter struct {
	attribute  string
	incomplete map[string]struct{}
}

// shouldResolve reports whether a non-emitted open finding may be auto-resolved.
// With no filter every candidate is resolvable. With a filter, a finding resolves
// only when it carries a scope key that was NOT capped this pass; findings without
// a scope key stay open because we cannot prove their scope was fully represented.
func (f *staleScopeFilter) shouldResolve(finding *ports.FindingRecord) bool {
	if f == nil {
		return true
	}
	if finding == nil {
		return false
	}
	key := strings.TrimSpace(finding.Attributes[f.attribute])
	if key == "" {
		return false
	}
	_, capped := f.incomplete[key]
	return !capped
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
func (s *Service) resolveStaleGraphFindings(ctx context.Context, tenantID string, _ string, ruleID string, emittedFindingIDs map[string]struct{}, scopeFilter *staleScopeFilter) error {
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
		if !scopeFilter.shouldResolve(finding) {
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
