package reports

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPlaybookEffectivenessWindow       = 30 * 24 * time.Hour
	defaultPlaybookEffectivenessMaxPlaybooks = 25
)

// PlaybookEffectivenessReportOptions controls playbook effectiveness report generation.
type PlaybookEffectivenessReportOptions struct {
	Now          time.Time
	Window       time.Duration
	PlaybookID   string
	TenantID     string
	TargetKind   string
	MaxPlaybooks int
}

// PlaybookEffectivenessSummary captures top-line playbook effectiveness KPIs.
type PlaybookEffectivenessSummary struct {
	Runs                              int     `json:"runs"`
	CompletedRuns                     int     `json:"completed_runs"`
	SuccessfulRuns                    int     `json:"successful_runs"`
	FailedRuns                        int     `json:"failed_runs"`
	RollbackRuns                      int     `json:"rollback_runs"`
	ApprovalBottlenecks               int     `json:"approval_bottlenecks"`
	RepeatedTargetExecutions          int     `json:"repeated_target_executions"`
	CompletionRatePercent             float64 `json:"completion_rate_percent"`
	SuccessRatePercent                float64 `json:"success_rate_percent"`
	RollbackRatePercent               float64 `json:"rollback_rate_percent"`
	RepeatExecutionRatePercent        float64 `json:"repeat_execution_rate_percent"`
	AverageCompletionMinutes          float64 `json:"average_completion_minutes"`
	MedianSuccessfulCompletionMinutes float64 `json:"median_successful_completion_minutes"`
}

// PlaybookEffectivenessPlaybookRollup summarizes one playbook's execution quality.
type PlaybookEffectivenessPlaybookRollup struct {
	PlaybookID                        string  `json:"playbook_id"`
	PlaybookName                      string  `json:"playbook_name"`
	Runs                              int     `json:"runs"`
	CompletedRuns                     int     `json:"completed_runs"`
	SuccessfulRuns                    int     `json:"successful_runs"`
	FailedRuns                        int     `json:"failed_runs"`
	RollbackRuns                      int     `json:"rollback_runs"`
	ApprovalBottlenecks               int     `json:"approval_bottlenecks"`
	RepeatedTargetExecutions          int     `json:"repeated_target_executions"`
	CompletionRatePercent             float64 `json:"completion_rate_percent"`
	SuccessRatePercent                float64 `json:"success_rate_percent"`
	RollbackRatePercent               float64 `json:"rollback_rate_percent"`
	RepeatExecutionRatePercent        float64 `json:"repeat_execution_rate_percent"`
	AverageCompletionMinutes          float64 `json:"average_completion_minutes"`
	MedianSuccessfulCompletionMinutes float64 `json:"median_successful_completion_minutes"`
}

// PlaybookEffectivenessStageRollup summarizes one stage's stability and approval friction.
type PlaybookEffectivenessStageRollup struct {
	PlaybookID          string  `json:"playbook_id"`
	PlaybookName        string  `json:"playbook_name"`
	StageID             string  `json:"stage_id"`
	StageName           string  `json:"stage_name"`
	Executions          int     `json:"executions"`
	Failures            int     `json:"failures"`
	Skipped             int     `json:"skipped"`
	ApprovalBottlenecks int     `json:"approval_bottlenecks"`
	FailureRatePercent  float64 `json:"failure_rate_percent"`
}

// PlaybookEffectivenessTargetKindRollup summarizes effectiveness for one target kind.
type PlaybookEffectivenessTargetKindRollup struct {
	TargetKind          string  `json:"target_kind"`
	Runs                int     `json:"runs"`
	SuccessfulRuns      int     `json:"successful_runs"`
	RollbackRuns        int     `json:"rollback_runs"`
	SuccessRatePercent  float64 `json:"success_rate_percent"`
	RollbackRatePercent float64 `json:"rollback_rate_percent"`
}

// PlaybookEffectivenessTenantRollup summarizes effectiveness for one tenant.
type PlaybookEffectivenessTenantRollup struct {
	TenantID            string  `json:"tenant_id"`
	Runs                int     `json:"runs"`
	SuccessfulRuns      int     `json:"successful_runs"`
	RollbackRuns        int     `json:"rollback_runs"`
	SuccessRatePercent  float64 `json:"success_rate_percent"`
	RollbackRatePercent float64 `json:"rollback_rate_percent"`
}

// PlaybookFailureStepRollup identifies the highest-friction failing stages.
type PlaybookFailureStepRollup struct {
	PlaybookID   string `json:"playbook_id"`
	PlaybookName string `json:"playbook_name"`
	StageID      string `json:"stage_id"`
	StageName    string `json:"stage_name"`
	Failures     int    `json:"failures"`
}

// PlaybookEffectivenessRecommendation suggests one operational follow-up.
type PlaybookEffectivenessRecommendation struct {
	Priority        string `json:"priority"`
	Title           string `json:"title"`
	Detail          string `json:"detail"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

// PlaybookEffectivenessReport packages playbook execution quality rollups.
type PlaybookEffectivenessReport struct {
	GeneratedAt     time.Time                               `json:"generated_at"`
	Summary         PlaybookEffectivenessSummary            `json:"summary"`
	Playbooks       []PlaybookEffectivenessPlaybookRollup   `json:"playbooks,omitempty"`
	Stages          []PlaybookEffectivenessStageRollup      `json:"stages,omitempty"`
	TargetKinds     []PlaybookEffectivenessTargetKindRollup `json:"target_kinds,omitempty"`
	Tenants         []PlaybookEffectivenessTenantRollup     `json:"tenants,omitempty"`
	FailureSteps    []PlaybookFailureStepRollup             `json:"failure_steps,omitempty"`
	Recommendations []PlaybookEffectivenessRecommendation   `json:"recommendations,omitempty"`
}

type playbookRunAggregate struct {
	RunID          string
	PlaybookID     string
	PlaybookName   string
	TenantID       string
	StartedAt      time.Time
	OutcomeAt      time.Time
	OutcomeNodeID  string
	LatestAt       time.Time
	OutcomeVerdict string
	OutcomeStatus  string
	RollbackState  string
	TargetIDs      []string
	TargetKinds    map[string]struct{}
	Stages         []playbookStageAggregate
	Actions        []playbookActionAggregate
}

type playbookStageAggregate struct {
	ID               string
	Name             string
	Status           string
	ApprovalRequired bool
	ApprovalStatus   string
	ObservedAt       time.Time
}

type playbookActionAggregate struct {
	ID         string
	Status     string
	ObservedAt time.Time
}

type playbookRollupAccumulator struct {
	PlaybookID               string
	PlaybookName             string
	Runs                     int
	CompletedRuns            int
	SuccessfulRuns           int
	FailedRuns               int
	RollbackRuns             int
	ApprovalBottlenecks      int
	RepeatedTargetExecutions int
	CompletionMinutes        []float64
	SuccessfulMinutes        []float64
}

type playbookTargetKindAccumulator struct {
	TargetKind     string
	Runs           int
	CompletedRuns  int
	SuccessfulRuns int
	RollbackRuns   int
}

type playbookTenantAccumulator struct {
	TenantID       string
	Runs           int
	CompletedRuns  int
	SuccessfulRuns int
	RollbackRuns   int
}

type playbookStageAccumulator struct {
	PlaybookID          string
	PlaybookName        string
	StageID             string
	StageName           string
	Executions          int
	Failures            int
	Skipped             int
	ApprovalBottlenecks int
}

// BuildPlaybookEffectivenessReport derives BI-ready rollups over playbook workflow runs.
func BuildPlaybookEffectivenessReport(g *Graph, opts PlaybookEffectivenessReportOptions) PlaybookEffectivenessReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	window := opts.Window
	if window <= 0 {
		window = defaultPlaybookEffectivenessWindow
	}
	maxPlaybooks := opts.MaxPlaybooks
	if maxPlaybooks <= 0 {
		maxPlaybooks = defaultPlaybookEffectivenessMaxPlaybooks
	}

	report := PlaybookEffectivenessReport{GeneratedAt: now}
	if g == nil {
		report.Recommendations = []PlaybookEffectivenessRecommendation{{
			Priority:        "high",
			Title:           "Playbook world-model graph is not initialized",
			Detail:          "No playbook effectiveness metrics are available because the graph is nil.",
			SuggestedAction: "Initialize and populate the graph with platform playbook lifecycle events before requesting this report.",
		}}
		return report
	}

	playbookFilter := normalizePlaybookEffectivenessIdentifier(opts.PlaybookID)
	tenantFilter := normalizePlaybookEffectivenessIdentifier(opts.TenantID)
	targetKindFilter := normalizePlaybookEffectivenessIdentifier(opts.TargetKind)
	windowStart := now.Add(-window)

	runs := buildPlaybookRunAggregates(g)
	repeatSeen := make(map[string]int)
	playbookAcc := make(map[string]*playbookRollupAccumulator)
	targetKindAcc := make(map[string]*playbookTargetKindAccumulator)
	tenantAcc := make(map[string]*playbookTenantAccumulator)
	stageAcc := make(map[string]*playbookStageAccumulator)
	failureSteps := make(map[string]*PlaybookFailureStepRollup)
	completionMinutes := make([]float64, 0)
	successfulMinutes := make([]float64, 0)

	sort.Slice(runs, func(i, j int) bool {
		if !runs[i].LatestAt.Equal(runs[j].LatestAt) {
			return runs[i].LatestAt.Before(runs[j].LatestAt)
		}
		return runs[i].RunID < runs[j].RunID
	})

	for _, run := range runs {
		if run == nil {
			continue
		}
		if run.LatestAt.IsZero() || run.LatestAt.Before(windowStart) {
			continue
		}
		if playbookFilter != "" && normalizePlaybookEffectivenessIdentifier(run.PlaybookID) != playbookFilter {
			continue
		}
		if tenantFilter != "" && normalizePlaybookEffectivenessIdentifier(run.TenantID) != tenantFilter {
			continue
		}
		if targetKindFilter != "" {
			if _, ok := run.TargetKinds[targetKindFilter]; !ok {
				continue
			}
		}

		report.Summary.Runs++

		key := normalizePlaybookEffectivenessIdentifier(run.PlaybookID)
		if key == "" {
			key = "unknown"
		}
		playbookRollup := playbookAcc[key]
		if playbookRollup == nil {
			playbookRollup = &playbookRollupAccumulator{PlaybookID: run.PlaybookID, PlaybookName: run.PlaybookName}
			playbookAcc[key] = playbookRollup
		}
		playbookRollup.Runs++

		if playbookRunCompleted(run) {
			report.Summary.CompletedRuns++
			playbookRollup.CompletedRuns++
			if minutes, ok := playbookCompletionMinutes(run); ok {
				completionMinutes = append(completionMinutes, minutes)
				playbookRollup.CompletionMinutes = append(playbookRollup.CompletionMinutes, minutes)
			}
		}
		if playbookRunSuccessful(run) {
			report.Summary.SuccessfulRuns++
			playbookRollup.SuccessfulRuns++
			if minutes, ok := playbookCompletionMinutes(run); ok {
				successfulMinutes = append(successfulMinutes, minutes)
				playbookRollup.SuccessfulMinutes = append(playbookRollup.SuccessfulMinutes, minutes)
			}
		}
		if playbookRunFailed(run) {
			report.Summary.FailedRuns++
			playbookRollup.FailedRuns++
		}
		if playbookRunRolledBack(run) {
			report.Summary.RollbackRuns++
			playbookRollup.RollbackRuns++
		}

		runApprovalBottlenecks := countPlaybookApprovalBottlenecks(run)
		report.Summary.ApprovalBottlenecks += runApprovalBottlenecks
		playbookRollup.ApprovalBottlenecks += runApprovalBottlenecks

		signature := playbookTargetSignature(run)
		if signature != "" {
			repeatKey := key + "|" + signature
			repeatSeen[repeatKey]++
			if repeatSeen[repeatKey] > 1 {
				report.Summary.RepeatedTargetExecutions++
				playbookRollup.RepeatedTargetExecutions++
			}
		}

		for targetKind := range run.TargetKinds {
			acc := targetKindAcc[targetKind]
			if acc == nil {
				acc = &playbookTargetKindAccumulator{TargetKind: targetKind}
				targetKindAcc[targetKind] = acc
			}
			acc.Runs++
			if playbookRunCompleted(run) {
				acc.CompletedRuns++
			}
			if playbookRunSuccessful(run) {
				acc.SuccessfulRuns++
			}
			if playbookRunRolledBack(run) {
				acc.RollbackRuns++
			}
		}

		tenantKey := normalizePlaybookEffectivenessIdentifier(run.TenantID)
		if tenantKey == "" {
			tenantKey = "unknown"
		}
		tenantRollup := tenantAcc[tenantKey]
		if tenantRollup == nil {
			tenantRollup = &playbookTenantAccumulator{TenantID: run.TenantID}
			tenantAcc[tenantKey] = tenantRollup
		}
		tenantRollup.Runs++
		if playbookRunCompleted(run) {
			tenantRollup.CompletedRuns++
		}
		if playbookRunSuccessful(run) {
			tenantRollup.SuccessfulRuns++
		}
		if playbookRunRolledBack(run) {
			tenantRollup.RollbackRuns++
		}

		for _, stage := range run.Stages {
			stageKey := key + "|" + normalizePlaybookEffectivenessIdentifier(stage.ID)
			acc := stageAcc[stageKey]
			if acc == nil {
				acc = &playbookStageAccumulator{
					PlaybookID:   run.PlaybookID,
					PlaybookName: run.PlaybookName,
					StageID:      stage.ID,
					StageName:    stage.Name,
				}
				stageAcc[stageKey] = acc
			}
			acc.Executions++
			if playbookStageFailed(stage) {
				acc.Failures++
				failure := failureSteps[stageKey]
				if failure == nil {
					failure = &PlaybookFailureStepRollup{
						PlaybookID:   run.PlaybookID,
						PlaybookName: run.PlaybookName,
						StageID:      stage.ID,
						StageName:    stage.Name,
					}
					failureSteps[stageKey] = failure
				}
				failure.Failures++
			}
			if playbookStageSkipped(stage) {
				acc.Skipped++
			}
			if playbookStageApprovalBottleneck(stage) {
				acc.ApprovalBottlenecks++
			}
		}
	}

	if report.Summary.Runs > 0 {
		report.Summary.CompletionRatePercent = roundMetric((float64(report.Summary.CompletedRuns) / float64(report.Summary.Runs)) * 100)
		report.Summary.SuccessRatePercent = roundMetric((float64(report.Summary.SuccessfulRuns) / float64(report.Summary.Runs)) * 100)
		report.Summary.RepeatExecutionRatePercent = roundMetric((float64(report.Summary.RepeatedTargetExecutions) / float64(report.Summary.Runs)) * 100)
	}
	if report.Summary.CompletedRuns > 0 {
		report.Summary.RollbackRatePercent = roundMetric((float64(report.Summary.RollbackRuns) / float64(report.Summary.CompletedRuns)) * 100)
		report.Summary.AverageCompletionMinutes = roundMetric(averageFloat64(completionMinutes))
	}
	if len(successfulMinutes) > 0 {
		report.Summary.MedianSuccessfulCompletionMinutes = roundMetric(medianFloat64(successfulMinutes))
	}

	report.Playbooks = buildPlaybookEffectivenessPlaybookRollups(playbookAcc, maxPlaybooks)
	report.Stages = buildPlaybookEffectivenessStageRollups(stageAcc)
	report.TargetKinds = buildPlaybookEffectivenessTargetKindRollups(targetKindAcc)
	report.Tenants = buildPlaybookEffectivenessTenantRollups(tenantAcc)
	report.FailureSteps = buildPlaybookFailureStepRollups(failureSteps)
	report.Recommendations = buildPlaybookEffectivenessRecommendations(report)

	return report
}

func buildPlaybookRunAggregates(g *Graph) []*playbookRunAggregate {
	if g == nil {
		return nil
	}

	runs := make(map[string]*playbookRunAggregate)
	getRun := func(runID string) *playbookRunAggregate {
		runID = normalizePlaybookEffectivenessIdentifier(runID)
		if runID == "" {
			return nil
		}
		agg := runs[runID]
		if agg == nil {
			agg = &playbookRunAggregate{
				RunID:       runID,
				TargetKinds: make(map[string]struct{}),
			}
			runs[runID] = agg
		}
		return agg
	}

	for _, node := range g.GetNodesByKind(NodeKind("communication_thread")) {
		if !isPlaybookThread(node) {
			continue
		}
		run := getRun(graphNodePropertyString(node, "playbook_run_id"))
		if run == nil {
			continue
		}
		playbookRunApplyNodeIdentity(run, node)
		if observedAt, ok := graphObservedAt(node); ok {
			playbookRunObserve(run, observedAt)
		}
		playbookRunCollectTargets(g, run, graphNodePropertyStrings(node, "target_ids"))
	}

	for _, node := range g.GetNodesByKind(NodeKindDecision) {
		if !isPlaybookStage(node) {
			continue
		}
		run := getRun(graphNodePropertyString(node, "playbook_run_id"))
		if run == nil {
			continue
		}
		playbookRunApplyNodeIdentity(run, node)
		stage := playbookStageAggregate{
			ID:               graphNodePropertyString(node, "stage_id"),
			Name:             graphNodePropertyString(node, "stage_name"),
			Status:           graphNodePropertyString(node, "status"),
			ApprovalRequired: graphNodePropertyBool(node, "approval_required"),
			ApprovalStatus:   graphNodePropertyString(node, "approval_status"),
		}
		stage.ObservedAt, _ = graphObservedAt(node)
		if stage.ID == "" {
			stage.ID = strings.TrimSpace(node.ID)
		}
		if stage.Name == "" {
			stage.Name = stage.ID
		}
		run.Stages = append(run.Stages, stage)
		if !stage.ObservedAt.IsZero() {
			playbookRunObserve(run, stage.ObservedAt)
		}
		playbookRunCollectTargets(g, run, graphNodePropertyStrings(node, "target_ids"))
	}

	for _, node := range g.GetNodesByKind(NodeKindAction) {
		if !isPlaybookAction(node) {
			continue
		}
		run := getRun(graphNodePropertyString(node, "playbook_run_id"))
		if run == nil {
			continue
		}
		playbookRunApplyNodeIdentity(run, node)
		action := playbookActionAggregate{
			ID:     graphNodePropertyString(node, "action_id"),
			Status: graphNodePropertyString(node, "status"),
		}
		action.ObservedAt, _ = graphObservedAt(node)
		if action.ID == "" {
			action.ID = strings.TrimSpace(node.ID)
		}
		run.Actions = append(run.Actions, action)
		if !action.ObservedAt.IsZero() {
			playbookRunObserve(run, action.ObservedAt)
		}
		playbookRunCollectTargets(g, run, graphNodePropertyStrings(node, "target_ids"))
	}

	for _, node := range g.GetNodesByKind(NodeKindOutcome) {
		if !isPlaybookOutcome(node) {
			continue
		}
		run := getRun(graphNodePropertyString(node, "playbook_run_id"))
		if run == nil {
			continue
		}
		playbookRunApplyNodeIdentity(run, node)
		outcomeAt, _ := graphObservedAt(node)
		if outcomeAt.IsZero() {
			continue
		}
		if outcomeAt.After(run.OutcomeAt) || (outcomeAt.Equal(run.OutcomeAt) && strings.TrimSpace(node.ID) > run.OutcomeNodeID) {
			run.OutcomeAt = outcomeAt
			run.OutcomeNodeID = strings.TrimSpace(node.ID)
			run.OutcomeVerdict = graphNodePropertyString(node, "verdict")
			run.OutcomeStatus = graphNodePropertyString(node, "status")
			run.RollbackState = graphNodePropertyString(node, "rollback_state")
		}
		playbookRunObserve(run, outcomeAt)
		playbookRunCollectTargets(g, run, graphNodePropertyStrings(node, "target_ids"))
	}

	out := make([]*playbookRunAggregate, 0, len(runs))
	for _, run := range runs {
		out = append(out, run)
	}
	return out
}

func buildPlaybookEffectivenessPlaybookRollups(acc map[string]*playbookRollupAccumulator, maxPlaybooks int) []PlaybookEffectivenessPlaybookRollup {
	out := make([]PlaybookEffectivenessPlaybookRollup, 0, len(acc))
	for _, item := range acc {
		rollup := PlaybookEffectivenessPlaybookRollup{
			PlaybookID:               item.PlaybookID,
			PlaybookName:             item.PlaybookName,
			Runs:                     item.Runs,
			CompletedRuns:            item.CompletedRuns,
			SuccessfulRuns:           item.SuccessfulRuns,
			FailedRuns:               item.FailedRuns,
			RollbackRuns:             item.RollbackRuns,
			ApprovalBottlenecks:      item.ApprovalBottlenecks,
			RepeatedTargetExecutions: item.RepeatedTargetExecutions,
		}
		if item.Runs > 0 {
			rollup.CompletionRatePercent = roundMetric((float64(item.CompletedRuns) / float64(item.Runs)) * 100)
			rollup.SuccessRatePercent = roundMetric((float64(item.SuccessfulRuns) / float64(item.Runs)) * 100)
			rollup.RepeatExecutionRatePercent = roundMetric((float64(item.RepeatedTargetExecutions) / float64(item.Runs)) * 100)
		}
		if item.CompletedRuns > 0 {
			rollup.RollbackRatePercent = roundMetric((float64(item.RollbackRuns) / float64(item.CompletedRuns)) * 100)
			rollup.AverageCompletionMinutes = roundMetric(averageFloat64(item.CompletionMinutes))
		}
		if len(item.SuccessfulMinutes) > 0 {
			rollup.MedianSuccessfulCompletionMinutes = roundMetric(medianFloat64(item.SuccessfulMinutes))
		}
		out = append(out, rollup)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Runs != out[j].Runs {
			return out[i].Runs > out[j].Runs
		}
		if out[i].SuccessfulRuns != out[j].SuccessfulRuns {
			return out[i].SuccessfulRuns > out[j].SuccessfulRuns
		}
		return out[i].PlaybookID < out[j].PlaybookID
	})
	if maxPlaybooks > 0 && len(out) > maxPlaybooks {
		out = out[:maxPlaybooks]
	}
	return out
}

func buildPlaybookEffectivenessStageRollups(acc map[string]*playbookStageAccumulator) []PlaybookEffectivenessStageRollup {
	out := make([]PlaybookEffectivenessStageRollup, 0, len(acc))
	for _, item := range acc {
		rollup := PlaybookEffectivenessStageRollup{
			PlaybookID:          item.PlaybookID,
			PlaybookName:        item.PlaybookName,
			StageID:             item.StageID,
			StageName:           item.StageName,
			Executions:          item.Executions,
			Failures:            item.Failures,
			Skipped:             item.Skipped,
			ApprovalBottlenecks: item.ApprovalBottlenecks,
		}
		if item.Executions > 0 {
			rollup.FailureRatePercent = roundMetric((float64(item.Failures) / float64(item.Executions)) * 100)
		}
		out = append(out, rollup)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Failures != out[j].Failures {
			return out[i].Failures > out[j].Failures
		}
		if out[i].ApprovalBottlenecks != out[j].ApprovalBottlenecks {
			return out[i].ApprovalBottlenecks > out[j].ApprovalBottlenecks
		}
		if out[i].PlaybookID != out[j].PlaybookID {
			return out[i].PlaybookID < out[j].PlaybookID
		}
		return out[i].StageID < out[j].StageID
	})
	return out
}

func buildPlaybookEffectivenessTargetKindRollups(acc map[string]*playbookTargetKindAccumulator) []PlaybookEffectivenessTargetKindRollup {
	out := make([]PlaybookEffectivenessTargetKindRollup, 0, len(acc))
	for _, item := range acc {
		rollup := PlaybookEffectivenessTargetKindRollup{
			TargetKind:     item.TargetKind,
			Runs:           item.Runs,
			SuccessfulRuns: item.SuccessfulRuns,
			RollbackRuns:   item.RollbackRuns,
		}
		if item.Runs > 0 {
			rollup.SuccessRatePercent = roundMetric((float64(item.SuccessfulRuns) / float64(item.Runs)) * 100)
		}
		if item.CompletedRuns > 0 {
			rollup.RollbackRatePercent = roundMetric((float64(item.RollbackRuns) / float64(item.CompletedRuns)) * 100)
		}
		out = append(out, rollup)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Runs != out[j].Runs {
			return out[i].Runs > out[j].Runs
		}
		return out[i].TargetKind < out[j].TargetKind
	})
	return out
}

func buildPlaybookEffectivenessTenantRollups(acc map[string]*playbookTenantAccumulator) []PlaybookEffectivenessTenantRollup {
	out := make([]PlaybookEffectivenessTenantRollup, 0, len(acc))
	for _, item := range acc {
		rollup := PlaybookEffectivenessTenantRollup{
			TenantID:       item.TenantID,
			Runs:           item.Runs,
			SuccessfulRuns: item.SuccessfulRuns,
			RollbackRuns:   item.RollbackRuns,
		}
		if item.Runs > 0 {
			rollup.SuccessRatePercent = roundMetric((float64(item.SuccessfulRuns) / float64(item.Runs)) * 100)
		}
		if item.CompletedRuns > 0 {
			rollup.RollbackRatePercent = roundMetric((float64(item.RollbackRuns) / float64(item.CompletedRuns)) * 100)
		}
		out = append(out, rollup)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Runs != out[j].Runs {
			return out[i].Runs > out[j].Runs
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

func buildPlaybookFailureStepRollups(acc map[string]*PlaybookFailureStepRollup) []PlaybookFailureStepRollup {
	out := make([]PlaybookFailureStepRollup, 0, len(acc))
	for _, item := range acc {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Failures != out[j].Failures {
			return out[i].Failures > out[j].Failures
		}
		if out[i].PlaybookID != out[j].PlaybookID {
			return out[i].PlaybookID < out[j].PlaybookID
		}
		return out[i].StageID < out[j].StageID
	})
	return out
}

func buildPlaybookEffectivenessRecommendations(report PlaybookEffectivenessReport) []PlaybookEffectivenessRecommendation {
	recommendations := make([]PlaybookEffectivenessRecommendation, 0, 3)
	if report.Summary.Runs == 0 {
		return []PlaybookEffectivenessRecommendation{{
			Priority:        "high",
			Title:           "No playbook execution history is available",
			Detail:          "The world-model graph does not contain any playbook runs in the selected scope.",
			SuggestedAction: "Emit platform.playbook.run.started, stage.completed, action.executed, and run.completed events before requesting this report.",
		}}
	}
	if report.Summary.RollbackRatePercent >= 20 {
		recommendations = append(recommendations, PlaybookEffectivenessRecommendation{
			Priority:        "high",
			Title:           "Playbook outcomes are unstable",
			Detail:          "A meaningful share of completed playbook runs ended in rollback or reversal signals.",
			SuggestedAction: "Review the highest-rollback playbooks and verify their targeted actions are durable.",
		})
	}
	if report.Summary.ApprovalBottlenecks > 0 {
		recommendations = append(recommendations, PlaybookEffectivenessRecommendation{
			Priority:        "medium",
			Title:           "Approval friction is slowing playbook completion",
			Detail:          "Approval-required stages are accumulating bottleneck signals in the selected window.",
			SuggestedAction: "Audit approver routing and convert low-risk approval gates into auto-approved or batched flows where possible.",
		})
	}
	if report.Summary.RepeatedTargetExecutions > 0 {
		recommendations = append(recommendations, PlaybookEffectivenessRecommendation{
			Priority:        "medium",
			Title:           "Some targets require repeated playbook runs",
			Detail:          "Repeated executions on the same targets suggest the remediation did not stick.",
			SuggestedAction: "Inspect the top repeated targets and add post-condition checks or stronger remediation steps.",
		})
	}
	if len(recommendations) == 0 {
		recommendations = append(recommendations, PlaybookEffectivenessRecommendation{
			Priority:        "low",
			Title:           "Playbook runs are stable in the selected scope",
			Detail:          "No major rollback, approval-friction, or repeat-target issues were detected in the selected window.",
			SuggestedAction: "Keep monitoring completion and success trends as additional playbook history accumulates.",
		})
	}
	return recommendations
}

func playbookRunApplyNodeIdentity(run *playbookRunAggregate, node *Node) {
	if run == nil || node == nil {
		return
	}
	if run.PlaybookID == "" {
		run.PlaybookID = graphNodePropertyString(node, "playbook_id")
	}
	if run.PlaybookName == "" {
		run.PlaybookName = graphNodePropertyString(node, "playbook_name")
	}
	if run.TenantID == "" {
		run.TenantID = graphNodePropertyString(node, "tenant_id")
	}
}

func playbookRunObserve(run *playbookRunAggregate, observedAt time.Time) {
	if run == nil || observedAt.IsZero() {
		return
	}
	observedAt = observedAt.UTC()
	if run.StartedAt.IsZero() || observedAt.Before(run.StartedAt) {
		run.StartedAt = observedAt
	}
	if observedAt.After(run.LatestAt) {
		run.LatestAt = observedAt
	}
}

func playbookRunCollectTargets(g *Graph, run *playbookRunAggregate, targetIDs []string) {
	if run == nil {
		return
	}
	seenTargets := make(map[string]struct{}, len(run.TargetIDs))
	for _, existing := range run.TargetIDs {
		seenTargets[existing] = struct{}{}
	}
	for _, targetID := range targetIDs {
		targetID = normalizePlaybookEffectivenessIdentifier(targetID)
		if targetID == "" {
			continue
		}
		if _, ok := seenTargets[targetID]; !ok {
			run.TargetIDs = append(run.TargetIDs, targetID)
			seenTargets[targetID] = struct{}{}
		}
		if g == nil {
			continue
		}
		targetNode, ok := g.GetNode(targetID)
		if !ok || targetNode == nil {
			continue
		}
		targetKind := normalizePlaybookEffectivenessIdentifier(string(targetNode.Kind))
		if targetKind != "" {
			run.TargetKinds[targetKind] = struct{}{}
		}
	}
}

func playbookRunCompleted(run *playbookRunAggregate) bool {
	return run != nil && !run.OutcomeAt.IsZero()
}

func playbookRunSuccessful(run *playbookRunAggregate) bool {
	if !playbookRunCompleted(run) {
		return false
	}
	if strings.EqualFold(run.OutcomeStatus, "failed") || strings.EqualFold(run.OutcomeVerdict, "negative") {
		return false
	}
	return isPositiveEvalVerdict(run.OutcomeVerdict)
}

func playbookRunFailed(run *playbookRunAggregate) bool {
	if !playbookRunCompleted(run) {
		return false
	}
	if strings.EqualFold(run.OutcomeStatus, "failed") {
		return true
	}
	return strings.EqualFold(run.OutcomeVerdict, "negative")
}

func playbookRunRolledBack(run *playbookRunAggregate) bool {
	if !playbookRunCompleted(run) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(run.RollbackState)) {
	case "", "none", "stable", "not_required", "not-required":
	default:
		return true
	}
	for _, action := range run.Actions {
		switch strings.ToLower(strings.TrimSpace(action.Status)) {
		case "reverted", "reversed", "rolled_back", "rolled-back":
			return true
		}
	}
	return false
}

func playbookCompletionMinutes(run *playbookRunAggregate) (float64, bool) {
	if run == nil || run.StartedAt.IsZero() || run.OutcomeAt.IsZero() || run.OutcomeAt.Before(run.StartedAt) {
		return 0, false
	}
	return roundMetric(run.OutcomeAt.Sub(run.StartedAt).Minutes()), true
}

func countPlaybookApprovalBottlenecks(run *playbookRunAggregate) int {
	total := 0
	for _, stage := range run.Stages {
		if playbookStageApprovalBottleneck(stage) {
			total++
		}
	}
	return total
}

func playbookStageApprovalBottleneck(stage playbookStageAggregate) bool {
	if !stage.ApprovalRequired {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(stage.ApprovalStatus)) {
	case "approved", "auto_approved", "auto-approved":
		return false
	case "pending", "rejected", "denied", "timed_out", "timed-out":
		return true
	}
	return playbookStageFailed(stage) || playbookStageSkipped(stage)
}

func playbookStageFailed(stage playbookStageAggregate) bool {
	return strings.EqualFold(strings.TrimSpace(stage.Status), "failed")
}

func playbookStageSkipped(stage playbookStageAggregate) bool {
	return strings.EqualFold(strings.TrimSpace(stage.Status), "skipped")
}

func playbookTargetSignature(run *playbookRunAggregate) string {
	if run == nil || len(run.TargetIDs) == 0 {
		return ""
	}
	targets := append([]string(nil), run.TargetIDs...)
	sort.Strings(targets)
	return strings.Join(targets, ",")
}

func isPlaybookThread(node *Node) bool {
	if node == nil || node.Kind != NodeKind("communication_thread") {
		return false
	}
	return strings.EqualFold(graphNodePropertyString(node, "channel_name"), "playbook") || graphNodePropertyString(node, "playbook_run_id") != ""
}

func isPlaybookStage(node *Node) bool {
	if node == nil || node.Kind != NodeKindDecision {
		return false
	}
	return strings.EqualFold(graphNodePropertyString(node, "decision_type"), "playbook_stage") || graphNodePropertyString(node, "playbook_run_id") != ""
}

func isPlaybookAction(node *Node) bool {
	if node == nil || node.Kind != NodeKindAction {
		return false
	}
	return graphNodePropertyString(node, "playbook_run_id") != ""
}

func isPlaybookOutcome(node *Node) bool {
	if node == nil || node.Kind != NodeKindOutcome {
		return false
	}
	return strings.EqualFold(graphNodePropertyString(node, "outcome_type"), "playbook_run") || graphNodePropertyString(node, "playbook_run_id") != ""
}

func graphNodePropertyStrings(node *Node, key string) []string {
	if node == nil || node.Properties == nil {
		return nil
	}
	value, ok := node.Properties[key]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if normalized := normalizePlaybookEffectivenessIdentifier(item); normalized != "" {
				out = append(out, normalized)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if normalized := normalizePlaybookEffectivenessIdentifier(identityAnyToString(item)); normalized != "" {
				out = append(out, normalized)
			}
		}
		return out
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil
		}
		if strings.Contains(trimmed, ",") {
			parts := strings.Split(trimmed, ",")
			out := make([]string, 0, len(parts))
			for _, part := range parts {
				if normalized := normalizePlaybookEffectivenessIdentifier(part); normalized != "" {
					out = append(out, normalized)
				}
			}
			return out
		}
		return []string{normalizePlaybookEffectivenessIdentifier(trimmed)}
	default:
		return nil
	}
}

func graphNodePropertyBool(node *Node, key string) bool {
	if node == nil || node.Properties == nil {
		return false
	}
	value, ok := node.Properties[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return err == nil && parsed
	default:
		return false
	}
}

func normalizePlaybookEffectivenessIdentifier(value string) string {
	return strings.TrimSpace(value)
}
