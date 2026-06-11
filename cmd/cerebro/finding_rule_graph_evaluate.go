package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/bootstrap"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/ports"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type findingRuleGraphEvaluateOptions struct {
	RuntimeID string
	RuleID    string
}

type findingRuleGraphEvaluateResult struct {
	RuntimeID   string                                     `json:"runtime_id"`
	SourceID    string                                     `json:"source_id,omitempty"`
	TenantID    string                                     `json:"tenant_id,omitempty"`
	Evaluations []findingRuleGraphEvaluateEvaluationResult `json:"evaluations"`
}

type findingRuleGraphEvaluateEvaluationResult struct {
	RuleID          string   `json:"rule_id"`
	RunID           string   `json:"run_id,omitempty"`
	Status          string   `json:"status,omitempty"`
	RowsRead        uint32   `json:"rows_read"`
	Truncated       bool     `json:"truncated,omitempty"`
	FindingsEmitted int      `json:"findings_emitted"`
	FindingIDs      []string `json:"finding_ids,omitempty"`
	EvidenceCount   int      `json:"evidence_count"`
	StartedAt       string   `json:"started_at,omitempty"`
	FinishedAt      string   `json:"finished_at,omitempty"`
}

func runFindingRuleGraphEvaluate(args []string) error {
	options, err := parseFindingRuleGraphEvaluateArgs(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	closeTelemetry, err := configureOpenTelemetry(ctx, cfg)
	if err != nil {
		return fmt.Errorf("configure telemetry: %w", err)
	}
	defer shutdownTelemetry(ctx, closeTelemetry, cfg.ShutdownTimeout)
	deps, closeDeps, err := bootstrap.OpenDependencies(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open dependencies: %w", err)
	}
	defer func() {
		if err := closeDeps(); err != nil {
			log.Printf("close dependencies: %v", err)
		}
	}()
	service := findings.New(
		sourceRuntimeStore(deps.StateStore),
		eventReplayer(deps.AppendLog),
		findingStore(deps.StateStore),
		findingEvaluationRunStore(deps.StateStore),
		findingEvidenceStore(deps.StateStore),
		claimStore(deps.StateStore),
	).WithGraphStore(sourceProjectionGraphStore(deps.GraphStore)).WithGraphQueryStore(findingGraphQueryStore(deps.GraphStore)).WithAppendLog(deps.AppendLog)
	evaluation, err := service.EvaluateSourceRuntimeGraphRules(ctx, findings.EvaluateGraphRulesRequest{
		RuntimeID: options.RuntimeID,
		RuleIDs:   []string{options.RuleID},
	})
	result := summarizeFindingRuleGraphEvaluation(evaluation)
	if printErr := printJSON(result); printErr != nil {
		return printErr
	}
	return err
}

func parseFindingRuleGraphEvaluateArgs(args []string) (findingRuleGraphEvaluateOptions, error) {
	if len(args) < 2 || strings.TrimSpace(args[0]) == "" {
		return findingRuleGraphEvaluateOptions{}, usageError(fmt.Sprintf(findingRuleGraphEvaluateUsage, os.Args[0]))
	}
	options := findingRuleGraphEvaluateOptions{RuntimeID: strings.TrimSpace(args[0])}
	values := map[string]string{}
	for _, arg := range args[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return findingRuleGraphEvaluateOptions{}, fmt.Errorf("invalid graph-evaluate argument %q; want key=value", arg)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "rule_id" {
			return findingRuleGraphEvaluateOptions{}, fmt.Errorf("unsupported graph-evaluate argument %q", key)
		}
		if _, exists := values[key]; exists {
			return findingRuleGraphEvaluateOptions{}, fmt.Errorf("duplicate graph-evaluate argument %q", key)
		}
		values[key] = value
	}
	options.RuleID = values["rule_id"]
	if options.RuleID == "" {
		return findingRuleGraphEvaluateOptions{}, usageError(fmt.Sprintf(findingRuleGraphEvaluateUsage, os.Args[0]))
	}
	return options, nil
}

func summarizeFindingRuleGraphEvaluation(result *findings.EvaluateGraphRulesResult) *findingRuleGraphEvaluateResult {
	if result == nil {
		return &findingRuleGraphEvaluateResult{}
	}
	summary := &findingRuleGraphEvaluateResult{
		Evaluations: make([]findingRuleGraphEvaluateEvaluationResult, 0, len(result.Evaluations)),
	}
	if runtime := result.Runtime; runtime != nil {
		summary.RuntimeID = strings.TrimSpace(runtime.GetId())
		summary.SourceID = strings.TrimSpace(runtime.GetSourceId())
		summary.TenantID = strings.TrimSpace(runtime.GetTenantId())
	}
	for _, evaluation := range result.Evaluations {
		if evaluation == nil {
			continue
		}
		summary.Evaluations = append(summary.Evaluations, summarizeFindingRuleGraphRuleEvaluation(evaluation))
	}
	return summary
}

func summarizeFindingRuleGraphRuleEvaluation(evaluation *findings.GraphRuleEvaluationResult) findingRuleGraphEvaluateEvaluationResult {
	summary := findingRuleGraphEvaluateEvaluationResult{
		RowsRead:        evaluation.RowsRead,
		Truncated:       evaluation.Truncated,
		FindingsEmitted: len(evaluation.Findings),
		FindingIDs:      findingRecordIDs(evaluation.Findings),
		EvidenceCount:   len(evaluation.Evidence),
	}
	if rule := evaluation.Rule; rule != nil {
		summary.RuleID = strings.TrimSpace(rule.GetId())
	}
	if run := evaluation.Run; run != nil {
		summary.RunID = strings.TrimSpace(run.GetId())
		summary.Status = strings.TrimSpace(run.GetStatus())
		summary.StartedAt = formatProtoTimestamp(run.GetStartedAt())
		summary.FinishedAt = formatProtoTimestamp(run.GetFinishedAt())
	}
	return summary
}

func findingRecordIDs(records []*ports.FindingRecord) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		if record == nil || strings.TrimSpace(record.ID) == "" {
			continue
		}
		ids = append(ids, strings.TrimSpace(record.ID))
	}
	return ids
}

func formatProtoTimestamp(timestamp *timestamppb.Timestamp) string {
	if timestamp == nil {
		return ""
	}
	return timestamp.AsTime().UTC().Format(time.RFC3339Nano)
}
