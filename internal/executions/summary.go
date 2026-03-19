package executions

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/actionengine"
	"github.com/writer/cerebro/internal/executionstore"
	"github.com/writer/cerebro/internal/functionscan"
	reports "github.com/writer/cerebro/internal/graph/reports"
	"github.com/writer/cerebro/internal/imagescan"
	"github.com/writer/cerebro/internal/workloadscan"
)

type ListOptions struct {
	Namespaces         []string
	Statuses           []string
	ExcludeStatuses    []string
	ReportID           string
	Limit              int
	Offset             int
	OrderBySubmittedAt bool
}

type Summary struct {
	Namespace     string     `json:"namespace"`
	RunID         string     `json:"run_id"`
	Kind          string     `json:"kind"`
	Status        string     `json:"status"`
	Stage         string     `json:"stage"`
	SubmittedAt   time.Time  `json:"submitted_at"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DisplayName   string     `json:"display_name,omitempty"`
	ScopeID       string     `json:"scope_id,omitempty"`
	RequestedBy   string     `json:"requested_by,omitempty"`
	ExecutionMode string     `json:"execution_mode,omitempty"`
	StatusURL     string     `json:"status_url,omitempty"`
	JobID         string     `json:"job_id,omitempty"`
	Error         string     `json:"error,omitempty"`
	Provider      string     `json:"provider,omitempty"`
	Target        string     `json:"target,omitempty"`
}

func List(ctx context.Context, store executionstore.Store, opts ListOptions) ([]Summary, error) {
	if store == nil {
		return nil, nil
	}
	query := executionstore.RunListOptions{
		Namespaces:         opts.Namespaces,
		Statuses:           opts.Statuses,
		ExcludeStatuses:    opts.ExcludeStatuses,
		Limit:              opts.Limit,
		Offset:             opts.Offset,
		OrderBySubmittedAt: opts.OrderBySubmittedAt,
	}
	applyPaginationAfterFilter := false
	if strings.TrimSpace(opts.ReportID) != "" {
		reportNamespaces, ok := reportFilterNamespaces(opts.Namespaces)
		if !ok {
			return nil, nil
		}
		query.Namespaces = reportNamespaces
		query.Limit = 0
		query.Offset = 0
		applyPaginationAfterFilter = true
	}
	envs, err := store.ListAllRuns(ctx, query)
	if err != nil {
		return nil, err
	}
	summaries := make([]Summary, 0, len(envs))
	for _, env := range envs {
		summary, ok, err := summarizeEnvelope(env, opts)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool {
		if opts.OrderBySubmittedAt {
			if summaries[i].SubmittedAt.Equal(summaries[j].SubmittedAt) {
				return summaries[i].RunID > summaries[j].RunID
			}
			return summaries[i].SubmittedAt.After(summaries[j].SubmittedAt)
		}
		if summaries[i].UpdatedAt.Equal(summaries[j].UpdatedAt) {
			return summaries[i].RunID > summaries[j].RunID
		}
		return summaries[i].UpdatedAt.After(summaries[j].UpdatedAt)
	})
	if applyPaginationAfterFilter {
		summaries = paginateSummaries(summaries, opts.Offset, opts.Limit)
	}
	return summaries, nil
}

func reportFilterNamespaces(namespaces []string) ([]string, bool) {
	if len(namespaces) == 0 {
		return []string{executionstore.NamespacePlatformReportRun}, true
	}
	for _, namespace := range namespaces {
		if strings.TrimSpace(namespace) == executionstore.NamespacePlatformReportRun {
			return []string{executionstore.NamespacePlatformReportRun}, true
		}
	}
	return nil, false
}

func paginateSummaries(summaries []Summary, offset, limit int) []Summary {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(summaries) {
		return nil
	}
	end := len(summaries)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return summaries[offset:end]
}

func summarizeEnvelope(env executionstore.RunEnvelope, opts ListOptions) (Summary, bool, error) {
	switch env.Namespace {
	case executionstore.NamespacePlatformReportRun:
		return summarizeReportRun(env, opts)
	case executionstore.NamespaceWorkloadScan:
		return summarizeWorkloadRun(env)
	case executionstore.NamespaceImageScan:
		return summarizeImageRun(env)
	case executionstore.NamespaceFunctionScan:
		return summarizeFunctionRun(env)
	case executionstore.NamespaceActionEngine:
		return summarizeActionExecution(env)
	default:
		return Summary{
			Namespace:   env.Namespace,
			RunID:       env.RunID,
			Kind:        env.Kind,
			Status:      env.Status,
			Stage:       env.Stage,
			SubmittedAt: env.SubmittedAt,
			StartedAt:   env.StartedAt,
			CompletedAt: env.CompletedAt,
			UpdatedAt:   env.UpdatedAt,
			DisplayName: env.RunID,
		}, true, nil
	}
}

func summarizeReportRun(env executionstore.RunEnvelope, opts ListOptions) (Summary, bool, error) {
	var payload struct {
		Run *reports.ReportRun `json:"run"`
	}
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return Summary{}, false, fmt.Errorf("decode report execution %q: %w", env.RunID, err)
	}
	if payload.Run == nil {
		return Summary{}, false, nil
	}
	reportID := strings.TrimSpace(payload.Run.ReportID)
	if filter := strings.TrimSpace(opts.ReportID); filter != "" && filter != reportID {
		return Summary{}, false, nil
	}
	return Summary{
		Namespace:     env.Namespace,
		RunID:         env.RunID,
		Kind:          firstNonEmpty(strings.TrimSpace(payload.Run.ReportID), env.Kind),
		Status:        env.Status,
		Stage:         env.Stage,
		SubmittedAt:   env.SubmittedAt,
		StartedAt:     env.StartedAt,
		CompletedAt:   env.CompletedAt,
		UpdatedAt:     env.UpdatedAt,
		DisplayName:   "report:" + reportID,
		ScopeID:       reportID,
		RequestedBy:   strings.TrimSpace(payload.Run.RequestedBy),
		ExecutionMode: strings.TrimSpace(payload.Run.ExecutionMode),
		StatusURL:     strings.TrimSpace(payload.Run.StatusURL),
		JobID:         strings.TrimSpace(payload.Run.JobID),
		Error:         strings.TrimSpace(payload.Run.Error),
	}, true, nil
}

func summarizeWorkloadRun(env executionstore.RunEnvelope) (Summary, bool, error) {
	var run workloadscan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Summary{}, false, fmt.Errorf("decode workload execution %q: %w", env.RunID, err)
	}
	return Summary{
		Namespace:   env.Namespace,
		RunID:       env.RunID,
		Kind:        env.Kind,
		Status:      env.Status,
		Stage:       env.Stage,
		SubmittedAt: env.SubmittedAt,
		StartedAt:   env.StartedAt,
		CompletedAt: env.CompletedAt,
		UpdatedAt:   env.UpdatedAt,
		DisplayName: "workload:" + run.Target.Identity(),
		ScopeID:     run.Target.Identity(),
		RequestedBy: strings.TrimSpace(run.RequestedBy),
		Error:       strings.TrimSpace(run.Error),
		Provider:    string(run.Provider),
		Target:      run.Target.Identity(),
	}, true, nil
}

func summarizeImageRun(env executionstore.RunEnvelope) (Summary, bool, error) {
	var run imagescan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Summary{}, false, fmt.Errorf("decode image execution %q: %w", env.RunID, err)
	}
	target := run.Target.Reference()
	return Summary{
		Namespace:   env.Namespace,
		RunID:       env.RunID,
		Kind:        env.Kind,
		Status:      env.Status,
		Stage:       env.Stage,
		SubmittedAt: env.SubmittedAt,
		StartedAt:   env.StartedAt,
		CompletedAt: env.CompletedAt,
		UpdatedAt:   env.UpdatedAt,
		DisplayName: "image:" + target,
		ScopeID:     target,
		RequestedBy: strings.TrimSpace(run.RequestedBy),
		Error:       strings.TrimSpace(run.Error),
		Provider:    string(run.Registry),
		Target:      target,
	}, true, nil
}

func summarizeFunctionRun(env executionstore.RunEnvelope) (Summary, bool, error) {
	var run functionscan.RunRecord
	if err := json.Unmarshal(env.Payload, &run); err != nil {
		return Summary{}, false, fmt.Errorf("decode function execution %q: %w", env.RunID, err)
	}
	target := run.Target.Identity()
	return Summary{
		Namespace:   env.Namespace,
		RunID:       env.RunID,
		Kind:        env.Kind,
		Status:      env.Status,
		Stage:       env.Stage,
		SubmittedAt: env.SubmittedAt,
		StartedAt:   env.StartedAt,
		CompletedAt: env.CompletedAt,
		UpdatedAt:   env.UpdatedAt,
		DisplayName: "function:" + target,
		ScopeID:     target,
		RequestedBy: strings.TrimSpace(run.RequestedBy),
		Error:       strings.TrimSpace(run.Error),
		Provider:    string(run.Provider),
		Target:      target,
	}, true, nil
}

func summarizeActionExecution(env executionstore.RunEnvelope) (Summary, bool, error) {
	var execution actionengine.Execution
	if err := json.Unmarshal(env.Payload, &execution); err != nil {
		return Summary{}, false, fmt.Errorf("decode action execution %q: %w", env.RunID, err)
	}
	scopeID := firstNonEmpty(strings.TrimSpace(execution.ResourceID), strings.TrimSpace(execution.SignalID))
	return Summary{
		Namespace:   env.Namespace,
		RunID:       env.RunID,
		Kind:        firstNonEmpty(env.Kind, "action_execution"),
		Status:      env.Status,
		Stage:       env.Stage,
		SubmittedAt: env.SubmittedAt,
		StartedAt:   env.StartedAt,
		CompletedAt: env.CompletedAt,
		UpdatedAt:   env.UpdatedAt,
		DisplayName: firstNonEmpty(strings.TrimSpace(execution.PlaybookName), strings.TrimSpace(execution.PlaybookID), env.RunID),
		ScopeID:     scopeID,
		Error:       strings.TrimSpace(execution.Error),
		Target:      scopeID,
	}, true, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
