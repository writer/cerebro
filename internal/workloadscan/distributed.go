package workloadscan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultDistributedDedupTTL = 30 * time.Minute
	distributedRunPageSize     = 500
)

type DistributedDispatchRequest struct {
	GroupID                string            `json:"group_id,omitempty"`
	RequestedBy            string            `json:"requested_by,omitempty"`
	SubmittedAt            time.Time         `json:"submitted_at,omitempty"`
	Targets                []TargetPriority  `json:"targets,omitempty"`
	ScannerHosts           []ScannerHost     `json:"scanner_hosts,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	MaxConcurrentSnapshots int               `json:"max_concurrent_snapshots,omitempty"`
	DryRun                 bool              `json:"dry_run,omitempty"`
}

type DistributedDispatchStatus string

const (
	DistributedDispatchStatusQueued       DistributedDispatchStatus = "queued"
	DistributedDispatchStatusDeduplicated DistributedDispatchStatus = "deduplicated"
)

type DistributedDispatch struct {
	Status        DistributedDispatchStatus `json:"status"`
	RunID         string                    `json:"run_id,omitempty"`
	ExistingRunID string                    `json:"existing_run_id,omitempty"`
	Target        VMTarget                  `json:"target"`
	ScannerHost   ScannerHost               `json:"scanner_host,omitempty"`
}

type DistributedDispatchReport struct {
	GroupID      string                `json:"group_id"`
	SubmittedAt  time.Time             `json:"submitted_at"`
	QueuedRuns   int                   `json:"queued_runs"`
	Deduplicated int                   `json:"deduplicated"`
	Dispatches   []DistributedDispatch `json:"dispatches,omitempty"`
}

type DistributedGroupSummary struct {
	GroupID         string         `json:"group_id"`
	TotalRuns       int            `json:"total_runs"`
	Queued          int            `json:"queued"`
	Running         int            `json:"running"`
	Succeeded       int            `json:"succeeded"`
	Failed          int            `json:"failed"`
	TotalFindings   int64          `json:"total_findings"`
	TotalVolumes    int            `json:"total_volumes"`
	ScannerHostRuns map[string]int `json:"scanner_host_runs,omitempty"`
	Complete        bool           `json:"complete"`
}

type CoordinatorOptions struct {
	Store    RunStore
	Logger   *slog.Logger
	DedupTTL time.Duration
	Now      func() time.Time
}

type Coordinator struct {
	store    RunStore
	logger   *slog.Logger
	dedupTTL time.Duration
	now      func() time.Time
}

func NewCoordinator(opts CoordinatorOptions) *Coordinator {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	dedupTTL := opts.DedupTTL
	if dedupTTL <= 0 {
		dedupTTL = defaultDistributedDedupTTL
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Coordinator{
		store:    opts.Store,
		logger:   logger,
		dedupTTL: dedupTTL,
		now:      now,
	}
}

func (c *Coordinator) QueueDistributedRuns(ctx context.Context, req DistributedDispatchRequest) (*DistributedDispatchReport, error) {
	if c == nil {
		return nil, fmt.Errorf("workload scan coordinator is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.store == nil {
		return nil, fmt.Errorf("workload scan store is not configured")
	}
	submittedAt := req.SubmittedAt.UTC()
	if submittedAt.IsZero() {
		submittedAt = c.now().UTC()
	}
	groupID := strings.TrimSpace(req.GroupID)
	if groupID == "" {
		groupID = "distributed_workload_scan:" + uuid.NewString()
	}
	report := &DistributedDispatchReport{
		GroupID:     groupID,
		SubmittedAt: submittedAt,
		Dispatches:  make([]DistributedDispatch, 0, len(req.Targets)),
	}
	if len(req.Targets) == 0 {
		return report, nil
	}
	if len(req.ScannerHosts) == 0 {
		return nil, fmt.Errorf("at least one scanner host is required")
	}

	activeRuns, err := c.activeRunsByDedupKey(ctx)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]string, len(req.Targets))
	cursors := make(map[string]int)

	for _, target := range req.Targets {
		normalizedTarget := normalizeDistributedTarget(target)
		dedupKey := distributedDedupKey(normalizedTarget)
		if dedupKey == "" {
			return nil, fmt.Errorf("distributed scan target identity is required")
		}
		dispatch := DistributedDispatch{Target: normalizedTarget}
		if runID, ok := seen[dedupKey]; ok {
			dispatch.Status = DistributedDispatchStatusDeduplicated
			dispatch.ExistingRunID = runID
			report.Deduplicated++
			report.Dispatches = append(report.Dispatches, dispatch)
			continue
		}
		if existing, ok := activeRuns[dedupKey]; ok {
			dispatch.Status = DistributedDispatchStatusDeduplicated
			dispatch.ExistingRunID = existing.ID
			report.Deduplicated++
			report.Dispatches = append(report.Dispatches, dispatch)
			seen[dedupKey] = existing.ID
			continue
		}

		scannerHost, err := selectDistributedScannerHost(normalizedTarget, req.ScannerHosts, cursors)
		if err != nil {
			return nil, err
		}
		runID := "workload_scan:" + uuid.NewString()
		claimed, err := c.store.ClaimDistributedDedup(ctx, dedupKey, runID, c.dedupTTL)
		if err != nil {
			return nil, err
		}
		if !claimed {
			dispatch.Status = DistributedDispatchStatusDeduplicated
			if existing, ok := activeRuns[dedupKey]; ok {
				dispatch.ExistingRunID = existing.ID
				seen[dedupKey] = existing.ID
			}
			report.Deduplicated++
			report.Dispatches = append(report.Dispatches, dispatch)
			continue
		}

		assignedAt := submittedAt
		run := &RunRecord{
			ID:                     runID,
			Provider:               normalizedTarget.Provider,
			Status:                 RunStatusQueued,
			Stage:                  RunStageQueued,
			Target:                 normalizedTarget,
			ScannerHost:            scannerHost,
			RequestedBy:            strings.TrimSpace(req.RequestedBy),
			DryRun:                 req.DryRun,
			MaxConcurrentSnapshots: req.MaxConcurrentSnapshots,
			Metadata:               cloneStringMap(req.Metadata),
			Priority:               ClonePriorityAssessment(&target.Assessment),
			SubmittedAt:            submittedAt,
			UpdatedAt:              submittedAt,
			Distributed: &DistributedRunState{
				GroupID:    groupID,
				DedupKey:   dedupKey,
				AssignedAt: &assignedAt,
			},
		}
		if err := c.store.SaveRun(ctx, run); err != nil {
			_ = c.store.ReleaseDistributedDedup(ctx, dedupKey)
			return nil, err
		}
		c.recordRunEvent(ctx, run, RunStatusQueued, RunStageQueued, "distributed workload scan queued", map[string]any{
			"group_id":        groupID,
			"dedup_key":       dedupKey,
			"scanner_host_id": scannerHost.HostID,
		})
		dispatch.Status = DistributedDispatchStatusQueued
		dispatch.RunID = run.ID
		dispatch.ScannerHost = scannerHost
		report.QueuedRuns++
		report.Dispatches = append(report.Dispatches, dispatch)
		activeRuns[dedupKey] = run
		seen[dedupKey] = run.ID
	}

	return report, nil
}

func (c *Coordinator) ClaimNextRun(ctx context.Context, host ScannerHost) (*RunRecord, bool, error) {
	if c == nil {
		return nil, false, fmt.Errorf("workload scan coordinator is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.store == nil {
		return nil, false, fmt.Errorf("workload scan store is not configured")
	}
	if strings.TrimSpace(host.HostID) == "" {
		return nil, false, fmt.Errorf("scanner host id is required")
	}
	for offset := 0; ; offset += distributedRunPageSize {
		runs, err := c.store.ListRuns(ctx, RunListOptions{
			Statuses:           []RunStatus{RunStatusQueued},
			Limit:              distributedRunPageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return nil, false, err
		}
		if len(runs) == 0 {
			return nil, false, nil
		}
		for i := range runs {
			run := runs[i]
			if !sameScannerHostAssignment(run.ScannerHost, host) {
				continue
			}
			return c.claimQueuedRun(ctx, &run, host, false)
		}
		for i := range runs {
			run := runs[i]
			if sameScannerHostAssignment(run.ScannerHost, host) {
				continue
			}
			if !scannerHostSupportsTarget(host, run.Target) {
				continue
			}
			return c.claimQueuedRun(ctx, &run, host, true)
		}
		if len(runs) < distributedRunPageSize {
			return nil, false, nil
		}
	}
}

func (c *Coordinator) claimQueuedRun(ctx context.Context, run *RunRecord, host ScannerHost, stolen bool) (*RunRecord, bool, error) {
	if run == nil {
		return nil, false, nil
	}
	next := cloneRunRecord(run)
	claimedAt := c.now().UTC()
	next.Status = RunStatusRunning
	next.Stage = RunStageInventory
	next.ScannerHost = host
	if next.StartedAt == nil {
		next.StartedAt = &claimedAt
	}
	next.UpdatedAt = claimedAt
	if next.Distributed == nil {
		next.Distributed = &DistributedRunState{DedupKey: distributedDedupKey(next.Target)}
	}
	next.Distributed.ClaimedAt = &claimedAt
	next.Distributed.ClaimedBy = strings.TrimSpace(host.HostID)
	swapped, err := c.store.CompareAndSwapRun(ctx, run, next)
	if err != nil {
		return nil, false, err
	}
	if !swapped {
		return nil, false, nil
	}
	message := "distributed workload scan claimed"
	payload := map[string]any{
		"scanner_host_id": host.HostID,
	}
	if stolen {
		message = "distributed workload scan claimed via work-stealing"
		payload["stolen"] = true
	}
	c.recordRunEvent(ctx, next, next.Status, next.Stage, message, payload)
	return next, true, nil
}

func (c *Coordinator) AggregateGroup(ctx context.Context, groupID string) (*DistributedGroupSummary, error) {
	if c == nil {
		return nil, fmt.Errorf("workload scan coordinator is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if c.store == nil {
		return nil, fmt.Errorf("workload scan store is not configured")
	}
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, fmt.Errorf("distributed group id is required")
	}
	summary := &DistributedGroupSummary{
		GroupID:         groupID,
		ScannerHostRuns: map[string]int{},
	}
	for offset := 0; ; offset += distributedRunPageSize {
		runs, err := c.store.ListRuns(ctx, RunListOptions{
			Limit:              distributedRunPageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return nil, err
		}
		if len(runs) == 0 {
			break
		}
		for i := range runs {
			run := runs[i]
			if run.Distributed == nil || strings.TrimSpace(run.Distributed.GroupID) != groupID {
				continue
			}
			summary.TotalRuns++
			switch run.Status {
			case RunStatusQueued:
				summary.Queued++
			case RunStatusRunning:
				summary.Running++
			case RunStatusSucceeded:
				summary.Succeeded++
			case RunStatusFailed:
				summary.Failed++
			}
			summary.TotalFindings += run.Summary.Findings
			summary.TotalVolumes += run.Summary.VolumeCount
			if hostID := strings.TrimSpace(run.ScannerHost.HostID); hostID != "" {
				summary.ScannerHostRuns[hostID]++
			}
		}
		if len(runs) < distributedRunPageSize {
			break
		}
	}
	summary.Complete = summary.TotalRuns > 0 && summary.Queued == 0 && summary.Running == 0
	return summary, nil
}

func (c *Coordinator) activeRunsByDedupKey(ctx context.Context) (map[string]*RunRecord, error) {
	active := make(map[string]*RunRecord)
	for offset := 0; ; offset += distributedRunPageSize {
		runs, err := c.store.ListRuns(ctx, RunListOptions{
			ActiveOnly:         true,
			Limit:              distributedRunPageSize,
			Offset:             offset,
			OrderBySubmittedAt: true,
		})
		if err != nil {
			return nil, err
		}
		if len(runs) == 0 {
			break
		}
		for i := range runs {
			run := runs[i]
			key := distributedDedupKeyForRun(&run)
			if key == "" {
				continue
			}
			active[key] = &run
		}
		if len(runs) < distributedRunPageSize {
			break
		}
	}
	return active, nil
}

func (c *Coordinator) recordRunEvent(ctx context.Context, run *RunRecord, status RunStatus, stage RunStage, message string, data map[string]any) {
	if c.store == nil || run == nil {
		return
	}
	if _, err := c.store.AppendEvent(ctx, run.ID, RunEvent{
		Status:     status,
		Stage:      stage,
		Message:    strings.TrimSpace(message),
		Data:       cloneAnyMap(data),
		RecordedAt: c.now().UTC(),
	}); err != nil {
		c.logger.Warn("failed to persist distributed workload scan event", "run_id", run.ID, "stage", stage, "error", err)
	}
}

func selectDistributedScannerHost(target VMTarget, hosts []ScannerHost, cursors map[string]int) (ScannerHost, error) {
	eligible := make([]ScannerHost, 0, len(hosts))
	for _, host := range hosts {
		if scannerHostSupportsTarget(host, target) {
			eligible = append(eligible, host)
		}
	}
	if len(eligible) == 0 {
		return ScannerHost{}, fmt.Errorf("no eligible scanner host available for %s target %s in region %s", target.Provider, target.Identity(), target.Region)
	}
	bucket := string(target.Provider) + ":" + strings.ToLower(strings.TrimSpace(target.Region))
	index := 0
	if len(eligible) > 1 {
		index = cursors[bucket] % len(eligible)
	}
	cursors[bucket]++
	return eligible[index], nil
}

func scannerHostSupportsTarget(host ScannerHost, target VMTarget) bool {
	if strings.TrimSpace(host.HostID) == "" {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(host.Region), strings.TrimSpace(target.Region)) {
		return false
	}
	switch target.Provider {
	case ProviderAWS:
		return strings.TrimSpace(host.Zone) != ""
	case ProviderGCP:
		return strings.TrimSpace(host.ProjectID) != "" && strings.TrimSpace(host.Zone) != ""
	case ProviderAzure:
		return strings.TrimSpace(host.SubscriptionID) != "" && strings.TrimSpace(host.ResourceGroup) != ""
	default:
		return false
	}
}

func sameScannerHostAssignment(assigned, host ScannerHost) bool {
	if !strings.EqualFold(strings.TrimSpace(assigned.HostID), strings.TrimSpace(host.HostID)) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(assigned.Region), strings.TrimSpace(host.Region)) {
		return false
	}
	if assigned.Zone != "" && host.Zone != "" && !strings.EqualFold(strings.TrimSpace(assigned.Zone), strings.TrimSpace(host.Zone)) {
		return false
	}
	if assigned.ProjectID != "" && host.ProjectID != "" && !strings.EqualFold(strings.TrimSpace(assigned.ProjectID), strings.TrimSpace(host.ProjectID)) {
		return false
	}
	if assigned.SubscriptionID != "" && host.SubscriptionID != "" && !strings.EqualFold(strings.TrimSpace(assigned.SubscriptionID), strings.TrimSpace(host.SubscriptionID)) {
		return false
	}
	if assigned.ResourceGroup != "" && host.ResourceGroup != "" && !strings.EqualFold(strings.TrimSpace(assigned.ResourceGroup), strings.TrimSpace(host.ResourceGroup)) {
		return false
	}
	return true
}

func normalizeDistributedTarget(target TargetPriority) VMTarget {
	normalized := target.Target
	if normalized.Provider == "" {
		normalized.Provider = target.Provider
	}
	return normalized
}

func distributedDedupKeyForRun(run *RunRecord) string {
	if run == nil {
		return ""
	}
	if run.Distributed != nil && strings.TrimSpace(run.Distributed.DedupKey) != "" {
		return strings.TrimSpace(run.Distributed.DedupKey)
	}
	return distributedDedupKey(run.Target)
}

func distributedDedupKey(target VMTarget) string {
	switch target.Provider {
	case ProviderAWS:
		instanceID := strings.TrimSpace(target.InstanceID)
		if instanceID == "" {
			return ""
		}
		return strings.ToLower(strings.Join([]string{
			string(target.Provider),
			strings.TrimSpace(target.AccountID),
			strings.TrimSpace(target.Region),
			instanceID,
		}, ":"))
	case ProviderGCP:
		if strings.TrimSpace(target.ProjectID) == "" || strings.TrimSpace(target.Zone) == "" || strings.TrimSpace(target.InstanceName) == "" {
			return ""
		}
		return strings.ToLower(strings.Join([]string{
			string(target.Provider),
			target.ProjectID,
			target.Zone,
			target.InstanceName,
		}, ":"))
	case ProviderAzure:
		if strings.TrimSpace(target.SubscriptionID) == "" || strings.TrimSpace(target.ResourceGroup) == "" || strings.TrimSpace(target.InstanceName) == "" {
			return ""
		}
		return strings.ToLower(strings.Join([]string{
			string(target.Provider),
			target.SubscriptionID,
			target.ResourceGroup,
			target.Region,
			target.InstanceName,
		}, ":"))
	default:
		return ""
	}
}

func cloneRunRecord(in *RunRecord) *RunRecord {
	if in == nil {
		return nil
	}
	out := *in
	out.Metadata = cloneStringMap(in.Metadata)
	out.Priority = ClonePriorityAssessment(in.Priority)
	out.Volumes = append([]VolumeScanRecord(nil), in.Volumes...)
	if in.StartedAt != nil {
		startedAt := in.StartedAt.UTC()
		out.StartedAt = &startedAt
	}
	if in.CompletedAt != nil {
		completedAt := in.CompletedAt.UTC()
		out.CompletedAt = &completedAt
	}
	if in.Distributed != nil {
		distributed := *in.Distributed
		if in.Distributed.AssignedAt != nil {
			assignedAt := in.Distributed.AssignedAt.UTC()
			distributed.AssignedAt = &assignedAt
		}
		if in.Distributed.ClaimedAt != nil {
			claimedAt := in.Distributed.ClaimedAt.UTC()
			distributed.ClaimedAt = &claimedAt
		}
		out.Distributed = &distributed
	}
	return &out
}
