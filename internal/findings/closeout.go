package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const defaultCloseoutBatchSize = 1000

// ErrCloseoutAnotherRunning indicates that a concurrent closeout run was rejected.
var ErrCloseoutAnotherRunning = errors.New("another closeout run is in flight")

// ErrCloseoutInvalidRequest indicates one or more required CloseoutRequest fields are missing.
var ErrCloseoutInvalidRequest = errors.New("invalid closeout request")

// ErrCloseoutUnavailable indicates that the bulk tombstone primitive is missing a dependency.
var ErrCloseoutUnavailable = errors.New("closeout primitive is unavailable")

// CloseoutSelector scopes one bulk tombstone candidate resolution.
//
// The resolved selector is what is persisted to closeout_run.selector_json so the
// audit row reflects the actual selection logic that was applied, including any
// defaulted Statuses.
type CloseoutSelector struct {
	TenantID       string        `json:"tenant_id"`
	RuleIDs        []string      `json:"rule_ids,omitempty"`
	Sources        []string      `json:"sources,omitempty"`
	OlderThan      time.Duration `json:"older_than,omitempty"`
	Statuses       []string      `json:"statuses"`
	AnchorURIRegex string        `json:"anchor_uri_regex,omitempty"`
}

// CloseoutRequest carries the inputs for one TombstoneFindingsBulk invocation.
type CloseoutRequest struct {
	Selector     CloseoutSelector
	Reason       string
	Actor        string
	RunID        string
	DryRun       bool
	MaxBatchSize int
	ChangeTicket string
	Environment  string
}

// CloseoutResult reports the observable outcome of one TombstoneFindingsBulk invocation.
type CloseoutResult struct {
	RunID         string
	Proposed      []*ports.FindingRecord
	ProposedCount int
	AppliedCount  int
	BatchSizes    []int
	BatchErrors   []error
}

// TombstoneFindingsBulk runs the bulk tombstone primitive end to end:
//
//   - resolves the selector (default Statuses=[open], OlderThan filter, default-batch-size),
//   - inserts a closeout_run row with status='running' BEFORE any per-finding write,
//   - for apply: tombstones each candidate via Service.updateFindingStatusAndRisk so manual
//     state (assignee/notes/tickets) is preserved by the underlying store guard,
//   - appends one finding_tombstone_events audit row per candidate,
//   - emits one workflow.v1.finding.tombstoned event per candidate,
//   - flips closeout_run to succeeded/failed with finished_at + error_message on every
//     exit path (success, batch error, ctx cancel/timeout, panic),
//   - fails fast when another run is in flight (singleton partial unique index),
//   - is idempotent on RunID (duplicate run_id returns AppliedCount=0 without mutation),
//   - batches per MaxBatchSize.
//
// The persisted selector_json captures the resolved selector (after defaults applied) so
// the audit reflects what was actually used.
func (s *Service) TombstoneFindingsBulk(ctx context.Context, req CloseoutRequest) (result *CloseoutResult, err error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	if s.closeoutStore == nil || s.tombstoneEventStore == nil {
		return nil, fmt.Errorf("%w: closeout/tombstone-event stores not wired", ErrCloseoutUnavailable)
	}
	runID := strings.TrimSpace(req.RunID)
	if runID == "" {
		return nil, fmt.Errorf("%w: run id is required", ErrCloseoutInvalidRequest)
	}
	actor := strings.TrimSpace(req.Actor)
	if actor == "" {
		return nil, fmt.Errorf("%w: actor is required", ErrCloseoutInvalidRequest)
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrCloseoutInvalidRequest)
	}
	selector := resolveCloseoutSelector(req.Selector)
	if strings.TrimSpace(selector.TenantID) == "" {
		return nil, fmt.Errorf("%w: tenant id is required", ErrCloseoutInvalidRequest)
	}
	if len(selector.RuleIDs) == 0 && len(selector.Sources) == 0 {
		return nil, fmt.Errorf("%w: at least one rule id or source is required", ErrCloseoutInvalidRequest)
	}
	batchSize := req.MaxBatchSize
	if batchSize <= 0 {
		batchSize = defaultCloseoutBatchSize
	}

	selectorJSON, marshalErr := json.Marshal(selector)
	if marshalErr != nil {
		return nil, fmt.Errorf("encode closeout selector: %w", marshalErr)
	}

	startedAt := time.Now().UTC()
	insertErr := s.closeoutStore.InsertCloseoutRun(ctx, ports.CloseoutRunInsert{
		RunID:        runID,
		Actor:        actor,
		ChangeTicket: strings.TrimSpace(req.ChangeTicket),
		SelectorJSON: selectorJSON,
		DryRun:       req.DryRun,
		StartedAt:    startedAt,
	})
	if insertErr != nil {
		if errors.Is(insertErr, ports.ErrCloseoutRunInFlight) {
			return nil, fmt.Errorf("%w: %s", ErrCloseoutAnotherRunning, insertErr.Error())
		}
		if errors.Is(insertErr, ports.ErrCloseoutRunAlreadyExists) {
			return &CloseoutResult{RunID: runID, AppliedCount: 0}, nil
		}
		return nil, fmt.Errorf("insert closeout_run %q: %w", runID, insertErr)
	}

	result = &CloseoutResult{RunID: runID}
	finishBackground := func(status, errMessage string, applied int) {
		bgCtx := context.WithoutCancel(ctx)
		_ = s.closeoutStore.FinishCloseoutRun(bgCtx, ports.CloseoutRunFinish{
			RunID:         runID,
			Status:        status,
			ErrorMessage:  errMessage,
			ProposedCount: result.ProposedCount,
			AppliedCount:  applied,
			FinishedAt:    time.Now().UTC(),
		})
	}
	defer func() {
		if rec := recover(); rec != nil {
			finishBackground("failed", fmt.Sprintf("panic: %v", rec), result.AppliedCount)
			err = fmt.Errorf("closeout panicked: %v", rec)
		}
	}()

	proposed, listErr := s.listCloseoutCandidates(ctx, selector)
	if listErr != nil {
		finishBackground("failed", listErr.Error(), 0)
		return nil, fmt.Errorf("list closeout candidates: %w", listErr)
	}
	result.Proposed = proposed
	result.ProposedCount = len(proposed)

	if req.DryRun {
		finishErr := s.closeoutStore.FinishCloseoutRun(context.WithoutCancel(ctx), ports.CloseoutRunFinish{
			RunID:         runID,
			Status:        "succeeded",
			ProposedCount: result.ProposedCount,
			AppliedCount:  0,
			FinishedAt:    time.Now().UTC(),
		})
		if finishErr != nil {
			return result, fmt.Errorf("finish closeout_run %q: %w", runID, finishErr)
		}
		return result, nil
	}

	applied := 0
	for start := 0; start < len(proposed); start += batchSize {
		end := start + batchSize
		if end > len(proposed) {
			end = len(proposed)
		}
		batch := proposed[start:end]
		result.BatchSizes = append(result.BatchSizes, len(batch))
		if cerr := ctx.Err(); cerr != nil {
			finishBackground("failed", cerr.Error(), applied)
			result.AppliedCount = applied
			return result, cerr
		}
		for _, candidate := range batch {
			if applyErr := s.tombstoneOneFinding(ctx, candidate, runID, actor, reason); applyErr != nil {
				result.BatchErrors = append(result.BatchErrors, applyErr)
				finishBackground("failed", applyErr.Error(), applied)
				result.AppliedCount = applied
				return result, applyErr
			}
			applied++
		}
	}
	result.AppliedCount = applied
	finishErr := s.closeoutStore.FinishCloseoutRun(context.WithoutCancel(ctx), ports.CloseoutRunFinish{
		RunID:         runID,
		Status:        "succeeded",
		ProposedCount: result.ProposedCount,
		AppliedCount:  applied,
		FinishedAt:    time.Now().UTC(),
	})
	if finishErr != nil {
		return result, fmt.Errorf("finish closeout_run %q: %w", runID, finishErr)
	}
	return result, nil
}

func (s *Service) tombstoneOneFinding(ctx context.Context, finding *ports.FindingRecord, runID, actor, reason string) error {
	if finding == nil {
		return errors.New("finding is required")
	}
	findingID := strings.TrimSpace(finding.ID)
	if findingID == "" {
		return errors.New("finding id is required")
	}
	priorStatus := strings.TrimSpace(finding.Status)
	if priorStatus == "" {
		priorStatus = findingStatusOpen
	}
	anchorURI := findingTombstoneAnchorURI(finding)
	now := time.Now().UTC()
	updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
		FindingID: findingID,
		Status:    findingStatusResolved,
		Reason:    reason,
		UpdatedAt: now,
		Tombstone: &ports.FindingTombstoneApply{
			By:           actor,
			Reason:       reason,
			RunID:        runID,
			PriorStatus:  priorStatus,
			TombstonedAt: now,
		},
	})
	if err != nil {
		return fmt.Errorf("tombstone finding %q: %w", findingID, err)
	}
	if err := s.tombstoneEventStore.InsertFindingTombstoneEvent(ctx, ports.FindingTombstoneEvent{
		FindingID:    findingID,
		TenantID:     strings.TrimSpace(finding.TenantID),
		RuleID:       strings.TrimSpace(finding.RuleID),
		AnchorURI:    anchorURI,
		PriorStatus:  priorStatus,
		Reason:       reason,
		Actor:        actor,
		RunID:        runID,
		TombstonedAt: now,
	}); err != nil {
		return fmt.Errorf("audit finding %q tombstone: %w", findingID, err)
	}
	tenantID, sourceID := findingGraphScope(updated)
	snapshot := findingWorkflowSnapshot(updated, tenantID, sourceID)
	event, err := workflowevents.NewFindingTombstonedEvent(workflowevents.FindingTombstoned{
		Finding:      snapshot,
		PriorStatus:  priorStatus,
		Reason:       reason,
		Actor:        actor,
		RunID:        runID,
		TombstonedAt: now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("build finding tombstoned event for %q: %w", findingID, err)
	}
	if err := s.recordAndProjectWorkflowEvent(ctx, event); err != nil {
		return fmt.Errorf("emit finding tombstoned event for %q: %w", findingID, err)
	}
	return nil
}

func (s *Service) listCloseoutCandidates(ctx context.Context, selector CloseoutSelector) ([]*ports.FindingRecord, error) {
	ruleIDs := expandCloseoutRuleIDs(selector)
	seen := map[string]struct{}{}
	var out []*ports.FindingRecord
	cutoff := time.Time{}
	if selector.OlderThan > 0 {
		cutoff = time.Now().UTC().Add(-selector.OlderThan)
	}
	for _, ruleID := range ruleIDs {
		for _, status := range selector.Statuses {
			results, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
				TenantID: strings.TrimSpace(selector.TenantID),
				RuleID:   strings.TrimSpace(ruleID),
				Status:   strings.TrimSpace(status),
			})
			if err != nil {
				return nil, fmt.Errorf("list findings for rule %q status %q: %w", ruleID, status, err)
			}
			for _, finding := range results {
				if finding == nil {
					continue
				}
				key := strings.TrimSpace(finding.ID)
				if _, ok := seen[key]; ok {
					continue
				}
				if finding.Tombstoned {
					continue
				}
				if !cutoff.IsZero() && finding.LastObservedAt.After(cutoff) {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, finding)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].ID) < strings.TrimSpace(out[j].ID)
	})
	return out, nil
}

func expandCloseoutRuleIDs(selector CloseoutSelector) []string {
	seen := map[string]struct{}{}
	ordered := make([]string, 0, len(selector.RuleIDs))
	for _, id := range selector.RuleIDs {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		ordered = append(ordered, trimmed)
	}
	if len(selector.Sources) == 0 {
		return ordered
	}
	sourceSet := make(map[string]struct{}, len(selector.Sources))
	for _, src := range selector.Sources {
		trimmed := strings.TrimSpace(src)
		if trimmed == "" {
			continue
		}
		sourceSet[trimmed] = struct{}{}
	}
	if len(sourceSet) == 0 {
		return ordered
	}
	matched := []string{}
	for ruleID, sourceID := range BuiltinRuleSourceIDs() {
		if _, ok := sourceSet[strings.TrimSpace(sourceID)]; !ok {
			continue
		}
		trimmed := strings.TrimSpace(ruleID)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		matched = append(matched, trimmed)
	}
	sort.Strings(matched)
	return append(ordered, matched...)
}

func resolveCloseoutSelector(in CloseoutSelector) CloseoutSelector {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	if len(out.Statuses) == 0 {
		out.Statuses = []string{findingStatusOpen}
	} else {
		normalized := make([]string, 0, len(out.Statuses))
		for _, status := range out.Statuses {
			trimmed := strings.TrimSpace(status)
			if trimmed != "" {
				normalized = append(normalized, trimmed)
			}
		}
		if len(normalized) == 0 {
			normalized = []string{findingStatusOpen}
		}
		out.Statuses = normalized
	}
	if len(out.RuleIDs) > 0 {
		ruleIDs := make([]string, 0, len(out.RuleIDs))
		for _, ruleID := range out.RuleIDs {
			trimmed := strings.TrimSpace(ruleID)
			if trimmed != "" {
				ruleIDs = append(ruleIDs, trimmed)
			}
		}
		out.RuleIDs = ruleIDs
	}
	if len(out.Sources) > 0 {
		sources := make([]string, 0, len(out.Sources))
		for _, source := range out.Sources {
			trimmed := strings.TrimSpace(source)
			if trimmed != "" {
				sources = append(sources, trimmed)
			}
		}
		out.Sources = sources
	}
	return out
}

func findingTombstoneAnchorURI(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	if primary := findingPrimaryResourceURN(finding); primary != "" {
		return primary
	}
	tenantID, _ := findingGraphScope(finding)
	return findingGraphFindingURN(tenantID, finding)
}
