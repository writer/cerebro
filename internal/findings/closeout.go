package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const (
	defaultCloseoutBatchSize = 1000
	// closeoutStaleRunCutoff bounds how long a status='running' closeout_run row
	// remains protected before TombstoneFindingsBulk treats it as a stale lock
	// (operator crashed, container killed, etc.) and recycles it on the next run.
	// CROSS-008 mandates the singleton --apply guard is held at both this CLI
	// run-row layer and the GitHub Actions concurrency layer; the 1h cutoff makes
	// the lock self-healing without manual SQL intervention.
	closeoutStaleRunCutoff = time.Hour
	// closeoutHeartbeatInterval is intentionally below closeoutStaleRunCutoff/3
	// so long-running apply batches refresh closeout_run before a second
	// invocation can mistake them for abandoned work.
	closeoutHeartbeatInterval = closeoutStaleRunCutoff / 4
)

// ErrCloseoutAnotherRunning indicates that a concurrent closeout run was rejected.
var ErrCloseoutAnotherRunning = errors.New("another closeout run is in flight")

// ErrCloseoutInvalidRequest indicates one or more required CloseoutRequest fields are missing.
var ErrCloseoutInvalidRequest = errors.New("invalid closeout request")

// ErrCloseoutUnavailable indicates that the bulk tombstone primitive is missing a dependency.
var ErrCloseoutUnavailable = errors.New("closeout primitive is unavailable")

// ErrCloseoutRunFailed indicates that a duplicate run_id resolved to a previously failed closeout_run.
var ErrCloseoutRunFailed = errors.New("closeout run failed")

// CloseoutRunFailedError preserves the failed closeout_run metadata returned
// when an idempotency retry reloads a run whose persisted status is "failed".
type CloseoutRunFailedError struct {
	RunID        string
	ErrorMessage string
}

func (e *CloseoutRunFailedError) Error() string {
	if e == nil {
		return ErrCloseoutRunFailed.Error()
	}
	runID := strings.TrimSpace(e.RunID)
	errorMessage := strings.TrimSpace(e.ErrorMessage)
	switch {
	case runID != "" && errorMessage != "":
		return fmt.Sprintf("%s: run_id %q: %s", ErrCloseoutRunFailed, runID, errorMessage)
	case runID != "":
		return fmt.Sprintf("%s: run_id %q", ErrCloseoutRunFailed, runID)
	case errorMessage != "":
		return fmt.Sprintf("%s: %s", ErrCloseoutRunFailed, errorMessage)
	default:
		return ErrCloseoutRunFailed.Error()
	}
}

func (e *CloseoutRunFailedError) Unwrap() error {
	return ErrCloseoutRunFailed
}

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

// CloseoutBatchEvent carries per-batch progress emitted by TombstoneFindingsBulk
// when the caller wires a BatchLogger. CloudWatch consumers (VAL-CLI-010)
// require one log line per batch with pinned keys.
type CloseoutBatchEvent struct {
	RunID      string
	Actor      string
	Env        string
	BatchIndex int
	BatchSize  int
}

// CloseoutBatchLogger receives one CloseoutBatchEvent per successfully attempted
// batch (i.e. each entry recorded in result.BatchSizes). The CLI populates this
// to emit `closeout.batch` structured log lines so the run boundary is observable
// in CloudWatch without leaking through the structural-lint err-string ban.
type CloseoutBatchLogger func(event CloseoutBatchEvent)

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
	BatchLogger  CloseoutBatchLogger
}

// CloseoutResult reports the observable outcome of one TombstoneFindingsBulk invocation.
//
// For a newly executed run, AppliedCount reflects committed candidates only:
// when a batch fails mid-way the value is the number of rows successfully
// tombstoned in earlier batches. For a duplicate run_id, the result is reloaded
// from the persisted closeout_run row and the counts reflect that prior run.
// PerRule mirrors committed candidates for newly executed runs.
type CloseoutResult struct {
	RunID         string
	Proposed      []*ports.FindingRecord
	ProposedCount int
	AppliedCount  int
	BatchSizes    []int
	BatchErrors   []error
	PerRule       []CloseoutPerRuleCount
	// S3SummaryKey is populated when a caller reloads an existing closeout_run
	// row so the CLI can report the persisted audit object without overwriting it.
	S3SummaryKey string
}

func (s *Service) closeoutResultFromRunRecord(ctx context.Context, run *ports.CloseoutRunRecord) (*CloseoutResult, error) {
	if run == nil {
		return &CloseoutResult{}, nil
	}
	result := &CloseoutResult{
		RunID:         strings.TrimSpace(run.RunID),
		ProposedCount: run.ProposedCount,
		AppliedCount:  run.AppliedCount,
		S3SummaryKey:  strings.TrimSpace(run.S3SummaryKey),
	}
	var failedErr error
	if strings.TrimSpace(run.Status) == "failed" {
		errorMessage := strings.TrimSpace(run.ErrorMessage)
		failedErr = &CloseoutRunFailedError{
			RunID:        result.RunID,
			ErrorMessage: errorMessage,
		}
		if errorMessage != "" {
			result.BatchErrors = append(result.BatchErrors, failedErr)
		}
	}
	if run.AppliedCount <= 0 || s == nil || s.store == nil {
		return result, failedErr
	}
	proposed, perRule, err := s.reloadCloseoutAppliedFindings(ctx, run)
	if err != nil {
		if failedErr != nil {
			return result, errors.Join(failedErr, err)
		}
		return nil, err
	}
	result.Proposed = proposed
	result.PerRule = perRule
	return result, failedErr
}

func (s *Service) closeoutHeartbeatEvery() time.Duration {
	if s != nil && s.closeoutHeartbeatInterval > 0 {
		return s.closeoutHeartbeatInterval
	}
	return closeoutHeartbeatInterval
}

func (s *Service) startCloseoutRunHeartbeat(ctx context.Context, runID string) func() {
	if s == nil || s.closeoutStore == nil || strings.TrimSpace(runID) == "" {
		return func() {}
	}
	interval := s.closeoutHeartbeatEvery()
	if interval <= 0 {
		return func() {}
	}
	heartbeatCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = s.closeoutStore.RefreshCloseoutRunHeartbeat(heartbeatCtx, runID, time.Now().UTC())
			case <-heartbeatCtx.Done():
				return
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func (s *Service) reloadCloseoutAppliedFindings(ctx context.Context, run *ports.CloseoutRunRecord) ([]*ports.FindingRecord, []CloseoutPerRuleCount, error) {
	if run == nil {
		return nil, nil, nil
	}
	var selector CloseoutSelector
	if len(run.SelectorJSON) > 0 {
		if err := json.Unmarshal(run.SelectorJSON, &selector); err != nil {
			return nil, nil, fmt.Errorf("decode closeout_run %q selector_json: %w", strings.TrimSpace(run.RunID), err)
		}
	}
	selector = resolveCloseoutSelector(selector)
	if selector.TenantID == "" || len(selector.RuleIDs) == 0 {
		return nil, nil, nil
	}
	counts := map[string]int{}
	seen := map[string]struct{}{}
	var proposed []*ports.FindingRecord
	for _, ruleID := range expandCloseoutRuleIDs(selector) {
		records, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
			TenantID: selector.TenantID,
			RuleID:   ruleID,
			Status:   findingStatusResolved,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("reload applied closeout findings for rule %q: %w", ruleID, err)
		}
		for _, record := range records {
			if record == nil || !record.Tombstoned || strings.TrimSpace(record.TombstonedRunID) != strings.TrimSpace(run.RunID) {
				continue
			}
			id := strings.TrimSpace(record.ID)
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			proposed = append(proposed, record)
			counts[strings.TrimSpace(record.RuleID)]++
		}
	}
	sort.SliceStable(proposed, func(i, j int) bool {
		return strings.TrimSpace(proposed[i].ID) < strings.TrimSpace(proposed[j].ID)
	})
	return proposed, sortPerRuleApplied(counts), nil
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
//   - is idempotent on RunID (duplicate run_id reloads the persisted run without mutation),
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
	if len(selector.RuleIDs) == 0 {
		return nil, fmt.Errorf("%w: at least one rule id is required", ErrCloseoutInvalidRequest)
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
	insertRow := ports.CloseoutRunInsert{
		RunID:        runID,
		Actor:        actor,
		ChangeTicket: strings.TrimSpace(req.ChangeTicket),
		SelectorJSON: selectorJSON,
		DryRun:       req.DryRun,
		StartedAt:    startedAt,
		HeartbeatAt:  startedAt,
	}
	insertErr := s.closeoutStore.InsertCloseoutRun(ctx, insertRow)
	if insertErr != nil && errors.Is(insertErr, ports.ErrCloseoutRunInFlight) {
		cutoff := time.Now().UTC().Add(-closeoutStaleRunCutoff)
		broken, breakErr := s.closeoutStore.BreakStaleRunningCloseoutRuns(ctx, cutoff, "stale closeout_run reclaimed by run "+runID)
		if breakErr == nil && broken > 0 {
			insertErr = s.closeoutStore.InsertCloseoutRun(ctx, insertRow)
		}
	}
	if insertErr != nil {
		if errors.Is(insertErr, ports.ErrCloseoutRunInFlight) {
			return nil, fmt.Errorf("%w: %s", ErrCloseoutAnotherRunning, insertErr.Error())
		}
		if errors.Is(insertErr, ports.ErrCloseoutRunAlreadyExists) {
			existing, getErr := s.closeoutStore.GetCloseoutRun(context.WithoutCancel(ctx), runID)
			if getErr != nil {
				return nil, fmt.Errorf("load existing closeout_run %q: %w", runID, getErr)
			}
			if strings.TrimSpace(existing.Status) == "failed" {
				initialProposed, initialPerRule, reloadErr := s.reloadCloseoutAppliedFindings(context.WithoutCancel(ctx), existing)
				if reloadErr != nil {
					return nil, reloadErr
				}
				initialApplied := closeoutPerRuleAppliedTotal(initialPerRule)
				if initialApplied == 0 {
					initialApplied = existing.AppliedCount
				}
				initialPerRule = closeoutPerRuleWithFallback(initialPerRule, selector, initialApplied)
				retryErr := s.closeoutStore.RetryFailedCloseoutRun(ctx, runID, time.Now().UTC())
				if retryErr != nil && errors.Is(retryErr, ports.ErrCloseoutRunInFlight) {
					cutoff := time.Now().UTC().Add(-closeoutStaleRunCutoff)
					broken, breakErr := s.closeoutStore.BreakStaleRunningCloseoutRuns(ctx, cutoff, "stale closeout_run reclaimed by retry "+runID)
					if breakErr == nil && broken > 0 {
						retryErr = s.closeoutStore.RetryFailedCloseoutRun(ctx, runID, time.Now().UTC())
					}
				}
				if retryErr != nil {
					if errors.Is(retryErr, ports.ErrCloseoutRunInFlight) {
						return nil, fmt.Errorf("%w: %s", ErrCloseoutAnotherRunning, retryErr.Error())
					}
					if errors.Is(retryErr, ports.ErrCloseoutRunAlreadyExists) {
						current, currentErr := s.closeoutStore.GetCloseoutRun(context.WithoutCancel(ctx), runID)
						if currentErr != nil {
							return nil, fmt.Errorf("load existing closeout_run %q after retry race: %w", runID, currentErr)
						}
						return s.closeoutResultFromRunRecord(context.WithoutCancel(ctx), current)
					}
					return nil, fmt.Errorf("retry closeout_run %q: %w", runID, retryErr)
				}
				return s.executeCloseoutRun(ctx, req, selector, runID, actor, reason, batchSize, initialApplied, existing.ProposedCount, initialPerRule, initialProposed, true)
			}
			return s.closeoutResultFromRunRecord(context.WithoutCancel(ctx), existing)
		}
		return nil, fmt.Errorf("insert closeout_run %q: %w", runID, insertErr)
	}

	return s.executeCloseoutRun(ctx, req, selector, runID, actor, reason, batchSize, 0, 0, nil, nil, true)
}

func (s *Service) executeCloseoutRun(ctx context.Context, req CloseoutRequest, selector CloseoutSelector, runID, actor, reason string, batchSize int, initialApplied int, initialProposed int, initialPerRule []CloseoutPerRuleCount, initialProposedRecords []*ports.FindingRecord, heartbeat bool) (result *CloseoutResult, err error) {
	result = &CloseoutResult{RunID: runID, AppliedCount: initialApplied, ProposedCount: initialProposed}
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
	if heartbeat && !req.DryRun {
		stopHeartbeat := s.startCloseoutRunHeartbeat(ctx, runID)
		defer stopHeartbeat()
	}

	proposed, listErr := s.listCloseoutCandidates(ctx, selector)
	if listErr != nil {
		finishBackground("failed", listErr.Error(), initialApplied)
		return nil, fmt.Errorf("list closeout candidates: %w", listErr)
	}
	result.Proposed = append(append([]*ports.FindingRecord(nil), initialProposedRecords...), proposed...)
	result.ProposedCount = maxInt(initialProposed, initialApplied+len(proposed))

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

	applied := initialApplied
	perRuleApplied := closeoutPerRuleCountsMap(initialPerRule)
	for start, batchIndex := 0, 0; start < len(proposed); start, batchIndex = start+batchSize, batchIndex+1 {
		end := start + batchSize
		if end > len(proposed) {
			end = len(proposed)
		}
		batch := proposed[start:end]
		result.BatchSizes = append(result.BatchSizes, len(batch))
		if req.BatchLogger != nil {
			req.BatchLogger(CloseoutBatchEvent{
				RunID:      runID,
				Actor:      actor,
				Env:        strings.TrimSpace(req.Environment),
				BatchIndex: batchIndex,
				BatchSize:  len(batch),
			})
		}
		if cerr := ctx.Err(); cerr != nil {
			result.PerRule = sortPerRuleApplied(perRuleApplied)
			finishBackground("failed", cerr.Error(), applied)
			result.AppliedCount = applied
			return result, cerr
		}
		for _, candidate := range batch {
			appliedCandidate, applyErr := s.tombstoneOneFinding(ctx, candidate, runID, actor, reason)
			if appliedCandidate {
				applied++
				perRuleApplied[strings.TrimSpace(candidate.RuleID)]++
			}
			if applyErr != nil {
				result.BatchErrors = append(result.BatchErrors, applyErr)
				result.PerRule = sortPerRuleApplied(perRuleApplied)
				finishBackground("failed", applyErr.Error(), applied)
				result.AppliedCount = applied
				return result, applyErr
			}
		}
	}
	result.AppliedCount = applied
	result.PerRule = sortPerRuleApplied(perRuleApplied)
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

func closeoutPerRuleCountsMap(counts []CloseoutPerRuleCount) map[string]int {
	out := map[string]int{}
	for _, count := range counts {
		ruleID := strings.TrimSpace(count.RuleID)
		if ruleID == "" || count.Applied <= 0 {
			continue
		}
		out[ruleID] += count.Applied
	}
	return out
}

func closeoutPerRuleAppliedTotal(counts []CloseoutPerRuleCount) int {
	total := 0
	for _, count := range counts {
		if count.Applied > 0 {
			total += count.Applied
		}
	}
	return total
}

func closeoutPerRuleWithFallback(counts []CloseoutPerRuleCount, selector CloseoutSelector, applied int) []CloseoutPerRuleCount {
	if len(counts) != 0 || applied <= 0 {
		return counts
	}
	ruleIDs := expandCloseoutRuleIDs(selector)
	if len(ruleIDs) != 1 {
		return counts
	}
	return []CloseoutPerRuleCount{{RuleID: ruleIDs[0], Applied: applied}}
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func (s *Service) tombstoneOneFinding(ctx context.Context, finding *ports.FindingRecord, runID, actor, reason string) (bool, error) {
	if finding == nil {
		return false, errors.New("finding is required")
	}
	findingID := strings.TrimSpace(finding.ID)
	if findingID == "" {
		return false, errors.New("finding id is required")
	}
	expectedStatus := normalizedFindingStatus(finding.Status)
	if atomicStore, ok := s.store.(ports.FindingTombstoneAtomicStore); ok {
		now := time.Now().UTC()
		atomicResult, err := atomicStore.TombstoneFindingAtomic(ctx, ports.FindingTombstoneAtomicRequest{
			FindingID:      findingID,
			ExpectedStatus: expectedStatus,
			Status:         findingStatusResolved,
			Reason:         reason,
			Actor:          actor,
			RunID:          runID,
			AnchorURI:      findingTombstoneAnchorURI(finding),
			EventIDs:       append([]string(nil), finding.EventIDs...),
			UpdatedAt:      now,
			EmitWorkflowEvent: func(ctx context.Context, updated *ports.FindingRecord, priorStatus string, tombstonedAt time.Time) error {
				return s.emitFindingTombstonedWorkflow(ctx, updated, priorStatus, reason, actor, runID, tombstonedAt)
			},
		})
		if err != nil {
			return atomicResult != nil && atomicResult.Applied, fmt.Errorf("tombstone finding %q: %w", findingID, err)
		}
		return atomicResult != nil && atomicResult.Applied, nil
	}
	live, err := s.store.GetFinding(ctx, findingID)
	if err != nil {
		return false, fmt.Errorf("reload finding %q before tombstone: %w", findingID, err)
	}
	if live == nil || live.Tombstoned {
		return false, nil
	}
	priorStatus := normalizedFindingStatus(live.Status)
	if expectedStatus != "" && priorStatus != expectedStatus {
		return false, nil
	}
	anchorURI := findingTombstoneAnchorURI(live)
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
		return false, fmt.Errorf("tombstone finding %q: %w", findingID, err)
	}
	if err := s.tombstoneEventStore.InsertFindingTombstoneEvent(ctx, ports.FindingTombstoneEvent{
		FindingID:    findingID,
		TenantID:     strings.TrimSpace(live.TenantID),
		RuleID:       strings.TrimSpace(live.RuleID),
		AnchorURI:    anchorURI,
		PriorStatus:  priorStatus,
		Reason:       reason,
		Actor:        actor,
		RunID:        runID,
		TombstonedAt: now,
	}); err != nil {
		return false, fmt.Errorf("audit finding %q tombstone: %w", findingID, err)
	}
	if err := s.emitFindingTombstonedWorkflow(ctx, updated, priorStatus, reason, actor, runID, now); err != nil {
		return true, err
	}
	return true, nil
}

func (s *Service) emitFindingTombstonedWorkflow(ctx context.Context, updated *ports.FindingRecord, priorStatus, reason, actor, runID string, tombstonedAt time.Time) error {
	if updated == nil {
		return errors.New("updated finding is required")
	}
	findingID := strings.TrimSpace(updated.ID)
	tenantID, sourceID := findingGraphScope(updated)
	snapshot := findingWorkflowSnapshot(updated, tenantID, sourceID)
	event, err := workflowevents.NewFindingTombstonedEvent(workflowevents.FindingTombstoned{
		Finding:      snapshot,
		PriorStatus:  priorStatus,
		Reason:       reason,
		Actor:        actor,
		RunID:        runID,
		TombstonedAt: tombstonedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("build finding tombstoned event for %q: %w", findingID, err)
	}
	if err := s.recordAndProjectWorkflowEvent(ctx, event); err != nil {
		return fmt.Errorf("emit finding tombstoned event for %q: %w", findingID, err)
	}
	return nil
}

func normalizedFindingStatus(status string) string {
	trimmed := strings.TrimSpace(status)
	if trimmed == "" {
		return findingStatusOpen
	}
	return trimmed
}

func (s *Service) listCloseoutCandidates(ctx context.Context, selector CloseoutSelector) ([]*ports.FindingRecord, error) {
	ruleIDs := expandCloseoutRuleIDs(selector)
	var anchorMatcher *regexp.Regexp
	if pattern := strings.TrimSpace(selector.AnchorURIRegex); pattern != "" {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile anchor_uri_regex %q: %w", pattern, err)
		}
		anchorMatcher = compiled
	}
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
				if anchorMatcher != nil && !anchorMatcher.MatchString(findingTombstoneAnchorURI(finding)) {
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
	sourceIDs := BuiltinRuleSourceIDs()
	narrowed := make([]string, 0, len(ordered))
	for _, ruleID := range ordered {
		sourceID, ok := sourceIDs[ruleID]
		if !ok {
			continue
		}
		if _, ok := sourceSet[strings.TrimSpace(sourceID)]; !ok {
			continue
		}
		narrowed = append(narrowed, ruleID)
	}
	return narrowed
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
	out.AnchorURIRegex = strings.TrimSpace(out.AnchorURIRegex)
	return out
}

func sortPerRuleApplied(counts map[string]int) []CloseoutPerRuleCount {
	out := make([]CloseoutPerRuleCount, 0, len(counts))
	for ruleID, applied := range counts {
		out = append(out, CloseoutPerRuleCount{RuleID: ruleID, Applied: applied})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RuleID < out[j].RuleID
	})
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
