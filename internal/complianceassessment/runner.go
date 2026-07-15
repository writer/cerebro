package complianceassessment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const resultChunkSize = 250

func (s *Service) Runner() platformjobs.Runner {
	return func(ctx context.Context, job *ports.Job, jobs *platformjobs.Service) (map[string]any, map[string]string, error) {
		if job == nil {
			return nil, nil, ErrRunNotFound
		}
		runID, _ := job.Payload["run_id"].(string)
		run, err := s.store.GetRun(ctx, job.TenantID, strings.TrimSpace(runID))
		if err != nil {
			return nil, nil, err
		}
		result := map[string]any{"run_id": run.ID, "state": run.State}
		refs := map[string]string{"assessment_run": run.ID}
		switch run.State {
		case RunComplete:
			return result, refs, nil
		case RunFailed:
			failureCode := strings.TrimSpace(run.FailureCode)
			if failureCode == "" {
				failureCode = "unspecified"
			}
			return result, refs, fmt.Errorf("assessment run %q is failed: %s", run.ID, failureCode)
		case RunCancelled, RunSuperseded:
			if jobs == nil {
				return result, refs, errors.New("assessment job runtime is unavailable for terminal reconciliation")
			}
			if _, err := jobs.Cancel(context.WithoutCancel(ctx), job.ID); err != nil {
				return result, refs, fmt.Errorf("reconcile terminal assessment job: %w", err)
			}
			return result, refs, nil
		}
		plan, err := s.store.GetPlan(ctx, run.TenantID, run.PlanRevisionID)
		if err != nil {
			return nil, nil, err
		}
		if plan.Status != PlanPublished || plan.RevisionID != run.PlanRevisionID {
			return nil, nil, s.failRun(ctx, run, "plan_unavailable")
		}
		if s.collector == nil {
			return nil, nil, s.failRun(ctx, run, "collector_unavailable")
		}
		if run.State == RunQueued {
			expectedVersion := run.Version
			run.State = RunCollecting
			run.Version++
			if err := s.appendRunDurably(ctx, workflowevents.EventKindComplianceInputManifestRecorded, "collection_started", run, expectedVersion); err != nil {
				return nil, nil, err
			}
		} else if run.State != RunCollecting && run.State != RunEvaluating {
			return nil, nil, s.failRun(ctx, run, "invalid_run_state")
		}
		manifest, results, collectErr := s.collector.Collect(ctx, run)
		if collectErr != nil {
			if errors.Is(collectErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return nil, nil, s.cancelRun(context.WithoutCancel(ctx), run)
			}
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "collection_failed")
		}
		manifest = NormalizeManifest(manifest)
		if err := ValidateInputManifest(manifest); err != nil || !manifestComplete(manifest) {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "collection_incomplete")
		}
		if err := validateCollectionBinding(plan, run, manifest); err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "collection_mismatch")
		}
		inputHash, err := CanonicalManifestDigest(manifest)
		if err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "input_hash_failed")
		}
		if run.State == RunEvaluating {
			if run.InputManifest == nil || run.InputHash == "" || run.InputHash != inputHash {
				return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "collection_changed")
			}
		} else {
			expectedVersion := run.Version
			run.State = RunEvaluating
			run.Version++
			run.InputManifest = &manifest
			run.InputHash = inputHash
			run.CollectionBarrierAt = CanonicalTime(s.now())
			if err := s.appendRunDurably(ctx, workflowevents.EventKindComplianceInputManifestRecorded, "input_manifest_recorded", run, expectedVersion); err != nil {
				return nil, nil, err
			}
		}
		results, err = canonicalResultSet(results)
		if err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "result_invalid")
		}
		if err := validateResultCoverage(plan, results); err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "result_scope_mismatch")
		}
		resultHash, err := CanonicalResultSetDigest(results)
		if err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "result_hash_failed")
		}
		if err := s.appendResultChunks(ctx, run, results); err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "result_projection_failed")
		}
		expectedVersion := run.Version
		run.State = RunComplete
		run.Version++
		run.AutomatedResultHash = resultHash
		run.ResultCount = uint64(len(results))
		run.CompletedAt = CanonicalTime(s.now())
		if err := s.appendRunDurably(ctx, workflowevents.EventKindComplianceAssessmentCompleted, "assessment_completed", run, expectedVersion); err != nil {
			return nil, nil, err
		}
		return map[string]any{"run_id": run.ID, "state": run.State, "result_count": run.ResultCount}, map[string]string{"assessment_run": run.ID}, nil
	}
}

func (s *Service) appendRunDurably(ctx context.Context, kind, operation string, run AssessmentRun, expectedVersion uint64) error {
	const retryInterval = 100 * time.Millisecond
	wantDigest, err := semanticHash(run)
	if err != nil {
		return err
	}
	for {
		err = s.appendRun(ctx, kind, operation, run, expectedVersion)
		if err == nil {
			return nil
		}
		if current, getErr := s.store.GetRun(ctx, run.TenantID, run.ID); getErr == nil {
			if currentDigest, hashErr := semanticHash(current); hashErr == nil && currentDigest == wantDigest {
				return nil
			}
		}
		if errors.Is(err, ErrAssessmentConflict) {
			return err
		}
		timer := time.NewTimer(retryInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func validateCollectionBinding(plan AssessmentPlanRevision, run AssessmentRun, manifest InputManifest) error {
	if manifest.ProgramID != run.ProgramID || manifest.ScopeRevisionID != run.ScopeRevisionID || manifest.PlanRevisionID != run.PlanRevisionID ||
		!manifest.PeriodStart.Equal(run.PeriodStart) || !manifest.PeriodEnd.Equal(run.PeriodEnd) {
		return ErrInvalidManifest
	}
	scopeDigest, err := semanticHash(plan.Scope)
	if err != nil || manifest.RequestedScopeDigest != scopeDigest {
		return ErrInvalidManifest
	}
	objectiveDigest, err := semanticHash(plan.Scope.ObjectiveIDs)
	if err != nil || manifest.ResolvedObjectiveSetDigest != objectiveDigest {
		return ErrInvalidManifest
	}
	for _, revision := range manifest.Revisions {
		if revision.Kind == "plan" && revision.ID == plan.ID && revision.RevisionID == plan.RevisionID && revision.Version == plan.Version && revision.Digest == plan.ContentDigest {
			return nil
		}
	}
	return ErrInvalidManifest
}

func validateResultCoverage(plan AssessmentPlanRevision, results []ObjectiveResult) error {
	expected := normalizedStrings(plan.Scope.ObjectiveIDs)
	actual := make([]string, 0, len(results))
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		if _, exists := seen[result.ObjectiveID]; exists {
			return ErrInvalidResult
		}
		seen[result.ObjectiveID] = struct{}{}
		actual = append(actual, result.ObjectiveID)
	}
	actual = normalizedStrings(actual)
	if len(actual) != len(expected) {
		return ErrInvalidResult
	}
	for index := range expected {
		if expected[index] != actual[index] {
			return ErrInvalidResult
		}
	}
	return nil
}

func (s *Service) appendResultChunks(ctx context.Context, run AssessmentRun, results []ObjectiveResult) error {
	previous := ""
	for start := 0; start < len(results); start += resultChunkSize {
		end := start + resultChunkSize
		if end > len(results) {
			end = len(results)
		}
		chunkResults := append([]ObjectiveResult(nil), results[start:end]...)
		payload, err := canonicalBytes(chunkResults)
		if err != nil {
			return err
		}
		chunkCount, err := boundedChunkCount(len(chunkResults))
		if err != nil {
			return err
		}
		chunk := ResultChunk{
			RunID: run.ID, Sequence: uint32(start/resultChunkSize + 1),
			FirstResultID: chunkResults[0].ID, LastResultID: chunkResults[len(chunkResults)-1].ID,
			Count: chunkCount, PreviousDigest: previous,
			Digest: digestResultChunkPayload(previous, payload), Results: chunkResults,
		}
		encoded, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
			Kind: workflowevents.EventKindComplianceResultChunkRecorded, TenantID: run.TenantID,
			AggregateType: "assessment_result_chunk", AggregateID: run.ID,
			RevisionID: fmt.Sprintf("%s-chunk-%06d", run.ID, chunk.Sequence), AggregateVersion: int64(chunk.Sequence),
			Operation: "result_chunk_recorded", ContentDigest: chunk.Digest, PayloadJSON: string(encoded),
			ActorID: run.RequestedBy, RecordedAt: CanonicalTime(s.now()).Format(time.RFC3339Nano),
		})
		if err != nil {
			return err
		}
		if err := s.log.Append(ctx, event); err != nil {
			return fmt.Errorf("append result chunk: %w", err)
		}
		if err := s.store.ApplyResultChunk(ctx, event.GetId(), run.TenantID, chunk); err != nil {
			return fmt.Errorf("project result chunk: %w", err)
		}
		previous = chunk.Digest
	}
	return nil
}

func digestResultChunkPayload(previous string, payload []byte) string {
	digest := sha256.Sum256(append([]byte(previous+"\n"), payload...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func boundedChunkCount(value int) (uint32, error) {
	if value < 1 || value > resultChunkSize {
		return 0, fmt.Errorf("result chunk count %d is out of bounds", value)
	}
	return uint32(value), nil
}

func (s *Service) failRun(ctx context.Context, run AssessmentRun, code string) error {
	expectedVersion := run.Version
	run.State = RunFailed
	run.Version++
	run.FailureCode = code
	run.CompletedAt = CanonicalTime(s.now())
	if err := s.appendRunDurably(ctx, workflowevents.EventKindComplianceAssessmentCompleted, "assessment_failed", run, expectedVersion); err != nil {
		return err
	}
	return fmt.Errorf("assessment run failed: %s", code)
}

func (s *Service) cancelRun(ctx context.Context, run AssessmentRun) error {
	expectedVersion := run.Version
	run.State = RunCancelled
	run.Version++
	run.FailureCode = "cancelled"
	run.CompletedAt = CanonicalTime(s.now())
	if err := s.appendRunDurably(ctx, workflowevents.EventKindComplianceAssessmentCancelled, "assessment_cancelled", run, expectedVersion); err != nil {
		return err
	}
	return context.Canceled
}

func manifestComplete(manifest InputManifest) bool {
	if len(manifest.Receipts) == 0 {
		return false
	}
	for _, receipt := range manifest.Receipts {
		if receipt.Completeness != CollectionComplete || receipt.ExpectedTotal == nil || receipt.RawCount < receipt.Included+receipt.Excluded {
			return false
		}
	}
	return true
}
