package complianceassessment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	platformjobs "github.com/writer/cerebro/internal/jobs"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const resultChunkSize = 250

func sortResults(results []ObjectiveResult) {
	sort.Slice(results, func(i, j int) bool {
		left, right := results[i], results[j]
		return left.ControlRef.FrameworkID+"\x00"+left.ControlRef.ControlID+"\x00"+left.ObjectiveID+"\x00"+left.ID <
			right.ControlRef.FrameworkID+"\x00"+right.ControlRef.ControlID+"\x00"+right.ObjectiveID+"\x00"+right.ID
	})
}

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
		if s.collector == nil {
			return nil, nil, s.failRun(ctx, run, "collector_unavailable")
		}
		expectedVersion := run.Version
		run.State = RunCollecting
		run.Version++
		if err := s.appendRun(ctx, workflowevents.EventKindComplianceInputManifestRecorded, "collection_started", run, expectedVersion); err != nil {
			return nil, nil, err
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
		inputHash, err := CanonicalManifestDigest(manifest)
		if err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "input_hash_failed")
		}
		expectedVersion = run.Version
		run.State = RunEvaluating
		run.Version++
		run.InputManifest = &manifest
		run.InputHash = inputHash
		run.CollectionBarrierAt = CanonicalTime(s.now())
		if err := s.appendRun(ctx, workflowevents.EventKindComplianceInputManifestRecorded, "input_manifest_recorded", run, expectedVersion); err != nil {
			return nil, nil, err
		}
		sortResults(results)
		for index := range results {
			results[index] = NormalizeResult(results[index])
			if err := ValidateObjectiveResult(results[index]); err != nil {
				return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "result_invalid")
			}
		}
		resultHash, err := s.appendResultChunks(ctx, run, results)
		if err != nil {
			return nil, nil, s.failRun(context.WithoutCancel(ctx), run, "result_projection_failed")
		}
		expectedVersion = run.Version
		run.State = RunComplete
		run.Version++
		run.AutomatedResultHash = resultHash
		run.ResultCount = uint64(len(results))
		run.CompletedAt = CanonicalTime(s.now())
		if err := s.appendRun(ctx, workflowevents.EventKindComplianceAssessmentCompleted, "assessment_completed", run, expectedVersion); err != nil {
			return nil, nil, err
		}
		return map[string]any{"run_id": run.ID, "state": run.State, "result_count": run.ResultCount}, map[string]string{"assessment_run": run.ID}, nil
	}
}

func (s *Service) appendResultChunks(ctx context.Context, run AssessmentRun, results []ObjectiveResult) (string, error) {
	previous := ""
	fullHash := sha256.New()
	for start := 0; start < len(results); start += resultChunkSize {
		end := start + resultChunkSize
		if end > len(results) {
			end = len(results)
		}
		chunkResults := append([]ObjectiveResult(nil), results[start:end]...)
		payload, err := canonicalBytes(chunkResults)
		if err != nil {
			return "", err
		}
		_, _ = fullHash.Write(payload)
		chunkCount, err := boundedChunkCount(len(chunkResults))
		if err != nil {
			return "", err
		}
		chunk := ResultChunk{
			RunID: run.ID, Sequence: uint32(start/resultChunkSize + 1),
			FirstResultID: chunkResults[0].ID, LastResultID: chunkResults[len(chunkResults)-1].ID,
			Count: chunkCount, PreviousDigest: previous,
			Digest: digestResultChunkPayload(previous, payload), Results: chunkResults,
		}
		encoded, err := json.Marshal(chunk)
		if err != nil {
			return "", err
		}
		event, err := workflowevents.NewComplianceAggregateEvent(workflowevents.ComplianceAggregateRecorded{
			Kind: workflowevents.EventKindComplianceResultChunkRecorded, TenantID: run.TenantID,
			AggregateType: "assessment_result_chunk", AggregateID: run.ID,
			RevisionID: fmt.Sprintf("%s-chunk-%06d", run.ID, chunk.Sequence), AggregateVersion: int64(chunk.Sequence),
			Operation: "result_chunk_recorded", ContentDigest: chunk.Digest, PayloadJSON: string(encoded),
			ActorID: run.RequestedBy, RecordedAt: CanonicalTime(s.now()).Format(time.RFC3339Nano),
		})
		if err != nil {
			return "", err
		}
		if err := s.log.Append(ctx, event); err != nil {
			return "", fmt.Errorf("append result chunk: %w", err)
		}
		if err := s.store.ApplyResultChunk(ctx, event.GetId(), run.TenantID, chunk); err != nil {
			return "", fmt.Errorf("project result chunk: %w", err)
		}
		previous = chunk.Digest
	}
	return "sha256:" + hex.EncodeToString(fullHash.Sum(nil)), nil
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
	if err := s.appendRun(ctx, workflowevents.EventKindComplianceAssessmentCompleted, "assessment_failed", run, expectedVersion); err != nil {
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
	if err := s.appendRun(ctx, workflowevents.EventKindComplianceAssessmentCancelled, "assessment_cancelled", run, expectedVersion); err != nil {
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
