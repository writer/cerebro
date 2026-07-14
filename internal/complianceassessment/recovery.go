package complianceassessment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const defaultAssessmentReplayPageSize = uint32(500)

var ErrAssessmentRecoveryUnavailable = errors.New("assessment projection recovery is unavailable")

// RecoverProjections replays assessment events oldest-first. ReplayPage walks
// newest pages first, so this keeps only opaque page cursors plus the bounded
// newest page in memory and refetches older pages in reverse order.
func (s *Service) RecoverProjections(ctx context.Context, pageSize uint32) (int, error) {
	if s == nil || s.store == nil || s.replayer == nil {
		return 0, ErrAssessmentRecoveryUnavailable
	}
	if pageSize == 0 {
		pageSize = defaultAssessmentReplayPageSize
	}
	request := assessmentReplayRequest(pageSize, "")
	first, err := s.replayer.ReplayPage(ctx, request)
	if err != nil {
		return 0, fmt.Errorf("replay assessment projection page: %w", err)
	}
	cursors := []string{""}
	seen := map[string]struct{}{"": {}}
	page := first
	for !page.Complete {
		cursor := strings.TrimSpace(page.NextCursor)
		if cursor == "" {
			return 0, errors.New("assessment replay page is incomplete without a next cursor")
		}
		if _, ok := seen[cursor]; ok {
			return 0, errors.New("assessment replay cursor repeated")
		}
		seen[cursor] = struct{}{}
		cursors = append(cursors, cursor)
		page, err = s.replayer.ReplayPage(ctx, assessmentReplayRequest(pageSize, cursor))
		if err != nil {
			return 0, fmt.Errorf("discover assessment projection page: %w", err)
		}
	}

	processed := 0
	for index := len(cursors) - 1; index > 0; index-- {
		page, err = s.replayer.ReplayPage(ctx, assessmentReplayRequest(pageSize, cursors[index]))
		if err != nil {
			return processed, fmt.Errorf("refetch assessment projection page: %w", err)
		}
		count, err := s.projectEvents(ctx, page.Events)
		processed += count
		if err != nil {
			return processed, err
		}
	}
	count, err := s.projectEvents(ctx, first.Events)
	processed += count
	return processed, err
}

func assessmentReplayRequest(pageSize uint32, cursor string) ports.ReplayRequest {
	return ports.ReplayRequest{
		KindPrefix: "workflow.v1.compliance.assessment_",
		Limit:      pageSize,
		Cursor:     strings.TrimSpace(cursor),
	}
}

func (s *Service) projectEvents(ctx context.Context, events []*cerebrov1.EventEnvelope) (int, error) {
	processed := 0
	for _, event := range events {
		projected, err := s.ProjectEvent(ctx, event)
		if err != nil {
			return processed, fmt.Errorf("project assessment event %q: %w", event.GetId(), err)
		}
		if projected {
			processed++
		}
	}
	return processed, nil
}

// ProjectEvent applies one append-log assessment event idempotently.
func (s *Service) ProjectEvent(ctx context.Context, event *cerebrov1.EventEnvelope) (bool, error) {
	if s == nil || s.store == nil {
		return false, ErrAssessmentRecoveryUnavailable
	}
	if event == nil {
		return false, errors.New("assessment event is required")
	}
	record, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		return false, err
	}
	switch record.Kind {
	case workflowevents.EventKindCompliancePlanRevisionRecorded, workflowevents.EventKindCompliancePlanPublished:
		var plan AssessmentPlanRevision
		if err := json.Unmarshal([]byte(record.PayloadJSON), &plan); err != nil {
			return false, fmt.Errorf("decode assessment plan event: %w", err)
		}
		if err := validateRecoveredAggregate(record, "assessment_plan", plan.TenantID, plan.ID, plan.RevisionID, plan.Version); err != nil {
			return false, err
		}
		if strings.TrimSpace(record.ContentDigest) != strings.TrimSpace(plan.ContentDigest) {
			return false, errors.New("assessment plan digest does not match envelope")
		}
		if err := validatePlan(plan); err != nil {
			return false, err
		}
		return true, s.store.ApplyPlan(ctx, event.GetId(), plan, plan.Version-1)
	case workflowevents.EventKindComplianceAssessmentRequested,
		workflowevents.EventKindComplianceAssessmentJobBound,
		workflowevents.EventKindComplianceInputManifestRecorded,
		workflowevents.EventKindComplianceAssessmentCompleted,
		workflowevents.EventKindComplianceAssessmentCancelled:
		var run AssessmentRun
		if err := json.Unmarshal([]byte(record.PayloadJSON), &run); err != nil {
			return false, fmt.Errorf("decode assessment run event: %w", err)
		}
		if err := validateRecoveredAggregate(record, "assessment_run", run.TenantID, run.ID, "", run.Version); err != nil {
			return false, err
		}
		digest, err := semanticHash(run)
		if err != nil {
			return false, fmt.Errorf("hash recovered assessment run: %w", err)
		}
		if strings.TrimSpace(record.ContentDigest) != digest {
			return false, errors.New("assessment run digest does not match envelope")
		}
		return true, s.store.ApplyRun(ctx, event.GetId(), run, run.Version-1)
	case workflowevents.EventKindComplianceResultChunkRecorded:
		var chunk ResultChunk
		if err := json.Unmarshal([]byte(record.PayloadJSON), &chunk); err != nil {
			return false, fmt.Errorf("decode assessment result chunk event: %w", err)
		}
		if strings.TrimSpace(record.AggregateType) != "assessment_result_chunk" || strings.TrimSpace(record.TenantID) == "" || strings.TrimSpace(record.AggregateID) != strings.TrimSpace(chunk.RunID) || record.AggregateVersion != int64(chunk.Sequence) {
			return false, errors.New("assessment result chunk envelope does not match payload")
		}
		if strings.TrimSpace(record.ContentDigest) != strings.TrimSpace(chunk.Digest) {
			return false, errors.New("assessment result chunk digest does not match envelope")
		}
		return true, s.store.ApplyResultChunk(ctx, event.GetId(), record.TenantID, chunk)
	default:
		return false, nil
	}
}

func validateRecoveredAggregate(record *workflowevents.ComplianceAggregateRecorded, aggregateType, tenantID, aggregateID, revisionID string, version uint64) error {
	encodedVersion, err := aggregateVersion(version)
	if err != nil {
		return errors.New("assessment event envelope does not match payload")
	}
	if record == nil || strings.TrimSpace(record.AggregateType) != aggregateType || strings.TrimSpace(record.TenantID) != strings.TrimSpace(tenantID) || strings.TrimSpace(record.AggregateID) != strings.TrimSpace(aggregateID) || record.AggregateVersion != encodedVersion {
		return errors.New("assessment event envelope does not match payload")
	}
	if strings.TrimSpace(revisionID) != "" && strings.TrimSpace(record.RevisionID) != strings.TrimSpace(revisionID) {
		return errors.New("assessment event revision does not match payload")
	}
	return nil
}
