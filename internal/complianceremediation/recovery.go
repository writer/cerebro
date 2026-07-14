package complianceremediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/complianceassessment"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

const defaultReplayPageSize = uint32(500)

// RecoverProjections replays remediation events oldest-first in bounded pages.
func (s *Service) RecoverProjections(ctx context.Context, pageSize uint32) (int, error) {
	if err := s.ready(); err != nil || s.replayer == nil {
		return 0, ErrUnavailable
	}
	if pageSize == 0 {
		pageSize = defaultReplayPageSize
	}
	first, err := s.replayer.ReplayPage(ctx, remediationReplayRequest(pageSize, ""))
	if err != nil {
		return 0, fmt.Errorf("replay remediation projection page: %w", err)
	}
	cursors := []string{""}
	seen := map[string]struct{}{"": {}}
	page := first
	for !page.Complete {
		cursor := strings.TrimSpace(page.NextCursor)
		if cursor == "" {
			return 0, errors.New("remediation replay page is incomplete without a next cursor")
		}
		if _, ok := seen[cursor]; ok {
			return 0, errors.New("remediation replay cursor repeated")
		}
		seen[cursor] = struct{}{}
		cursors = append(cursors, cursor)
		page, err = s.replayer.ReplayPage(ctx, remediationReplayRequest(pageSize, cursor))
		if err != nil {
			return 0, fmt.Errorf("discover remediation projection page: %w", err)
		}
	}
	processed := 0
	for index := len(cursors) - 1; index > 0; index-- {
		page, err = s.replayer.ReplayPage(ctx, remediationReplayRequest(pageSize, cursors[index]))
		if err != nil {
			return processed, fmt.Errorf("refetch remediation projection page: %w", err)
		}
		count, projectErr := s.projectEvents(ctx, page.Events)
		processed += count
		if projectErr != nil {
			return processed, projectErr
		}
	}
	count, err := s.projectEvents(ctx, first.Events)
	return processed + count, err
}

func remediationReplayRequest(pageSize uint32, cursor string) ports.ReplayRequest {
	return ports.ReplayRequest{
		KindPrefixes: []string{
			workflowevents.EventKindComplianceWorkItemUpdated,
			workflowevents.EventKindComplianceRemediationMilestoneUpdated,
		},
		ExactKindFilters: true,
		Limit:            pageSize,
		Cursor:           strings.TrimSpace(cursor),
	}
}

func (s *Service) projectEvents(ctx context.Context, events []*cerebrov1.EventEnvelope) (int, error) {
	processed := 0
	for _, event := range events {
		projected, err := s.ProjectEvent(ctx, event)
		if err != nil {
			return processed, fmt.Errorf("project remediation event %q: %w", event.GetId(), err)
		}
		if projected {
			processed++
		}
	}
	return processed, nil
}

// ProjectEvent validates and applies one append-log remediation event idempotently.
func (s *Service) ProjectEvent(ctx context.Context, event *cerebrov1.EventEnvelope) (bool, error) {
	if err := s.ready(); err != nil {
		return false, err
	}
	if event == nil {
		return false, errors.New("remediation event is required")
	}
	record, err := workflowevents.DecodeComplianceAggregate(event)
	if err != nil {
		return false, err
	}
	if record.Kind != workflowevents.EventKindComplianceWorkItemUpdated && record.Kind != workflowevents.EventKindComplianceRemediationMilestoneUpdated {
		return false, nil
	}
	metadata, err := recoveredMetadata(event, record)
	if err != nil {
		return false, err
	}
	if err := validatePayloadDigest(record); err != nil {
		return false, err
	}
	switch strings.TrimSpace(record.AggregateType) {
	case "work_occurrence":
		var payload workOccurrencePayload
		if err := json.Unmarshal([]byte(record.PayloadJSON), &payload); err != nil {
			return false, fmt.Errorf("decode work occurrence event: %w", err)
		}
		if err := validateWorkEnvelope(record, payload.Item); err != nil {
			return false, err
		}
		return true, s.projector.ProjectWorkOccurrence(ctx, metadata, payload.Item, payload.Occurrence)
	case "work_action":
		var payload workActionPayload
		if err := json.Unmarshal([]byte(record.PayloadJSON), &payload); err != nil {
			return false, fmt.Errorf("decode work action event: %w", err)
		}
		if err := validateWorkEnvelope(record, payload.Item); err != nil {
			return false, err
		}
		return true, s.projector.ProjectWorkAction(ctx, metadata, payload.Item, payload.Action)
	case "work_reopen":
		var payload workReopenPayload
		if err := json.Unmarshal([]byte(record.PayloadJSON), &payload); err != nil {
			return false, fmt.Errorf("decode work reopen event: %w", err)
		}
		if err := validateWorkEnvelope(record, payload.Item); err != nil {
			return false, err
		}
		if payload.Reopen.WorkItemID != payload.Item.ID || payload.Reopen.Trigger != payload.Item.LastReopenTrigger {
			return false, errors.New("work reopen record does not match work item")
		}
		return true, s.projector.ProjectWorkReopen(ctx, metadata, payload.Item, payload.Reopen)
	case "remediation_plan":
		var payload remediationPayload
		if err := json.Unmarshal([]byte(record.PayloadJSON), &payload); err != nil {
			return false, fmt.Errorf("decode remediation plan event: %w", err)
		}
		if strings.TrimSpace(record.TenantID) != strings.TrimSpace(payload.Plan.TenantID) || strings.TrimSpace(record.AggregateID) != strings.TrimSpace(payload.Plan.ID) || !aggregateVersionMatches(record.AggregateVersion, payload.Plan.Version) {
			return false, errors.New("remediation plan envelope does not match payload")
		}
		if payload.Reopen != nil && (payload.Reopen.PlanID != payload.Plan.ID || payload.Reopen.Trigger != payload.Plan.LastReopenTrigger) {
			return false, errors.New("remediation reopen record does not match plan")
		}
		if payload.Reopen != nil {
			return true, s.projector.ProjectRemediationReopen(ctx, metadata, payload.Plan, *payload.Reopen)
		}
		return true, s.projector.ProjectRemediationPlan(ctx, metadata, payload.Plan)
	default:
		return false, nil
	}
}

func recoveredMetadata(event *cerebrov1.EventEnvelope, record *workflowevents.ComplianceAggregateRecorded) (ProjectionMetadata, error) {
	if record == nil || record.AggregateVersion < 1 || strings.TrimSpace(record.TenantID) == "" || strings.TrimSpace(record.AggregateID) == "" || strings.TrimSpace(event.GetId()) == "" {
		return ProjectionMetadata{}, errors.New("remediation event identity is incomplete")
	}
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(record.RecordedAt))
	if err != nil {
		return ProjectionMetadata{}, fmt.Errorf("parse remediation event time: %w", err)
	}
	return ProjectionMetadata{EventID: event.GetId(), ExpectedVersion: uint64(record.AggregateVersion - 1), OccurredAt: at.UTC()}, nil
}

func validatePayloadDigest(record *workflowevents.ComplianceAggregateRecorded) error {
	payload := []byte(record.PayloadJSON)
	digest := sha256.Sum256(payload)
	want := "sha256:" + hex.EncodeToString(digest[:])
	if strings.TrimSpace(record.ContentDigest) != want {
		return errors.New("remediation event payload digest does not match envelope")
	}
	return nil
}

func validateWorkEnvelope(record *workflowevents.ComplianceAggregateRecorded, item complianceassessment.WorkItem) error {
	if strings.TrimSpace(record.TenantID) != strings.TrimSpace(item.Basis.TenantID) ||
		strings.TrimSpace(record.AggregateID) != strings.TrimSpace(item.ID) ||
		!aggregateVersionMatches(record.AggregateVersion, item.Version) {
		return errors.New("work item envelope does not match payload")
	}
	return nil
}

func aggregateVersionMatches(recordVersion int64, payloadVersion uint64) bool {
	encodedVersion, err := encodeAggregateVersion(payloadVersion)
	return err == nil && recordVersion == encodedVersion
}
