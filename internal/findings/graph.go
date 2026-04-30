package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/knowledge"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
	"github.com/writer/cerebro/internal/workflowprojection"
)

const (
	findingDecisionStatusCompleted = "completed"
)

func (s *Service) projectFindingAnchor(ctx context.Context, finding *ports.FindingRecord) error {
	if s == nil || s.graph == nil {
		return nil
	}
	if finding == nil {
		return errors.New("finding is required")
	}
	tenantID, sourceID := findingGraphScope(finding)
	recordedAt := finding.LastObservedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = finding.FirstObservedAt.UTC()
	}
	if recordedAt.IsZero() {
		recordedAt = time.Now().UTC()
	}
	event, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    findingWorkflowSnapshot(finding, tenantID, sourceID),
		RecordedAt: recordedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	return s.recordAndProjectWorkflowEvent(ctx, event)
}

func (s *Service) projectFindingNote(ctx context.Context, finding *ports.FindingRecord, note ports.FindingNote) error {
	if s == nil || s.graph == nil {
		return nil
	}
	if finding == nil {
		return errors.New("finding is required")
	}
	body := strings.TrimSpace(note.Body)
	if body == "" {
		return nil
	}
	createdAt := note.CreatedAt.UTC()
	if createdAt.IsZero() {
		return nil
	}
	tenantID, sourceID := findingGraphScope(finding)
	event, err := workflowevents.NewFindingNoteAddedEvent(workflowevents.FindingNoteAdded{
		Finding:   findingWorkflowSnapshot(finding, tenantID, sourceID),
		NoteID:    strings.TrimSpace(note.ID),
		Body:      body,
		CreatedAt: createdAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	return s.recordAndProjectWorkflowEvent(ctx, event)
}

func (s *Service) projectFindingTicket(ctx context.Context, finding *ports.FindingRecord, ticket ports.FindingTicket) error {
	if s == nil || s.graph == nil {
		return nil
	}
	if finding == nil {
		return errors.New("finding is required")
	}
	normalizedURL := strings.TrimSpace(ticket.URL)
	if normalizedURL == "" {
		return nil
	}
	linkedAt := ticket.LinkedAt.UTC()
	if linkedAt.IsZero() {
		return nil
	}
	tenantID, sourceID := findingGraphScope(finding)
	event, err := workflowevents.NewFindingTicketLinkedEvent(workflowevents.FindingTicketLinked{
		Finding:    findingWorkflowSnapshot(finding, tenantID, sourceID),
		URL:        normalizedURL,
		Name:       strings.TrimSpace(ticket.Name),
		ExternalID: strings.TrimSpace(ticket.ExternalID),
		LinkedAt:   linkedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	return s.recordAndProjectWorkflowEvent(ctx, event)
}

func (s *Service) recordFindingStatusWorkflow(ctx context.Context, finding *ports.FindingRecord) error {
	if s == nil || s.graph == nil || finding == nil {
		return nil
	}
	status := strings.TrimSpace(finding.Status)
	if status != findingStatusResolved && status != findingStatusSuppressed {
		return nil
	}
	tenantID, sourceID := findingGraphScope(finding)
	targetURNs := []string{findingGraphFindingURN(tenantID, finding)}
	decisionType := "finding-resolution"
	if status == findingStatusSuppressed {
		decisionType = "finding-suppression"
	}
	decisionID := workflowevents.CanonicalWorkflowID(tenantID, "decision", findingStatusDecisionID(finding), decisionType, targetURNs, finding.StatusUpdatedAt)
	outcomeID := workflowevents.CanonicalWorkflowID(tenantID, "outcome", findingStatusOutcomeID(finding), decisionType, append([]string{decisionID}, targetURNs...), finding.StatusUpdatedAt)
	statusEvent, err := workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
		Finding:     findingWorkflowSnapshot(finding, tenantID, sourceID),
		Status:      status,
		Reason:      strings.TrimSpace(finding.StatusReason),
		UpdatedAt:   finding.StatusUpdatedAt.UTC().Format(time.RFC3339Nano),
		DecisionID:  decisionID,
		OutcomeID:   outcomeID,
		OutcomeType: decisionType,
	})
	if err != nil {
		return err
	}
	if err := s.recordAndProjectWorkflowEvent(ctx, statusEvent); err != nil {
		return err
	}
	if s.graphQuery == nil {
		return nil
	}
	workflowMetadata := map[string]any{
		"tenant_id":            strings.TrimSpace(finding.TenantID),
		"finding_id":           strings.TrimSpace(finding.ID),
		"finding_status":       status,
		"runtime_id":           strings.TrimSpace(finding.RuntimeID),
		"rule_id":              strings.TrimSpace(finding.RuleID),
		"policy_id":            strings.TrimSpace(finding.PolicyID),
		"check_id":             strings.TrimSpace(finding.CheckID),
		"primary_resource_urn": findingPrimaryResourceURN(finding),
	}
	if rationale := strings.TrimSpace(finding.StatusReason); rationale != "" {
		workflowMetadata["rationale"] = rationale
	}
	service := knowledge.New(s.graphQuery, s.graph).WithAppendLog(s.appendLog)
	decision, err := service.WriteDecision(ctx, knowledge.DecisionWriteRequest{
		ID:            findingStatusDecisionID(finding),
		DecisionType:  decisionType,
		Status:        findingDecisionStatusCompleted,
		Rationale:     strings.TrimSpace(finding.StatusReason),
		TargetIDs:     targetURNs,
		SourceSystem:  "findings",
		SourceEventID: strings.TrimSpace(finding.ID),
		ObservedAt:    finding.StatusUpdatedAt,
		ValidFrom:     finding.StatusUpdatedAt,
		Metadata:      workflowMetadata,
	})
	if err != nil {
		return err
	}
	_, err = service.WriteOutcome(ctx, knowledge.OutcomeWriteRequest{
		ID:            findingStatusOutcomeID(finding),
		DecisionID:    decision.DecisionID,
		OutcomeType:   decisionType,
		Verdict:       status,
		TargetIDs:     targetURNs,
		SourceSystem:  "findings",
		SourceEventID: strings.TrimSpace(finding.ID),
		ObservedAt:    finding.StatusUpdatedAt,
		ValidFrom:     finding.StatusUpdatedAt,
		Metadata:      workflowMetadata,
	})
	return err
}

func (s *Service) recordAndProjectWorkflowEvent(ctx context.Context, event *cerebrov1.EventEnvelope) error {
	if s == nil || event == nil {
		return nil
	}
	if s.appendLog != nil {
		if err := s.appendLog.Append(ctx, event); err != nil {
			return err
		}
	}
	if s.graph == nil {
		return nil
	}
	if _, err := workflowprojection.New(s.graph).Project(ctx, event); err != nil {
		return err
	}
	return nil
}

func findingWorkflowSnapshot(finding *ports.FindingRecord, tenantID string, sourceID string) workflowevents.FindingSnapshot {
	resourceURNs := uniqueSortedStrings(finding.ResourceURNs)
	eventIDs := uniqueSortedStrings(finding.EventIDs)
	risk := AnalyzeFindingRiskContext(finding, time.Time{})
	return workflowevents.FindingSnapshot{
		TenantID:           strings.TrimSpace(tenantID),
		SourceSystem:       strings.TrimSpace(sourceID),
		FindingID:          strings.TrimSpace(finding.ID),
		Fingerprint:        strings.TrimSpace(finding.Fingerprint),
		Title:              strings.TrimSpace(finding.Title),
		Summary:            strings.TrimSpace(finding.Summary),
		RuleID:             strings.TrimSpace(finding.RuleID),
		Severity:           strings.TrimSpace(finding.Severity),
		Status:             strings.TrimSpace(finding.Status),
		RuntimeID:          strings.TrimSpace(finding.RuntimeID),
		PolicyID:           strings.TrimSpace(finding.PolicyID),
		CheckID:            strings.TrimSpace(finding.CheckID),
		PrimaryResourceURN: findingPrimaryResourceURN(finding),
		ResourceURNs:       resourceURNs,
		EventIDs:           eventIDs,
		FirstObservedAt:    findingSnapshotTimestamp(finding.FirstObservedAt),
		LastObservedAt:     findingSnapshotTimestamp(finding.LastObservedAt),
		ResourceCount:      len(resourceURNs),
		EventCount:         len(eventIDs),
		ControlRefs:        findingControlRefSnapshots(finding.ControlRefs),
		RiskScore:          risk.Score,
		RiskReasons:        risk.Reasons,
		Metadata:           findingRiskMetadata(finding),
	}
}

func findingSnapshotTimestamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func findingControlRefSnapshots(refs []ports.FindingControlRef) []workflowevents.FindingControlRefSnapshot {
	if len(refs) == 0 {
		return nil
	}
	values := make([]workflowevents.FindingControlRefSnapshot, 0, len(refs))
	seen := map[string]struct{}{}
	for _, ref := range refs {
		frameworkName := strings.TrimSpace(ref.FrameworkName)
		controlID := strings.TrimSpace(ref.ControlID)
		if frameworkName == "" && controlID == "" {
			continue
		}
		key := frameworkName + "|" + controlID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, workflowevents.FindingControlRefSnapshot{
			FrameworkName: frameworkName,
			ControlID:     controlID,
		})
	}
	return values
}

func findingGraphScope(finding *ports.FindingRecord) (string, string) {
	tenantID := strings.TrimSpace(finding.TenantID)
	sourceID := strings.TrimSpace(finding.RuntimeID)
	if sourceID == "" {
		sourceID = "finding:" + strings.TrimSpace(finding.ID)
	}
	return tenantID, sourceID
}

func findingGraphFindingURN(tenantID string, finding *ports.FindingRecord) string {
	return fmt.Sprintf("urn:cerebro:%s:finding:%s", strings.TrimSpace(tenantID), strings.TrimSpace(finding.ID))
}

func findingGraphTicketURN(tenantID string, ticketURL string) string {
	return fmt.Sprintf("urn:cerebro:%s:ticket:linked:%s", strings.TrimSpace(tenantID), findingGraphHash(strings.TrimSpace(ticketURL)))
}

func findingPrimaryResourceURN(finding *ports.FindingRecord) string {
	if finding == nil {
		return ""
	}
	if resourceURN := strings.TrimSpace(finding.Attributes["primary_resource_urn"]); resourceURN != "" {
		return resourceURN
	}
	for _, resourceURN := range finding.ResourceURNs {
		if trimmed := strings.TrimSpace(resourceURN); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func findingGraphHash(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:8])
}

func findingStatusDecisionID(finding *ports.FindingRecord) string {
	return "finding-" + strings.TrimSpace(finding.ID) + "-decision-" + strings.TrimSpace(finding.Status)
}

func findingStatusOutcomeID(finding *ports.FindingRecord) string {
	return "finding-" + strings.TrimSpace(finding.ID) + "-outcome-" + strings.TrimSpace(finding.Status)
}
