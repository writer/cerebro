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
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/workflowevents"
	"github.com/writer/cerebro/internal/workflowprojection"
)

const (
	findingDecisionStatusCompleted = "completed"
	maxFindingSnapshotEventIDs     = 256
)

func (s *Service) projectFindingAnchor(ctx context.Context, finding *ports.FindingRecord) error {
	if err := s.projectFindingAnchorRevision(ctx, finding, ""); err != nil {
		return err
	}
	return s.markFindingRiskProjected(ctx, finding)
}

func (s *Service) projectFindingAnchorRevision(ctx context.Context, finding *ports.FindingRecord, revision string) error {
	if s == nil {
		return nil
	}
	if finding == nil {
		return errors.New("finding is required")
	}
	tenantID, sourceID := findingGraphScope(finding)
	if !findingWorkflowEventScopeValid(tenantID, sourceID, finding) {
		return nil
	}
	recordedAt := finding.LastObservedAt.UTC()
	if recordedAt.IsZero() {
		recordedAt = finding.FirstObservedAt.UTC()
	}
	if recordedAt.IsZero() {
		recordedAt = time.Now().UTC()
	}
	payload := workflowevents.FindingRecorded{
		Finding:    findingWorkflowSnapshot(finding, tenantID, sourceID),
		RecordedAt: recordedAt.Format(time.RFC3339Nano),
	}
	var event *cerebrov1.EventEnvelope
	var err error
	if strings.TrimSpace(revision) == "" {
		event, err = workflowevents.NewFindingRecordedEvent(payload)
	} else {
		refreshTime := time.Now().UTC()
		if findingClosedStatus(payload.Finding.Status) {
			event, err = workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
				Finding:   payload.Finding,
				Status:    payload.Finding.Status,
				Reason:    strings.TrimSpace(finding.StatusReason),
				Source:    "risk_refresh",
				UpdatedAt: refreshTime.Format(time.RFC3339Nano),
			})
		} else {
			event, err = workflowevents.NewFindingRecordedRevisionEvent(payload, revision, refreshTime)
		}
	}
	if err != nil {
		return err
	}
	return s.recordAndProjectWorkflowEvent(ctx, event)
}

func findingClosedStatus(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), findingStatusResolved) || strings.EqualFold(strings.TrimSpace(status), findingStatusSuppressed)
}

func (s *Service) markFindingRiskProjected(ctx context.Context, finding *ports.FindingRecord) error {
	if s == nil || s.graph == nil || finding == nil {
		return nil
	}
	request := ports.FindingRiskUpdate{
		FindingID:   finding.ID,
		FindingRisk: finding.FindingRisk,
		Attributes: map[string]string{
			FindingRiskGraphProjectedModelVersionAttribute: finding.RiskModelVersion,
		},
	}
	if marker, ok := s.store.(interface {
		MarkFindingRiskProjected(context.Context, ports.FindingRiskUpdate) (*ports.FindingRecord, error)
	}); ok {
		_, err := marker.MarkFindingRiskProjected(ctx, request)
		if errors.Is(err, ports.ErrFindingNotFound) {
			return nil
		}
		return err
	}
	riskUpdater, ok := s.store.(interface {
		UpdateFindingRisk(context.Context, ports.FindingRiskUpdate) (*ports.FindingRecord, error)
	})
	if !ok {
		return nil
	}
	_, err := riskUpdater.UpdateFindingRisk(ctx, request)
	return err
}

func (s *Service) projectFindingNote(ctx context.Context, finding *ports.FindingRecord, note ports.FindingNote) error {
	if s == nil {
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
	if !findingWorkflowEventScopeValid(tenantID, sourceID, finding) {
		return nil
	}
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
	if s == nil {
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
	if !findingWorkflowEventScopeValid(tenantID, sourceID, finding) {
		return nil
	}
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

func (s *Service) projectFindingExternalRefs(ctx context.Context, finding *ports.FindingRecord) error {
	if s == nil || finding == nil {
		return nil
	}
	for _, ref := range finding.ExternalRefs {
		if err := s.projectFindingExternalRef(ctx, finding, ref); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) projectFindingExternalRef(ctx context.Context, finding *ports.FindingRecord, ref ports.FindingExternalRef) error {
	if s == nil {
		return nil
	}
	if finding == nil {
		return errors.New("finding is required")
	}
	system := strings.TrimSpace(ref.System)
	kind := strings.TrimSpace(ref.Kind)
	externalID := strings.TrimSpace(ref.ExternalID)
	if system == "" || kind == "" || externalID == "" {
		return nil
	}
	linkedAt := ref.ObservedAt.UTC()
	if linkedAt.IsZero() {
		linkedAt = time.Now().UTC()
	}
	tenantID, sourceID := findingGraphScope(finding)
	if !findingWorkflowEventScopeValid(tenantID, sourceID, finding) {
		return nil
	}
	event, err := workflowevents.NewFindingExternalRefLinkedEvent(workflowevents.FindingExternalRefLinked{
		Finding:              findingWorkflowSnapshot(finding, tenantID, sourceID),
		System:               system,
		Kind:                 kind,
		ExternalID:           externalID,
		URL:                  strings.TrimSpace(ref.URL),
		ExternalStatus:       strings.TrimSpace(ref.ExternalStatus),
		ExternalStatusReason: strings.TrimSpace(ref.ExternalStatusReason),
		LifecycleOwner:       strings.TrimSpace(ref.LifecycleOwner),
		LinkedAt:             linkedAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		return err
	}
	return s.recordAndProjectWorkflowEvent(ctx, event)
}

func (s *Service) recordFindingStatusWorkflow(ctx context.Context, finding *ports.FindingRecord, statusSource string) error {
	if s == nil || finding == nil {
		return nil
	}
	status := strings.TrimSpace(finding.Status)
	if status != findingStatusResolved && status != findingStatusSuppressed {
		return nil
	}
	tenantID, sourceID := findingGraphScope(finding)
	if !findingWorkflowEventScopeValid(tenantID, sourceID, finding) {
		return nil
	}
	targetURNs := []string{findingGraphFindingURN(tenantID, finding)}
	decisionType := "finding-resolution"
	if status == findingStatusSuppressed {
		decisionType = "finding-suppression"
	}
	pruneGraph := workflowevents.FindingStatusPrunesGraph(status, statusSource)
	decisionID := ""
	outcomeID := ""
	if !pruneGraph {
		decisionID = workflowevents.CanonicalWorkflowID(tenantID, "decision", findingStatusDecisionID(finding), decisionType, targetURNs, finding.StatusUpdatedAt)
		outcomeID = workflowevents.CanonicalWorkflowID(tenantID, "outcome", findingStatusOutcomeID(finding), decisionType, append([]string{decisionID}, targetURNs...), finding.StatusUpdatedAt)
	}
	statusEvent, err := workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
		Finding:     findingWorkflowSnapshot(finding, tenantID, sourceID),
		Status:      status,
		Reason:      strings.TrimSpace(finding.StatusReason),
		Source:      strings.TrimSpace(statusSource),
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
	if pruneGraph {
		return nil
	}
	if s.graph == nil || s.graphQuery == nil {
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
		appendEvent := event
		if canonical, ok := canonicalFindingWorkflowEvent(event); ok {
			appendEvent = canonical
		}
		if err := s.appendLog.Append(ctx, appendEvent); err != nil {
			return err
		}
	}
	if s.graph != nil {
		if _, err := workflowprojection.New(s.graph).Project(ctx, event); err != nil {
			return err
		}
	}
	return nil
}

func canonicalFindingWorkflowEvent(event *cerebrov1.EventEnvelope) (*cerebrov1.EventEnvelope, bool) {
	kind := canonicalFindingWorkflowKind(event.GetKind())
	if kind == "" {
		return nil, false
	}
	attributes := make(map[string]string, len(event.GetAttributes())+1)
	for key, value := range event.GetAttributes() {
		attributes[key] = value
	}
	attributes["canonical_kind"] = kind
	return &cerebrov1.EventEnvelope{
		Id:         canonicalFindingWorkflowEventID(event.GetId(), kind),
		TenantId:   event.GetTenantId(),
		SourceId:   event.GetSourceId(),
		Kind:       kind,
		OccurredAt: event.GetOccurredAt(),
		SchemaRef:  event.GetSchemaRef(),
		Payload:    append([]byte(nil), event.GetPayload()...),
		Attributes: attributes,
	}, true
}

func canonicalFindingWorkflowKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case workflowevents.EventKindFindingRecorded:
		return securityevents.FindingRecorded
	case workflowevents.EventKindFindingStatusChanged:
		return securityevents.FindingStatusChanged
	case workflowevents.EventKindFindingNoteAdded:
		return securityevents.FindingNoteAdded
	case workflowevents.EventKindFindingTicketLinked:
		return securityevents.FindingTicketLinked
	case workflowevents.EventKindFindingExternalRefLinked:
		return securityevents.FindingExternalRefLinked
	default:
		return ""
	}
}

func canonicalFindingWorkflowEventID(id string, kind string) string {
	return strings.TrimSpace(id) + "|canonical|" + strings.TrimSpace(kind)
}

func findingWorkflowSnapshot(finding *ports.FindingRecord, tenantID string, sourceID string) workflowevents.FindingSnapshot {
	resourceURNs := uniqueSortedStrings(finding.ResourceURNs)
	eventIDs := uniqueSortedStrings(finding.EventIDs)
	eventCount := len(eventIDs)
	eventIDs = boundedFindingSnapshotIDs(eventIDs, maxFindingSnapshotEventIDs)
	var risk FindingRiskContext
	if finding.RiskScore == 0 || finding.LikelihoodScore == 0 || finding.ImpactScore == 0 || finding.ConfidenceScore == 0 {
		risk = AnalyzeFindingRiskContext(finding, time.Time{})
	}
	riskScore := finding.RiskScore
	if riskScore == 0 {
		riskScore = risk.Score
	}
	effectiveSeverity := firstNonEmpty(EffectiveSeverityFromRiskScore(riskScore), risk.EffectiveSeverity, finding.Attributes[FindingEffectiveSeverityAttribute])
	likelihoodScore := finding.LikelihoodScore
	if likelihoodScore == 0 {
		likelihoodScore = risk.LikelihoodScore
	}
	impactScore := finding.ImpactScore
	if impactScore == 0 {
		impactScore = risk.ImpactScore
	}
	confidenceScore := finding.ConfidenceScore
	if confidenceScore == 0 {
		confidenceScore = risk.ConfidenceScore
	}
	likelihoodLevel := firstNonEmpty(finding.LikelihoodLevel, risk.LikelihoodLevel)
	impactLevel := firstNonEmpty(finding.ImpactLevel, risk.ImpactLevel)
	modelVersion := firstNonEmpty(finding.RiskModelVersion, risk.RiskModelVersion)
	riskReasons := finding.RiskReasons
	if len(riskReasons) == 0 {
		riskReasons = risk.Reasons
	}
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
		EventCount:         eventCount,
		ControlRefs:        findingControlRefSnapshots(finding.ControlRefs),
		FindingRiskSnapshot: workflowevents.FindingRiskSnapshot{
			RiskScore:         riskScore,
			EffectiveSeverity: effectiveSeverity,
			LikelihoodScore:   likelihoodScore,
			ImpactScore:       impactScore,
			ConfidenceScore:   confidenceScore,
			LikelihoodLevel:   likelihoodLevel,
			ImpactLevel:       impactLevel,
			RiskModelVersion:  modelVersion,
			RiskReasons:       uniqueSortedStrings(riskReasons),
		},
		Metadata: findingRiskMetadata(finding),
	}
}

func boundedFindingSnapshotIDs(ids []string, max int) []string {
	if len(ids) <= max {
		return ids
	}
	return append([]string(nil), ids[:max]...)
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

func findingWorkflowEventScopeValid(tenantID string, sourceID string, finding *ports.FindingRecord) bool {
	return strings.TrimSpace(tenantID) != "" && strings.TrimSpace(sourceID) != "" && finding != nil && strings.TrimSpace(finding.ID) != ""
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
