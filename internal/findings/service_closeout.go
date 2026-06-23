package findings

import (
	"context"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type openFindingRetirementRule interface {
	RetiresOpenFindings() bool
}

func (s *Service) resolveRetiredOpenFindings(ctx context.Context, tenantID string, runtimeID string, ruleID string, emittedFindingIDs map[string]struct{}) error {
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(tenantID),
		RuntimeID: strings.TrimSpace(runtimeID),
		RuleID:    strings.TrimSpace(ruleID),
		Status:    findingStatusOpen,
	})
	if err != nil {
		return fmt.Errorf("list retired candidates for rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		if _, emitted := emittedFindingIDs[strings.TrimSpace(finding.ID)]; emitted {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonNoLongerEmitted,
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("resolve retired finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return fmt.Errorf("project retired finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
	}
	return nil
}

func (s *Service) resolveStaleOpenFindings(ctx context.Context, tenantID string, runtimeID string, ruleID string, evaluatedEventIDs map[string]struct{}, emittedFindingIDs map[string]struct{}) error {
	if len(evaluatedEventIDs) == 0 {
		return nil
	}
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(tenantID),
		RuntimeID: strings.TrimSpace(runtimeID),
		RuleID:    strings.TrimSpace(ruleID),
		Status:    findingStatusOpen,
	})
	if err != nil {
		return fmt.Errorf("list stale candidates for rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		if _, emitted := emittedFindingIDs[strings.TrimSpace(finding.ID)]; emitted {
			continue
		}
		if !findingReferencesEvaluatedEvent(finding, evaluatedEventIDs) {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonNoLongerEmitted,
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("resolve stale finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return fmt.Errorf("project stale finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
	}
	return nil
}

type counterAnchorLatestEvent struct {
	observedAt time.Time
	sequence   int
	closes     bool
	eventIDs   []string
}

func (s *Service) resolveCounterEventOpenFindings(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule Rule, counterRule CounterEventRule, evaluatedEvents []*cerebrov1.EventEnvelope) ([]*ports.FindingRecord, error) {
	if counterRule == nil || runtime == nil || rule == nil || len(evaluatedEvents) == 0 {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	ruleID := ""
	if spec := rule.Spec(); spec != nil {
		ruleID = strings.TrimSpace(spec.GetId())
	}
	latestByAnchor, err := latestCounterAnchorEvents(ctx, runtime, rule, counterRule, evaluatedEvents)
	if err != nil {
		return nil, err
	}
	if !hasLatestCounterAnchorClose(latestByAnchor) {
		return nil, nil
	}
	listRequest := ports.ListFindingsRequest{
		TenantID: tenantID,
		RuleID:   ruleID,
		Status:   findingStatusOpen,
	}
	if counterEventCloseLookupRuntimeScoped(rule) {
		listRequest.RuntimeID = runtimeID
	}
	findings, err := s.store.ListFindings(ctx, listRequest)
	if err != nil {
		return nil, fmt.Errorf("list counter-event candidates for rule %q: %w", ruleID, err)
	}
	resolved := []*ports.FindingRecord{}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		openAnchor := strings.TrimSpace(counterRule.OpenAnchor(finding.Attributes))
		if openAnchor == "" {
			continue
		}
		latest, ok := latestByAnchor[openAnchor]
		if !ok || !latest.closes {
			continue
		}
		if counterAnchorClosePrecedesFinding(latest, finding) {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonClosedByCounterEvent,
			UpdatedAt: time.Now().UTC(),
			EventIDs:  uniqueTrimmedStringsPreserveOrder(latest.eventIDs),
		})
		if err != nil {
			return nil, fmt.Errorf("resolve counter-event finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return nil, fmt.Errorf("project counter-event finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
		resolved = append(resolved, updated)
	}
	return resolved, nil
}

func latestCounterAnchorEvents(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule Rule, counterRule CounterEventRule, evaluatedEvents []*cerebrov1.EventEnvelope) (map[string]counterAnchorLatestEvent, error) {
	if aggregateRule, ok := counterRule.(AggregateCounterEventRule); ok {
		if latestByAnchor, handled := latestAggregateCounterAnchorEvents(aggregateRule, evaluatedEvents); handled {
			return latestByAnchor, nil
		}
	}
	latestByAnchor := make(map[string]counterAnchorLatestEvent)
	ruleID := ""
	if spec := rule.Spec(); spec != nil {
		ruleID = strings.TrimSpace(spec.GetId())
	}
	for sequence, event := range evaluatedEvents {
		if event == nil {
			continue
		}
		observedAt := counterAnchorEventObservedAt(event)
		records, err := rule.Evaluate(ctx, runtime, event)
		if err != nil {
			return nil, fmt.Errorf("evaluate counter-event chronology for rule %q event %q: %w", ruleID, strings.TrimSpace(event.GetId()), err)
		}
		for _, record := range records {
			if record == nil {
				continue
			}
			openAnchor := strings.TrimSpace(counterRule.OpenAnchor(record.Attributes))
			if openAnchor == "" {
				continue
			}
			recordLatestCounterAnchorEvent(latestByAnchor, openAnchor, counterAnchorLatestEvent{
				observedAt: observedAt,
				sequence:   sequence,
			})
		}
		anchor, closes := counterRule.CloseOnEvent(event)
		anchor = strings.TrimSpace(anchor)
		if closes && anchor != "" {
			eventIDs := []string(nil)
			if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
				eventIDs = []string{eventID}
			}
			recordLatestCounterAnchorEvent(latestByAnchor, anchor, counterAnchorLatestEvent{
				observedAt: observedAt,
				sequence:   sequence,
				closes:     true,
				eventIDs:   eventIDs,
			})
		}
	}
	return latestByAnchor, nil
}

func latestAggregateCounterAnchorEvents(rule AggregateCounterEventRule, evaluatedEvents []*cerebrov1.EventEnvelope) (map[string]counterAnchorLatestEvent, bool) {
	if rule == nil {
		return nil, false
	}
	latestByAnchorAndKey := map[string]map[string]counterAnchorLatestEvent{}
	handled := false
	for sequence, event := range evaluatedEvents {
		if event == nil {
			continue
		}
		observedAt := counterAnchorEventObservedAt(event)
		for _, state := range rule.CounterEventStates(event) {
			anchor := strings.TrimSpace(state.Anchor)
			key := strings.TrimSpace(state.Key)
			if anchor == "" || key == "" {
				continue
			}
			eventIDs := uniqueTrimmedStringsPreserveOrder(state.EventIDs)
			if len(eventIDs) == 0 {
				if eventID := strings.TrimSpace(event.GetId()); eventID != "" {
					eventIDs = []string{eventID}
				}
			}
			if latestByAnchorAndKey[anchor] == nil {
				latestByAnchorAndKey[anchor] = map[string]counterAnchorLatestEvent{}
			}
			recordLatestCounterAnchorEvent(latestByAnchorAndKey[anchor], key, counterAnchorLatestEvent{
				observedAt: observedAt,
				sequence:   sequence,
				closes:     state.Closes,
				eventIDs:   eventIDs,
			})
			handled = true
		}
	}
	if !handled {
		return nil, false
	}
	latestByAnchor := make(map[string]counterAnchorLatestEvent)
	for anchor, latestByKey := range latestByAnchorAndKey {
		if latest, ok := aggregateCounterAnchorClose(latestByKey); ok {
			latestByAnchor[anchor] = latest
		}
	}
	return latestByAnchor, true
}

func aggregateCounterAnchorClose(latestByKey map[string]counterAnchorLatestEvent) (counterAnchorLatestEvent, bool) {
	if len(latestByKey) == 0 {
		return counterAnchorLatestEvent{}, false
	}
	latestClose := counterAnchorLatestEvent{}
	eventIDs := []string{}
	for _, latest := range latestByKey {
		if !latest.closes {
			return counterAnchorLatestEvent{}, false
		}
		if !latestClose.closes || counterAnchorEventIsNewer(latest, latestClose) {
			latestClose = latest
		}
		eventIDs = append(eventIDs, latest.eventIDs...)
	}
	latestClose.closes = true
	latestClose.eventIDs = uniqueTrimmedStringsPreserveOrder(eventIDs)
	return latestClose, true
}

func recordLatestCounterAnchorEvent(latestByAnchor map[string]counterAnchorLatestEvent, anchor string, event counterAnchorLatestEvent) {
	anchor = strings.TrimSpace(anchor)
	if anchor == "" {
		return
	}
	current, ok := latestByAnchor[anchor]
	if !ok || counterAnchorEventIsNewer(event, current) {
		latestByAnchor[anchor] = event
	}
}

func counterAnchorEventIsNewer(next counterAnchorLatestEvent, current counterAnchorLatestEvent) bool {
	if !next.observedAt.Equal(current.observedAt) {
		return next.observedAt.After(current.observedAt)
	}
	return next.sequence >= current.sequence
}

func counterAnchorEventObservedAt(event *cerebrov1.EventEnvelope) time.Time {
	if event == nil || event.GetOccurredAt() == nil {
		return time.Time{}
	}
	return event.GetOccurredAt().AsTime().UTC()
}

func counterAnchorClosePrecedesFinding(event counterAnchorLatestEvent, finding *ports.FindingRecord) bool {
	if finding == nil || !event.closes || event.observedAt.IsZero() {
		return false
	}
	observedAt := finding.LastObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = finding.FirstObservedAt.UTC()
	}
	if observedAt.IsZero() {
		return false
	}
	return event.observedAt.Before(observedAt)
}

func hasLatestCounterAnchorClose(latestByAnchor map[string]counterAnchorLatestEvent) bool {
	for _, event := range latestByAnchor {
		if event.closes {
			return true
		}
	}
	return false
}

func (s *Service) resolveRuleOpenFindings(ctx context.Context, runtime *cerebrov1.SourceRuntime, rule Rule, evaluatedEvents []*cerebrov1.EventEnvelope, evaluatedEventIDs map[string]struct{}, emittedFindingIDs map[string]struct{}) ([]*ports.FindingRecord, error) {
	if runtime == nil || rule == nil {
		return nil, nil
	}
	tenantID := strings.TrimSpace(runtime.GetTenantId())
	runtimeID := strings.TrimSpace(runtime.GetId())
	ruleID := strings.TrimSpace(rule.Spec().GetId())
	if isTTLEvidenceRule(rule) {
		return nil, s.resolveTTLOpenFindings(ctx, tenantID, ruleID)
	}
	if retirementRule, ok := rule.(openFindingRetirementRule); ok && retirementRule.RetiresOpenFindings() {
		return nil, s.resolveRetiredOpenFindings(ctx, tenantID, runtimeID, ruleID, emittedFindingIDs)
	}
	if rule.SupportsRuntime(runtime) {
		var resolvedCounterFindings []*ports.FindingRecord
		if counterRule, ok := durableStateCounterEventRule(rule); ok {
			resolved, err := s.resolveCounterEventOpenFindings(ctx, runtime, rule, counterRule, evaluatedEvents)
			if err != nil {
				return nil, err
			}
			resolvedCounterFindings = resolved
		}
		if err := s.resolveStaleOpenFindings(ctx, tenantID, runtimeID, ruleID, evaluatedEventIDs, emittedFindingIDs); err != nil {
			return nil, err
		}
		return resolvedCounterFindings, nil
	}
	return nil, s.resolveAllOpenFindingsForRule(ctx, tenantID, runtimeID, ruleID)
}

func (s *Service) applyCounterEventResolutionResults(ctx context.Context, run *cerebrov1.FindingEvaluationRun, resultFindings []*ports.FindingRecord, resultEvidence *[]*cerebrov1.FindingEvidence, evidenceIDs map[string]struct{}, resolvedFindings []*ports.FindingRecord) error {
	if len(resolvedFindings) == 0 {
		return nil
	}
	replaceResultFindingsWithSnapshots(resultFindings, resolvedFindings)
	if evidenceIDs == nil {
		evidenceIDs = map[string]struct{}{}
	}
	for _, finding := range resolvedFindings {
		if finding == nil {
			continue
		}
		evidence, err := s.buildFindingEvidence(ctx, finding, run)
		if err != nil {
			return fmt.Errorf("build counter-event evidence for finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if _, seen := evidenceIDs[evidence.GetId()]; seen {
			continue
		}
		if err := s.evidenceStore.PutFindingEvidence(ctx, evidence); err != nil {
			return fmt.Errorf("persist counter-event evidence for finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		evidenceIDs[evidence.GetId()] = struct{}{}
		if resultEvidence != nil {
			*resultEvidence = append(*resultEvidence, evidence)
		}
	}
	return nil
}

func replaceResultFindingsWithSnapshots(resultFindings []*ports.FindingRecord, resolvedFindings []*ports.FindingRecord) {
	if len(resultFindings) == 0 || len(resolvedFindings) == 0 {
		return
	}
	byID := make(map[string]*ports.FindingRecord, len(resolvedFindings))
	byFingerprint := make(map[string]*ports.FindingRecord, len(resolvedFindings))
	for _, finding := range resolvedFindings {
		if finding == nil {
			continue
		}
		if id := strings.TrimSpace(finding.ID); id != "" {
			byID[id] = finding
		}
		if fingerprint := strings.TrimSpace(finding.Fingerprint); fingerprint != "" {
			byFingerprint[fingerprint] = finding
		}
	}
	for index, finding := range resultFindings {
		if finding == nil {
			continue
		}
		if updated, ok := byID[strings.TrimSpace(finding.ID)]; ok {
			resultFindings[index] = updated
			continue
		}
		if updated, ok := byFingerprint[strings.TrimSpace(finding.Fingerprint)]; ok {
			resultFindings[index] = updated
		}
	}
}

func durableStateCounterEventRule(rule Rule) (CounterEventRule, bool) {
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		return nil, false
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return nil, false
	}
	lifecycleKind := LifecycleKind(strings.TrimSpace(string(metadataRule.RuleMetadata().Lifecycle.Kind)))
	if lifecycleKind != LifecycleDurableState {
		return nil, false
	}
	return counterRule, true
}

func counterEventCloseLookupRuntimeScoped(rule Rule) bool {
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return true
	}
	definition := metadataRule.RuleMetadata()
	if LifecycleKind(strings.TrimSpace(string(definition.Lifecycle.Kind))) != LifecycleDurableState {
		return true
	}
	if len(definition.FingerprintFields) == 0 {
		return true
	}
	return fingerprintFieldsIncludeRuntimeID(definition.FingerprintFields)
}

func fingerprintFieldsIncludeRuntimeID(fields []string) bool {
	for _, field := range fields {
		switch strings.ToLower(strings.TrimSpace(field)) {
		case "runtime_id", "source_runtime_id":
			return true
		}
	}
	return false
}

func isTTLEvidenceRule(rule Rule) bool {
	if rule == nil {
		return false
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		return false
	}
	return metadataRule.RuleMetadata().Lifecycle.Kind == LifecycleTTLEvidence
}

func (s *Service) resolveAllOpenFindingsForRule(ctx context.Context, tenantID string, runtimeID string, ruleID string) error {
	findings, err := s.store.ListFindings(ctx, ports.ListFindingsRequest{
		TenantID:  strings.TrimSpace(tenantID),
		RuntimeID: strings.TrimSpace(runtimeID),
		RuleID:    strings.TrimSpace(ruleID),
		Status:    findingStatusOpen,
	})
	if err != nil {
		return fmt.Errorf("list stale candidates for unsupported rule %q: %w", strings.TrimSpace(ruleID), err)
	}
	for _, finding := range findings {
		if finding == nil {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		updated, err := s.updateFindingStatusAndRisk(ctx, ports.FindingStatusUpdate{
			FindingID: strings.TrimSpace(finding.ID),
			Status:    findingStatusResolved,
			Reason:    workflowevents.FindingStatusReasonNoLongerEmitted,
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("resolve stale finding %q: %w", strings.TrimSpace(finding.ID), err)
		}
		if err := s.recordFindingStatusWorkflow(ctx, updated, workflowevents.FindingStatusSourceStaleEvaluation); err != nil {
			return fmt.Errorf("project stale finding %q resolution: %w", strings.TrimSpace(finding.ID), err)
		}
	}
	return nil
}

func findingReferencesEvaluatedEvent(finding *ports.FindingRecord, evaluatedEventIDs map[string]struct{}) bool {
	if finding == nil {
		return false
	}
	for _, eventID := range finding.EventIDs {
		if _, ok := evaluatedEventIDs[strings.TrimSpace(eventID)]; ok {
			return true
		}
	}
	return false
}
