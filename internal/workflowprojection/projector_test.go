package workflowprojection

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/mitre"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type projectionRecorder struct {
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func (r *projectionRecorder) Ping(context.Context) error { return nil }

func (r *projectionRecorder) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if r.entities == nil {
		r.entities = make(map[string]*ports.ProjectedEntity)
	}
	r.entities[entity.URN] = cloneProjectedEntity(entity)
	return nil
}

func (r *projectionRecorder) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if r.links == nil {
		r.links = make(map[string]*ports.ProjectedLink)
	}
	r.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = cloneProjectedLink(link)
	return nil
}

func (r *projectionRecorder) DeleteProjectedEntity(_ context.Context, urn string) error {
	delete(r.entities, urn)
	for key, link := range r.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(r.links, key)
		}
	}
	return nil
}

func (r *projectionRecorder) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	delete(r.links, link.FromURN+"|"+link.Relation+"|"+link.ToURN)
	return nil
}

func (r *projectionRecorder) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	findingURN, _ := request.Params["finding_urn"].(string)
	tenantID, _ := request.Params["tenant_id"].(string)
	lastSeen, _ := request.Params["last_seen"].(string)
	limit := request.RowLimit
	if limit <= 0 {
		limit = ports.MaxCypherQueryRows
	}
	if strings.Contains(request.Query, "context_urn") {
		allowedTypes := map[string]struct{}{}
		if entityTypes, ok := request.Params["entity_types"].([]string); ok {
			for _, entityType := range entityTypes {
				allowedTypes[entityType] = struct{}{}
			}
		}
		matching := make([]string, 0, len(r.links))
		for _, link := range r.links {
			if link == nil || link.FromURN != findingURN || link.Relation != relationHasContext {
				continue
			}
			if tenantID != "" && link.TenantID != tenantID {
				continue
			}
			if link.ToURN <= lastSeen {
				continue
			}
			entity := r.entities[link.ToURN]
			if len(allowedTypes) != 0 {
				if entity == nil {
					continue
				}
				if _, ok := allowedTypes[entity.EntityType]; !ok {
					continue
				}
			}
			matching = append(matching, link.ToURN)
		}
		sort.Strings(matching)
		if len(matching) > limit {
			matching = matching[:limit]
		}
		rows := make([]ports.CypherRow, 0, len(matching))
		for _, urn := range matching {
			rows = append(rows, ports.CypherRow{Values: map[string]any{"context_urn": urn}})
		}
		return rows, nil
	}
	matching := make([]string, 0, len(r.links))
	for _, link := range r.links {
		if link == nil || link.ToURN != findingURN || link.Relation != relationHasFinding {
			continue
		}
		if tenantID != "" && link.TenantID != tenantID {
			continue
		}
		if link.FromURN <= lastSeen {
			continue
		}
		matching = append(matching, link.FromURN)
	}
	sort.Strings(matching)
	if len(matching) > limit {
		matching = matching[:limit]
	}
	rows := make([]ports.CypherRow, 0, len(matching))
	for _, urn := range matching {
		rows = append(rows, ports.CypherRow{Values: map[string]any{"resource_urn": urn}})
	}
	return rows, nil
}

func assertWorkflowLink(t *testing.T, recorder *projectionRecorder, fromURN string, relation string, toURN string) {
	t.Helper()
	if recorder == nil || recorder.links == nil {
		t.Fatalf("projected link %s|%s|%s missing: no links recorded", fromURN, relation, toURN)
	}
	if _, ok := recorder.links[fromURN+"|"+relation+"|"+toURN]; !ok {
		t.Fatalf("projected link %s|%s|%s missing", fromURN, relation, toURN)
	}
}

func projectedEntityByAttribute(recorder *projectionRecorder, entityType string, key string, value string) *ports.ProjectedEntity {
	if recorder == nil {
		return nil
	}
	for _, entity := range recorder.entities {
		if entity == nil || entity.EntityType != entityType {
			continue
		}
		if entity.Attributes[key] == value {
			return entity
		}
	}
	return nil
}

func (r *projectionRecorder) CleanupProjectedEntities(_ context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	allowed := map[string]struct{}{}
	for _, entityType := range request.EntityTypes {
		allowed[entityType] = struct{}{}
	}
	result := ports.ProjectionCleanupResult{}
	for urn, entity := range r.entities {
		if entity == nil {
			continue
		}
		if request.TenantID != "" && entity.TenantID != request.TenantID {
			continue
		}
		if request.SourceID != "" && entity.SourceID != request.SourceID {
			continue
		}
		if request.FindingID != "" && entity.Attributes["finding_id"] != request.FindingID {
			continue
		}
		if len(allowed) != 0 {
			if _, ok := allowed[entity.EntityType]; !ok {
				continue
			}
		}
		if request.OnlyIsolated && request.FindingID == "" && projectionEntityHasLinks(r.links, urn) {
			continue
		}
		delete(r.entities, urn)
		for key, link := range r.links {
			if link.FromURN == urn || link.ToURN == urn {
				delete(r.links, key)
			}
		}
		result.EntitiesDeleted++
	}
	return result, nil
}

func projectionEntityHasLinks(links map[string]*ports.ProjectedLink, urn string) bool {
	for _, link := range links {
		if link.FromURN == urn || link.ToURN == urn {
			return true
		}
	}
	return false
}

func TestProjectKnowledgeWorkflowEvents(t *testing.T) {
	graph := &projectionRecorder{}
	service := New(graph)
	targetURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	decisionEvent, err := workflowevents.NewDecisionRecordedEvent(workflowevents.DecisionRecorded{
		TenantID:      "writer",
		DecisionID:    "urn:cerebro:writer:decision:decision-1",
		DecisionType:  "finding-triage",
		Status:        "approved",
		Rationale:     "accepted risk pending remediation",
		TargetIDs:     []string{targetURN},
		EvidenceIDs:   []string{"finding-evidence-1"},
		SourceSystem:  "findings",
		SourceEventID: "decision-source-event-1",
		ObservedAt:    "2026-04-27T12:00:00Z",
		ValidFrom:     "2026-04-27T12:00:00Z",
		Confidence:    0.91,
	})
	if err != nil {
		t.Fatalf("NewDecisionRecordedEvent() error = %v", err)
	}
	decisionResult, err := service.Project(context.Background(), decisionEvent)
	if err != nil {
		t.Fatalf("Project(decision) error = %v", err)
	}
	if decisionResult.EntitiesProjected != 2 {
		t.Fatalf("decision entities projected = %d, want 2", decisionResult.EntitiesProjected)
	}
	decisionTargetLink, ok := graph.links["urn:cerebro:writer:decision:decision-1|targets|"+targetURN]
	if !ok {
		t.Fatal("decision target link missing")
	}
	if got := decisionTargetLink.Attributes["source_event_id"]; got != "decision-source-event-1" {
		t.Fatalf("decision target source_event_id = %q", got)
	}
	if got := decisionTargetLink.Attributes["confidence"]; got != "0.91" {
		t.Fatalf("decision target confidence = %q", got)
	}
	if _, ok := graph.links["urn:cerebro:writer:decision:decision-1|based_on|urn:cerebro:writer:evidence:finding-evidence-1"]; !ok {
		t.Fatal("decision evidence link missing")
	}

	actionEvent, err := workflowevents.NewActionRecordedEvent(workflowevents.ActionRecorded{
		TenantID:         "writer",
		ActionID:         "urn:cerebro:writer:action:action-1",
		ActionType:       "remediation",
		Status:           "recorded",
		RecommendationID: "recommendation-1",
		Title:            "Open remediation ticket",
		DecisionID:       "urn:cerebro:writer:decision:decision-1",
		TargetIDs:        []string{targetURN},
		SourceSystem:     "platform.recommendations",
		SourceEventID:    "action-source-event-1",
		ObservedAt:       "2026-04-27T13:00:00Z",
		ValidFrom:        "2026-04-27T13:00:00Z",
		Confidence:       0.88,
		AutoGenerated:    true,
	})
	if err != nil {
		t.Fatalf("NewActionRecordedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), actionEvent); err != nil {
		t.Fatalf("Project(action) error = %v", err)
	}
	actionTargetLink, ok := graph.links["urn:cerebro:writer:action:action-1|targets|"+targetURN]
	if !ok {
		t.Fatal("action target link missing")
	}
	if got := actionTargetLink.Attributes["source_system"]; got != "platform.recommendations" {
		t.Fatalf("action target source_system = %q", got)
	}
	if got := actionTargetLink.Attributes["source_event_id"]; got != "action-source-event-1" {
		t.Fatalf("action target source_event_id = %q", got)
	}
	if _, ok := graph.links["urn:cerebro:writer:decision:decision-1|executed_by|urn:cerebro:writer:action:action-1"]; !ok {
		t.Fatal("decision action link missing")
	}

	outcomeEvent, err := workflowevents.NewOutcomeRecordedEvent(workflowevents.OutcomeRecorded{
		TenantID:      "writer",
		OutcomeID:     "urn:cerebro:writer:outcome:outcome-1",
		DecisionID:    "urn:cerebro:writer:decision:decision-1",
		OutcomeType:   "finding-resolution",
		Verdict:       "resolved",
		TargetIDs:     []string{targetURN},
		SourceSystem:  "findings",
		SourceEventID: "outcome-source-event-1",
		ObservedAt:    "2026-04-27T14:00:00Z",
		ValidFrom:     "2026-04-27T14:00:00Z",
		Confidence:    0.97,
	})
	if err != nil {
		t.Fatalf("NewOutcomeRecordedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), outcomeEvent); err != nil {
		t.Fatalf("Project(outcome) error = %v", err)
	}
	outcomeEvaluatesLink, ok := graph.links["urn:cerebro:writer:outcome:outcome-1|evaluates|urn:cerebro:writer:decision:decision-1"]
	if !ok {
		t.Fatal("outcome evaluates link missing")
	}
	if got := outcomeEvaluatesLink.Attributes["source_event_id"]; got != "outcome-source-event-1" {
		t.Fatalf("outcome evaluates source_event_id = %q", got)
	}
	outcomeTargetLink, ok := graph.links["urn:cerebro:writer:outcome:outcome-1|targets|"+targetURN]
	if !ok {
		t.Fatal("outcome target link missing")
	}
	if got := outcomeTargetLink.Attributes["valid_from"]; got != "2026-04-27T14:00:00Z" {
		t.Fatalf("outcome target valid_from = %q", got)
	}

	if _, err := service.Project(context.Background(), outcomeEvent); err != nil {
		t.Fatalf("Project(outcome replay) error = %v", err)
	}
	if got := len(graph.entities); got != 4 {
		t.Fatalf("len(entities) after replay = %d, want 4", got)
	}
}

func TestProjectFindingWorkflowEvents(t *testing.T) {
	graph := &projectionRecorder{}
	service := New(graph)
	finding := workflowevents.FindingSnapshot{
		TenantID:           "writer",
		SourceSystem:       "writer-okta-audit",
		FindingID:          "finding-1",
		Fingerprint:        "fp-1",
		Title:              "Okta Policy Rule Lifecycle Tampering",
		Summary:            "policy rule was deactivated by a privileged actor",
		RuleID:             "identity-okta-policy-rule-lifecycle-tampering",
		Severity:           "high",
		Status:             "open",
		RuntimeID:          "writer-okta-audit",
		PrimaryResourceURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		ResourceURNs:       []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
		EventIDs:           []string{"evt-1", "evt-2"},
		FirstObservedAt:    "2026-04-27T11:58:00Z",
		LastObservedAt:     "2026-04-27T11:59:00Z",
		ResourceCount:      1,
		EventCount:         2,
		FindingRiskSnapshot: workflowevents.FindingRiskSnapshot{
			RiskScore:         47,
			EffectiveSeverity: "MEDIUM",
			ConfidenceScore:   80,
			RiskReasons:       []string{"privileged_actor", "risky_action"},
		},
		Metadata: map[string]string{
			"actor_urn":         "urn:cerebro:writer:okta_actor:user:00u1",
			"coverage_status":   "gap",
			"d3fend_artifact":   "Credential",
			"d3fend_technique":  "Multi-factorAuthentication",
			"evidence_surface":  "identity",
			"resource_type":     "okta_resource",
			"rule_mitre_attack": "Initial Access:T1190",
			"rule_tags":         "okta,identity,defense-evasion,attack.t1562,mitre-ta0005",
			"source_family":     "okta",
		},
	}
	recordedEvent, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    finding,
		RecordedAt: "2026-04-27T11:59:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), recordedEvent); err != nil {
		t.Fatalf("Project(recorded) error = %v", err)
	}
	findingEntity, ok := graph.entities["urn:cerebro:writer:finding:finding-1"]
	if !ok {
		t.Fatal("finding anchor missing after recorded event")
	}
	if got := findingEntity.Attributes["risk_score"]; got != "47" {
		t.Fatalf("finding risk_score attribute = %q, want 47", got)
	}
	if got := findingEntity.Attributes["effective_severity"]; got != "MEDIUM" {
		t.Fatalf("finding effective_severity attribute = %q, want MEDIUM", got)
	}
	if got := findingEntity.Attributes["event_count"]; got != "2" {
		t.Fatalf("finding event_count attribute = %q, want 2", got)
	}
	if got := findingEntity.Attributes["actor_urn"]; got != "urn:cerebro:writer:okta_actor:user:00u1" {
		t.Fatalf("finding actor_urn attribute = %q, want normalized actor urn", got)
	}
	resourceFindingLink, ok := graph.links["urn:cerebro:writer:okta_resource:policyrule:pol-1|has_finding|urn:cerebro:writer:finding:finding-1"]
	if !ok {
		t.Fatal("resource finding link missing after recorded event")
	}
	if got := resourceFindingLink.Attributes["source_event_id"]; got != "evt-1" {
		t.Fatalf("has_finding source_event_id = %q", got)
	}
	if got := resourceFindingLink.Attributes["observed_at"]; got != "2026-04-27T11:59:00Z" {
		t.Fatalf("has_finding observed_at = %q", got)
	}
	if got := resourceFindingLink.Attributes["valid_from"]; got != "2026-04-27T11:58:00Z" {
		t.Fatalf("has_finding valid_from = %q", got)
	}
	if got := resourceFindingLink.Attributes["confidence"]; got != "0.8" {
		t.Fatalf("has_finding confidence = %q", got)
	}
	if _, ok := graph.links["urn:cerebro:writer:okta_user:00u1|has_finding|urn:cerebro:writer:finding:finding-1"]; !ok {
		t.Fatal("actor finding link missing after recorded event")
	}
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|has_context|urn:cerebro:writer:mitre_attack_technique:T1562"]; !ok {
		t.Fatal("finding MITRE ATT&CK technique context link missing after recorded event")
	}
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|has_context|urn:cerebro:writer:mitre_attack_tactic:TA0005"]; !ok {
		t.Fatal("finding MITRE ATT&CK tactic context link missing after recorded event")
	}
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|has_context|urn:cerebro:writer:mitre_attack_technique:T1190"]; !ok {
		t.Fatal("finding rule MITRE ATT&CK technique context link missing after recorded event")
	}
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|has_context|urn:cerebro:writer:mitre_attack_tactic:TA0001"]; !ok {
		t.Fatal("finding rule MITRE ATT&CK tactic context link missing after recorded event")
	}
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|has_context|urn:cerebro:writer:mitre_defend_technique:Multi-factorAuthentication"]; !ok {
		t.Fatal("finding MITRE D3FEND technique context link missing after recorded event")
	}
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|has_context|urn:cerebro:writer:mitre_defend_artifact:Credential"]; !ok {
		t.Fatal("finding MITRE D3FEND artifact context link missing after recorded event")
	}
	t1190CoverageURN := mitre.AttackCoverageURN("writer", "urn:cerebro:writer:finding:finding-1", "urn:cerebro:writer:mitre_attack_technique:T1190")
	t1190Coverage := graph.entities[t1190CoverageURN]
	if t1190Coverage == nil || t1190Coverage.EntityType != mitre.AttackCoverageEntityType {
		t.Fatalf("T1190 coverage entity = %#v, want MITRE ATT&CK coverage node", t1190Coverage)
	}
	if got := t1190Coverage.Attributes["coverage_state"]; got != "gap" {
		t.Fatalf("T1190 coverage_state = %q, want gap", got)
	}
	if got := t1190Coverage.Attributes["evidence_surface"]; got != "identity" {
		t.Fatalf("T1190 evidence_surface = %q, want identity", got)
	}
	assertWorkflowLink(t, graph, "urn:cerebro:writer:finding:finding-1", relationHasContext, t1190CoverageURN)
	assertWorkflowLink(t, graph, t1190CoverageURN, relationSupports, "urn:cerebro:writer:mitre_attack_technique:T1190")
	appLogComponent := projectedEntityByAttribute(graph, mitre.AttackDataComponentEntityType, "data_component_name", "Application Log Content")
	if appLogComponent == nil {
		t.Fatalf("MITRE ATT&CK data component Application Log Content missing: %#v", graph.entities)
	}
	appLogSource := projectedEntityByAttribute(graph, mitre.AttackDataSourceEntityType, "data_source_id", "DS0015")
	if appLogSource == nil {
		t.Fatalf("MITRE ATT&CK data source DS0015 missing: %#v", graph.entities)
	}
	assertWorkflowLink(t, graph, t1190CoverageURN, relationHasEvidence, appLogComponent.URN)
	assertWorkflowLink(t, graph, appLogComponent.URN, relationSupports, "urn:cerebro:writer:mitre_attack_technique:T1190")
	assertWorkflowLink(t, graph, appLogComponent.URN, relationBelongsTo, appLogSource.URN)
	assertWorkflowLink(t, graph, "urn:cerebro:writer:mitre_defend_technique:InboundTrafficFiltering", relationSupports, "urn:cerebro:writer:mitre_attack_technique:T1190")
	if _, ok := graph.links["urn:cerebro:writer:mitre_defend_technique:Multi-factorAuthentication|supports|urn:cerebro:writer:mitre_attack_technique:T1190"]; ok {
		t.Fatal("explicit D3FEND metadata should not create cross-product ATT&CK support links")
	}
	if _, ok := graph.links["urn:cerebro:writer:mitre_defend_technique:Multi-factorAuthentication|has_context|urn:cerebro:writer:mitre_defend_artifact:Credential"]; ok {
		t.Fatal("explicit D3FEND metadata should not create cross-product artifact links")
	}
	noteEvent, err := workflowevents.NewFindingNoteAddedEvent(workflowevents.FindingNoteAdded{
		Finding:   finding,
		NoteID:    "note-1",
		Body:      "Escalate to identity engineering.",
		CreatedAt: "2026-04-27T12:00:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingNoteAddedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), noteEvent); err != nil {
		t.Fatalf("Project(note) error = %v", err)
	}
	annotationURN := "urn:cerebro:writer:annotation:finding-note:finding-1:note-1"
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|annotated_with|"+annotationURN]; !ok {
		t.Fatal("finding annotation link missing")
	}

	ticketEvent, err := workflowevents.NewFindingTicketLinkedEvent(workflowevents.FindingTicketLinked{
		Finding:    finding,
		URL:        "https://jira.writer.com/browse/ENG-123",
		Name:       "ENG-123",
		ExternalID: "ENG-123",
		LinkedAt:   "2026-04-27T12:30:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingTicketLinkedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), ticketEvent); err != nil {
		t.Fatalf("Project(ticket) error = %v", err)
	}
	if _, ok := graph.entities["urn:cerebro:writer:finding:finding-1"]; !ok {
		t.Fatal("finding anchor missing")
	}
	if _, ok := graph.links["urn:cerebro:writer:okta_resource:policyrule:pol-1|has_finding|urn:cerebro:writer:finding:finding-1"]; !ok {
		t.Fatal("resource finding link missing")
	}

	externalRefEvent, err := workflowevents.NewFindingExternalRefLinkedEvent(workflowevents.FindingExternalRefLinked{
		Finding:        finding,
		System:         "panopticon",
		Kind:           "case",
		ExternalID:     "case-123",
		URL:            "https://panopticon.example/cases/123",
		ExternalStatus: "investigating",
		LifecycleOwner: "external_owned",
		LinkedAt:       "2026-04-27T12:35:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingExternalRefLinkedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), externalRefEvent); err != nil {
		t.Fatalf("Project(external ref) error = %v", err)
	}
	externalRefURN := findingExternalRefURN("writer", "panopticon", "case", "case-123")
	externalRefEntity := graph.entities[externalRefURN]
	if externalRefEntity == nil {
		t.Fatal("external ref entity missing")
	}
	if got := externalRefEntity.Attributes["lifecycle_owner"]; got != "external_owned" {
		t.Fatalf("external ref lifecycle_owner = %q, want external_owned", got)
	}
	if _, ok := graph.links["urn:cerebro:writer:finding:finding-1|tracked_by|"+externalRefURN]; !ok {
		t.Fatal("finding external ref link missing")
	}

	finding.Status = "resolved"
	manualStatusEvent, err := workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
		Finding:     finding,
		Status:      "resolved",
		Reason:      workflowevents.FindingStatusReasonNoLongerEmitted,
		Source:      workflowevents.FindingStatusSourceManual,
		UpdatedAt:   "2026-04-27T12:45:00Z",
		OutcomeType: "finding-resolution",
	})
	if err != nil {
		t.Fatalf("NewFindingStatusChangedEvent(manual) error = %v", err)
	}
	if _, err := service.Project(context.Background(), manualStatusEvent); err != nil {
		t.Fatalf("Project(manual status) error = %v", err)
	}
	if _, ok := graph.entities["urn:cerebro:writer:finding:finding-1"]; !ok {
		t.Fatal("manually resolved finding anchor should remain for workflow history")
	}
	if _, ok := graph.links["urn:cerebro:writer:okta_resource:policyrule:pol-1|has_finding|urn:cerebro:writer:finding:finding-1"]; ok {
		t.Fatal("manually resolved finding should not keep active has_finding link")
	}
	if _, ok := graph.links["urn:cerebro:writer:okta_user:00u1|has_finding|urn:cerebro:writer:finding:finding-1"]; ok {
		t.Fatal("manually resolved finding should not keep active actor has_finding link")
	}

	if _, err := service.Project(context.Background(), recordedEvent); err != nil {
		t.Fatalf("Project(recorded legacy manual reset) error = %v", err)
	}
	legacyManualStatusEvent, err := workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
		Finding:     finding,
		Status:      "resolved",
		Reason:      workflowevents.FindingStatusReasonNoLongerEmitted,
		DecisionID:  "urn:cerebro:writer:decision:finding-resolution",
		OutcomeID:   "urn:cerebro:writer:outcome:finding-resolution",
		UpdatedAt:   "2026-04-27T12:48:00Z",
		OutcomeType: "finding-resolution",
	})
	if err != nil {
		t.Fatalf("NewFindingStatusChangedEvent(legacy manual) error = %v", err)
	}
	if _, err := service.Project(context.Background(), legacyManualStatusEvent); err != nil {
		t.Fatalf("Project(legacy manual status) error = %v", err)
	}
	if _, ok := graph.entities["urn:cerebro:writer:finding:finding-1"]; !ok {
		t.Fatal("legacy manual finding status with workflow IDs should keep finding anchor")
	}

	if _, err := service.Project(context.Background(), recordedEvent); err != nil {
		t.Fatalf("Project(recorded legacy reset) error = %v", err)
	}
	legacyStatusEvent, err := workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
		Finding:     finding,
		Status:      "resolved",
		Reason:      workflowevents.FindingStatusReasonNoLongerEmitted,
		UpdatedAt:   "2026-04-27T12:50:00Z",
		OutcomeType: "finding-resolution",
	})
	if err != nil {
		t.Fatalf("NewFindingStatusChangedEvent(legacy) error = %v", err)
	}
	if _, err := service.Project(context.Background(), legacyStatusEvent); err != nil {
		t.Fatalf("Project(legacy status) error = %v", err)
	}
	if _, ok := graph.entities["urn:cerebro:writer:finding:finding-1"]; ok {
		t.Fatal("legacy stale finding status should prune finding anchor")
	}

	if _, err := service.Project(context.Background(), recordedEvent); err != nil {
		t.Fatalf("Project(recorded stale reset) error = %v", err)
	}
	finding.Status = "resolved"
	statusEvent, err := workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
		Finding:     finding,
		Status:      "resolved",
		Reason:      workflowevents.FindingStatusReasonNoLongerEmitted,
		Source:      workflowevents.FindingStatusSourceStaleEvaluation,
		UpdatedAt:   "2026-04-27T13:00:00Z",
		OutcomeType: "finding-resolution",
	})
	if err != nil {
		t.Fatalf("NewFindingStatusChangedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), statusEvent); err != nil {
		t.Fatalf("Project(status) error = %v", err)
	}
	if _, ok := graph.entities["urn:cerebro:writer:finding:finding-1"]; ok {
		t.Fatal("resolved finding anchor should be pruned from graph")
	}
	if _, ok := graph.links["urn:cerebro:writer:okta_resource:policyrule:pol-1|has_finding|urn:cerebro:writer:finding:finding-1"]; ok {
		t.Fatal("resolved finding has_finding link should be pruned from graph")
	}
	if _, ok := graph.links["urn:cerebro:writer:okta_user:00u1|has_finding|urn:cerebro:writer:finding:finding-1"]; ok {
		t.Fatal("resolved finding actor has_finding link should be pruned from graph")
	}
	if _, ok := graph.entities[annotationURN]; ok {
		t.Fatal("isolated finding note annotation should be pruned from graph")
	}
}

func TestProjectFindingRecordedLinksPrimaryResourceWhenResourceURNsEmpty(t *testing.T) {
	graph := &projectionRecorder{}
	service := New(graph)
	finding := workflowevents.FindingSnapshot{
		TenantID:           "example",
		SourceSystem:       "example-okta-audit",
		FindingID:          "finding-primary-only",
		Fingerprint:        "fp-primary-only",
		Title:              "Identity API Token Or OAuth App Created",
		Summary:            "OAuth credential was created",
		RuleID:             "identity-api-token-or-oauth-app-created",
		Severity:           "high",
		Status:             "open",
		PrimaryResourceURN: "urn:cerebro:example:okta_resource:oauth2clientsecretentity:secret-1",
	}
	recordedEvent, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    finding,
		RecordedAt: "2026-05-28T18:59:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), recordedEvent); err != nil {
		t.Fatalf("Project(recorded) error = %v", err)
	}
	linkKey := "urn:cerebro:example:okta_resource:oauth2clientsecretentity:secret-1|has_finding|urn:cerebro:example:finding:finding-primary-only"
	if _, ok := graph.links[linkKey]; !ok {
		t.Fatalf("primary resource finding link %q missing", linkKey)
	}

	finding.Status = "resolved"
	statusEvent, err := workflowevents.NewFindingStatusChangedEvent(workflowevents.FindingStatusChanged{
		Finding:     finding,
		Status:      "resolved",
		Reason:      "manually resolved",
		Source:      workflowevents.FindingStatusSourceManual,
		UpdatedAt:   "2026-05-28T19:00:00Z",
		OutcomeType: "finding-resolution",
	})
	if err != nil {
		t.Fatalf("NewFindingStatusChangedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), statusEvent); err != nil {
		t.Fatalf("Project(status) error = %v", err)
	}
	if _, ok := graph.links[linkKey]; ok {
		t.Fatalf("primary resource finding link %q should be removed after resolved status", linkKey)
	}
}

func TestProjectFindingRecordedPrunesStaleActiveLinks(t *testing.T) {
	graph := &projectionRecorder{}
	service := New(graph)
	finding := workflowevents.FindingSnapshot{
		TenantID:           "writer",
		SourceSystem:       "findings",
		FindingID:          "finding-shrinks",
		Fingerprint:        "fp-shrinks",
		Title:              "Shrinking resource finding",
		RuleID:             "graph-resource-multiple-open-findings",
		Severity:           "high",
		Status:             "open",
		RuntimeID:          "runtime-graph",
		PrimaryResourceURN: "urn:cerebro:writer:resource:a",
		ResourceURNs: []string{
			"urn:cerebro:writer:resource:a",
			"urn:cerebro:writer:resource:b",
		},
	}
	recordedEvent, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    finding,
		RecordedAt: "2026-04-27T11:59:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), recordedEvent); err != nil {
		t.Fatalf("Project(initial recorded) error = %v", err)
	}
	anchorURN := "urn:cerebro:writer:finding:finding-shrinks"
	if _, ok := graph.links["urn:cerebro:writer:resource:b|has_finding|"+anchorURN]; !ok {
		t.Fatal("initial secondary resource finding link missing")
	}

	graph.links["urn:cerebro:writer:resource:other|has_finding|urn:cerebro:writer:finding:other"] = &ports.ProjectedLink{
		TenantID: "writer",
		FromURN:  "urn:cerebro:writer:resource:other",
		ToURN:    "urn:cerebro:writer:finding:other",
		Relation: relationHasFinding,
	}
	finding.ResourceURNs = []string{"urn:cerebro:writer:resource:a"}
	recordedEvent, err = workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    finding,
		RecordedAt: "2026-04-27T12:01:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent(shrunk) error = %v", err)
	}
	result, err := service.Project(context.Background(), recordedEvent)
	if err != nil {
		t.Fatalf("Project(shrunk recorded) error = %v", err)
	}
	if result.LinksDeleted != 1 {
		t.Fatalf("LinksDeleted = %d, want 1", result.LinksDeleted)
	}
	if _, ok := graph.links["urn:cerebro:writer:resource:a|has_finding|"+anchorURN]; !ok {
		t.Fatal("current resource finding link was pruned")
	}
	if _, ok := graph.links["urn:cerebro:writer:resource:b|has_finding|"+anchorURN]; ok {
		t.Fatal("stale secondary resource finding link was not pruned")
	}
	if _, ok := graph.links["urn:cerebro:writer:resource:other|has_finding|urn:cerebro:writer:finding:other"]; !ok {
		t.Fatal("unrelated finding link was pruned")
	}
}

func TestProjectFindingRecordedPrunesStaleMITREContextLinks(t *testing.T) {
	graph := &projectionRecorder{}
	service := New(graph)
	finding := workflowevents.FindingSnapshot{
		TenantID:           "writer",
		SourceSystem:       "findings",
		FindingID:          "finding-mitre",
		Fingerprint:        "fp-mitre",
		Title:              "Finding with MITRE context",
		RuleID:             "policy-test",
		Severity:           "high",
		Status:             "open",
		RuntimeID:          "runtime-graph",
		PrimaryResourceURN: "urn:cerebro:writer:resource:a",
		ResourceURNs:       []string{"urn:cerebro:writer:resource:a"},
		Metadata: map[string]string{
			"rule_mitre_attack": "Initial Access:T1190",
		},
	}
	recordedEvent, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    finding,
		RecordedAt: "2026-04-27T11:59:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent(initial) error = %v", err)
	}
	if _, err := service.Project(context.Background(), recordedEvent); err != nil {
		t.Fatalf("Project(initial recorded) error = %v", err)
	}
	anchorURN := "urn:cerebro:writer:finding:finding-mitre"
	if _, ok := graph.links[anchorURN+"|has_context|urn:cerebro:writer:mitre_attack_technique:T1190"]; !ok {
		t.Fatal("initial MITRE ATT&CK technique link missing")
	}
	if _, ok := graph.links[anchorURN+"|has_context|urn:cerebro:writer:mitre_attack_tactic:TA0001"]; !ok {
		t.Fatal("initial MITRE ATT&CK tactic link missing")
	}
	initialCoverageURN := mitre.AttackCoverageURN("writer", anchorURN, "urn:cerebro:writer:mitre_attack_technique:T1190")
	if _, ok := graph.links[anchorURN+"|has_context|"+initialCoverageURN]; !ok {
		t.Fatal("initial MITRE ATT&CK coverage link missing")
	}

	finding.Metadata = map[string]string{
		"rule_mitre_attack": "Discovery:T1087",
	}
	recordedEvent, err = workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    finding,
		RecordedAt: "2026-04-27T12:05:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent(updated) error = %v", err)
	}
	result, err := service.Project(context.Background(), recordedEvent)
	if err != nil {
		t.Fatalf("Project(updated recorded) error = %v", err)
	}
	if result.LinksDeleted != 3 {
		t.Fatalf("LinksDeleted = %d, want 3 stale MITRE context links", result.LinksDeleted)
	}
	if _, ok := graph.links[anchorURN+"|has_context|urn:cerebro:writer:mitre_attack_technique:T1190"]; ok {
		t.Fatal("stale MITRE ATT&CK technique link was not pruned")
	}
	if _, ok := graph.links[anchorURN+"|has_context|urn:cerebro:writer:mitre_attack_tactic:TA0001"]; ok {
		t.Fatal("stale MITRE ATT&CK tactic link was not pruned")
	}
	if _, ok := graph.links[anchorURN+"|has_context|"+initialCoverageURN]; ok {
		t.Fatal("stale MITRE ATT&CK coverage link was not pruned")
	}
	if _, ok := graph.links[anchorURN+"|has_context|urn:cerebro:writer:mitre_attack_technique:T1087"]; !ok {
		t.Fatal("updated MITRE ATT&CK technique link missing")
	}
	if _, ok := graph.links[anchorURN+"|has_context|urn:cerebro:writer:mitre_attack_tactic:TA0007"]; !ok {
		t.Fatal("updated MITRE ATT&CK tactic link missing")
	}
	updatedCoverageURN := mitre.AttackCoverageURN("writer", anchorURN, "urn:cerebro:writer:mitre_attack_technique:T1087")
	if _, ok := graph.links[anchorURN+"|has_context|"+updatedCoverageURN]; !ok {
		t.Fatal("updated MITRE ATT&CK coverage link missing")
	}
}

func TestProjectFindingRecordedPrunesBeyondCypherRowLimit(t *testing.T) {
	graph := &projectionRecorder{links: map[string]*ports.ProjectedLink{}}
	service := New(graph)
	anchorURN := "urn:cerebro:writer:finding:legacy-overflow"
	staleCount := ports.MaxCypherQueryRows + 25
	for i := 0; i < staleCount; i++ {
		resourceURN := fmt.Sprintf("urn:cerebro:writer:resource:legacy-%06d", i)
		graph.links[resourceURN+"|has_finding|"+anchorURN] = &ports.ProjectedLink{
			TenantID: "writer",
			FromURN:  resourceURN,
			ToURN:    anchorURN,
			Relation: relationHasFinding,
		}
	}

	finding := workflowevents.FindingSnapshot{
		TenantID:           "writer",
		SourceSystem:       "findings",
		FindingID:          "legacy-overflow",
		Fingerprint:        "fp-legacy-overflow",
		Title:              "Legacy overflow finding",
		RuleID:             "graph-resource-multiple-open-findings",
		Severity:           "high",
		Status:             "open",
		RuntimeID:          "runtime-graph",
		PrimaryResourceURN: "urn:cerebro:writer:resource:keep",
		ResourceURNs:       []string{"urn:cerebro:writer:resource:keep"},
	}
	recordedEvent, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    finding,
		RecordedAt: "2026-05-27T07:30:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	result, err := service.Project(context.Background(), recordedEvent)
	if err != nil {
		t.Fatalf("Project(legacy overflow) error = %v", err)
	}
	if int(result.LinksDeleted) != staleCount {
		t.Fatalf("LinksDeleted = %d, want %d", result.LinksDeleted, staleCount)
	}
	for key, link := range graph.links {
		if link == nil || link.ToURN != anchorURN {
			continue
		}
		if link.FromURN != "urn:cerebro:writer:resource:keep" {
			t.Fatalf("stale legacy link %s survived pruning", key)
		}
	}
}

func cloneProjectedEntity(entity *ports.ProjectedEntity) *ports.ProjectedEntity {
	attributes := make(map[string]string, len(entity.Attributes))
	for key, value := range entity.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		RuntimeID:  entity.RuntimeID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
}

func cloneProjectedLink(link *ports.ProjectedLink) *ports.ProjectedLink {
	attributes := make(map[string]string, len(link.Attributes))
	for key, value := range link.Attributes {
		attributes[key] = value
	}
	return &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		RuntimeID:  link.RuntimeID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
}
