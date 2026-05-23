package workflowprojection

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type tombstoneGraphSpy struct {
	*projectionRecorder
	upsertEntityCalls int
	upsertLinkCalls   int
	deleteEntityCalls int
	deleteLinkCalls   int
	cleanupCalls      int
	deletedLinks      []*ports.ProjectedLink
}

func newTombstoneGraphSpy() *tombstoneGraphSpy {
	return &tombstoneGraphSpy{projectionRecorder: &projectionRecorder{}}
}

func (s *tombstoneGraphSpy) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	s.upsertEntityCalls++
	return s.projectionRecorder.UpsertProjectedEntity(ctx, entity)
}

func (s *tombstoneGraphSpy) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	s.upsertLinkCalls++
	return s.projectionRecorder.UpsertProjectedLink(ctx, link)
}

func (s *tombstoneGraphSpy) DeleteProjectedEntity(ctx context.Context, urn string) error {
	s.deleteEntityCalls++
	return s.projectionRecorder.DeleteProjectedEntity(ctx, urn)
}

func (s *tombstoneGraphSpy) DeleteProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	s.deleteLinkCalls++
	s.deletedLinks = append(s.deletedLinks, cloneProjectedLink(link))
	return s.projectionRecorder.DeleteProjectedLink(ctx, link)
}

func (s *tombstoneGraphSpy) CleanupProjectedEntities(ctx context.Context, req ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	s.cleanupCalls++
	return s.projectionRecorder.CleanupProjectedEntities(ctx, req)
}

func tombstonedFindingSnapshot(findingID, anchorURN string) workflowevents.FindingSnapshot {
	return workflowevents.FindingSnapshot{
		TenantID:           "writer",
		SourceSystem:       "writer-okta-audit",
		FindingID:          findingID,
		Fingerprint:        "fp-" + findingID,
		Title:              "Okta Policy Rule Lifecycle Tampering",
		RuleID:             "identity-okta-policy-rule-lifecycle-tampering",
		Severity:           "high",
		Status:             "resolved",
		RuntimeID:          "writer-okta-audit",
		PrimaryResourceURN: anchorURN,
		ResourceURNs:       []string{anchorURN},
		FirstObservedAt:    "2026-04-27T11:58:00Z",
		LastObservedAt:     "2026-04-27T11:59:00Z",
	}
}

func canonicalFindingTombstonedPayload(findingID, anchorURN, priorStatus string) workflowevents.FindingTombstoned {
	return workflowevents.FindingTombstoned{
		Finding:      tombstonedFindingSnapshot(findingID, anchorURN),
		PriorStatus:  priorStatus,
		Reason:       "bulk closeout: pre-conversion backlog",
		Actor:        "operator@writer.com",
		RunID:        "run-2026-04-27-001",
		TombstonedAt: "2026-04-27T12:00:00Z",
	}
}

func TestProject_DispatchesFindingTombstoned(t *testing.T) {
	graph := newTombstoneGraphSpy()
	service := New(graph)
	anchorURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	findingID := "finding-1"

	finding := tombstonedFindingSnapshot(findingID, anchorURN)
	recorded, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
		Finding:    workflowevents.FindingSnapshot{TenantID: finding.TenantID, SourceSystem: finding.SourceSystem, FindingID: findingID, Fingerprint: finding.Fingerprint, Title: finding.Title, RuleID: finding.RuleID, Severity: finding.Severity, Status: "open", RuntimeID: finding.RuntimeID, PrimaryResourceURN: anchorURN, ResourceURNs: []string{anchorURN}, FirstObservedAt: finding.FirstObservedAt, LastObservedAt: finding.LastObservedAt},
		RecordedAt: "2026-04-27T11:59:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingRecordedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), recorded); err != nil {
		t.Fatalf("Project(recorded) error = %v", err)
	}

	upsertsBefore := graph.upsertEntityCalls + graph.upsertLinkCalls
	deletesBefore := graph.deleteLinkCalls

	event, err := workflowevents.NewFindingTombstonedEvent(canonicalFindingTombstonedPayload(findingID, anchorURN, "open"))
	if err != nil {
		t.Fatalf("NewFindingTombstonedEvent() error = %v", err)
	}
	result, err := service.Project(context.Background(), event)
	if err != nil {
		t.Fatalf("Project(tombstoned) error = %v", err)
	}
	if got := graph.deleteLinkCalls - deletesBefore; got != 1 {
		t.Fatalf("DeleteProjectedLink calls during tombstone dispatch = %d, want 1", got)
	}
	if got := graph.upsertEntityCalls + graph.upsertLinkCalls - upsertsBefore; got != 0 {
		t.Fatalf("upsert calls during tombstone dispatch = %d, want 0", got)
	}
	if result.LinksDeleted != 1 {
		t.Fatalf("result.LinksDeleted = %d, want 1", result.LinksDeleted)
	}
	expectedLinkKey := anchorURN + "|" + relationHasFinding + "|" + findingURN(finding.TenantID, findingID)
	if _, ok := graph.links[expectedLinkKey]; ok {
		t.Fatalf("expected link %q to be deleted but it is still present", expectedLinkKey)
	}
}

func TestProjectFindingTombstoned_CallsOnlyDeleteFindingActiveLinks(t *testing.T) {
	graph := newTombstoneGraphSpy()
	service := New(graph)
	anchorURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	findingID := "finding-1"

	graph.entities = map[string]*ports.ProjectedEntity{
		anchorURN:                       {URN: anchorURN, TenantID: "writer", SourceID: "writer-okta-audit", EntityType: "okta_resource"},
		findingURN("writer", findingID): {URN: findingURN("writer", findingID), TenantID: "writer", SourceID: "writer-okta-audit", EntityType: findingEntityType},
	}
	graph.links = map[string]*ports.ProjectedLink{
		anchorURN + "|" + relationHasFinding + "|" + findingURN("writer", findingID): {
			TenantID: "writer",
			SourceID: "writer-okta-audit",
			FromURN:  anchorURN,
			ToURN:    findingURN("writer", findingID),
			Relation: relationHasFinding,
		},
	}

	event, err := workflowevents.NewFindingTombstonedEvent(canonicalFindingTombstonedPayload(findingID, anchorURN, "open"))
	if err != nil {
		t.Fatalf("NewFindingTombstonedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project(tombstoned) error = %v", err)
	}

	if graph.upsertEntityCalls != 0 {
		t.Fatalf("UpsertProjectedEntity calls = %d, want 0", graph.upsertEntityCalls)
	}
	if graph.upsertLinkCalls != 0 {
		t.Fatalf("UpsertProjectedLink calls = %d, want 0", graph.upsertLinkCalls)
	}
	if graph.deleteEntityCalls != 0 {
		t.Fatalf("DeleteProjectedEntity calls = %d, want 0", graph.deleteEntityCalls)
	}
	if graph.cleanupCalls != 0 {
		t.Fatalf("CleanupProjectedEntities calls = %d, want 0", graph.cleanupCalls)
	}
	if graph.deleteLinkCalls != 1 {
		t.Fatalf("DeleteProjectedLink calls = %d, want 1", graph.deleteLinkCalls)
	}
	if len(graph.deletedLinks) != 1 {
		t.Fatalf("deletedLinks length = %d, want 1", len(graph.deletedLinks))
	}
	got := graph.deletedLinks[0]
	if got.FromURN != anchorURN {
		t.Fatalf("deleted link FromURN = %q, want %q", got.FromURN, anchorURN)
	}
	if got.ToURN != findingURN("writer", findingID) {
		t.Fatalf("deleted link ToURN = %q, want %q", got.ToURN, findingURN("writer", findingID))
	}
	if got.Relation != relationHasFinding {
		t.Fatalf("deleted link Relation = %q, want %q", got.Relation, relationHasFinding)
	}
}

func TestProjector_FindingTombstoned_RemovesOnlyOwnEdges(t *testing.T) {
	graph := newTombstoneGraphSpy()
	service := New(graph)
	anchorURN := "urn:cerebro:writer:okta_resource:policyrule:pol-1"
	siblingFindingID := "finding-2"
	tombstoneFindingID := "finding-1"

	for _, id := range []string{tombstoneFindingID, siblingFindingID} {
		recorded, err := workflowevents.NewFindingRecordedEvent(workflowevents.FindingRecorded{
			Finding: workflowevents.FindingSnapshot{
				TenantID:           "writer",
				SourceSystem:       "writer-okta-audit",
				FindingID:          id,
				Fingerprint:        "fp-" + id,
				Title:              "Okta Policy Rule Lifecycle Tampering",
				RuleID:             "identity-okta-policy-rule-lifecycle-tampering",
				Severity:           "high",
				Status:             "open",
				RuntimeID:          "writer-okta-audit",
				PrimaryResourceURN: anchorURN,
				ResourceURNs:       []string{anchorURN},
				FirstObservedAt:    "2026-04-27T11:58:00Z",
				LastObservedAt:     "2026-04-27T11:59:00Z",
			},
			RecordedAt: "2026-04-27T11:59:00Z",
		})
		if err != nil {
			t.Fatalf("NewFindingRecordedEvent(%s) error = %v", id, err)
		}
		if _, err := service.Project(context.Background(), recorded); err != nil {
			t.Fatalf("Project(recorded %s) error = %v", id, err)
		}
	}

	noteEvent, err := workflowevents.NewFindingNoteAddedEvent(workflowevents.FindingNoteAdded{
		Finding: workflowevents.FindingSnapshot{
			TenantID:           "writer",
			SourceSystem:       "writer-okta-audit",
			FindingID:          siblingFindingID,
			Fingerprint:        "fp-" + siblingFindingID,
			Status:             "open",
			RuntimeID:          "writer-okta-audit",
			PrimaryResourceURN: anchorURN,
			ResourceURNs:       []string{anchorURN},
		},
		NoteID:    "note-sibling",
		Body:      "Investigate root cause.",
		CreatedAt: "2026-04-27T12:05:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingNoteAddedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), noteEvent); err != nil {
		t.Fatalf("Project(note) error = %v", err)
	}
	ticketEvent, err := workflowevents.NewFindingTicketLinkedEvent(workflowevents.FindingTicketLinked{
		Finding: workflowevents.FindingSnapshot{
			TenantID:           "writer",
			SourceSystem:       "writer-okta-audit",
			FindingID:          siblingFindingID,
			Fingerprint:        "fp-" + siblingFindingID,
			Status:             "open",
			RuntimeID:          "writer-okta-audit",
			PrimaryResourceURN: anchorURN,
			ResourceURNs:       []string{anchorURN},
		},
		URL:        "https://jira.writer.com/browse/SEC-1",
		Name:       "SEC-1",
		ExternalID: "SEC-1",
		LinkedAt:   "2026-04-27T12:06:00Z",
	})
	if err != nil {
		t.Fatalf("NewFindingTicketLinkedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), ticketEvent); err != nil {
		t.Fatalf("Project(ticket) error = %v", err)
	}

	graph.entities[anchorURN] = &ports.ProjectedEntity{
		URN:        anchorURN,
		TenantID:   "writer",
		SourceID:   "writer-okta-audit",
		EntityType: "okta_resource",
		Label:      "policyrule:pol-1",
	}

	tombstoneFindingURN := findingURN("writer", tombstoneFindingID)
	siblingFindingURNValue := findingURN("writer", siblingFindingID)
	tombstoneEdgeKey := anchorURN + "|" + relationHasFinding + "|" + tombstoneFindingURN
	siblingEdgeKey := anchorURN + "|" + relationHasFinding + "|" + siblingFindingURNValue
	if _, ok := graph.links[tombstoneEdgeKey]; !ok {
		t.Fatalf("pre-condition: tombstone finding edge %q missing", tombstoneEdgeKey)
	}
	if _, ok := graph.links[siblingEdgeKey]; !ok {
		t.Fatalf("pre-condition: sibling finding edge %q missing", siblingEdgeKey)
	}

	event, err := workflowevents.NewFindingTombstonedEvent(canonicalFindingTombstonedPayload(tombstoneFindingID, anchorURN, "open"))
	if err != nil {
		t.Fatalf("NewFindingTombstonedEvent() error = %v", err)
	}
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project(tombstoned) error = %v", err)
	}

	if _, ok := graph.links[tombstoneEdgeKey]; ok {
		t.Fatalf("tombstone finding edge %q must be removed", tombstoneEdgeKey)
	}
	if _, ok := graph.links[siblingEdgeKey]; !ok {
		t.Fatalf("sibling finding edge %q must remain after tombstone", siblingEdgeKey)
	}
	if _, ok := graph.entities[anchorURN]; !ok {
		t.Fatalf("anchor entity %q must remain after tombstone", anchorURN)
	}
	if _, ok := graph.entities[tombstoneFindingURN]; !ok {
		t.Fatalf("tombstoned finding entity %q must remain (row kept for audit)", tombstoneFindingURN)
	}
	if _, ok := graph.entities[siblingFindingURNValue]; !ok {
		t.Fatalf("sibling finding entity %q must remain after tombstone", siblingFindingURNValue)
	}

	annotationURN := findingAnnotationURN("writer", siblingFindingID, "note-sibling", "Investigate root cause.", "2026-04-27T12:05:00Z")
	if _, ok := graph.entities[annotationURN]; !ok {
		t.Fatalf("sibling annotation entity %q must remain after tombstone", annotationURN)
	}
	annotationEdgeKey := siblingFindingURNValue + "|" + relationAnnotatedWith + "|" + annotationURN
	if _, ok := graph.links[annotationEdgeKey]; !ok {
		t.Fatalf("sibling annotation edge %q must remain after tombstone", annotationEdgeKey)
	}
	ticketURN := findingTicketURN("writer", "https://jira.writer.com/browse/SEC-1")
	if _, ok := graph.entities[ticketURN]; !ok {
		t.Fatalf("sibling ticket entity %q must remain after tombstone", ticketURN)
	}
	ticketEdgeKey := siblingFindingURNValue + "|" + relationTrackedBy + "|" + ticketURN
	if _, ok := graph.links[ticketEdgeKey]; !ok {
		t.Fatalf("sibling ticket edge %q must remain after tombstone", ticketEdgeKey)
	}

	if graph.deleteEntityCalls != 0 {
		t.Fatalf("DeleteProjectedEntity calls during tombstone = %d, want 0", graph.deleteEntityCalls)
	}
	if graph.cleanupCalls != 0 {
		t.Fatalf("CleanupProjectedEntities calls during tombstone = %d, want 0", graph.cleanupCalls)
	}
	if len(graph.deletedLinks) != 1 {
		t.Fatalf("deletedLinks length = %d, want 1", len(graph.deletedLinks))
	}
	deleted := graph.deletedLinks[0]
	if deleted.FromURN != anchorURN || deleted.ToURN != tombstoneFindingURN || deleted.Relation != relationHasFinding {
		t.Fatalf("deleted link = %+v, want has_finding(%s -> %s)", deleted, anchorURN, tombstoneFindingURN)
	}
}
