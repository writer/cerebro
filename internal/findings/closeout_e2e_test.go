package findings

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/workflowevents"
)

type e2eGraphFake struct {
	entities map[string]*ports.ProjectedEntity
	links    map[string]*ports.ProjectedLink
}

func newE2EGraphFake() *e2eGraphFake {
	return &e2eGraphFake{
		entities: map[string]*ports.ProjectedEntity{},
		links:    map[string]*ports.ProjectedLink{},
	}
}

func (g *e2eGraphFake) Ping(context.Context) error { return nil }

func (g *e2eGraphFake) UpsertProjectedEntity(_ context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return nil
	}
	attributes := make(map[string]string, len(entity.Attributes))
	for k, v := range entity.Attributes {
		attributes[k] = v
	}
	g.entities[entity.URN] = &ports.ProjectedEntity{
		URN:        entity.URN,
		TenantID:   entity.TenantID,
		SourceID:   entity.SourceID,
		EntityType: entity.EntityType,
		Label:      entity.Label,
		Attributes: attributes,
	}
	return nil
}

func (g *e2eGraphFake) UpsertProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	attributes := make(map[string]string, len(link.Attributes))
	for k, v := range link.Attributes {
		attributes[k] = v
	}
	g.links[link.FromURN+"|"+link.Relation+"|"+link.ToURN] = &ports.ProjectedLink{
		TenantID:   link.TenantID,
		SourceID:   link.SourceID,
		FromURN:    link.FromURN,
		ToURN:      link.ToURN,
		Relation:   link.Relation,
		Attributes: attributes,
	}
	return nil
}

func (g *e2eGraphFake) DeleteProjectedLink(_ context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return nil
	}
	delete(g.links, link.FromURN+"|"+link.Relation+"|"+link.ToURN)
	return nil
}

func (g *e2eGraphFake) DeleteProjectedEntity(_ context.Context, urn string) error {
	delete(g.entities, urn)
	for key, link := range g.links {
		if link.FromURN == urn || link.ToURN == urn {
			delete(g.links, key)
		}
	}
	return nil
}

// TestService_TombstonedFindingEmitMintsFreshGraphEdge exercises the
// tombstone-then-emit lifecycle end-to-end (architecture components 4 + 5 + 6
// together): a finding F1 on anchor A is tombstoned via TombstoneFindingsBulk
// which removes has_finding(A → F1), then a fresh upstream emit on the same
// (rule_id, anchor_uri, fingerprint) mints F2 with tombstoned=FALSE and the
// incremented tombstone_generation, replays through the workflow events stream,
// and restores has_finding(A → F2) in the graph.
func TestService_TombstonedFindingEmitMintsFreshGraphEdge(t *testing.T) {
	fx := newCloseoutFixture(t)
	graph := newE2EGraphFake()
	fx.service.WithGraphStore(graph)

	anchor := "urn:cerebro:tenant-a:github_repo:writer/cerebro"
	fingerprint := "fp-stable-target"
	baseID := "f-stable"

	first := fx.seedFinding(baseID, "open", fx.now.Add(-48*time.Hour), func(f *ports.FindingRecord) {
		f.Fingerprint = fingerprint
		f.ResourceURNs = []string{anchor}
		f.EventIDs = []string{"event-initial-emit"}
	})
	ctx := context.Background()
	if err := fx.service.projectFindingAnchor(ctx, fx.store.findings[first.ID]); err != nil {
		t.Fatalf("project F1 anchor: %v", err)
	}

	firstAnchorEdgeKey := anchor + "|" + "has_finding" + "|" + findingGraphFindingURN(fx.tenantID, fx.store.findings[first.ID])
	if _, ok := graph.links[firstAnchorEdgeKey]; !ok {
		t.Fatalf("pre-condition: missing has_finding(A → F1) edge %q (links=%v)", firstAnchorEdgeKey, graph.links)
	}

	result, err := fx.service.TombstoneFindingsBulk(ctx, fx.request("run-e2e-1", false))
	if err != nil {
		t.Fatalf("TombstoneFindingsBulk: %v", err)
	}
	if result.AppliedCount != 1 {
		t.Fatalf("AppliedCount = %d, want 1", result.AppliedCount)
	}

	tombstonedF1 := fx.store.findings[first.ID]
	if !tombstonedF1.Tombstoned {
		t.Fatalf("F1.Tombstoned = false, want true after bulk tombstone")
	}
	if _, ok := graph.links[firstAnchorEdgeKey]; ok {
		t.Fatalf("expected has_finding(A → F1) edge %q to be removed after tombstone", firstAnchorEdgeKey)
	}
	tombstoneEvents := 0
	for _, evt := range fx.appendLog.events {
		if evt.GetKind() == workflowevents.EventKindFindingTombstoned {
			tombstoneEvents++
		}
	}
	if tombstoneEvents != 1 {
		t.Fatalf("FindingTombstoned events emitted for F1 = %d, want 1", tombstoneEvents)
	}

	nextGeneration := tombstonedF1.TombstoneGeneration + 1
	secondID := fmt.Sprintf("%s#g%d", baseID, nextGeneration)
	freshEmit := &ports.FindingRecord{
		ID:              secondID,
		Fingerprint:     fingerprint,
		TenantID:        fx.tenantID,
		RuntimeID:       fx.runtimeID,
		RuleID:          fx.ruleID,
		Title:           "T " + baseID,
		Severity:        "MEDIUM",
		Status:          "open",
		Summary:         "S " + baseID,
		ResourceURNs:    []string{anchor},
		EventIDs:        []string{"event-fresh-emit"},
		FirstObservedAt: fx.now.Add(-time.Minute),
		LastObservedAt:  fx.now,
		FindingTombstone: ports.FindingTombstone{
			TombstoneGeneration: nextGeneration,
		},
	}
	if _, err := fx.store.UpsertFinding(ctx, freshEmit); err != nil {
		t.Fatalf("UpsertFinding F2: %v", err)
	}
	storedF2 := fx.store.findings[secondID]
	if err := fx.service.projectFindingAnchor(ctx, storedF2); err != nil {
		t.Fatalf("project F2 anchor: %v", err)
	}

	if storedF2.Tombstoned {
		t.Fatalf("F2.Tombstoned = true, want false")
	}
	if got, want := storedF2.TombstoneGeneration, tombstonedF1.TombstoneGeneration+1; got != want {
		t.Fatalf("F2.TombstoneGeneration = %d, want F1.TombstoneGeneration+1 = %d", got, want)
	}

	recordedForF2 := 0
	for _, evt := range fx.appendLog.events {
		if evt.GetKind() != workflowevents.EventKindFindingRecorded {
			continue
		}
		payload, decodeErr := workflowevents.DecodeFindingRecorded(evt)
		if decodeErr != nil {
			t.Fatalf("decode FindingRecorded: %v", decodeErr)
		}
		if payload.Finding.FindingID == secondID {
			recordedForF2++
		}
	}
	if recordedForF2 != 1 {
		t.Fatalf("FindingRecorded events for F2 = %d, want 1", recordedForF2)
	}

	freshAnchorEdgeKey := anchor + "|" + "has_finding" + "|" + findingGraphFindingURN(fx.tenantID, storedF2)
	if freshAnchorEdgeKey == firstAnchorEdgeKey {
		t.Fatalf("F2 edge key %q must differ from F1 edge key", freshAnchorEdgeKey)
	}
	if _, ok := graph.links[freshAnchorEdgeKey]; !ok {
		t.Fatalf("expected has_finding(A → F2) edge %q after fresh emit (links=%v)", freshAnchorEdgeKey, graph.links)
	}
}
