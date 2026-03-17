package graph

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestGraphMutationRecordsRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	records := []GraphMutationRecord{
		{
			Sequence:   1,
			RecordedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
			Type:       GraphMutationAddNode,
			Node: &Node{
				ID:        "workload:payments",
				Kind:      NodeKindWorkload,
				Account:   "acct-a",
				Provider:  "aws",
				Risk:      RiskLow,
				CreatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
				UpdatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
				Version:   1,
			},
		},
		{
			Sequence:      2,
			RecordedAt:    time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
			Type:          GraphMutationSetNodeProperty,
			NodeID:        "workload:payments",
			PropertyKey:   "internet_exposed",
			PropertyValue: true,
		},
	}
	for _, record := range records {
		if err := AppendGraphMutationRecord(&buf, record); err != nil {
			t.Fatalf("AppendGraphMutationRecord: %v", err)
		}
	}

	loaded, err := LoadGraphMutationRecords(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("LoadGraphMutationRecords: %v", err)
	}
	if len(loaded) != len(records) {
		t.Fatalf("len(loaded) = %d, want %d", len(loaded), len(records))
	}
	if loaded[0].Version != graphMutationRecordVersion {
		t.Fatalf("loaded[0].Version = %q, want %q", loaded[0].Version, graphMutationRecordVersion)
	}
	if loaded[0].Node == nil || loaded[0].Node.ID != "workload:payments" {
		t.Fatalf("loaded[0].Node = %#v, want workload:payments", loaded[0].Node)
	}
	if loaded[1].NodeID != "workload:payments" || loaded[1].PropertyKey != "internet_exposed" {
		t.Fatalf("loaded[1] = %#v, want property mutation", loaded[1])
	}
	if exposed, ok := loaded[1].PropertyValue.(bool); !ok || !exposed {
		t.Fatalf("loaded[1].PropertyValue = %#v, want true", loaded[1].PropertyValue)
	}
}

func TestLoadGraphMutationRecordsNormalizesJSONNumbers(t *testing.T) {
	raw := []byte("{\"sequence\":1,\"type\":\"add_node\",\"node\":{\"id\":\"workload:payments\",\"kind\":\"workload\",\"properties\":{\"key_count\":2,\"nested\":{\"attempts\":3},\"latency_ms\":2.5,\"ports\":[443,8443]}}}\n")

	loaded, err := LoadGraphMutationRecords(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("LoadGraphMutationRecords: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("len(loaded) = %d, want 1", len(loaded))
	}
	if loaded[0].Node == nil {
		t.Fatal("loaded[0].Node = nil, want node")
	}
	if got, ok := loaded[0].Node.Properties["key_count"].(int); !ok || got != 2 {
		t.Fatalf("key_count = %#v, want int(2)", loaded[0].Node.Properties["key_count"])
	}
	nested, ok := loaded[0].Node.Properties["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested = %#v, want map[string]any", loaded[0].Node.Properties["nested"])
	}
	if got, ok := nested["attempts"].(int); !ok || got != 3 {
		t.Fatalf("nested[attempts] = %#v, want int(3)", nested["attempts"])
	}
	if got, ok := loaded[0].Node.Properties["latency_ms"].(float64); !ok || got != 2.5 {
		t.Fatalf("latency_ms = %#v, want float64(2.5)", loaded[0].Node.Properties["latency_ms"])
	}
	ports, ok := loaded[0].Node.Properties["ports"].([]any)
	if !ok || len(ports) != 2 {
		t.Fatalf("ports = %#v, want []any{443,8443}", loaded[0].Node.Properties["ports"])
	}
	if got, ok := ports[0].(int); !ok || got != 443 {
		t.Fatalf("ports[0] = %#v, want int(443)", ports[0])
	}
	if got, ok := ports[1].(int); !ok || got != 8443 {
		t.Fatalf("ports[1] = %#v, want int(8443)", ports[1])
	}
}

func TestReplayGraphMutationRecordsRebuildsCheckpointedGraph(t *testing.T) {
	originalNow := temporalNowUTC
	temporalNowUTC = func() time.Time {
		return time.Date(2026, 3, 16, 18, 5, 0, 0, time.UTC)
	}
	t.Cleanup(func() { temporalNowUTC = originalNow })

	base := New()
	base.AddNode(&Node{
		ID:        "workload:payments",
		Kind:      NodeKindWorkload,
		Account:   "acct-a",
		Provider:  "aws",
		Risk:      RiskLow,
		CreatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
		Version:   1,
	})
	checkpoint := CreateSnapshot(base)

	live := RestoreFromSnapshot(checkpoint)
	live.AddNode(&Node{
		ID:        "workload:queue",
		Kind:      NodeKindWorkload,
		Account:   "acct-a",
		Provider:  "aws",
		Risk:      RiskMedium,
		CreatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
		Version:   1,
	})
	live.AddEdge(&Edge{
		ID:        "payments-queue",
		Source:    "workload:payments",
		Target:    "workload:queue",
		Kind:      EdgeKindTargets,
		Effect:    EdgeEffectAllow,
		CreatedAt: time.Date(2026, 3, 16, 18, 2, 0, 0, time.UTC),
		Version:   1,
	})
	if !live.SetNodeProperty("workload:payments", "internet_exposed", true) {
		t.Fatal("live.SetNodeProperty returned false")
	}
	if !live.RemoveNode("workload:queue") {
		t.Fatal("live.RemoveNode returned false")
	}

	records := []GraphMutationRecord{
		{
			Sequence:   1,
			RecordedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
			Type:       GraphMutationAddNode,
			Node: &Node{
				ID:        "workload:queue",
				Kind:      NodeKindWorkload,
				Account:   "acct-a",
				Provider:  "aws",
				Risk:      RiskMedium,
				CreatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
				UpdatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
				Version:   1,
			},
		},
		{
			Sequence:   2,
			RecordedAt: time.Date(2026, 3, 16, 18, 2, 0, 0, time.UTC),
			Type:       GraphMutationAddEdge,
			Edge: &Edge{
				ID:        "payments-queue",
				Source:    "workload:payments",
				Target:    "workload:queue",
				Kind:      EdgeKindTargets,
				Effect:    EdgeEffectAllow,
				CreatedAt: time.Date(2026, 3, 16, 18, 2, 0, 0, time.UTC),
				Version:   1,
			},
		},
		{
			Sequence:      3,
			RecordedAt:    time.Date(2026, 3, 16, 18, 3, 0, 0, time.UTC),
			Type:          GraphMutationSetNodeProperty,
			NodeID:        "workload:payments",
			PropertyKey:   "internet_exposed",
			PropertyValue: true,
		},
		{
			Sequence:   4,
			RecordedAt: time.Date(2026, 3, 16, 18, 4, 0, 0, time.UTC),
			Type:       GraphMutationRemoveNode,
			NodeID:     "workload:queue",
		},
	}

	replayed := RestoreFromSnapshot(checkpoint)
	if err := ReplayGraphMutationRecords(replayed, records); err != nil {
		t.Fatalf("ReplayGraphMutationRecords: %v", err)
	}

	if live.NodeCount() != replayed.NodeCount() {
		t.Fatalf("NodeCount = %d, want %d", replayed.NodeCount(), live.NodeCount())
	}
	if live.EdgeCount() != replayed.EdgeCount() {
		t.Fatalf("EdgeCount = %d, want %d", replayed.EdgeCount(), live.EdgeCount())
	}
	payments, ok := replayed.GetNode("workload:payments")
	if !ok {
		t.Fatal("replayed graph missing workload:payments")
	}
	if got := payments.Properties["internet_exposed"]; got != true {
		t.Fatalf("payments.Properties[internet_exposed] = %v, want true", got)
	}
	if _, ok := replayed.GetNode("workload:queue"); ok {
		t.Fatal("replayed graph unexpectedly retained removed node")
	}
	if got := len(replayed.GetOutEdges("workload:payments")); got != 0 {
		t.Fatalf("len(GetOutEdges(workload:payments)) = %d, want 0", got)
	}
}

func TestReplayGraphMutationRecordsSkipsDuplicateSequence(t *testing.T) {
	g := New()
	records := []GraphMutationRecord{
		{
			Sequence:   1,
			RecordedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
			Type:       GraphMutationAddNode,
			Node: &Node{
				ID:        "workload:payments",
				Kind:      NodeKindWorkload,
				CreatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
				UpdatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
				Version:   1,
			},
		},
		{
			Sequence:   1,
			RecordedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
			Type:       GraphMutationAddNode,
			Node: &Node{
				ID:        "workload:payments",
				Kind:      NodeKindWorkload,
				CreatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
				UpdatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
				Version:   1,
			},
		},
	}

	if err := ReplayGraphMutationRecords(g, records); err != nil {
		t.Fatalf("ReplayGraphMutationRecords: %v", err)
	}

	node, ok := g.GetNode("workload:payments")
	if !ok {
		t.Fatal("expected replayed node to exist")
	}
	if node.Version != 1 {
		t.Fatalf("node.Version = %d, want 1", node.Version)
	}
}

func TestReplayGraphMutationRecordsRejectsConflictingDuplicateSequence(t *testing.T) {
	g := New()
	records := []GraphMutationRecord{
		{
			Sequence:   1,
			RecordedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
			Type:       GraphMutationAddNode,
			Node: &Node{
				ID:      "workload:payments",
				Kind:    NodeKindWorkload,
				Version: 1,
			},
		},
		{
			Sequence:      1,
			RecordedAt:    time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
			Type:          GraphMutationSetNodeProperty,
			NodeID:        "workload:payments",
			PropertyKey:   "internet_exposed",
			PropertyValue: true,
		},
	}

	err := ReplayGraphMutationRecords(g, records)
	if err == nil {
		t.Fatal("expected conflicting duplicate sequence to fail")
	}
	if !strings.Contains(err.Error(), "conflicting record types share sequence 1") {
		t.Fatalf("ReplayGraphMutationRecords error = %v, want conflicting sequence error", err)
	}
}

func TestReplayGraphMutationRecordsAllowsCheckpointOverlapNoOps(t *testing.T) {
	base := New()
	base.AddNode(&Node{
		ID:        "workload:queue",
		Kind:      NodeKindWorkload,
		CreatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
		Version:   1,
	})
	if !base.SetNodeProperty("workload:queue", "internet_exposed", true) {
		t.Fatal("base.SetNodeProperty returned false")
	}
	if !base.RemoveNode("workload:queue") {
		t.Fatal("base.RemoveNode returned false")
	}

	checkpoint := CreateSnapshot(base)
	replayed := RestoreFromSnapshot(checkpoint)
	records := []GraphMutationRecord{
		{
			Sequence:      1,
			RecordedAt:    time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
			Type:          GraphMutationSetNodeProperty,
			NodeID:        "workload:queue",
			PropertyKey:   "internet_exposed",
			PropertyValue: true,
		},
		{
			Sequence:   2,
			RecordedAt: time.Date(2026, 3, 16, 18, 2, 0, 0, time.UTC),
			Type:       GraphMutationRemoveNode,
			NodeID:     "workload:queue",
		},
	}

	if err := ReplayGraphMutationRecords(replayed, records); err != nil {
		t.Fatalf("ReplayGraphMutationRecords: %v", err)
	}
	if replayed.NodeCount() != 0 {
		t.Fatalf("NodeCount = %d, want 0", replayed.NodeCount())
	}
	if _, ok := replayed.GetNode("workload:queue"); ok {
		t.Fatal("replayed graph unexpectedly retained workload:queue")
	}
}

func TestApplyGraphMutationRecordRemoveNodeAllowsDeletedNoOp(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:        "workload:queue",
		Kind:      NodeKindWorkload,
		CreatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 3, 16, 18, 0, 0, 0, time.UTC),
		Version:   1,
	})
	if !g.RemoveNode("workload:queue") {
		t.Fatal("g.RemoveNode returned false")
	}

	record := GraphMutationRecord{
		Sequence:   1,
		RecordedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
		Type:       GraphMutationRemoveNode,
		NodeID:     "workload:queue",
	}
	if err := ApplyGraphMutationRecord(g, record); err != nil {
		t.Fatalf("ApplyGraphMutationRecord: %v", err)
	}
}

func TestApplyGraphMutationRecordAddNodeSkipsStaleCheckpointOverlap(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:        "workload:payments",
		Kind:      NodeKindWorkload,
		UpdatedAt: time.Date(2026, 3, 16, 18, 2, 0, 0, time.UTC),
		Version:   2,
		Properties: map[string]any{
			"state": "checkpoint",
		},
	})

	record := GraphMutationRecord{
		Sequence:   1,
		RecordedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
		Type:       GraphMutationAddNode,
		Node: &Node{
			ID:        "workload:payments",
			Kind:      NodeKindWorkload,
			UpdatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
			Version:   1,
			Properties: map[string]any{
				"state": "stale-wal",
			},
		},
	}
	if err := ApplyGraphMutationRecord(g, record); err != nil {
		t.Fatalf("ApplyGraphMutationRecord: %v", err)
	}

	node, ok := g.GetNode("workload:payments")
	if !ok {
		t.Fatal("expected node to exist")
	}
	if node.Version != 2 {
		t.Fatalf("node.Version = %d, want 2", node.Version)
	}
	if got := node.Properties["state"]; got != "checkpoint" {
		t.Fatalf("node.Properties[state] = %#v, want checkpoint", got)
	}
}

func TestApplyGraphMutationRecordAddNodeAppliesNewerNode(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		ID:        "workload:payments",
		Kind:      NodeKindWorkload,
		UpdatedAt: time.Date(2026, 3, 16, 18, 1, 0, 0, time.UTC),
		Version:   1,
		Properties: map[string]any{
			"state": "checkpoint",
		},
	})

	record := GraphMutationRecord{
		Sequence:   2,
		RecordedAt: time.Date(2026, 3, 16, 18, 2, 0, 0, time.UTC),
		Type:       GraphMutationAddNode,
		Node: &Node{
			ID:        "workload:payments",
			Kind:      NodeKindWorkload,
			UpdatedAt: time.Date(2026, 3, 16, 18, 2, 0, 0, time.UTC),
			Version:   2,
			Properties: map[string]any{
				"state": "newer-wal",
			},
		},
	}
	if err := ApplyGraphMutationRecord(g, record); err != nil {
		t.Fatalf("ApplyGraphMutationRecord: %v", err)
	}

	node, ok := g.GetNode("workload:payments")
	if !ok {
		t.Fatal("expected node to exist")
	}
	if node.Version != 2 {
		t.Fatalf("node.Version = %d, want 2", node.Version)
	}
	if got := node.Properties["state"]; got != "newer-wal" {
		t.Fatalf("node.Properties[state] = %#v, want newer-wal", got)
	}
}

func TestApplyGraphMutationRecordAddEdgeRejectsSchemaEnforcementFailure(t *testing.T) {
	sourceKind := NodeKind("test_wal_source_kind_v1")
	targetKind := NodeKind("test_wal_target_kind_v1")
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:          sourceKind,
		Categories:    []NodeKindCategory{NodeCategoryBusiness},
		Relationships: []EdgeKind{EdgeKindReportsTo},
	}); err != nil {
		t.Fatalf("register source kind: %v", err)
	}
	if _, err := RegisterNodeKindDefinition(NodeKindDefinition{
		Kind:       targetKind,
		Categories: []NodeKindCategory{NodeCategoryBusiness},
	}); err != nil {
		t.Fatalf("register target kind: %v", err)
	}

	g := New()
	g.SetSchemaValidationMode(SchemaValidationEnforce)
	g.AddNode(&Node{ID: "node:source", Kind: sourceKind, Properties: map[string]any{"owner": "team-a"}})
	g.AddNode(&Node{ID: "node:target", Kind: targetKind})

	err := ApplyGraphMutationRecord(g, GraphMutationRecord{
		Sequence:   1,
		RecordedAt: time.Date(2026, 3, 16, 18, 3, 0, 0, time.UTC),
		Type:       GraphMutationAddEdge,
		Edge: &Edge{
			ID:     "edge:reject",
			Source: "node:source",
			Target: "node:target",
			Kind:   EdgeKindCanRead,
			Effect: EdgeEffectAllow,
		},
	})
	if err == nil {
		t.Fatal("expected ApplyGraphMutationRecord to reject invalid edge replay")
	}
	if got := g.EdgeCount(); got != 0 {
		t.Fatalf("EdgeCount() = %d, want 0", got)
	}
}
