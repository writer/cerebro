package graph

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSpannerWorldModelSchemaStatements(t *testing.T) {
	statements, err := SpannerWorldModelSchemaStatements()
	if err != nil {
		t.Fatalf("SpannerWorldModelSchemaStatements() error = %v", err)
	}
	if len(statements) < 12 {
		t.Fatalf("expected at least 12 DDL statements, got %d", len(statements))
	}
	ddl := strings.Join(statements, ";\n")
	wantFragments := []string{
		"CREATE TABLE entities",
		"CREATE TABLE entity_relationships",
		"CREATE TABLE sources",
		"CREATE TABLE evidence",
		"CREATE TABLE evidence_targets",
		"CREATE TABLE observations",
		"CREATE TABLE observation_targets",
		"CREATE TABLE claims",
		"CREATE TABLE claim_sources",
		"CREATE TABLE claim_evidence",
		"CREATE TABLE claim_relationships",
		"edge_id STRING(2048) NOT NULL",
		"CREATE OR REPLACE PROPERTY GRAPH cerebro_world_model",
		"INTERLEAVE IN PARENT claims",
		"KEY (evidence_id, edge_id)",
		"KEY (observation_id, edge_id)",
		"KEY (claim_id, edge_id)",
		"observed_at TIMESTAMP NOT NULL",
		"valid_from TIMESTAMP NOT NULL",
		"transaction_from TIMESTAMP NOT NULL",
	}
	for _, fragment := range wantFragments {
		if !strings.Contains(ddl, fragment) {
			t.Fatalf("expected DDL to contain %q", fragment)
		}
	}
}

func TestSpannerWorldModelNodeRecordRoundTrip(t *testing.T) {
	base := time.Date(2026, 3, 23, 12, 0, 0, 0, time.UTC)
	meta := NormalizeWriteMetadata(
		base.Add(-10*time.Minute),
		base.Add(-9*time.Minute),
		ptrTime(base.Add(4*time.Hour)),
		"platform",
		"evt-123",
		0.91,
		WriteMetadataDefaults{
			RecordedAt:      base.Add(-8 * time.Minute),
			TransactionFrom: base.Add(-7 * time.Minute),
			TransactionTo:   ptrTime(base.Add(8 * time.Hour)),
		},
	)

	tests := []struct {
		name    string
		node    *Node
		convert func(*Node) (*Node, error)
		check   func(t *testing.T, node *Node)
	}{
		{
			name: "entity",
			node: func() *Node {
				properties := map[string]any{
					"service_id":    "payments",
					"canonical_ref": "service:payments",
					"owner_team":    "platform",
				}
				meta.ApplyTo(properties)
				return &Node{
					ID:         "service:payments",
					Kind:       NodeKindService,
					Name:       "Payments",
					TenantID:   "tenant-a",
					Provider:   "gcp",
					Account:    "prod",
					Region:     "us-central1",
					Properties: properties,
					Tags: map[string]string{
						"env": "prod",
					},
					Risk:      RiskHigh,
					Findings:  []string{"internet_exposed"},
					CreatedAt: base.Add(-30 * time.Minute),
					UpdatedAt: base.Add(-5 * time.Minute),
					Version:   7,
				}
			}(),
			convert: func(node *Node) (*Node, error) {
				record, err := SpannerWorldModelEntityRecordFromNode(node)
				if err != nil {
					return nil, err
				}
				return record.ToNode(), nil
			},
			check: func(t *testing.T, node *Node) {
				t.Helper()
				if node.Kind != NodeKindService {
					t.Fatalf("Kind = %q, want %q", node.Kind, NodeKindService)
				}
				if got := nodePropertyString(node, "service_id"); got != "payments" {
					t.Fatalf("service_id = %q, want payments", got)
				}
				if got := nodePropertyString(node, "source_system"); got != "platform" {
					t.Fatalf("source_system = %q, want platform", got)
				}
			},
		},
		{
			name: "claim",
			node: func() *Node {
				properties := map[string]any{
					"claim_type":  "ownership",
					"subject_id":  "service:payments",
					"predicate":   "owned_by",
					"object_id":   "person:alice",
					"status":      "active",
					"summary":     "Alice owns Payments",
					"source_name": "pagerduty",
				}
				meta.ApplyTo(properties)
				return &Node{
					ID:         "claim:payments:owner",
					Kind:       NodeKindClaim,
					Name:       "Alice owns Payments",
					Provider:   "platform",
					Properties: properties,
					Risk:       RiskNone,
					CreatedAt:  base.Add(-30 * time.Minute),
					UpdatedAt:  base.Add(-5 * time.Minute),
					Version:    3,
				}
			}(),
			convert: func(node *Node) (*Node, error) {
				record, err := SpannerWorldModelClaimRecordFromNode(node)
				if err != nil {
					return nil, err
				}
				return record.ToNode(), nil
			},
			check: func(t *testing.T, node *Node) {
				t.Helper()
				if node.Kind != NodeKindClaim {
					t.Fatalf("Kind = %q, want %q", node.Kind, NodeKindClaim)
				}
				if got := nodePropertyString(node, "subject_id"); got != "service:payments" {
					t.Fatalf("subject_id = %q, want service:payments", got)
				}
				if got := nodePropertyString(node, "predicate"); got != "owned_by" {
					t.Fatalf("predicate = %q, want owned_by", got)
				}
				if got := nodePropertyString(node, "object_id"); got != "person:alice" {
					t.Fatalf("object_id = %q, want person:alice", got)
				}
			},
		},
		{
			name: "evidence",
			node: func() *Node {
				properties := map[string]any{
					"evidence_type": "ticket_comment",
					"detail":        "On-call acknowledged ownership",
					"subject_id":    "service:payments",
					"url":           "https://example.test/evidence/1",
				}
				meta.ApplyTo(properties)
				return &Node{
					ID:         "evidence:ticket-comment:1",
					Kind:       NodeKindEvidence,
					Name:       "ticket_comment",
					Provider:   "platform",
					Properties: properties,
					Risk:       RiskNone,
					CreatedAt:  base.Add(-30 * time.Minute),
					UpdatedAt:  base.Add(-5 * time.Minute),
					Version:    2,
				}
			}(),
			convert: func(node *Node) (*Node, error) {
				record, err := SpannerWorldModelEvidenceRecordFromNode(node)
				if err != nil {
					return nil, err
				}
				return record.ToNode(), nil
			},
			check: func(t *testing.T, node *Node) {
				t.Helper()
				if node.Kind != NodeKindEvidence {
					t.Fatalf("Kind = %q, want %q", node.Kind, NodeKindEvidence)
				}
				if got := nodePropertyString(node, "evidence_type"); got != "ticket_comment" {
					t.Fatalf("evidence_type = %q, want ticket_comment", got)
				}
				if got := nodePropertyString(node, "subject_id"); got != "service:payments" {
					t.Fatalf("subject_id = %q, want service:payments", got)
				}
			},
		},
		{
			name: "observation",
			node: func() *Node {
				properties := map[string]any{
					"observation_type": "runtime_finding",
					"subject_id":       "service:payments",
					"detail":           "Error budget exhausted",
				}
				meta.ApplyTo(properties)
				return &Node{
					ID:         "observation:payments:1",
					Kind:       NodeKindObservation,
					Name:       "runtime_finding",
					Provider:   "platform",
					Properties: properties,
					Risk:       RiskNone,
					CreatedAt:  base.Add(-30 * time.Minute),
					UpdatedAt:  base.Add(-5 * time.Minute),
					Version:    5,
				}
			}(),
			convert: func(node *Node) (*Node, error) {
				record, err := SpannerWorldModelObservationRecordFromNode(node)
				if err != nil {
					return nil, err
				}
				return record.ToNode(), nil
			},
			check: func(t *testing.T, node *Node) {
				t.Helper()
				if node.Kind != NodeKindObservation {
					t.Fatalf("Kind = %q, want %q", node.Kind, NodeKindObservation)
				}
				if got := nodePropertyString(node, "observation_type"); got != "runtime_finding" {
					t.Fatalf("observation_type = %q, want runtime_finding", got)
				}
				if got := nodePropertyString(node, "subject_id"); got != "service:payments" {
					t.Fatalf("subject_id = %q, want service:payments", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roundTripped, err := tt.convert(tt.node)
			if err != nil {
				t.Fatalf("convert() error = %v", err)
			}
			if roundTripped == nil {
				t.Fatal("convert() returned nil node")
			}
			if roundTripped.ID != tt.node.ID {
				t.Fatalf("ID = %q, want %q", roundTripped.ID, tt.node.ID)
			}
			if roundTripped.Name != tt.node.Name {
				t.Fatalf("Name = %q, want %q", roundTripped.Name, tt.node.Name)
			}
			if roundTripped.Provider != tt.node.Provider {
				t.Fatalf("Provider = %q, want %q", roundTripped.Provider, tt.node.Provider)
			}
			if got, ok := nodePropertyTime(roundTripped, "observed_at"); !ok || !got.Equal(meta.ObservedAt) {
				t.Fatalf("observed_at = (%v, %v), want %v", got, ok, meta.ObservedAt)
			}
			if got, ok := nodePropertyTime(roundTripped, "valid_from"); !ok || !got.Equal(meta.ValidFrom) {
				t.Fatalf("valid_from = (%v, %v), want %v", got, ok, meta.ValidFrom)
			}
			if got, ok := nodePropertyTime(roundTripped, "recorded_at"); !ok || !got.Equal(meta.RecordedAt) {
				t.Fatalf("recorded_at = (%v, %v), want %v", got, ok, meta.RecordedAt)
			}
			if got, ok := nodePropertyTime(roundTripped, "transaction_from"); !ok || !got.Equal(meta.TransactionFrom) {
				t.Fatalf("transaction_from = (%v, %v), want %v", got, ok, meta.TransactionFrom)
			}
			if got, ok := nodePropertyTime(roundTripped, "valid_to"); !ok || !got.Equal(*meta.ValidTo) {
				t.Fatalf("valid_to = (%v, %v), want %v", got, ok, *meta.ValidTo)
			}
			if got, ok := nodePropertyTime(roundTripped, "transaction_to"); !ok || !got.Equal(*meta.TransactionTo) {
				t.Fatalf("transaction_to = (%v, %v), want %v", got, ok, *meta.TransactionTo)
			}
			tt.check(t, roundTripped)
		})
	}
}

func TestSpannerWorldModelEdgeRecordRoundTrip(t *testing.T) {
	base := time.Date(2026, 3, 23, 14, 0, 0, 0, time.UTC)
	meta := NormalizeWriteMetadata(
		base.Add(-10*time.Minute),
		base.Add(-9*time.Minute),
		ptrTime(base.Add(4*time.Hour)),
		"platform",
		"evt-edge-123",
		0.87,
		WriteMetadataDefaults{
			RecordedAt:      base.Add(-8 * time.Minute),
			TransactionFrom: base.Add(-7 * time.Minute),
			TransactionTo:   ptrTime(base.Add(8 * time.Hour)),
		},
	)

	tests := []struct {
		name    string
		edge    *Edge
		convert func(*Edge) (*Edge, error)
		check   func(t *testing.T, edge *Edge)
	}{
		{
			name: "entity relationship",
			edge: contractSpannerWorldModelEdge("edge:service:calls:db", "service:payments", "database:payments", EdgeKindCalls, EdgeEffectAllow, 50, meta),
			convert: func(edge *Edge) (*Edge, error) {
				record, err := SpannerWorldModelEntityRelationshipRecordFromEdge(edge)
				if err != nil {
					return nil, err
				}
				return record.ToEdge(), nil
			},
			check: func(t *testing.T, edge *Edge) {
				t.Helper()
				if edge.Kind != EdgeKindCalls {
					t.Fatalf("Kind = %q, want %q", edge.Kind, EdgeKindCalls)
				}
				if edge.Effect != EdgeEffectAllow {
					t.Fatalf("Effect = %q, want %q", edge.Effect, EdgeEffectAllow)
				}
			},
		},
		{
			name: "evidence target",
			edge: contractSpannerWorldModelEdge("edge:evidence:targets:service", "evidence:ticket:1", "service:payments", EdgeKindTargets, EdgeEffectAllow, 0, meta),
			convert: func(edge *Edge) (*Edge, error) {
				record, err := SpannerWorldModelEvidenceTargetRecordFromEdge(edge)
				if err != nil {
					return nil, err
				}
				return record.ToEdge(), nil
			},
			check: func(t *testing.T, edge *Edge) {
				t.Helper()
				if edge.Kind != EdgeKindTargets {
					t.Fatalf("Kind = %q, want %q", edge.Kind, EdgeKindTargets)
				}
			},
		},
		{
			name: "observation target",
			edge: contractSpannerWorldModelEdge("edge:observation:targets:service", "observation:payments:1", "service:payments", EdgeKindTargets, EdgeEffectAllow, 0, meta),
			convert: func(edge *Edge) (*Edge, error) {
				record, err := SpannerWorldModelObservationTargetRecordFromEdge(edge)
				if err != nil {
					return nil, err
				}
				return record.ToEdge(), nil
			},
			check: func(t *testing.T, edge *Edge) {
				t.Helper()
				if edge.Kind != EdgeKindTargets {
					t.Fatalf("Kind = %q, want %q", edge.Kind, EdgeKindTargets)
				}
			},
		},
		{
			name: "claim source",
			edge: contractSpannerWorldModelEdge("edge:claim:asserted_by:source", "claim:payments:owner", "source:cmdb", EdgeKindAssertedBy, EdgeEffectAllow, 0, meta),
			convert: func(edge *Edge) (*Edge, error) {
				record, err := SpannerWorldModelClaimSourceRecordFromEdge(edge)
				if err != nil {
					return nil, err
				}
				return record.ToEdge(), nil
			},
			check: func(t *testing.T, edge *Edge) {
				t.Helper()
				if edge.Kind != EdgeKindAssertedBy {
					t.Fatalf("Kind = %q, want %q", edge.Kind, EdgeKindAssertedBy)
				}
			},
		},
		{
			name: "claim evidence",
			edge: contractSpannerWorldModelEdge("edge:claim:based_on:evidence", "claim:payments:owner", "evidence:ticket:1", EdgeKindBasedOn, EdgeEffectAllow, 0, meta),
			convert: func(edge *Edge) (*Edge, error) {
				record, err := SpannerWorldModelClaimEvidenceRecordFromEdge(edge)
				if err != nil {
					return nil, err
				}
				return record.ToEdge(), nil
			},
			check: func(t *testing.T, edge *Edge) {
				t.Helper()
				if edge.Kind != EdgeKindBasedOn {
					t.Fatalf("Kind = %q, want %q", edge.Kind, EdgeKindBasedOn)
				}
			},
		},
		{
			name: "claim relationship",
			edge: contractSpannerWorldModelEdge("edge:claim:supports:related", "claim:payments:owner", "claim:payments:tier", EdgeKindSupports, EdgeEffectAllow, 0, meta),
			convert: func(edge *Edge) (*Edge, error) {
				record, err := SpannerWorldModelClaimRelationshipRecordFromEdge(edge)
				if err != nil {
					return nil, err
				}
				return record.ToEdge(), nil
			},
			check: func(t *testing.T, edge *Edge) {
				t.Helper()
				if edge.Kind != EdgeKindSupports {
					t.Fatalf("Kind = %q, want %q", edge.Kind, EdgeKindSupports)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roundTripped, err := tt.convert(tt.edge)
			if err != nil {
				t.Fatalf("convert() error = %v", err)
			}
			if roundTripped == nil {
				t.Fatal("convert() returned nil edge")
			}
			if roundTripped.ID != tt.edge.ID {
				t.Fatalf("ID = %q, want %q", roundTripped.ID, tt.edge.ID)
			}
			if roundTripped.Source != tt.edge.Source {
				t.Fatalf("Source = %q, want %q", roundTripped.Source, tt.edge.Source)
			}
			if roundTripped.Target != tt.edge.Target {
				t.Fatalf("Target = %q, want %q", roundTripped.Target, tt.edge.Target)
			}
			if got, ok := temporalPropertyTime(roundTripped.Properties, "observed_at"); !ok || !got.Equal(meta.ObservedAt) {
				t.Fatalf("observed_at = (%v, %v), want %v", got, ok, meta.ObservedAt)
			}
			if got, ok := temporalPropertyTime(roundTripped.Properties, "valid_from"); !ok || !got.Equal(meta.ValidFrom) {
				t.Fatalf("valid_from = (%v, %v), want %v", got, ok, meta.ValidFrom)
			}
			if got, ok := temporalPropertyTime(roundTripped.Properties, "recorded_at"); !ok || !got.Equal(meta.RecordedAt) {
				t.Fatalf("recorded_at = (%v, %v), want %v", got, ok, meta.RecordedAt)
			}
			if got, ok := temporalPropertyTime(roundTripped.Properties, "transaction_from"); !ok || !got.Equal(meta.TransactionFrom) {
				t.Fatalf("transaction_from = (%v, %v), want %v", got, ok, meta.TransactionFrom)
			}
			tt.check(t, roundTripped)
		})
	}
}

func TestSpannerWorldModelCanonicalAdapterRoundTrip(t *testing.T) {
	ctx := context.Background()
	adapter := NewMemorySpannerWorldModelCanonicalAdapter()

	base := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	meta := NormalizeWriteMetadata(
		base,
		base,
		ptrTime(base.Add(6*time.Hour)),
		"platform",
		"evt-adapter-123",
		0.92,
		WriteMetadataDefaults{
			RecordedAt:      base.Add(5 * time.Minute),
			TransactionFrom: base.Add(5 * time.Minute),
			TransactionTo:   ptrTime(base.Add(8 * time.Hour)),
		},
	)

	nodes := []*Node{
		contractSpannerWorldModelEntityNode("service:payments", NodeKindService, "Payments", meta),
		contractSpannerWorldModelEntityNode("database:payments", NodeKindDatabase, "Payments DB", meta),
		contractSpannerWorldModelSourceNode("source:cmdb", meta),
		contractSpannerWorldModelEvidenceNode("evidence:ticket:1", meta),
		contractSpannerWorldModelObservationNode("observation:payments:1", meta),
		contractSpannerWorldModelClaimNode("claim:payments:owner", "service:payments", meta),
		contractSpannerWorldModelClaimNode("claim:payments:tier", "service:payments", meta),
	}
	edges := []*Edge{
		contractSpannerWorldModelEdge("edge:service:calls:db", "service:payments", "database:payments", EdgeKindCalls, EdgeEffectAllow, 50, meta),
		contractSpannerWorldModelEdge("edge:evidence:targets:service", "evidence:ticket:1", "service:payments", EdgeKindTargets, EdgeEffectAllow, 0, meta),
		contractSpannerWorldModelEdge("edge:observation:targets:service", "observation:payments:1", "service:payments", EdgeKindTargets, EdgeEffectAllow, 0, meta),
		contractSpannerWorldModelEdge("edge:claim:asserted_by:source", "claim:payments:owner", "source:cmdb", EdgeKindAssertedBy, EdgeEffectAllow, 0, meta),
		contractSpannerWorldModelEdge("edge:claim:based_on:evidence", "claim:payments:owner", "evidence:ticket:1", EdgeKindBasedOn, EdgeEffectAllow, 0, meta),
		contractSpannerWorldModelEdge("edge:claim:supports:related", "claim:payments:owner", "claim:payments:tier", EdgeKindSupports, EdgeEffectAllow, 0, meta),
	}

	for _, node := range nodes {
		if err := adapter.UpsertNode(ctx, node); err != nil {
			t.Fatalf("UpsertNode(%q) error = %v", node.ID, err)
		}
	}
	for _, edge := range edges {
		if err := adapter.UpsertEdge(ctx, edge); err != nil {
			t.Fatalf("UpsertEdge(%q) error = %v", edge.ID, err)
		}
	}

	for _, want := range nodes {
		got, ok, err := adapter.LookupNode(ctx, want.ID)
		if err != nil {
			t.Fatalf("LookupNode(%q) error = %v", want.ID, err)
		}
		if !ok || got == nil {
			t.Fatalf("expected node %q to round-trip", want.ID)
		}
		if got.ID != want.ID || got.Kind != want.Kind {
			t.Fatalf("round-tripped node = (%q, %q), want (%q, %q)", got.ID, got.Kind, want.ID, want.Kind)
		}
	}
	for _, want := range edges {
		got, ok, err := adapter.LookupEdge(ctx, want.ID)
		if err != nil {
			t.Fatalf("LookupEdge(%q) error = %v", want.ID, err)
		}
		if !ok || got == nil {
			t.Fatalf("expected edge %q to round-trip", want.ID)
		}
		if got.ID != want.ID || got.Kind != want.Kind {
			t.Fatalf("round-tripped edge = (%q, %q), want (%q, %q)", got.ID, got.Kind, want.ID, want.Kind)
		}
	}

	snapshot, err := adapter.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(snapshot.Nodes) != len(nodes) {
		t.Fatalf("snapshot nodes = %d, want %d", len(snapshot.Nodes), len(nodes))
	}
	if len(snapshot.Edges) != len(edges) {
		t.Fatalf("snapshot edges = %d, want %d", len(snapshot.Edges), len(edges))
	}
}

func TestSpannerWorldModelCanonicalAdapterRejectsEmptyEntityKind(t *testing.T) {
	ctx := context.Background()
	adapter := NewMemorySpannerWorldModelCanonicalAdapter()

	node := &Node{
		ID:   "service:payments",
		Name: "Payments",
	}

	err := adapter.UpsertNode(ctx, node)
	if err == nil {
		t.Fatal("UpsertNode() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "node kind is required") {
		t.Fatalf("UpsertNode() error = %v, want node kind is required", err)
	}
}

func TestSpannerWorldModelCanonicalAdapterRejectsNonEntityTargets(t *testing.T) {
	ctx := context.Background()
	adapter := NewMemorySpannerWorldModelCanonicalAdapter()

	base := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	meta := NormalizeWriteMetadata(
		base,
		base,
		nil,
		"platform",
		"evt-adapter-invalid-target-123",
		0.92,
		WriteMetadataDefaults{
			RecordedAt:      base.Add(5 * time.Minute),
			TransactionFrom: base.Add(5 * time.Minute),
		},
	)

	nodes := []*Node{
		contractSpannerWorldModelEntityNode("service:payments", NodeKindService, "Payments", meta),
		contractSpannerWorldModelEvidenceNode("evidence:ticket:1", meta),
		contractSpannerWorldModelObservationNode("observation:payments:1", meta),
		contractSpannerWorldModelClaimNode("claim:payments:owner", "service:payments", meta),
	}
	for _, node := range nodes {
		if err := adapter.UpsertNode(ctx, node); err != nil {
			t.Fatalf("UpsertNode(%q) error = %v", node.ID, err)
		}
	}

	tests := []struct {
		name string
		edge *Edge
	}{
		{
			name: "evidence target must be entity",
			edge: contractSpannerWorldModelEdge("edge:evidence:targets:claim", "evidence:ticket:1", "claim:payments:owner", EdgeKindTargets, EdgeEffectAllow, 0, meta),
		},
		{
			name: "observation target must be entity",
			edge: contractSpannerWorldModelEdge("edge:observation:targets:evidence", "observation:payments:1", "evidence:ticket:1", EdgeKindTargets, EdgeEffectAllow, 0, meta),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.UpsertEdge(ctx, tt.edge)
			if err == nil {
				t.Fatalf("UpsertEdge(%q) error = nil, want error", tt.edge.ID)
			}
			if !strings.Contains(err.Error(), "not yet modeled") {
				t.Fatalf("UpsertEdge(%q) error = %v, want not yet modeled", tt.edge.ID, err)
			}
		})
	}
}

func ptrTime(value time.Time) *time.Time {
	v := value.UTC()
	return &v
}

func contractSpannerWorldModelEntityNode(id string, kind NodeKind, name string, meta WriteMetadata) *Node {
	properties := map[string]any{
		"canonical_ref": id,
	}
	meta.ApplyTo(properties)
	return &Node{
		ID:         id,
		Kind:       kind,
		Name:       name,
		Provider:   "platform",
		Properties: properties,
		Risk:       RiskMedium,
		CreatedAt:  meta.ObservedAt,
		UpdatedAt:  meta.RecordedAt,
		Version:    1,
	}
}

func contractSpannerWorldModelSourceNode(id string, meta WriteMetadata) *Node {
	properties := map[string]any{
		"source_type":       "cmdb",
		"canonical_name":    "Payments CMDB",
		"trust_tier":        "authoritative",
		"reliability_score": 0.99,
	}
	meta.ApplyTo(properties)
	return &Node{
		ID:         id,
		Kind:       NodeKindSource,
		Name:       "Payments CMDB",
		Provider:   "platform",
		Properties: properties,
		CreatedAt:  meta.ObservedAt,
		UpdatedAt:  meta.RecordedAt,
		Version:    1,
	}
}

func contractSpannerWorldModelEvidenceNode(id string, meta WriteMetadata) *Node {
	properties := map[string]any{
		"evidence_type": "ticket",
		"detail":        "Ticket captured ownership evidence",
	}
	meta.ApplyTo(properties)
	return &Node{
		ID:         id,
		Kind:       NodeKindEvidence,
		Name:       "ticket",
		Provider:   "platform",
		Properties: properties,
		CreatedAt:  meta.ObservedAt,
		UpdatedAt:  meta.RecordedAt,
		Version:    1,
	}
}

func contractSpannerWorldModelObservationNode(id string, meta WriteMetadata) *Node {
	properties := map[string]any{
		"observation_type": "runtime",
		"detail":           "Latency breach",
		"subject_id":       "service:payments",
	}
	meta.ApplyTo(properties)
	return &Node{
		ID:         id,
		Kind:       NodeKindObservation,
		Name:       "runtime",
		Provider:   "platform",
		Properties: properties,
		CreatedAt:  meta.ObservedAt,
		UpdatedAt:  meta.RecordedAt,
		Version:    1,
	}
}

func contractSpannerWorldModelClaimNode(id, subjectID string, meta WriteMetadata) *Node {
	properties := map[string]any{
		"claim_type": "ownership",
		"subject_id": subjectID,
		"predicate":  "owned_by",
		"object_id":  "person:alice",
		"status":     "active",
		"summary":    "Alice owns Payments",
	}
	meta.ApplyTo(properties)
	return &Node{
		ID:         id,
		Kind:       NodeKindClaim,
		Name:       "Alice owns Payments",
		Provider:   "platform",
		Properties: properties,
		CreatedAt:  meta.ObservedAt,
		UpdatedAt:  meta.RecordedAt,
		Version:    1,
	}
}

func contractSpannerWorldModelEdge(id, source, target string, kind EdgeKind, effect EdgeEffect, priority int, meta WriteMetadata) *Edge {
	properties := map[string]any{
		"graph_edge_id": id,
	}
	meta.ApplyTo(properties)
	return &Edge{
		ID:         id,
		Source:     source,
		Target:     target,
		Kind:       kind,
		Effect:     effect,
		Priority:   priority,
		Properties: properties,
		CreatedAt:  meta.ObservedAt,
		Version:    1,
	}
}
