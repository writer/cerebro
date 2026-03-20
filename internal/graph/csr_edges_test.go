package graph

import "testing"

func TestCSREdgeSnapshotMatchesAdjacency(t *testing.T) {
	g := setupTestGraph()
	snapshot := g.csrEdgeSnapshot()
	if snapshot == nil {
		t.Fatal("expected CSR edge snapshot")
	}

	sourceOrdinal, ok := snapshot.lookupOrdinal("role:admin")
	if !ok {
		t.Fatal("expected ordinal for role:admin")
	}

	wantOut := g.GetOutEdges("role:admin")
	gotOut := make([]*Edge, 0, len(wantOut))
	snapshot.forEachOutEdgeOrdinal(sourceOrdinal, func(edge *Edge, targetOrdinal NodeOrdinal, targetID string) bool {
		if edge == nil {
			t.Fatal("expected non-nil out edge")
		}
		if targetID != edge.Target {
			t.Fatalf("targetID = %q, want %q", targetID, edge.Target)
		}
		resolvedTarget, ok := snapshot.resolveOrdinal(targetOrdinal)
		if !ok || resolvedTarget != edge.Target {
			t.Fatalf("resolved target = %q, want %q", resolvedTarget, edge.Target)
		}
		gotOut = append(gotOut, edge)
		return true
	})
	assertEdgeSliceEqual(t, wantOut, gotOut)

	targetOrdinal, ok := snapshot.lookupOrdinal("bucket:sensitive")
	if !ok {
		t.Fatal("expected ordinal for bucket:sensitive")
	}

	wantIn := g.GetInEdges("bucket:sensitive")
	gotIn := make([]*Edge, 0, len(wantIn))
	snapshot.forEachInEdgeOrdinal(targetOrdinal, func(edge *Edge, sourceOrdinal NodeOrdinal, sourceID string) bool {
		if edge == nil {
			t.Fatal("expected non-nil in edge")
		}
		if sourceID != edge.Source {
			t.Fatalf("sourceID = %q, want %q", sourceID, edge.Source)
		}
		resolvedSource, ok := snapshot.resolveOrdinal(sourceOrdinal)
		if !ok || resolvedSource != edge.Source {
			t.Fatalf("resolved source = %q, want %q", resolvedSource, edge.Source)
		}
		gotIn = append(gotIn, edge)
		return true
	})
	assertEdgeSliceEqual(t, wantIn, gotIn)

	denySourceOrdinal, ok := snapshot.lookupOrdinal("user:bob")
	if !ok {
		t.Fatal("expected ordinal for user:bob")
	}
	if !snapshot.hasDenyOrdinals(denySourceOrdinal, targetOrdinal) {
		t.Fatal("expected deny pair for user:bob -> bucket:sensitive")
	}
	if snapshot.hasDenyOrdinals(sourceOrdinal, targetOrdinal) {
		t.Fatal("did not expect deny pair for role:admin -> bucket:sensitive")
	}
}

func TestCSREdgeSnapshotInvalidatesOnMutation(t *testing.T) {
	g := setupTestGraph()

	first := g.csrEdgeSnapshot()
	if first == nil {
		t.Fatal("expected initial CSR edge snapshot")
	}
	if again := g.csrEdgeSnapshot(); again != first {
		t.Fatal("expected CSR edge snapshot to be reused until mutation")
	}

	g.AddNode(&Node{ID: "role:csr-new", Kind: NodeKindRole, Account: "111111111111"})
	g.AddEdge(&Edge{
		ID:     "e:csr-new",
		Source: "user:alice",
		Target: "role:csr-new",
		Kind:   EdgeKindCanAssume,
		Effect: EdgeEffectAllow,
	})

	second := g.csrEdgeSnapshot()
	if second == nil {
		t.Fatal("expected rebuilt CSR edge snapshot")
	}
	if second == first {
		t.Fatal("expected mutation to invalidate CSR edge snapshot")
	}

	aliceOrdinal, ok := second.lookupOrdinal("user:alice")
	if !ok {
		t.Fatal("expected ordinal for user:alice")
	}
	foundNewRole := false
	second.forEachOutEdgeOrdinal(aliceOrdinal, func(edge *Edge, _ NodeOrdinal, targetID string) bool {
		if edge != nil && targetID == "role:csr-new" {
			foundNewRole = true
			return false
		}
		return true
	})
	if !foundNewRole {
		t.Fatal("expected rebuilt snapshot to include new outbound edge")
	}

	if !g.RemoveEdge("user:alice", "role:csr-new", EdgeKindCanAssume) {
		t.Fatal("expected temporary edge removal to succeed")
	}

	third := g.csrEdgeSnapshot()
	if third == nil {
		t.Fatal("expected rebuilt CSR edge snapshot after removal")
	}
	if third == second {
		t.Fatal("expected edge removal to invalidate CSR edge snapshot")
	}

	aliceOrdinal, ok = third.lookupOrdinal("user:alice")
	if !ok {
		t.Fatal("expected ordinal for user:alice in rebuilt snapshot")
	}
	stillPresent := false
	third.forEachOutEdgeOrdinal(aliceOrdinal, func(edge *Edge, _ NodeOrdinal, targetID string) bool {
		if edge != nil && targetID == "role:csr-new" {
			stillPresent = true
			return false
		}
		return true
	})
	if stillPresent {
		t.Fatal("expected removed edge to be absent from rebuilt snapshot")
	}
}

func assertEdgeSliceEqual(t *testing.T, want, got []*Edge) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("edge count mismatch: want %d got %d", len(want), len(got))
	}
	for i := range want {
		if want[i] == nil || got[i] == nil {
			t.Fatalf("unexpected nil edge at index %d: want %#v got %#v", i, want[i], got[i])
		}
		if want[i].ID != got[i].ID || want[i].Source != got[i].Source || want[i].Target != got[i].Target || want[i].Kind != got[i].Kind || want[i].Effect != got[i].Effect {
			t.Fatalf("edge %d mismatch: want %#v got %#v", i, want[i], got[i])
		}
	}
}
