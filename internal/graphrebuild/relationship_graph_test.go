package graphrebuild

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

// TestRebuildDryRunMergesDopplerSecretProjectWithoutFragmentation pins the
// doppler projects family projecting a typed doppler_project node so the secret
// belongs_to edge merges onto it instead of fragmenting into an isolated
// runtime_project node. Both replay orders must converge on the same merged
// graph.
func TestRebuildDryRunMergesDopplerSecretProjectWithoutFragmentation(t *testing.T) {
	secret := func() *cerebrov1.EventEnvelope {
		return testRuntimeEvent("doppler-secret-1", "doppler.secrets", "writer-doppler", map[string]string{
			"secret_id":   "secret-1",
			"secret_name": "DATABASE_URL",
			"project_id":  "proj-1",
		})
	}
	project := func() *cerebrov1.EventEnvelope {
		return testRuntimeEvent("doppler-project-1", "doppler.projects", "writer-doppler", map[string]string{
			"resource_id":   "proj-1",
			"resource_type": "project",
			"resource_name": "Platform",
		})
	}
	orders := []struct {
		name   string
		events []*cerebrov1.EventEnvelope
	}{
		{name: "secret_first", events: []*cerebrov1.EventEnvelope{secret(), project()}},
		{name: "project_first", events: []*cerebrov1.EventEnvelope{project(), secret()}},
	}
	for _, order := range orders {
		t.Run(order.name, func(t *testing.T) {
			result := replayDryRun(t, "writer-doppler", "doppler", order.events)

			projectURN := "urn:cerebro:writer:doppler_project:proj-1"
			secretURN := "urn:cerebro:writer:secret:secret-1"
			if result.GraphNodes != 2 {
				t.Fatalf("GraphNodes = %d, want 2 (entities=%#v)", result.GraphNodes, result.PreviewEntities)
			}
			if containsEntityURN(result.PreviewEntities, "urn:cerebro:writer:runtime_project:proj-1") {
				t.Fatalf("found fragmented runtime_project node: %#v", result.PreviewEntities)
			}
			if !containsEntityURN(result.PreviewEntities, projectURN) {
				t.Fatalf("missing merged doppler_project node: %#v", result.PreviewEntities)
			}
			if !containsLink(result.PreviewLinks, secretURN, "belongs_to", projectURN) {
				t.Fatalf("missing belongs_to edge to merged project: %#v", result.PreviewLinks)
			}
			if !containsAssertion(result.GraphAssertions, "cross_kind_identity_fragmentation", 0, 0, true) {
				t.Fatalf("cross_kind_identity_fragmentation not clean: %#v", result.GraphAssertions)
			}
			if !containsTopologyPreview(result.GraphTopology, "isolated", 0) {
				t.Fatalf("expected no isolated nodes: %#v", result.GraphTopology)
			}
		})
	}
}

// TestRebuildDryRunMergesHashicorpVaultSecretOwnerWithUser is the clean
// counterpart: the secret owned_by edge merges onto the real user node (which
// carries its own outgoing edges), with no identity fragmentation.
func TestRebuildDryRunMergesHashicorpVaultSecretOwnerWithUser(t *testing.T) {
	events := []*cerebrov1.EventEnvelope{
		testRuntimeEvent("vault-user-1", "hashicorp_vault.users", "writer-vault", map[string]string{
			"user_id":     "user-1",
			"resource_id": "user-1",
			"email":       "user@example.test",
		}),
		testRuntimeEvent("vault-secret-1", "hashicorp_vault.secrets", "writer-vault", map[string]string{
			"secret_id":     "vsecret-1",
			"secret_name":   "api-key",
			"owner_user_id": "user-1",
		}),
	}
	result := replayDryRun(t, "writer-vault", "hashicorp_vault", events)

	secretURN := "urn:cerebro:writer:secret:vsecret-1"
	userURN := "urn:cerebro:writer:hashicorp_vault_user:user-1"
	if !containsLink(result.PreviewLinks, secretURN, "owned_by", userURN) {
		t.Fatalf("missing owned_by edge: %#v", result.PreviewLinks)
	}
	hasOutgoing := false
	for _, link := range result.PreviewLinks {
		if link != nil && link.FromURN == userURN {
			hasOutgoing = true
			break
		}
	}
	if !hasOutgoing {
		t.Fatalf("owner target did not merge with the real user node (no outgoing edges from %s): %#v", userURN, result.PreviewLinks)
	}
	if !containsAssertion(result.GraphAssertions, "cross_kind_identity_fragmentation", 0, 0, true) {
		t.Fatalf("cross_kind_identity_fragmentation not clean: %#v", result.GraphAssertions)
	}
	if !containsTopologyPreview(result.GraphTopology, "isolated", 0) {
		t.Fatalf("expected no isolated nodes: %#v", result.GraphTopology)
	}
}

func replayDryRun(t *testing.T, runtimeID string, sourceID string, events []*cerebrov1.EventEnvelope) *Result {
	t.Helper()
	for _, event := range events {
		event.SourceId = sourceID
		event.TenantId = "writer"
	}
	service := New(nil, &runtimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {Id: runtimeID, SourceId: sourceID, TenantId: "writer"},
		},
	}, &eventReplayer{events: events})
	result, err := service.RebuildDryRun(context.Background(), Request{
		Mode:         modeReplay,
		RuntimeID:    runtimeID,
		EventLimit:   uint32(len(events)),
		PreviewLimit: 20,
	})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	return result
}
