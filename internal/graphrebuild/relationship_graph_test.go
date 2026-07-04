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
			if result.GraphNodes != 2 {
				t.Fatalf("GraphNodes = %d, want 2 (entities=%#v)", result.GraphNodes, result.PreviewEntities)
			}
			if containsEntityURN(result.PreviewEntities, "urn:cerebro:writer:runtime_project:proj-1") {
				t.Fatalf("found fragmented runtime_project node: %#v", result.PreviewEntities)
			}
			if !containsEntityURN(result.PreviewEntities, projectURN) {
				t.Fatalf("missing merged doppler_project node: %#v", result.PreviewEntities)
			}
			if !containsLink(result.PreviewLinks, "urn:cerebro:writer:secret:secret-1", "belongs_to", projectURN) {
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

// TestRebuildDryRunLinksHashicorpVaultSecretToMount pins the relationship
// Vault can prove from /sys/mounts: a secret engine belongs to its mounted
// Vault engine, with no identity fragmentation.
func TestRebuildDryRunLinksHashicorpVaultSecretToMount(t *testing.T) {
	events := []*cerebrov1.EventEnvelope{
		testRuntimeEvent("vault-secret-1", "hashicorp_vault.secrets", "writer-vault", map[string]string{
			"secret_id":   "vsecret-1",
			"secret_name": "kv/",
			"vault_id":    "kv",
		}),
	}
	result := replayDryRun(t, "writer-vault", "hashicorp_vault", events)

	vaultURN := "urn:cerebro:writer:hashicorp_vault_vault:kv"
	if !containsLink(result.PreviewLinks, "urn:cerebro:writer:secret:vsecret-1", "belongs_to", vaultURN) {
		t.Fatalf("missing belongs_to edge: %#v", result.PreviewLinks)
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
		EventLimit:   uint32(len(events)), // #nosec G115 -- test event counts are tiny and fit uint32
		PreviewLimit: 20,
	})
	if err != nil {
		t.Fatalf("RebuildDryRun() error = %v", err)
	}
	return result
}
