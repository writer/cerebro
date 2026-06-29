package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestCerebrasAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "cerebras", Kind: "cerebras.projects", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := cerebrasProjectsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestCerebrasSecretProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "cerebras", Kind: "cerebras.api_keys", Attributes: map[string]string{"secret_id": "secret-1", "secret_name": "DB Password", "secret_type": "password", "secret_status": "active", "evidence_id": "evidence-1"}}
	entities, links, err := cerebrasApiKeysProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected secret")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestCerebrasUsageReportsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "cerebras", Kind: "cerebras.usage_reports", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := cerebrasUsageReportsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestCerebrasDeploymentProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "cerebras", Kind: "cerebras.model_deployments", Attributes: map[string]string{"deployment_id": "dep-1", "deployment_name": "Production", "deployment_environment": "production", "deployment_status": "ready", "evidence_id": "evidence-1"}}
	entities, links, err := cerebrasModelDeploymentsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected deployment")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}
