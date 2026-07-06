package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestApigeeDeveloperProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apigee", Kind: "apigee.developers", Attributes: map[string]string{"user_id": "dev-1", "email": "dev@fixture.invalid", "display_name": "Developer One"}}
	entities, _, err := apigeeDevelopersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected developer identity")
	}
}

func TestApigeeOrganizationProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apigee", Kind: "apigee.organizations", Attributes: map[string]string{"resource_id": "org-1", "resource_type": "apigee_organization", "resource_name": "org-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := apigeeOrganizationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected organization entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestApigeeAPIProxiesProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apigee", Kind: "apigee.api_proxies", Attributes: map[string]string{"resource_id": "proxy-1", "resource_type": "apigee_api_proxy", "resource_name": "proxy-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := apigeeAPIProxiesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected API proxy entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestApigeeDeploymentProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apigee", Kind: "apigee.deployments", Attributes: map[string]string{"deployment_id": "dep-1", "deployment_name": "Production", "deployment_environment": "production", "deployment_status": "ready", "evidence_id": "evidence-1"}}
	entities, links, err := apigeeDeploymentsProjections(event)
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

func TestApigeeAppsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apigee", Kind: "apigee.apps", Attributes: map[string]string{"resource_id": "app-1", "resource_type": "apigee_app", "resource_name": "orders-app", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := apigeeAppsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected app entities")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}
