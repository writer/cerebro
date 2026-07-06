package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAirbyteCloudAssetProjection(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		project ProjectFunc
	}{
		{name: "organizations", kind: "airbyte_cloud.organizations", project: airbyteCloudOrganizationsProjections},
		{name: "sources", kind: "airbyte_cloud.sources", project: airbyteCloudSourcesProjections},
		{name: "connections", kind: "airbyte_cloud.connections", project: airbyteCloudConnectionsProjections},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbyte_cloud", Kind: tc.kind, Attributes: map[string]string{"resource_id": tc.name + "-1", "resource_type": "airbyte_" + tc.name, "resource_name": tc.name + "-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
			entities, links, err := tc.project(event)
			if err != nil {
				t.Fatalf("projection error = %v", err)
			}
			if len(entities) == 0 {
				t.Fatal("expected projected entities")
			}
			if len(links) == 0 {
				t.Fatal("expected projected evidence links")
			}
		})
	}
}

func TestAirbyteCloudPolicyProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbyte_cloud", Kind: "airbyte_cloud.permissions", Attributes: map[string]string{"policy_id": "permission-1", "policy_name": "workspace_admin", "policy_type": "airbyte_permission", "policy_status": "active", "evidence_id": "evidence-1"}}
	entities, links, err := airbyteCloudPermissionsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected policy")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestAirbyteCloudIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "airbyte_cloud", Kind: "airbyte_cloud.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := airbyteCloudUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}
