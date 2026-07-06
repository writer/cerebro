package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAnomaloAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "anomalo", Kind: "anomalo.warehouses", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "warehouse", "resource_name": "warehouse-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := anomaloWarehousesProjections(event)
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

func TestAnomaloPolicyProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "anomalo", Kind: "anomalo.checks", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Row count check", "policy_type": "RowCount", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := anomaloChecksProjections(event)
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

func TestAnomaloTableProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "anomalo", Kind: "anomalo.tables", Attributes: map[string]string{"resource_id": "table-1", "resource_type": "table", "resource_name": "warehouse.schema.table"}}
	entities, _, err := anomaloTablesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected table")
	}
}

func TestAnomaloNotificationChannelProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "anomalo", Kind: "anomalo.notification_channels", Attributes: map[string]string{"resource_id": "channel-1", "resource_type": "notification_channel", "resource_name": "Data alerts"}}
	entities, _, err := anomaloNotificationChannelsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected notification channel")
	}
}

func TestAnomaloOrganizationProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "anomalo", Kind: "anomalo.organizations", Attributes: map[string]string{"resource_id": "org-1", "resource_type": "organization", "resource_name": "Primary Organization"}}
	entities, links, err := anomaloOrganizationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatalf("entities = %d, want organization projection", len(entities))
	}
	if len(links) != 0 {
		t.Fatalf("links = %d, want no evidence links", len(links))
	}
}
