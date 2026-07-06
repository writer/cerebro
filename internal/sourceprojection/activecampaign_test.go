package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestActivecampaignAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activecampaign", Kind: "activecampaign.accounts", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := activecampaignAccountsProjections(event)
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

func TestActivecampaignCampaignProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activecampaign", Kind: "activecampaign.campaigns", Attributes: map[string]string{"resource_id": "campaign-1", "resource_type": "activecampaign_campaign", "resource_name": "Welcome Campaign", "evidence_id": "evidence-1"}}
	entities, links, err := activecampaignCampaignsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected campaign")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestActivecampaignContactProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activecampaign", Kind: "activecampaign.contacts", Attributes: map[string]string{"resource_id": "contact-1", "resource_type": "activecampaign_contact", "resource_name": "contact@example.test"}}
	entities, links, err := activecampaignContactsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected contact")
	}
	if len(links) != 0 {
		t.Fatalf("links = %d, want no evidence link without evidence_id", len(links))
	}
}

func TestActivecampaignIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activecampaign", Kind: "activecampaign.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := activecampaignUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestActivecampaignAutomationProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "activecampaign", Kind: "activecampaign.automations", Attributes: map[string]string{"resource_id": "automation-1", "resource_type": "activecampaign_automation", "resource_name": "Subscription Automation"}}
	entities, links, err := activecampaignAutomationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected automation")
	}
	if len(links) != 0 {
		t.Fatalf("links = %d, want no evidence link without evidence_id", len(links))
	}
}
