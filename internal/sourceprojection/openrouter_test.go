package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestOpenrouterAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "openrouter", Kind: "openrouter.usage_reports", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := openrouterUsageReportsProjections(event)
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

func TestOpenrouterSecretProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "openrouter", Kind: "openrouter.api_keys", Attributes: map[string]string{"secret_id": "secret-1", "secret_name": "DB Password", "secret_type": "password", "secret_status": "active", "evidence_id": "evidence-1"}}
	entities, links, err := openrouterApiKeysProjections(event)
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

func TestOpenrouterSecretProjectionDerivesStatusFromDisabledFlag(t *testing.T) {
	tests := []struct {
		name       string
		attrs      map[string]string
		wantStatus string
	}{
		{name: "active api key", attrs: map[string]string{"api_key_disabled": "false"}, wantStatus: "active"},
		{name: "disabled api key", attrs: map[string]string{"api_key_disabled": "true"}, wantStatus: "disabled"},
		{name: "disabled provider key", attrs: map[string]string{"provider_key_disabled": "true"}, wantStatus: "disabled"},
		{name: "explicit status wins", attrs: map[string]string{"api_key_disabled": "true", "secret_status": "rotating"}, wantStatus: "rotating"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := map[string]string{"secret_id": "secret-1", "secret_name": "OpenRouter key", "secret_type": "openrouter_api_key"}
			for key, value := range tt.attrs {
				attrs[key] = value
			}
			event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "openrouter", Kind: "openrouter.api_keys", Attributes: attrs}
			entities, _, err := openrouterApiKeysProjections(event)
			if err != nil {
				t.Fatalf("projection error = %v", err)
			}
			var secretStatus string
			for _, entity := range entities {
				if entity.EntityType == "secret" {
					secretStatus = entity.Attributes["secret_status"]
					break
				}
			}
			if secretStatus == "" {
				t.Fatal("expected projected secret")
			}
			if got := secretStatus; got != tt.wantStatus {
				t.Fatalf("secret_status = %q, want %q", got, tt.wantStatus)
			}
		})
	}
}

func TestOpenrouterIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "openrouter", Kind: "openrouter.organization_members", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := openrouterOrganizationMembersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}
