package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestApolloAccountProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apollo", Kind: "apollo.accounts", Attributes: map[string]string{"resource_id": "account-1", "resource_type": "apollo_account", "resource_name": "Apollo Account", "domain": "example.test", "organization_id": "org-1"}}
	entities, _, err := apolloAccountsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected account entity")
	}
}

func TestApolloIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apollo", Kind: "apollo.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := apolloUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestApolloContactProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "apollo", Kind: "apollo.contacts", Attributes: map[string]string{"user_id": "contact-1", "email": "contact@example.test", "display_name": "Contact One"}}
	entities, _, err := apolloContactsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected contact identity")
	}
}
