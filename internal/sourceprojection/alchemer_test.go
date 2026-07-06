package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAlchemerAccountProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alchemer", Kind: "alchemer.account", Attributes: map[string]string{"resource_id": "acct-1", "resource_type": "account", "resource_name": "Writer Account", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := alchemerAccountProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want projected account with evidence", len(entities), len(links))
	}
}

func TestAlchemerAccountTeamProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alchemer", Kind: "alchemer.account_teams", Attributes: map[string]string{"resource_id": "team-1", "resource_type": "account_team", "resource_name": "Security Team", "evidence_id": "evidence-1"}}
	entities, links, err := alchemerAccountTeamsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want projected team with evidence", len(entities), len(links))
	}
}

func TestAlchemerIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alchemer", Kind: "alchemer.account_users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := alchemerAccountUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAlchemerContactListProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alchemer", Kind: "alchemer.contact_lists", Attributes: map[string]string{"resource_id": "list-1", "resource_type": "contact_list", "resource_name": "Customers", "evidence_id": "evidence-1"}}
	entities, links, err := alchemerContactListsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want projected contact list with evidence", len(entities), len(links))
	}
}

func TestAlchemerPolicyProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alchemer", Kind: "alchemer.sso_integrations", Attributes: map[string]string{"policy_id": "sso-1", "policy_name": "Corporate SSO", "policy_type": "sso_integration", "policy_status": "Active", "evidence_id": "evidence-1"}}
	entities, links, err := alchemerSSOIntegrationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want projected SSO policy with evidence", len(entities), len(links))
	}
}

func TestAlchemerSurveyProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "alchemer", Kind: "alchemer.surveys", Attributes: map[string]string{"resource_id": "survey-1", "resource_type": "survey", "resource_name": "Security Survey", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := alchemerSurveysProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want projected survey with evidence", len(entities), len(links))
	}
}
