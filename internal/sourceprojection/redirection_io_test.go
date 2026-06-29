package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestRedirectionIoAuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.aggregate_log", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := redirectionIoAggregateLogProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}

func TestRedirectionIoIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.user", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := redirectionIoUserProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestRedirectionIoPolicyProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.agent_rule", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoAgentRuleProjections(event)
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

func TestRedirectionIoAlertProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.notification", Attributes: map[string]string{"alert_id": "alert-1", "alert_name": "High Error Rate", "alert_severity": "critical", "alert_status": "open", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoNotificationProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected alert")
	}
	if len(links) == 0 {
		t.Fatal("expected projected evidence links")
	}
}

func TestRedirectionIoAssetProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.smart_list", Attributes: map[string]string{"resource_id": "asset-1", "resource_type": "host", "resource_name": "host-1", "evidence_id": "evidence-1", "evidence_cas_uri": "cas://cases/evidence-1", "evidence_cas_digest": "sha256:test"}}
	entities, links, err := redirectionIoSmartListProjections(event)
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

func TestRedirectionIoLogProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.log", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := redirectionIoLogProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}

func TestRedirectionIoAgentRuleComplexeProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.agent_rule_complexe", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoAgentRuleComplexeProjections(event)
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

func TestRedirectionIoAgentRuleStraightProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.agent_rule_straight", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoAgentRuleStraightProjections(event)
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

func TestRedirectionIoExportRuleProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.export_rule", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoExportRuleProjections(event)
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

func TestRedirectionIoRuleProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.rule", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoRuleProjections(event)
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

func TestRedirectionIoRuleChangeProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.rule_change", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoRuleChangeProjections(event)
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

func TestRedirectionIoRuleSetVersionProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "redirection_io", Kind: "redirection_io.rule_set_version", Attributes: map[string]string{"policy_id": "policy-1", "policy_name": "Require MFA", "policy_type": "access", "policy_status": "enabled", "evidence_id": "evidence-1"}}
	entities, links, err := redirectionIoRuleSetVersionProjections(event)
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
