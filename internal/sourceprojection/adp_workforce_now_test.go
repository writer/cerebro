package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAdpWorkforceNowIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "adp_workforce_now", Kind: "adp_workforce_now.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := adpWorkforceNowUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAdpWorkforceNowEventNotificationsProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "adp_workforce_now", Kind: "adp_workforce_now.event_notifications", Attributes: map[string]string{"event_type": "worker.hire", "actor_id": "user-1", "resource_id": "worker-1", "resource_type": "worker"}}
	entities, links, err := adpWorkforceNowEventNotificationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want event notification projection", len(entities), len(links))
	}
}
