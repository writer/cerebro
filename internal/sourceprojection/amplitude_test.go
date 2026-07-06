package sourceprojection

import (
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAmplitudeIdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "amplitude", Kind: "amplitude.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := amplitudeUsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAmplitudeIdentityGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "amplitude", Kind: "amplitude.groups", Attributes: map[string]string{"group_id": "group-1", "group_name": "Amplitude Admins"}}
	entities, _, err := amplitudeGroupsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity group")
	}
}
