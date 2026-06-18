package sourceprojection

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func duoEvent(kind string, attrs map[string]string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         "duo-" + kind,
		TenantId:   "writer",
		SourceId:   "duo",
		Kind:       kind,
		Attributes: attrs,
	}
}

func TestProjectDuoUserIdentityPosture(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.user", map[string]string{
		"user_id":     "user-1",
		"username":    "alice",
		"email":       "alice@writer.com",
		"status":      "bypass",
		"is_enrolled": "false",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:duo_user:user-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"

	user := state.entities[userURN]
	if user == nil || user.EntityType != "duo.user" {
		t.Fatalf("duo.user entity missing or wrong: %#v", user)
	}
	for key, want := range map[string]string{
		"status":      "bypass",
		"is_enrolled": "false",
	} {
		if got := user.Attributes[key]; got != want {
			t.Fatalf("user posture attribute %q = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
}

func TestProjectDuoWebAuthnCredentialMFAControlLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.web_authn_credential", map[string]string{
		"credential_id": "cred-1",
		"label":         "YubiKey",
		"user_id":       "user-1",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	factorURN := "urn:cerebro:writer:duo_web_authn_credential:cred-1"
	userURN := "urn:cerebro:writer:duo_user:user-1"

	factor := state.entities[factorURN]
	if factor == nil || factor.EntityType != "duo.web_authn_credential" {
		t.Fatalf("duo.web_authn_credential entity missing or wrong: %#v", factor)
	}
	assertProjectedLink(t, state, factorURN, relationAssignedTo, userURN)
	assertProjectedLink(t, state, userURN, relationContains, factorURN)
}

func TestRegistryRoutesDuoCoreKinds(t *testing.T) {
	cases := []struct {
		kind       string
		attrs      map[string]string
		entityType string
	}{
		{"duo.user", map[string]string{"user_id": "user-1", "status": "active", "is_enrolled": "true"}, "duo.user"},
		{"duo.group", map[string]string{"group_id": "group-1", "name": "Engineering"}, "duo.group"},
		{"duo.endpoint", map[string]string{"endpoint_id": "endpoint-1", "hostname": "mba-1"}, "duo.endpoint"},
		{"duo.phone", map[string]string{"phone_id": "phone-1", "platform": "Apple iOS"}, "duo.phone"},
		{"duo.token", map[string]string{"token_id": "token-1", "type": "h6"}, "duo.token"},
		{"duo.web_authn_credential", map[string]string{"credential_id": "cred-1", "user_id": "user-1"}, "duo.web_authn_credential"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			event := duoEvent(tc.kind, tc.attrs)
			entities, _, err := BuiltinRegistry().Project(event)
			if err != nil {
				t.Fatalf("Project(%s) error = %v", tc.kind, err)
			}
			found := false
			for _, entity := range entities {
				if entity.EntityType == tc.entityType {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("kind %q did not route to projector producing %q; entities=%#v", tc.kind, tc.entityType, entities)
			}
		})
	}
}
