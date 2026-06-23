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
		"user_id":             "user-1",
		"username":            "alice",
		"email":               "alice@writer.com",
		"realname":            "Alice Example",
		"status":              "bypass",
		"is_enrolled":         "false",
		"last_login_at":       "2024-01-15T10:30:00Z",
		"lockout_reason":      "not_locked",
		"last_directory_sync": "2024-01-14T08:00:00Z",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:duo_user:user-1"
	identityURN := "urn:cerebro:writer:identity:email:alice@writer.com"
	identifierURN := "urn:cerebro:writer:identifier:email:alice@writer.com"

	user := state.entities[userURN]
	if user == nil || user.EntityType != "duo.user" {
		t.Fatalf("duo.user entity missing or wrong: %#v", user)
	}
	if user.Label != "alice" {
		t.Fatalf("user label = %q, want alice", user.Label)
	}
	for key, want := range map[string]string{
		"user_id":             "user-1",
		"username":            "alice",
		"email":               "alice@writer.com",
		"realname":            "Alice Example",
		"status":              "bypass",
		"is_enrolled":         "false",
		"last_login_at":       "2024-01-15T10:30:00Z",
		"lockout_reason":      "not_locked",
		"last_directory_sync": "2024-01-14T08:00:00Z",
		"mfa_enrolled":        "false",
		"active":              "true",
	} {
		if got := user.Attributes[key]; got != want {
			t.Fatalf("user attribute %q = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, userURN, relationRepresentsIdentity, identityURN)
	assertProjectedLink(t, state, userURN, relationHasIdentifier, identifierURN)
}

func TestProjectDuoUserMFAEnrolledActive(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.user", map[string]string{
		"user_id":     "user-2",
		"username":    "bob",
		"email":       "bob@writer.com",
		"status":      "active",
		"is_enrolled": "true",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:duo_user:user-2"
	user := state.entities[userURN]
	if user == nil {
		t.Fatal("duo.user entity missing")
	}
	for key, want := range map[string]string{
		"mfa_enrolled": "true",
		"active":       "true",
	} {
		if got := user.Attributes[key]; got != want {
			t.Fatalf("user attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestProjectDuoUserDisabledPosture(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.user", map[string]string{
		"user_id":     "user-3",
		"username":    "charlie",
		"status":      "disabled",
		"is_enrolled": "false",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	user := state.entities["urn:cerebro:writer:duo_user:user-3"]
	if user == nil {
		t.Fatal("duo.user entity missing")
	}
	for key, want := range map[string]string{
		"mfa_enrolled": "false",
		"active":       "false",
	} {
		if got := user.Attributes[key]; got != want {
			t.Fatalf("user attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestProjectDuoUserEmptyIDSkipped(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.user", map[string]string{
		"user_id":  "",
		"username": "ghost",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if len(state.entities) != 0 {
		t.Fatalf("expected no entities for empty user_id, got %d", len(state.entities))
	}
}

func TestProjectDuoUserNoEmailSkipsIdentityLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.user", map[string]string{
		"user_id":  "user-4",
		"username": "noemail",
		"status":   "active",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	userURN := "urn:cerebro:writer:duo_user:user-4"
	if state.entities[userURN] == nil {
		t.Fatal("duo.user entity missing")
	}
	if len(state.links) != 0 {
		t.Fatalf("expected no links for user without email, got %d", len(state.links))
	}
}

func TestProjectDuoGroupAttributes(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.group", map[string]string{
		"group_id":    "group-1",
		"name":        "Engineering",
		"description": "Eng team",
		"status":      "Active",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	groupURN := "urn:cerebro:writer:duo_group:group-1"
	group := state.entities[groupURN]
	if group == nil || group.EntityType != "duo.group" {
		t.Fatalf("duo.group entity missing or wrong: %#v", group)
	}
	if group.Label != "Engineering" {
		t.Fatalf("group label = %q, want Engineering", group.Label)
	}
	for key, want := range map[string]string{
		"group_id":    "group-1",
		"name":        "Engineering",
		"description": "Eng team",
		"status":      "Active",
	} {
		if got := group.Attributes[key]; got != want {
			t.Fatalf("group attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestProjectDuoGroupEmptyIDSkipped(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.group", map[string]string{
		"group_id": "",
		"name":     "Ghost Group",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	if len(state.entities) != 0 {
		t.Fatalf("expected no entities for empty group_id, got %d", len(state.entities))
	}
}

func TestProjectDuoEndpointAttributes(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.endpoint", map[string]string{
		"endpoint_id":            "ep-1",
		"hostname":               "mba-alice",
		"os":                     "macOS",
		"os_version":             "14.2",
		"browser":                "Chrome",
		"disk_encryption_status": "Encrypted",
		"last_seen_at":           "2024-01-15T12:00:00Z",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	epURN := "urn:cerebro:writer:duo_endpoint:ep-1"
	ep := state.entities[epURN]
	if ep == nil || ep.EntityType != "duo.endpoint" {
		t.Fatalf("duo.endpoint entity missing or wrong: %#v", ep)
	}
	if ep.Label != "mba-alice" {
		t.Fatalf("endpoint label = %q, want mba-alice", ep.Label)
	}
	for key, want := range map[string]string{
		"endpoint_id":            "ep-1",
		"hostname":               "mba-alice",
		"os":                     "macOS",
		"os_version":             "14.2",
		"browser":                "Chrome",
		"disk_encryption_status": "Encrypted",
		"last_seen_at":           "2024-01-15T12:00:00Z",
	} {
		if got := ep.Attributes[key]; got != want {
			t.Fatalf("endpoint attribute %q = %q, want %q", key, got, want)
		}
	}
}

func TestProjectDuoPhoneFactorOwnerLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.phone", map[string]string{
		"phone_id":    "phone-1",
		"name":        "iPhone",
		"number":      "+15551234567",
		"platform":    "Apple iOS",
		"model":       "iPhone 15",
		"activated":   "true",
		"encrypted":   "Encrypted",
		"screenlock":  "Locked",
		"tampered":    "Not tampered",
		"user_id":     "user-1",
		"last_seen_at": "2024-01-15T10:00:00Z",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	phoneURN := "urn:cerebro:writer:duo_phone:phone-1"
	userURN := "urn:cerebro:writer:duo_user:user-1"

	phone := state.entities[phoneURN]
	if phone == nil || phone.EntityType != "duo.phone" {
		t.Fatalf("duo.phone entity missing or wrong: %#v", phone)
	}
	for key, want := range map[string]string{
		"phone_id":    "phone-1",
		"platform":    "Apple iOS",
		"model":       "iPhone 15",
		"activated":   "true",
		"encrypted":   "Encrypted",
		"screenlock":  "Locked",
		"tampered":    "Not tampered",
		"factor_type": "phone",
	} {
		if got := phone.Attributes[key]; got != want {
			t.Fatalf("phone attribute %q = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, phoneURN, relationAssignedTo, userURN)
	assertProjectedLink(t, state, userURN, relationContains, phoneURN)
}

func TestProjectDuoPhoneNoOwnerSkipsLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.phone", map[string]string{
		"phone_id": "phone-2",
		"name":     "Orphan Phone",
		"platform": "Android",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	phoneURN := "urn:cerebro:writer:duo_phone:phone-2"
	if state.entities[phoneURN] == nil {
		t.Fatal("duo.phone entity missing")
	}
	if len(state.links) != 0 {
		t.Fatalf("expected no links for phone without user_id, got %d", len(state.links))
	}
}

func TestProjectDuoTokenFactorOwnerLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.token", map[string]string{
		"token_id": "token-1",
		"serial":   "SN-123",
		"type":     "h6",
		"totp_step": "30",
		"user_id":  "user-1",
	})
	if _, err := service.Project(context.Background(), event); err != nil {
		t.Fatalf("Project() error = %v", err)
	}

	tokenURN := "urn:cerebro:writer:duo_token:token-1"
	userURN := "urn:cerebro:writer:duo_user:user-1"

	token := state.entities[tokenURN]
	if token == nil || token.EntityType != "duo.token" {
		t.Fatalf("duo.token entity missing or wrong: %#v", token)
	}
	for key, want := range map[string]string{
		"token_id":    "token-1",
		"serial":      "SN-123",
		"type":        "h6",
		"totp_step":   "30",
		"factor_type": "hardware_token",
	} {
		if got := token.Attributes[key]; got != want {
			t.Fatalf("token attribute %q = %q, want %q", key, got, want)
		}
	}
	assertProjectedLink(t, state, tokenURN, relationAssignedTo, userURN)
	assertProjectedLink(t, state, userURN, relationContains, tokenURN)
}

func TestProjectDuoWebAuthnCredentialMFAControlLink(t *testing.T) {
	state := &projectionRecorder{}
	service := New(state, nil)

	event := duoEvent("duo.web_authn_credential", map[string]string{
		"credential_id":   "cred-1",
		"label":           "YubiKey",
		"credential_name": "yk-5c",
		"user_id":         "user-1",
		"last_used_at":    "2024-01-15T09:00:00Z",
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
	for key, want := range map[string]string{
		"credential_id":   "cred-1",
		"label":           "YubiKey",
		"credential_name": "yk-5c",
		"factor_type":     "webauthn",
		"last_used_at":    "2024-01-15T09:00:00Z",
	} {
		if got := factor.Attributes[key]; got != want {
			t.Fatalf("webauthn attribute %q = %q, want %q", key, got, want)
		}
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
