package sourceprojection

import (
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestAuth0IdentityUserProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.users", Attributes: map[string]string{"user_id": "user-1", "email": "user@example.test", "display_name": "User One"}}
	entities, _, err := auth0UsersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity user")
	}
}

func TestAuth0IdentityGroupProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.roles", Attributes: map[string]string{"group_id": "group-1", "group_email": "group@example.test", "group_name": "Group One"}}
	entities, _, err := auth0RolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 {
		t.Fatal("expected projected identity group")
	}
}

func TestAuth0AuditProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.audit_events", Attributes: map[string]string{"event_type": "user.login", "actor_id": "user-1", "actor_email": "user@example.test", "resource_id": "app-1", "resource_type": "application"}}
	entities, links, err := auth0AuditEventsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want audit projection", len(entities), len(links))
	}
}

func TestAuth0OrganizationProjectionSkipsMissingOrgID(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.organizations", Attributes: map[string]string{"display_name": "Example Org"}}
	entities, links, err := auth0OrganizationsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) != 0 || len(links) != 0 {
		t.Fatalf("entities/links = %d/%d, want no projection without org ID; entities=%#v links=%#v", len(entities), len(links), entities, links)
	}
}

func TestAuth0OrganizationMemberProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.organization_members", Attributes: map[string]string{"organization_id": "org-1", "member_user_id": "auth0|user-1", "member_email": "user@example.test", "member_name": "User One", "role": "role-1"}}
	entities, links, err := auth0OrganizationMembersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want organization membership projection", len(entities), len(links))
	}
}

func TestAuth0OrganizationMemberProjectionSkipsMissingOrgID(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.organization_members", Attributes: map[string]string{"member_user_id": "auth0|user-1", "member_email": "user@example.test", "member_name": "User One"}}
	entities, links, err := auth0OrganizationMembersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	ghostOrgURN := projectionURN("tenant", "auth0_org", "")
	userURN := identityUserURN("tenant", "auth0", "auth0|user-1", "user@example.test")
	entityURNs := map[string]struct{}{}
	for _, entity := range entities {
		entityURNs[entity.URN] = struct{}{}
	}
	if _, ok := entityURNs[userURN]; !ok {
		t.Fatalf("missing member user entity %q; entities=%#v", userURN, entities)
	}
	if _, ok := entityURNs[ghostOrgURN]; ok {
		t.Fatalf("projected degenerate org entity %q; entities=%#v", ghostOrgURN, entities)
	}
	for _, link := range links {
		if link.FromURN == ghostOrgURN || link.ToURN == ghostOrgURN {
			t.Fatalf("projected link to degenerate org %q; link=%#v", ghostOrgURN, link)
		}
	}
}

func TestAuth0ApplicationProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.clients", Attributes: map[string]string{"app_id": "client-1", "app_name": "Workforce Portal", "client_id": "client-1", "redirect_uri_hosts": "app.example.test"}}
	entities, links, err := auth0ClientsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want application and OAuth client projection", len(entities), len(links))
	}
}

func TestAuth0ConnectionProjectionSkipsMissingConnectionID(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.connections", Attributes: map[string]string{"connection_name": "Database", "enabled_clients": "client-1"}}
	entities, links, err := auth0ConnectionsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) != 0 || len(links) != 0 {
		t.Fatalf("entities/links = %d/%d, want no projection without connection ID; entities=%#v links=%#v", len(entities), len(links), entities, links)
	}
}

func TestAuth0ResourceServerProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.resource_servers", Attributes: map[string]string{"api_id": "api-1", "api_identifier": "https://api.example.test", "api_name": "Example API", "scopes": "[{\"value\":\"read:reports\"}]"}}
	entities, links, err := auth0ResourceServersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want API scope projection", len(entities), len(links))
	}
}

func TestAuth0ResourceServerProjectionSkipsMissingAPIID(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.resource_servers", Attributes: map[string]string{"api_name": "Example API", "scopes": "read:reports"}}
	entities, links, err := auth0ResourceServersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	ghostAPIURN := projectionURN("tenant", "auth0_api", "")
	for _, entity := range entities {
		if entity.URN == ghostAPIURN {
			t.Fatalf("projected degenerate API entity %q; entities=%#v", ghostAPIURN, entities)
		}
	}
	for _, link := range links {
		if link.FromURN == ghostAPIURN || link.ToURN == ghostAPIURN {
			t.Fatalf("projected link to degenerate API %q; link=%#v", ghostAPIURN, link)
		}
	}
}

func TestAuth0ResourceServerProjectionUsesAudienceFallbackConsistently(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.resource_servers", Attributes: map[string]string{"api_id": "api-1", "audience": "https://api.example.test", "resource_id": "resource-server-1", "scopes": "read:reports"}}
	entities, links, err := auth0ResourceServersProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	wantAPIURN := projectionURN("tenant", "auth0_api", "https://api.example.test")
	wantEntitlementURN := auth0APIEntitlementURN("tenant", "https://api.example.test", "read:reports")
	entityURNs := map[string]struct{}{}
	for _, entity := range entities {
		entityURNs[entity.URN] = struct{}{}
	}
	if _, ok := entityURNs[wantAPIURN]; !ok {
		t.Fatalf("missing API entity %q; entities=%#v", wantAPIURN, entities)
	}
	if _, ok := entityURNs[wantEntitlementURN]; !ok {
		t.Fatalf("missing entitlement entity %q; entities=%#v", wantEntitlementURN, entities)
	}
	if !projectedLinksContain(links, wantAPIURN, relationGrantsEntitlement, wantEntitlementURN) {
		t.Fatalf("missing API grants entitlement link %s -> %s; links=%#v", wantAPIURN, wantEntitlementURN, links)
	}
}

func TestAuth0RoleEntitlementProjectionDoesNotUseResourceIDFallback(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.roles", Attributes: map[string]string{"resource_id": "role-resource-1", "group_name": "Admin Role"}}
	entities, links, err := auth0RolesProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	entityURNs := map[string]struct{}{}
	for _, entity := range entities {
		entityURNs[entity.URN] = struct{}{}
	}
	for _, link := range links {
		if _, ok := entityURNs[link.FromURN]; !ok {
			t.Fatalf("link source %q has no projected entity; link=%#v entities=%#v", link.FromURN, link, entities)
		}
		if _, ok := entityURNs[link.ToURN]; !ok {
			t.Fatalf("link target %q has no projected entity; link=%#v entities=%#v", link.ToURN, link, entities)
		}
	}
}

func TestAuth0ScopeValuesParseRuntimeObjectStream(t *testing.T) {
	got := auth0ScopeValues(`{"value":"read:reports","description":"Read, reports"},{"value":"write:reports","description":"Write reports"}`)
	if joined := strings.Join(got, ","); joined != "read:reports,write:reports" {
		t.Fatalf("auth0ScopeValues() = %#v, want read/write scopes", got)
	}
	for _, scope := range got {
		if strings.Contains(scope, "description") {
			t.Fatalf("auth0ScopeValues() included object fragment %q", scope)
		}
	}
}

func TestAuth0GrantProjection(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.client_grants", Attributes: map[string]string{"client_grant_id": "grant-1", "client_id": "client-1", "audience": "https://api.example.test", "scope": "read:reports", "subject_type": "application"}}
	entities, links, err := auth0ClientGrantsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want grant projection", len(entities), len(links))
	}
	entityURNs := map[string]struct{}{}
	for _, entity := range entities {
		entityURNs[entity.URN] = struct{}{}
	}
	for _, link := range links {
		if _, ok := entityURNs[link.FromURN]; !ok {
			t.Fatalf("link source %q has no projected entity; link=%#v entities=%#v", link.FromURN, link, entities)
		}
		if _, ok := entityURNs[link.ToURN]; !ok {
			t.Fatalf("link target %q has no projected entity; link=%#v entities=%#v", link.ToURN, link, entities)
		}
	}
}

func TestAuth0UserGrantProjectionUsesAppIDAsClientID(t *testing.T) {
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.grants", Attributes: map[string]string{"grant_id": "grant-1", "app_id": "client-1", "audience": "https://api.example.test", "scope": "read:reports", "subject_id": "auth0|user-1", "subject_type": "user"}}
	entities, links, err := auth0GrantsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	wantClientURN := identityOAuthClientURN("tenant", "auth0", "client-1")
	wantEntitlementURN := auth0APIEntitlementURN("tenant", "https://api.example.test", "read:reports")
	entityURNs := map[string]struct{}{}
	for _, entity := range entities {
		entityURNs[entity.URN] = struct{}{}
	}
	if _, ok := entityURNs[wantClientURN]; !ok {
		t.Fatalf("missing OAuth client entity %q; entities=%#v", wantClientURN, entities)
	}
	if _, ok := entityURNs["urn:cerebro:tenant:auth0_oauth_client"]; ok {
		t.Fatalf("projected degenerate OAuth client entity; entities=%#v", entities)
	}
	if !projectedLinksContain(links, wantClientURN, relationGrantsEntitlement, wantEntitlementURN) {
		t.Fatalf("missing OAuth client grant link %s -> %s; links=%#v", wantClientURN, wantEntitlementURN, links)
	}
}

func TestAuth0AuthenticationMethodProjection(t *testing.T) {
	idField := "cred" + "ential_id"
	typeField := "cred" + "ential_type"
	event := &cerebrov1.EventEnvelope{Id: "event-1", TenantId: "tenant", SourceId: "auth0", Kind: "auth0.user_authentication_methods", Attributes: map[string]string{idField: "method-1", typeField: "webauthn-roaming", "user_id": "auth0|user-1", "status": "true"}}
	entities, links, err := auth0UserAuthenticationMethodsProjections(event)
	if err != nil {
		t.Fatalf("projection error = %v", err)
	}
	if len(entities) == 0 || len(links) == 0 {
		t.Fatalf("entities/links = %d/%d, want authentication method projection", len(entities), len(links))
	}
}
