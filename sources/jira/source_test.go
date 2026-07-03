package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/jiraapi"
)

func TestSourceCheckAndReadUsersUsesJiraREST(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice@example.test:api-token"))
	requests := []*http.Request{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Clone(r.Context()))
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("Authorization = %q, want %q", got, wantAuth)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/api/3/myself":
			_ = json.NewEncoder(w).Encode(map[string]any{"accountId": "current-user"})
		case "/rest/api/3/users/search":
			if got := r.URL.Query().Get("startAt"); got != "0" {
				t.Fatalf("startAt = %q, want 0", got)
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"accountId":    "acct-1",
				"accountType":  "atlassian",
				"active":       true,
				"displayName":  "User One",
				"emailAddress": "user@example.test",
				"timeZone":     "America/Los_Angeles",
			}})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    defaultFamily,
		"username":  "alice@example.test",
		"password":  "api-token",
		"site_url":  "example.atlassian.net",
		"per_page":  "2",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "jira.users" {
		t.Fatalf("kind = %q", event.Kind)
	}
	for key, want := range map[string]string{
		"account_id":      "acct-1",
		"display_name":    "User One",
		"email":           "user@example.test",
		"resource_id":     "acct-1",
		"resource_type":   "identity_user",
		"source_event_id": "acct-1",
		"user_id":         "acct-1",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if len(requests) < 3 {
		t.Fatalf("request count = %d, want health, check, and read", len(requests))
	}
}

func TestSourceCheckProjectRolesUsesConfiguredFanoutProjectKey(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/api/3/myself":
			_ = json.NewEncoder(w).Encode(map[string]any{"accountId": "current-user"})
		case "/rest/api/3/project/ENG/roledetails":
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":          "tenant",
		"base_url":           server.URL,
		"family":             jiraapi.FamilyProjectRoles,
		"project_id_or_keys": "ENG",
		"username":           "alice@example.test",
		"password":           "api-token",
		"site_url":           "example.atlassian.net",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if strings.Join(requests, ",") != "/rest/api/3/myself,/rest/api/3/project/ENG/roledetails" {
		t.Fatalf("requests = %v, want health then scoped project roles check", requests)
	}
}

func TestReadMapsJiraManagementFamilies(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/api/3/group/bulk":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{{"groupId": "group-1", "name": "jira-administrators"}},
			})
		case "/rest/api/3/project/search":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{{
					"id":             "10001",
					"key":            "ENG",
					"name":           "Engineering",
					"projectTypeKey": "software",
					"simplified":     true,
					"lead":           map[string]any{"accountId": "acct-lead"},
					"insight":        map[string]any{"lastIssueUpdateTime": "2026-05-01T12:00:00.000+0000"},
				}},
			})
		case "/rest/api/3/permissionscheme":
			if got := r.URL.Query().Get("expand"); got != "permissions" {
				t.Fatalf("expand = %q, want permissions", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"permissionSchemes": []map[string]any{{
					"id":          1001,
					"name":        "Default Permission Scheme",
					"description": "Default project access",
					"permissions": []map[string]any{{"id": 10, "permission": "BROWSE_PROJECTS", "holder": map[string]any{"type": "group", "parameter": "jira-administrators", "value": "group-1"}}},
				}},
			})
		case "/rest/api/3/auditing/record":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"offset": 0,
				"limit":  100,
				"total":  1,
				"records": []map[string]any{{
					"id":              "audit-1",
					"created":         "2026-05-01T12:34:56.789+0000",
					"summary":         "Project updated",
					"category":        "projects",
					"authorAccountId": "acct-1",
					"objectItem":      map[string]any{"id": "10001", "name": "Engineering", "typeName": "PROJECT"},
				}},
			})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	tests := []struct {
		family     string
		wantAttrs  map[string]string
		wantSchema string
	}{
		{
			family: jiraapi.FamilyGroups,
			wantAttrs: map[string]string{
				"group_id":      "group-1",
				"group_name":    "jira-administrators",
				"resource_type": "identity_group",
			},
			wantSchema: "jira/groups/v1",
		},
		{
			family: jiraapi.FamilyProjects,
			wantAttrs: map[string]string{
				"project_id":    "10001",
				"project_key":   "ENG",
				"project_name":  "Engineering",
				"resource_type": "project",
			},
			wantSchema: "jira/projects/v1",
		},
		{
			family: jiraapi.FamilyPermissionSchemes,
			wantAttrs: map[string]string{
				"policy_id":     "1001",
				"policy_name":   "Default Permission Scheme",
				"policy_type":   "permission_scheme",
				"resource_type": "permission_scheme",
			},
			wantSchema: "jira/permission_schemes/v1",
		},
		{
			family: jiraapi.FamilyAuditEvents,
			wantAttrs: map[string]string{
				"actor_id":        "acct-1",
				"event_type":      "Project updated",
				"resource_id":     "10001",
				"resource_name":   "Engineering",
				"resource_type":   "PROJECT",
				"source_event_id": "audit-1",
			},
			wantSchema: "jira/audit_events/v1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"tenant_id": "tenant",
				"base_url":  server.URL,
				"family":    tt.family,
				"username":  "alice@example.test",
				"password":  "api-token",
				"site_url":  "example.atlassian.net",
				"per_page":  "100",
			}), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].SchemaRef; got != tt.wantSchema {
				t.Fatalf("schema_ref = %q, want %q", got, tt.wantSchema)
			}
			for key, want := range tt.wantAttrs {
				if got := pull.Events[0].Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
			if tt.family == jiraapi.FamilyAuditEvents {
				want := time.Date(2026, 5, 1, 12, 34, 56, 789_000_000, time.UTC)
				if !pull.Events[0].OccurredAt.AsTime().Equal(want) {
					t.Fatalf("occurred_at = %s, want %s", pull.Events[0].OccurredAt.AsTime().Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
				}
			}
		})
	}
}

func TestReadAuditEventsAllowsMissingObjectItem(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/auditing/record" {
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"offset": 0,
			"limit":  100,
			"total":  1,
			"records": []map[string]any{{
				"id":              "audit-2",
				"created":         "2026-05-01T12:34:56.789+0000",
				"summary":         "Global configuration updated",
				"category":        "configuration",
				"authorAccountId": "acct-1",
			}},
		})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    jiraapi.FamilyAuditEvents,
		"username":  "alice@example.test",
		"password":  "api-token",
		"site_url":  "example.atlassian.net",
		"per_page":  "100",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if got := event.Attributes["resource_id"]; got != "" {
		t.Fatalf("resource_id = %q, want empty for audit record without objectItem", got)
	}
	if got := event.Attributes["event_type"]; got != "Global configuration updated" {
		t.Fatalf("event_type = %q, want summary", got)
	}
	if got := event.Attributes["source_event_id"]; got != "audit-2" {
		t.Fatalf("source_event_id = %q, want audit-2", got)
	}
}

func TestReadGroupMembersFansOutConfiguredGroupIDs(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	groups := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/group/member" {
			t.Fatalf("path = %q, want group member endpoint", r.URL.Path)
		}
		groupID := r.URL.Query().Get("groupId")
		groups = append(groups, groupID)
		if got := r.URL.Query().Get("includeInactiveUsers"); got != "true" {
			t.Fatalf("includeInactiveUsers = %q, want true", got)
		}
		w.Header().Set("Content-Type", "application/json")
		members := []map[string]any{{"accountId": "acct-" + groupID, "displayName": "Member " + groupID, "emailAddress": groupID + "@example.test", "active": true, "accountType": "atlassian"}}
		if groupID == "group-a" {
			members = append(members, map[string]any{"accountId": "acct-" + groupID + "-2", "displayName": "Second " + groupID, "emailAddress": "second-" + groupID + "@example.test", "active": true, "accountType": "atlassian"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"values": members})
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    jiraapi.FamilyGroupMembers,
		"group_ids": "group-a,group-b",
		"username":  "alice@example.test",
		"password":  "api-token",
		"site_url":  "example.atlassian.net",
		"per_page":  "50",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 2 {
		t.Fatalf("first events = %d, want 2", len(first.Events))
	}
	if got := first.Events[0].Attributes["group_id"]; got != "group-a" {
		t.Fatalf("first group_id = %q, want group-a", got)
	}
	if first.Events[0].Id == first.Events[1].Id {
		t.Fatalf("same-group member event ids collapsed: %q", first.Events[0].Id)
	}
	if got := first.Events[0].Attributes["member_type"]; got != "user" {
		t.Fatalf("first member_type = %q, want user", got)
	}
	if got := first.Events[0].Attributes["account_type"]; got != "atlassian" {
		t.Fatalf("first account_type = %q, want atlassian", got)
	}
	if first.NextCursor == nil {
		t.Fatal("first NextCursor = nil, want fanout cursor")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("second events = %d, want 1", len(second.Events))
	}
	if got := second.Events[0].Attributes["group_id"]; got != "group-b" {
		t.Fatalf("second group_id = %q, want group-b", got)
	}
	if strings.Join(groups, ",") != "group-a,group-b" {
		t.Fatalf("group fanout = %v, want group-a then group-b", groups)
	}
	if first.Events[0].Id == second.Events[0].Id {
		t.Fatalf("fanout event ids collapsed: %q", first.Events[0].Id)
	}
}

func TestReadProjectRolesEnrichesRoleActors(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/api/3/project/ENG/roledetails":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 10002, "name": "Administrators", "self": "https://example.atlassian.net/rest/api/3/project/ENG/role/10002"}})
		case "/rest/api/3/project/ENG/role/10002":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":          10002,
				"name":        "Administrators",
				"description": "Project administrators",
				"scope":       map[string]any{"type": "PROJECT", "project": map[string]any{"id": "10001", "key": "ENG"}},
				"actors": []map[string]any{
					{"id": 20001, "type": "atlassian-user-role-actor", "displayName": "User One", "actorUser": map[string]any{"accountId": "acct-1"}},
					{"id": 20002, "type": "atlassian-group-role-actor", "displayName": "jira-administrators", "actorGroup": map[string]any{"groupId": "group-1", "name": "jira-administrators"}},
				},
			})
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":          "tenant",
		"base_url":           server.URL,
		"family":             jiraapi.FamilyProjectRoles,
		"project_id_or_keys": "ENG",
		"username":           "alice@example.test",
		"password":           "api-token",
		"site_url":           "example.atlassian.net",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	for key, want := range map[string]string{
		"project_id_or_key": "ENG",
		"project_id":        "10001",
		"project_key":       "ENG",
		"resource_id":       "10002",
		"role_id":           "10002",
		"role_name":         "Administrators",
		"resource_type":     "project_role",
		"source_event_id":   "10002",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("attribute %s = %q, want %q", key, got, want)
		}
	}
	var payload struct {
		Actors []map[string]any `json:"actors"`
	}
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("payload decode error = %v", err)
	}
	if len(payload.Actors) != 2 {
		t.Fatalf("actors = %d, want 2", len(payload.Actors))
	}
}

func TestReadProjectRolesRequiresRoleActorDetail(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/rest/api/3/project/ENG/roledetails":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 10002, "name": "Administrators", "self": "https://example.atlassian.net/rest/api/3/project/ENG/role/10002"}})
		case "/rest/api/3/project/ENG/role/10002":
			http.Error(w, `{"error":"role detail unavailable"}`, http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected path = %q", r.URL.Path)
		}
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id":          "tenant",
		"base_url":           server.URL,
		"family":             jiraapi.FamilyProjectRoles,
		"project_id_or_keys": "ENG",
		"username":           "alice@example.test",
		"password":           "api-token",
		"site_url":           "example.atlassian.net",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want required role detail error")
	}
}

func TestReadProviderUnavailableReturnsProviderError(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice@example.test:api-token"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("Authorization = %q, want %q", got, wantAuth)
		}
		if r.URL.Path != "/rest/api/3/users/search" {
			t.Fatalf("path = %q, want Jira users endpoint", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "maintenance"})
	}))
	defer server.Close()

	_, err = source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"tenant_id": "tenant",
		"base_url":  server.URL,
		"family":    jiraapi.FamilyUsers,
		"username":  "alice@example.test",
		"password":  "api-token",
		"site_url":  "example.atlassian.net",
		"per_page":  "100",
	}), nil)
	if err == nil {
		t.Fatal("Read() error = nil, want provider error")
	}
	if got := err.Error(); !strings.Contains(got, "jira API returned 503") {
		t.Fatalf("Read() error = %q, want provider status", got)
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}

	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range jiraapi.FamilyNames() {
		values := map[string]string{
			"family":    family,
			"tenant_id": "tenant",
		}
		switch family {
		case jiraapi.FamilyGroupMembers:
			values["group_ids"] = "group-1"
		case jiraapi.FamilyProjectRoles:
			values["project_id_or_keys"] = "ENG"
		}
		familyConfigs[family] = sourcecdk.NewConfig(values)
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
	for _, tt := range []struct {
		family          string
		kind            string
		wantResourceURN string
	}{
		{family: jiraapi.FamilyUsers, kind: "jira.users", wantResourceURN: "urn:cerebro:tenant:jira_users:acct-1"},
		{family: jiraapi.FamilyGroups, kind: "jira.groups", wantResourceURN: "urn:cerebro:tenant:jira_groups:group-1"},
		{family: jiraapi.FamilyGroupMembers, kind: "jira.group_members", wantResourceURN: "urn:cerebro:tenant:jira_users:acct-1"},
		{family: jiraapi.FamilyProjects, kind: "jira.projects", wantResourceURN: "urn:cerebro:tenant:jira_projects:10001"},
		{family: jiraapi.FamilyProjectRoles, kind: "jira.project_roles", wantResourceURN: "urn:cerebro:tenant:jira_project_roles:10002"},
		{family: jiraapi.FamilyPermissionSchemes, kind: "jira.permission_schemes", wantResourceURN: "urn:cerebro:tenant:jira_permission_schemes:1001"},
		{family: jiraapi.FamilyAuditEvents, kind: "jira.audit_events", wantResourceURN: "urn:cerebro:tenant:jira_audit_events:audit-1"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), familyConfigs[tt.family], nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if got := event.Kind; got != tt.kind {
				t.Fatalf("event kind = %q, want %q", got, tt.kind)
			}
			if got := event.Attributes["resource_urn"]; got != tt.wantResourceURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.wantResourceURN)
			}
		})
	}
}
