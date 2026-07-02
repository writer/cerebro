package snyk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/sources/internal/snykapi"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := source.Spec().GetId(); got != sourceID {
		t.Fatalf("Spec().Id = %q, want %q", got, sourceID)
	}
}

func TestSourceCheckAndRead(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token test-token" {
			t.Fatalf("Authorization"+" = %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/orgs" {
			t.Fatalf("path = %q, want /orgs", r.URL.Path)
		}
		if got := r.URL.Query().Get("version"); got != defaultAPIVersion {
			t.Fatalf("version = %q, want %q", got, defaultAPIVersion)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{{
			"id": "org-1",
			"attributes": map[string]string{
				"name":       "Security",
				"slug":       "security",
				"created_at": "2026-06-01T00:00:00Z",
				"updated_at": "2026-06-02T00:00:00Z",
			},
		}}})
	}))
	defer server.Close()
	cfgValues := map[string]string{"tenant_id": "tenant", "base_url": server.URL, "family": defaultFamily, "token": "test-token"}
	cfg := sourcecdk.NewConfig(cfgValues)
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
	if event.Kind != "snyk.orgs" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if got := event.Attributes["org_id"]; got != "org-1" {
		t.Fatalf("org_id = %q, want org-1", got)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
}

func TestRuntimeUsesSnykRESTPathsAndVersionedPagination(t *testing.T) {
	for _, tt := range []struct {
		family    string
		kind      string
		path      string
		record    map[string]any
		wantAttrs map[string]string
		wantQuery map[string]string
		config    map[string]string
		pageParam string
		wrapItems bool
	}{
		{
			family: familyOrgs,
			kind:   "snyk.orgs",
			path:   "/orgs",
			record: map[string]any{"id": "org-1", "attributes": map[string]any{"name": "Security", "slug": "security"}},
			wantAttrs: map[string]string{
				"org_id": "org-1",
				"name":   "Security",
			},
		},
		{
			family: familyGroups,
			kind:   "snyk.groups",
			path:   "/groups",
			record: map[string]any{"id": "group-1", "attributes": map[string]any{"name": "Engineering", "slug": "engineering"}},
			wantAttrs: map[string]string{
				"group_id": "group-1",
				"name":     "Engineering",
			},
		},
		{
			family: familyProjects,
			kind:   "snyk.projects",
			path:   "/orgs/org-1/projects",
			record: map[string]any{"id": "project-1", "attributes": map[string]any{"name": "Checkout API", "origin": "github", "type": "maven"}, "relationships": map[string]any{"target": map[string]any{"data": map[string]string{"id": "target-1"}}}},
			wantAttrs: map[string]string{
				"org_id":        "org-1",
				"project_id":    "project-1",
				"name":          "Checkout API",
				"target_id":     "target-1",
				"resource_type": "snyk_project",
			},
		},
		{
			family: familyTargets,
			kind:   "snyk.targets",
			path:   "/orgs/org-1/targets",
			record: map[string]any{"id": "target-1", "attributes": map[string]any{"display_name": "writer/cerebro", "source_type": "github", "url": "https://github.com/writer/cerebro", "is_private": true}},
			wantAttrs: map[string]string{
				"org_id":        "org-1",
				"target_id":     "target-1",
				"display_name":  "writer/cerebro",
				"is_private":    "true",
				"resource_type": "snyk_target",
			},
		},
		{
			family: familyAssets,
			kind:   "snyk.assets",
			path:   "/orgs/org-1/inventory/assets",
			record: map[string]any{"id": "asset-1", "attributes": map[string]any{"name": "writer/cerebro", "type": "repository", "updated_at": "2026-06-01T00:00:00Z"}},
			wantAttrs: map[string]string{
				"org_id":        "org-1",
				"asset_id":      "asset-1",
				"resource_id":   "asset-1",
				"resource_name": "writer/cerebro",
				"resource_type": "repository",
			},
		},
		{
			family: familyFindings,
			kind:   "snyk.findings",
			path:   "/orgs/org-1/issues",
			record: map[string]any{"id": "issue-1", "attributes": map[string]any{"title": "Critical package issue", "status": "open", "effective_severity_level": "critical", "type": "package_vulnerability"}, "relationships": map[string]any{"scan_item": map[string]any{"data": map[string]string{"id": "project-1", "type": "project"}}}},
			wantAttrs: map[string]string{
				"org_id":     "org-1",
				"finding_id": "issue-1",
				"severity":   "critical",
				"status":     "open",
				"issue_type": "package_vulnerability",
			},
		},
		{
			family: familyVulnerabilities,
			kind:   "snyk.vulnerabilities",
			path:   "/orgs/org-1/issues",
			record: map[string]any{"id": "vuln-1", "attributes": map[string]any{"title": "CVE-2026-0001", "status": "open", "effective_severity_level": "high", "type": "package_vulnerability"}},
			wantAttrs: map[string]string{
				"org_id":     "org-1",
				"finding_id": "vuln-1",
				"severity":   "high",
				"status":     "open",
				"issue_type": "package_vulnerability",
			},
			wantQuery: map[string]string{"type": "package_vulnerability"},
		},
		{
			family: familyOrgMemberships,
			kind:   "snyk.org_memberships",
			path:   "/orgs/org-1/memberships",
			record: map[string]any{"id": "membership-1", "attributes": map[string]any{"created_at": "2026-06-01T00:00:00Z"}, "relationships": map[string]any{"user": map[string]any{"data": map[string]string{"id": "user-1", "type": "user"}}, "role": map[string]any{"data": map[string]string{"id": "admin"}}}},
			wantAttrs: map[string]string{
				"group_id":       "org-1",
				"org_id":         "org-1",
				"membership_id":  "membership-1",
				"member_user_id": "user-1",
				"role":           "admin",
				"resource_type":  "user",
			},
		},
		{
			family: familyServiceAccounts,
			kind:   "snyk.service_accounts",
			path:   "/orgs/org-1/service_accounts",
			record: map[string]any{"id": "service-account-1", "attributes": map[string]any{"name": "CI scanner", "auth_type": "api_key", "level": "org", "role_id": "admin", "client_id": "client-1"}},
			wantAttrs: map[string]string{
				"org_id":             "org-1",
				"service_account_id": "service-account-1",
				"name":               "CI scanner",
				"role_id":            "admin",
			},
		},
		{
			family: familyAuditLogs,
			kind:   "snyk.audit_logs",
			path:   "/orgs/org-1/audit_logs/search",
			record: map[string]any{"created": "2026-06-01T00:00:00Z", "event": "org.project.create", "org_id": "org-1", "project_id": "project-1", "content": map[string]any{"user_id": "user-1", "email": "alice@example.test", "type": "project"}},
			wantAttrs: map[string]string{
				"org_id":          "org-1",
				"event_type":      "org.project.create",
				"external_id":     "2026-06-01T00:00:00Z-org.project.create-user-1-project-1",
				"source_event_id": "2026-06-01T00:00:00Z-org.project.create-user-1-project-1",
				"actor_id":        "user-1",
				"actor_email":     "alice@example.test",
				"resource_type":   "project",
			},
			pageParam: "size",
			wrapItems: true,
		},
		{
			family: familyCollections,
			kind:   "snyk.collections",
			path:   "/orgs/org-1/collections",
			record: map[string]any{"id": "collection-1", "attributes": map[string]any{"name": "Tier 0 services", "is_generated": false}, "relationships": map[string]any{"created_by_user": map[string]any{"data": map[string]string{"id": "user-1"}}, "org": map[string]any{"data": map[string]string{"id": "org-1"}}}, "meta": map[string]any{"projects_count": 4, "issues_critical_count": 2}},
			wantAttrs: map[string]string{
				"org_id":                "org-1",
				"collection_id":         "collection-1",
				"name":                  "Tier 0 services",
				"projects_count":        "4",
				"issues_critical_count": "2",
			},
		},
		{
			family: familyCloudEnvs,
			kind:   "snyk.cloud_environments",
			path:   "/orgs/org-1/cloud/environments",
			record: map[string]any{"id": "environment-1", "attributes": map[string]any{"name": "aws-prod", "kind": "aws", "native_id": "123456789012"}, "relationships": map[string]any{"organization": map[string]any{"data": map[string]string{"id": "org-1"}}, "project": map[string]any{"data": map[string]string{"id": "project-1"}}}},
			wantAttrs: map[string]string{
				"org_id":         "org-1",
				"environment_id": "environment-1",
				"resource_name":  "aws-prod",
				"kind":           "aws",
				"native_id":      "123456789012",
			},
		},
		{
			family: familyCloudResources,
			kind:   "snyk.cloud_resources",
			path:   "/orgs/org-1/cloud/resources",
			record: map[string]any{"id": "resource-1", "attributes": map[string]any{"name": "prod-bucket", "resource_type": "aws_s3_bucket", "native_id": "arn:aws:s3:::prod-bucket", "platform": "aws", "location": "us-east-1"}, "relationships": map[string]any{"organization": map[string]any{"data": map[string]string{"id": "org-1"}}, "environment": map[string]any{"data": map[string]string{"id": "environment-1"}}}},
			wantAttrs: map[string]string{
				"org_id":         "org-1",
				"resource_id":    "arn:aws:s3:::prod-bucket",
				"resource_name":  "prod-bucket",
				"resource_type":  "aws_s3_bucket",
				"environment_id": "environment-1",
			},
		},
		{
			family: familyCloudScans,
			kind:   "snyk.cloud_scans",
			path:   "/orgs/org-1/cloud/scans",
			record: map[string]any{"id": "scan-1", "attributes": map[string]any{"status": "finished", "kind": "scheduled", "created_at": "2026-06-01T00:00:00Z", "finished_at": "2026-06-01T00:05:00Z"}, "relationships": map[string]any{"environment": map[string]any{"data": map[string]string{"id": "environment-1"}}}},
			wantAttrs: map[string]string{
				"org_id":         "org-1",
				"scan_id":        "scan-1",
				"status":         "finished",
				"kind":           "scheduled",
				"resource_type":  "snyk_cloud_scan",
				"environment_id": "environment-1",
			},
		},
		{
			family: familyGroupMemberships,
			kind:   "snyk.group_memberships",
			path:   "/groups/group-1/memberships",
			record: map[string]any{"id": "group-membership-1", "attributes": map[string]any{"created_at": "2026-06-01T00:00:00Z"}, "relationships": map[string]any{"user": map[string]any{"data": map[string]string{"id": "user-1", "type": "user"}}, "role": map[string]any{"data": map[string]string{"id": "collaborator"}}}},
			wantAttrs: map[string]string{
				"group_id":       "group-1",
				"membership_id":  "group-membership-1",
				"member_user_id": "user-1",
				"role":           "collaborator",
			},
			config: map[string]string{"group_ids": "group-1"},
		},
		{
			family: familyGroupSvcAccounts,
			kind:   "snyk.group_service_accounts",
			path:   "/groups/group-1/service_accounts",
			record: map[string]any{"id": "group-service-account-1", "attributes": map[string]any{"name": "Group scanner", "auth_type": "api_key", "level": "group", "role_id": "admin"}},
			wantAttrs: map[string]string{
				"group_id":           "group-1",
				"service_account_id": "group-service-account-1",
				"name":               "Group scanner",
				"level":              "group",
			},
			config: map[string]string{"group_ids": "group-1"},
		},
		{
			family: familyGroupAuditLogs,
			kind:   "snyk.group_audit_logs",
			path:   "/groups/group-1/audit_logs/search",
			record: map[string]any{"created": "2026-06-01T00:00:00Z", "event": "group.member.add", "group_id": "group-1", "content": map[string]any{"user_id": "user-1", "email": "alice@example.test", "type": "membership"}},
			wantAttrs: map[string]string{
				"group_id":        "group-1",
				"event_type":      "group.member.add",
				"external_id":     "2026-06-01T00:00:00Z-group.member.add-user-1-group-1",
				"source_event_id": "2026-06-01T00:00:00Z-group.member.add-user-1-group-1",
				"actor_id":        "user-1",
				"resource_type":   "membership",
			},
			config:    map[string]string{"group_ids": "group-1"},
			pageParam: "size",
			wrapItems: true,
		},
		{
			family: familyAssetProjects,
			kind:   "snyk.asset_project_relationships",
			path:   "/orgs/org-1/inventory/assets/asset-1/relationships/projects",
			record: map[string]any{"id": "project-1", "type": "project", "attributes": map[string]any{"name": "Checkout API", "project_type": "sast", "target_id": "target-1", "risk_score": 890}},
			wantAttrs: map[string]string{
				"org_id":     "org-1",
				"asset_id":   "asset-1",
				"project_id": "project-1",
			},
			config: map[string]string{"asset_ids": "asset-1"},
		},
		{
			family: familyAssetTargets,
			kind:   "snyk.asset_target_relationships",
			path:   "/orgs/org-1/inventory/assets/asset-1/relationships/targets",
			record: map[string]any{"id": "target-1", "type": "target", "attributes": map[string]any{"display_name": "writer/cerebro", "target_origin": "github", "imported_at": "2026-06-01T00:00:00Z"}},
			wantAttrs: map[string]string{
				"org_id":    "org-1",
				"asset_id":  "asset-1",
				"target_id": "target-1",
			},
			config: map[string]string{"asset_ids": "asset-1"},
		},
	} {
		t.Run(tt.family, func(t *testing.T) {
			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.allowLoopbackForTest()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Token test-token" {
					t.Fatalf("Authorization = %q, want Token test-token", got)
				}
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("path = %q, want %s", got, tt.path)
				}
				if got := r.Method; got != http.MethodGet {
					t.Fatalf("method = %q, want GET", got)
				}
				assertSnykQuery(t, r.URL.Query(), defaultAPIVersion, tt.pageParam, "100", tt.wantQuery)
				w.Header().Set("Content-Type", "application/json")
				response := map[string]any{"data": []map[string]any{tt.record}}
				if tt.wrapItems {
					response = map[string]any{"data": map[string]any{"items": []map[string]any{tt.record}}}
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			values := map[string]string{
				"base_url":  server.URL,
				"family":    tt.family,
				"org_id":    "org-1",
				"tenant_id": "tenant",
				"token":     "test-token",
			}
			for key, value := range tt.config {
				values[key] = value
			}
			cfg := sourcecdk.NewConfig(values)
			pull, err := source.Read(context.Background(), cfg, nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("events = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, want := range tt.wantAttrs {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
			for key, want := range map[string]string{
				"family":          tt.family,
				"provider":        sourceID,
				"source_provider": sourceID,
			} {
				if got := event.Attributes[key]; got != want {
					t.Fatalf("attribute %s = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestAuditLogsDoNotDedupeSameTimestamp(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token test-token" {
			t.Fatalf("Authorization = %q, want Token test-token", got)
		}
		if got := r.URL.EscapedPath(); got != "/orgs/org-1/audit_logs/search" {
			t.Fatalf("path = %q, want audit log search", got)
		}
		assertSnykQuery(t, r.URL.Query(), defaultAPIVersion, "size", "100", nil)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"items": []map[string]any{
			{"created": "2026-06-01T00:00:00Z", "event": "org.project.create", "org_id": "org-1", "project_id": "project-1", "content": map[string]any{"user_id": "user-1", "email": "alice@example.test", "type": "project"}},
			{"created": "2026-06-01T00:00:00Z", "event": "org.project.create", "org_id": "org-1", "project_id": "project-2", "content": map[string]any{"user_id": "user-2", "email": "bob@example.test", "type": "project"}},
		}}})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyAuditLogs,
		"org_id":    "org-1",
		"tenant_id": "tenant",
		"token":     "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2 distinct same-timestamp audit logs", len(pull.Events))
	}
	for idx, want := range []string{
		"2026-06-01T00:00:00Z-org.project.create-user-1-project-1",
		"2026-06-01T00:00:00Z-org.project.create-user-2-project-2",
	} {
		attrs := pull.Events[idx].Attributes
		if got := attrs["external_id"]; got != want {
			t.Fatalf("event %d external_id = %q, want %q", idx, got, want)
		}
		if got := attrs["source_event_id"]; got != want {
			t.Fatalf("event %d source_event_id = %q, want %q", idx, got, want)
		}
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("same-timestamp audit logs collapsed to duplicate event id %q", pull.Events[0].Id)
	}
}

func TestGroupAuditLogsDoNotDedupeSameTimestamp(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token test-token" {
			t.Fatalf("Authorization = %q, want Token test-token", got)
		}
		if got := r.URL.EscapedPath(); got != "/groups/group-1/audit_logs/search" {
			t.Fatalf("path = %q, want group audit log search", got)
		}
		assertSnykQuery(t, r.URL.Query(), defaultAPIVersion, "size", "100", nil)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"items": []map[string]any{
			{"created": "2026-06-01T00:00:00Z", "event": "group.member.add", "group_id": "group-1", "content": map[string]any{"user_id": "user-1", "email": "alice@example.test", "type": "membership"}},
			{"created": "2026-06-01T00:00:00Z", "event": "group.member.add", "group_id": "group-1", "content": map[string]any{"user_id": "user-2", "email": "bob@example.test", "type": "membership"}},
		}}})
	}))
	defer server.Close()

	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyGroupAuditLogs,
		"group_id":  "group-1",
		"tenant_id": "tenant",
		"token":     "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 2 {
		t.Fatalf("events = %d, want 2 distinct same-timestamp group audit logs", len(pull.Events))
	}
	for idx, want := range []string{
		"2026-06-01T00:00:00Z-group.member.add-user-1-group-1",
		"2026-06-01T00:00:00Z-group.member.add-user-2-group-1",
	} {
		attrs := pull.Events[idx].Attributes
		if got := attrs["external_id"]; got != want {
			t.Fatalf("event %d external_id = %q, want %q", idx, got, want)
		}
		if got := attrs["source_event_id"]; got != want {
			t.Fatalf("event %d source_event_id = %q, want %q", idx, got, want)
		}
	}
	if pull.Events[0].Id == pull.Events[1].Id {
		t.Fatalf("same-timestamp group audit logs collapsed to duplicate event id %q", pull.Events[0].Id)
	}
}

func TestRuntimeExtractsSnykRelativeNextLinkCursor(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	requests := []url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Query())
		if got := r.URL.EscapedPath(); got != "/orgs/org-1/inventory/assets" {
			t.Fatalf("path = %q, want /orgs/org-1/inventory/assets", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("starting_after") {
		case "":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "asset-1", "attributes": map[string]string{"name": "Repo One", "type": "repository"}}},
				"links": map[string]string{
					"next": "/orgs/org-1/inventory/assets?version=2026-03-25&limit=100&starting_after=cursor-2",
				},
			})
		case "cursor-2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{"id": "asset-2", "attributes": map[string]string{"name": "Repo Two", "type": "repository"}}},
			})
		default:
			t.Fatalf("starting_after = %q, want empty or cursor-2", r.URL.Query().Get("starting_after"))
		}
	}))
	defer server.Close()

	cfg := sourcecdk.NewConfig(map[string]string{
		"base_url":  server.URL,
		"family":    familyAssets,
		"org_id":    "org-1",
		"tenant_id": "tenant",
		"token":     "test-token",
	})
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if first.NextCursor.GetOpaque() != "cursor-2" {
		t.Fatalf("first NextCursor = %q, want cursor-2", first.NextCursor.GetOpaque())
	}
	second, err := source.Read(context.Background(), cfg, &cerebrov1.SourceCursor{Opaque: "cursor-2"})
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if second.NextCursor != nil {
		t.Fatalf("second NextCursor = %#v, want nil", second.NextCursor)
	}
	if len(requests) != 2 || requests[1].Get("starting_after") != "cursor-2" {
		t.Fatalf("requests = %#v, want second request with starting_after=cursor-2", requests)
	}
}

func TestNewFixtureReplaysSnykFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range snykapi.FamilyNames() {
		values := map[string]string{
			"family":    family,
			"org_id":    "org-1",
			"tenant_id": "tenant",
		}
		switch family {
		case familyGroupMemberships, familyGroupSvcAccounts, familyGroupAuditLogs:
			values["group_ids"] = "group-1"
		case familyAssetProjects, familyAssetTargets:
			values["asset_ids"] = "asset-1"
		}
		familyConfigs[family] = sourcecdk.NewConfig(values)
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func assertSnykQuery(t *testing.T, query url.Values, wantVersion string, pageParam string, wantPageSize string, want map[string]string) {
	t.Helper()
	if got := query.Get("version"); got != wantVersion {
		t.Fatalf("version = %q, want %q", got, wantVersion)
	}
	if pageParam == "" {
		pageParam = "limit"
	}
	if got := query.Get(pageParam); got != wantPageSize {
		t.Fatalf("%s = %q, want %q", pageParam, got, wantPageSize)
	}
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
}
