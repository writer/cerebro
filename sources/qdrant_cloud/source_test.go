package qdrant_cloud

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	testAccountID = "11111111-1111-4111-8111-111111111111"
	testClusterID = "22222222-2222-4222-8222-222222222222"
	testUserID    = "33333333-3333-4333-8333-333333333333"
)

func TestSourceCheckAndRead(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireQdrantCloudAuth(t, r)
		if r.URL.Path != "/api/account/v1/accounts" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		writeJSON(t, w, qdrantAccountsBody())
	}))
	defer server.Close()

	cfg := qdrantTestConfig(defaultFamily, server.URL)
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
	if event.Kind != "qdrant_cloud.accounts" {
		t.Fatalf("kind = %q", event.Kind)
	}
	if strings.TrimSpace(event.Id) == "" {
		t.Fatalf("event id is empty: %#v", event)
	}
	if got := event.Attributes["resource_urn"]; got != "urn:cerebro:tenant:qdrant_cloud_accounts:"+testAccountID {
		t.Fatalf("resource_urn = %q", got)
	}
}

func TestSourceReadsProviderShapedFamilies(t *testing.T) {
	tests := []struct {
		family      string
		path        string
		body        map[string]any
		kind        string
		attr        string
		want        string
		wantQuery   map[string]string
		resourceURN string
	}{
		{
			family:      familyAccounts,
			path:        "/api/account/v1/accounts",
			body:        qdrantAccountsBody(),
			kind:        "qdrant_cloud.accounts",
			attr:        "account_owner_email",
			want:        "owner@example.test",
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_accounts:" + testAccountID,
		},
		{
			family: familyAccountMembers,
			path:   "/api/account/v1/accounts/" + testAccountID + "/members",
			body: map[string]any{"items": []map[string]any{{
				"accountMember": map[string]any{
					"createdAt":        "2026-05-02T10:00:00Z",
					"defaultAccountId": testAccountID,
					"email":            "platform.admin@example.test",
					"id":               testUserID,
					"lastModifiedAt":   "2026-05-30T12:35:00Z",
					"onboardingStatus": "ONBOARDING_STATUS_COMPLETED",
					"status":           "USER_STATUS_ACTIVE",
				},
				"isOwner": false,
			}}},
			kind:        "qdrant_cloud.account_members",
			attr:        "user_id",
			want:        testUserID,
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_account_members:" + testUserID,
		},
		{
			family: familyClusters,
			path:   "/api/cluster/v1/accounts/" + testAccountID + "/clusters",
			body: map[string]any{
				"items":     []map[string]any{qdrantClusterPayload()},
				"totalSize": 1,
			},
			kind:        "qdrant_cloud.clusters",
			attr:        "deployment_status",
			want:        "CLUSTER_PHASE_HEALTHY",
			wantQuery:   map[string]string{"pageSize": "100"},
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_clusters:" + testClusterID,
		},
		{
			family: familyDatabaseApiKeys,
			path:   "/api/cluster/auth/v2/accounts/" + testAccountID + "/database-api-keys",
			body: map[string]any{"items": []map[string]any{{
				"accessRules": []map[string]any{{
					"globalAccess": map[string]any{"accessType": "GLOBAL_ACCESS_RULE_ACCESS_TYPE_READ_ONLY"},
				}},
				"accountId":      testAccountID,
				"clusterId":      testClusterID,
				"createdAt":      "2026-05-04T12:00:00Z",
				"createdByEmail": "platform.admin@example.test",
				"expiresAt":      "2026-12-31T23:59:59Z",
				"id":             "44444444-4444-4444-8444-444444444444",
				"name":           "Production read key",
				"postfix":        "abcd1234",
			}}},
			kind:        "qdrant_cloud.database_api_keys",
			attr:        "secret_name",
			want:        "Production read key",
			wantQuery:   map[string]string{"clusterId": testClusterID},
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_database_api_keys:44444444-4444-4444-8444-444444444444",
		},
		{
			family: familyBackups,
			path:   "/api/cluster/backup/v1/accounts/" + testAccountID + "/backups",
			body: map[string]any{
				"items": []map[string]any{{
					"accountId":        testAccountID,
					"backupDuration":   "1800s",
					"backupScheduleId": "77777777-7777-4777-8777-777777777777",
					"clusterId":        testClusterID,
					"createdAt":        "2026-05-05T01:30:00Z",
					"id":               "55555555-5555-4555-8555-555555555555",
					"name":             "prod-search-2026-05-05",
					"retentionPeriod":  "2592000s",
					"status":           "BACKUP_STATUS_SUCCEEDED",
				}},
				"totalSize": 1,
			},
			kind:        "qdrant_cloud.backups",
			attr:        "backup_status",
			want:        "BACKUP_STATUS_SUCCEEDED",
			wantQuery:   map[string]string{"clusterId": testClusterID, "pageSize": "100"},
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_backups:55555555-5555-4555-8555-555555555555",
		},
		{
			family: familyBackupRestores,
			path:   "/api/cluster/backup/v1/accounts/" + testAccountID + "/backup_restores",
			body: map[string]any{
				"items": []map[string]any{{
					"accountId": testAccountID,
					"backupId":  "55555555-5555-4555-8555-555555555555",
					"clusterId": testClusterID,
					"createdAt": "2026-05-06T02:00:00Z",
					"id":        "66666666-6666-4666-8666-666666666666",
					"status":    "BACKUP_RESTORE_STATUS_SUCCEEDED",
				}},
				"totalSize": 1,
			},
			kind:        "qdrant_cloud.backup_restores",
			attr:        "deployment_status",
			want:        "BACKUP_RESTORE_STATUS_SUCCEEDED",
			wantQuery:   map[string]string{"clusterId": testClusterID, "pageSize": "100"},
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_backup_restores:66666666-6666-4666-8666-666666666666",
		},
		{
			family: familyBackupSchedules,
			path:   "/api/cluster/backup/v1/accounts/" + testAccountID + "/backup_schedules",
			body: map[string]any{
				"items": []map[string]any{{
					"accountId":       testAccountID,
					"clusterId":       testClusterID,
					"createdAt":       "2026-05-04T23:00:00Z",
					"id":              "77777777-7777-4777-8777-777777777777",
					"retentionPeriod": "2592000s",
					"schedule":        "0 1 * * *",
					"status":          "BACKUP_SCHEDULE_STATUS_ACTIVE",
				}},
				"totalSize": 1,
			},
			kind:        "qdrant_cloud.backup_schedules",
			attr:        "policy_status",
			want:        "BACKUP_SCHEDULE_STATUS_ACTIVE",
			wantQuery:   map[string]string{"clusterId": testClusterID, "pageSize": "100"},
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_backup_schedules:77777777-7777-4777-8777-777777777777",
		},
		{
			family: familyRoles,
			path:   "/api/iam/v1/accounts/" + testAccountID + "/roles",
			body: map[string]any{"items": []map[string]any{{
				"accountId":      testAccountID,
				"createdAt":      "2026-05-07T09:00:00Z",
				"description":    "Can read cluster, backup, and API key metadata",
				"id":             "88888888-8888-4888-8888-888888888888",
				"lastModifiedAt": "2026-05-30T09:00:00Z",
				"name":           "Security Auditor",
				"permissions":    []map[string]any{{"category": "Cluster", "value": "read:clusters"}},
				"roleType":       "ROLE_TYPE_CUSTOM",
			}}},
			kind:        "qdrant_cloud.roles",
			attr:        "role_type",
			want:        "ROLE_TYPE_CUSTOM",
			resourceURN: "urn:cerebro:tenant:qdrant_cloud_roles:88888888-8888-4888-8888-888888888888",
		},
	}

	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			source := newTestSource(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requireQdrantCloudAuth(t, r)
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				for key, want := range tt.wantQuery {
					if got := r.URL.Query().Get(key); got != want {
						t.Fatalf("query %s = %q, want %q", key, got, want)
					}
				}
				writeJSON(t, w, tt.body)
			}))
			defer server.Close()

			pull, err := source.Read(context.Background(), qdrantTestConfig(tt.family, server.URL), nil)
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
			if got := event.Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
			if got := event.Attributes["resource_urn"]; got != tt.resourceURN {
				t.Fatalf("resource_urn = %q, want %q", got, tt.resourceURN)
			}
		})
	}
}

func TestNewFixtureReplaysEveryRuntimeFamily(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	familyConfigs := map[string]sourcecdk.Config{}
	for _, family := range []string{
		familyAccountMembers,
		familyAccounts,
		familyBackupRestores,
		familyBackupSchedules,
		familyBackups,
		familyClusters,
		familyDatabaseApiKeys,
		familyRoles,
	} {
		familyConfigs[family] = sourcecdk.NewConfig(map[string]string{"tenant_id": "tenant", "family": family})
	}
	sourcecdk.RunFixtureSuite(t, context.Background(), sourcecdk.FixtureSuiteOptions{
		Source:          source,
		FamilyConfigs:   familyConfigs,
		RequireDiscover: true,
	})
}

func TestSourceProviderUnavailable(t *testing.T) {
	source := newTestSource(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireQdrantCloudAuth(t, r)
		http.Error(w, `{"error":"provider unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	err := source.Check(context.Background(), qdrantTestConfig(defaultFamily, server.URL))
	if err == nil {
		t.Fatal("Check() error = nil, want provider unavailable error")
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(err, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("Check() error = %v, want HTTP 503", err)
	}
}

func newTestSource(t *testing.T) *Source {
	t.Helper()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackForTest()
	return source
}

func qdrantTestConfig(family string, baseURL string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"account_id": testAccountID,
		"api_token":  "test-token",
		"base_url":   baseURL,
		"cluster_id": testClusterID,
		"family":     family,
		"tenant_id":  "tenant",
	})
}

func requireQdrantCloudAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "apikey test-token" {
		t.Fatalf("Authorization = %q, want apikey test-token", got)
	}
}

func qdrantAccountsBody() map[string]any {
	return map[string]any{"items": []map[string]any{{
		"company":         map[string]any{"domain": "example.test", "name": "Example Test Company"},
		"createdAt":       "2026-05-01T09:00:00Z",
		"externalOwnerId": "owner-ext-123",
		"id":              testAccountID,
		"lastModifiedAt":  "2026-05-30T12:30:00Z",
		"name":            "Production Account",
		"ownerEmail":      "owner@example.test",
		"privileges":      []string{"read:account", "read:clusters"},
	}}}
}

func qdrantClusterPayload() map[string]any {
	return map[string]any{
		"accountId":             testAccountID,
		"cloudProviderId":       "aws",
		"cloudProviderRegionId": "us-east-1",
		"configuration": map[string]any{
			"lastModifiedAt": "2026-05-29T08:15:00Z",
			"numberOfNodes":  3,
			"packageId":      "pkg-production-standard",
			"version":        "v1.14.1",
		},
		"createdAt": "2026-05-03T11:00:00Z",
		"id":        testClusterID,
		"name":      "prod-search",
		"state": map[string]any{
			"endpoint": map[string]any{"grpcPort": 6334, "restPort": 6333, "url": "https://prod-search.aws-us-east-1-0.qdrant.io"},
			"jwtRbac":  true,
			"nodesUp":  3,
			"phase":    "CLUSTER_PHASE_HEALTHY",
			"reason":   "Cluster is healthy",
			"version":  "v1.14.1",
		},
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
