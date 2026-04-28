package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "gcp" {
		t.Fatalf("Spec().Id = %q, want gcp", source.Spec().Id)
	}
}

func TestCheckRequiresProjectAndToken(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"token": "test-token"})); err == nil {
		t.Fatal("Check() error = nil, want missing project_id error")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"project_id": "writer-prod"})); err == nil {
		t.Fatal("Check() error = nil, want missing token error")
	}
}

func TestGCPPullFromRecordsPreservesNextCursorWithoutEvents(t *testing.T) {
	pull, err := gcpPullFromRecords[string](nil, "next-page", nil)
	if err != nil {
		t.Fatalf("gcpPullFromRecords() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
	if got := pull.NextCursor.GetOpaque(); got != "next-page" {
		t.Fatalf("NextCursor = %q, want next-page", got)
	}
}

func TestNewFixtureReplaysGCPFamilies(t *testing.T) {
	source, err := NewFixture()
	if err != nil {
		t.Fatalf("NewFixture() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
	}{
		{family: familyServiceAcct, kind: "gcp.service_account"},
		{family: familyGroup, config: map[string]string{"customer_id": "C01"}, kind: "gcp.group"},
		{family: familyGroupMember, config: map[string]string{"group_key": "security@writer.com"}, kind: "gcp.group_membership"},
		{family: familyResourceExposure, kind: "gcp.resource_exposure"},
		{family: familyRoleAssign, kind: "gcp.iam_role_assignment"},
		{family: familySAImpersonation, config: map[string]string{"service_account_email": "sa@writer-prod.iam.gserviceaccount.com"}, kind: "gcp.service_account_impersonation"},
		{family: familyAudit, kind: "gcp.audit"},
		{family: familySAKey, config: map[string]string{"service_account_email": "sa@writer-prod.iam.gserviceaccount.com"}, kind: "gcp.service_account_key"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"project_id": "writer-prod", "family": tt.family, "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Read(%s).Events) = %d, want 1", tt.family, len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("Read(%s).Events[0].Kind = %q, want %q", tt.family, got, tt.kind)
			}
		})
	}
}

func TestReadLiveGCPServiceAccountPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": familyServiceAcct, "project_id": "writer-prod", "token": "test-token"})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check(service_account) error = %v", err)
	}
	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(service_account) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["email"]; got != "sa@writer-prod.iam.gserviceaccount.com" {
		t.Fatalf("email = %q, want service account email", got)
	}
}

func TestReadLiveGCPRoleAndAuditPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		kind   string
	}{
		{family: familyRoleAssign, kind: "gcp.iam_role_assignment"},
		{family: familyAudit, kind: "gcp.audit"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"base_url": server.URL, "family": tt.family, "project_id": "writer-prod", "token": "test-token"}), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
		})
	}
}

func TestReadLiveGCPServiceAccountKeyPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"base_url":              server.URL,
		"family":                familySAKey,
		"project_id":            "writer-prod",
		"service_account_email": "sa@writer-prod.iam.gserviceaccount.com",
		"token":                 "test-token",
	}), nil)
	if err != nil {
		t.Fatalf("Read(service_account_key) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(pull.Events))
	}
	if got := pull.Events[0].Attributes["credential_type"]; got != "gcp_service_account_key" {
		t.Fatalf("credential_type = %q, want gcp_service_account_key", got)
	}
}

func TestReadLiveGCPExposureAndImpersonationPreview(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, tt := range []struct {
		family string
		config map[string]string
		kind   string
		attr   string
		want   string
	}{
		{family: familyResourceExposure, kind: "gcp.resource_exposure", attr: "internet_exposed", want: "true"},
		{family: familySAImpersonation, config: map[string]string{"service_account_email": "sa@writer-prod.iam.gserviceaccount.com"}, kind: "gcp.service_account_impersonation", attr: "relationship", want: "can_impersonate"},
	} {
		t.Run(tt.family, func(t *testing.T) {
			config := map[string]string{"base_url": server.URL, "family": tt.family, "project_id": "writer-prod", "token": "test-token"}
			for key, value := range tt.config {
				config[key] = value
			}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read(%s) error = %v", tt.family, err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Kind; got != tt.kind {
				t.Fatalf("kind = %q, want %q", got, tt.kind)
			}
			if got := pull.Events[0].Attributes[tt.attr]; got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.attr, got, tt.want)
			}
		})
	}
}

func TestReadLiveGCPGroupMembershipResolvesGroupKeys(t *testing.T) {
	server := httptest.NewServer(newGCPAPIHandler(t))
	defer server.Close()
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, groupKey := range []string{"security@writer.com", "groups/abc"} {
		t.Run(groupKey, func(t *testing.T) {
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
				"base_url":  server.URL,
				"family":    familyGroupMember,
				"group_key": groupKey,
				"token":     "test-token",
			}), nil)
			if err != nil {
				t.Fatalf("Read(group_membership) error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(events) = %d, want 1", len(pull.Events))
			}
			if got := pull.Events[0].Attributes["member_email"]; got != "admin@writer.com" {
				t.Fatalf("member_email = %q, want admin@writer.com", got)
			}
		})
	}
}

func newGCPAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid token"}`))
			return
		}
		switch r.URL.Path {
		case "/v1/projects/writer-prod/serviceAccounts":
			writeJSON(t, w, map[string]any{"accounts": []map[string]any{{"name": "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com", "email": "sa@writer-prod.iam.gserviceaccount.com", "uniqueId": "sa-1", "displayName": "Prod SA"}}})
		case "/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys":
			writeJSON(t, w, map[string]any{"keys": []map[string]any{{"name": "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1", "keyType": "USER_MANAGED", "validAfterTime": "2026-04-23T00:00:00Z"}}})
		case "/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com:getIamPolicy":
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/iam.serviceAccountTokenCreator", "members": []string{"user:admin@writer.com"}}}})
		case "/compute/v1/projects/writer-prod/global/firewalls":
			writeJSON(t, w, map[string]any{"items": []map[string]any{{"id": "fw-1", "name": "allow-web", "network": "global/networks/default", "direction": "INGRESS", "sourceRanges": []string{"0.0.0.0/0"}, "allowed": []map[string]any{{"IPProtocol": "tcp", "ports": []string{"443"}}}}}})
		case "/v1/groups:lookup":
			if got := r.URL.Query().Get("groupKey.id"); got != "security@writer.com" {
				t.Fatalf("groupKey.id = %q, want security@writer.com", got)
			}
			writeJSON(t, w, map[string]any{"name": "groups/abc", "groupKey": map[string]any{"id": "security@writer.com"}})
		case "/v1/groups/abc/memberships":
			writeJSON(t, w, map[string]any{"memberships": []map[string]any{{"name": "groups/abc/memberships/member-1", "preferredMemberKey": map[string]any{"id": "user:admin@writer.com"}, "roles": []map[string]any{{"name": "MEMBER"}}}}})
		case "/v1/projects/writer-prod:getIamPolicy":
			writeJSON(t, w, map[string]any{"bindings": []map[string]any{{"role": "roles/owner", "members": []string{"serviceAccount:sa@writer-prod.iam.gserviceaccount.com"}}}})
		case "/v2/entries:list":
			writeJSON(t, w, map[string]any{"entries": []map[string]any{{"insertId": "audit-1", "timestamp": "2026-04-23T00:00:00Z", "protoPayload": map[string]any{"methodName": "SetIamPolicy", "serviceName": "cloudresourcemanager.googleapis.com", "resourceName": "projects/writer-prod", "authenticationInfo": map[string]any{"principalEmail": "admin@writer.com"}}, "resource": map[string]any{"type": "project", "labels": map[string]string{"project_id": "writer-prod"}}}}})
		default:
			http.NotFound(w, r)
		}
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
