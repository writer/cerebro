package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func jsonHTTPResponse(status int, payload interface{}) (*http.Response, error) {
	body := []byte("{}")
	if payload != nil {
		switch typed := payload.(type) {
		case string:
			body = []byte(typed)
		default:
			encoded, err := json.Marshal(typed)
			if err != nil {
				return nil, err
			}
			body = encoded
		}
	}

	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func TestGoogleWorkspaceProviderSync_IncludesGroupMembers(t *testing.T) {
	t.Parallel()

	provider := NewGoogleWorkspaceProvider()
	provider.domain = "example.com"
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/admin/directory/v1/users":
			query := req.URL.Query()
			if query.Get("domain") != "example.com" {
				t.Fatalf("unexpected users domain query: %q", query.Get("domain"))
			}
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"users": []map[string]interface{}{
					{
						"id":           "user-1",
						"primaryEmail": "user-1@example.com",
					},
				},
			})
		case "/admin/directory/v1/groups":
			query := req.URL.Query()
			if query.Get("domain") != "example.com" {
				t.Fatalf("unexpected groups domain query: %q", query.Get("domain"))
			}
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"groups": []map[string]interface{}{
					{
						"id":    "group-1",
						"email": "eng@example.com",
						"name":  "Engineering",
					},
				},
			})
		case "/admin/directory/v1/groups/group-1/members":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"members": []map[string]interface{}{
					{
						"id":     "member-1",
						"email":  "member-1@example.com",
						"role":   "MEMBER",
						"type":   "USER",
						"status": "ACTIVE",
					},
				},
			})
		case "/admin/directory/v1/customer/my_customer/domains":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"domains": []map[string]interface{}{
					{
						"domainName": "example.com",
						"isPrimary":  true,
						"verified":   true,
					},
				},
			})
		default:
			t.Fatalf("unexpected path %q", req.URL.Path)
			return nil, nil
		}
	})}

	result, err := provider.Sync(context.Background(), SyncOptions{FullSync: true})
	if err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected sync errors: %v", result.Errors)
	}

	rowsByTable := map[string]int64{}
	for _, table := range result.Tables {
		rowsByTable[table.Name] = table.Rows
	}

	if got := rowsByTable["google_workspace_users"]; got != 1 {
		t.Fatalf("google_workspace_users rows = %d, want 1", got)
	}
	if got := rowsByTable["google_workspace_groups"]; got != 1 {
		t.Fatalf("google_workspace_groups rows = %d, want 1", got)
	}
	if got := rowsByTable["google_workspace_group_members"]; got != 1 {
		t.Fatalf("google_workspace_group_members rows = %d, want 1", got)
	}
	if got := rowsByTable["google_workspace_domains"]; got != 1 {
		t.Fatalf("google_workspace_domains rows = %d, want 1", got)
	}
}

func TestGoogleWorkspaceProviderSyncGroupMembers_IgnoresPermissionDeniedGroups(t *testing.T) {
	t.Parallel()

	provider := NewGoogleWorkspaceProvider()
	provider.domain = "example.com"
	provider.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/admin/directory/v1/groups":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"groups": []map[string]interface{}{
					{"id": "group-no-access", "email": "locked@example.com"},
					{"id": "group-ok", "email": "open@example.com"},
				},
			})
		case "/admin/directory/v1/groups/group-no-access/members":
			return jsonHTTPResponse(http.StatusForbidden, map[string]interface{}{"error": "forbidden"})
		case "/admin/directory/v1/groups/group-ok/members":
			return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
				"members": []map[string]interface{}{
					{
						"id":     "member-1",
						"email":  "member-1@example.com",
						"role":   "MEMBER",
						"type":   "USER",
						"status": "ACTIVE",
					},
				},
			})
		default:
			t.Fatalf("unexpected path %q", req.URL.Path)
			return nil, nil
		}
	})}

	table, err := provider.syncGroupMembers(context.Background())
	if err != nil {
		t.Fatalf("syncGroupMembers failed: %v", err)
	}
	if table.Rows != 1 {
		t.Fatalf("syncGroupMembers rows = %d, want 1", table.Rows)
	}
	if table.Inserted != 1 {
		t.Fatalf("syncGroupMembers inserted = %d, want 1", table.Inserted)
	}
}
