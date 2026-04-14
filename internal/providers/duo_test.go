package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestDuoProviderSync_TableParity(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !duoAuthHeaderLooksValid(req.Header.Get("Authorization"), "ikey") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"stat":"FAIL","message":"unauthorized"}`))
			return
		}
		if strings.TrimSpace(req.Header.Get("Date")) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"stat":"FAIL","message":"missing date"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/admin/v1/users":
			offset, _ := strconv.Atoi(req.URL.Query().Get("offset"))
			users := []map[string]interface{}{}
			metadata := map[string]interface{}{}
			switch offset {
			case 0:
				users = duoTestUsers(300, 1)
				metadata["next_offset"] = 300
			case 300:
				users = duoTestUsers(1, 301)
			}

			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"stat":     "OK",
				"metadata": metadata,
				"response": users,
			})
			return

		case "/admin/v1/groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"stat": "OK",
				"response": []map[string]interface{}{
					{
						"group_id":           "group-1",
						"name":               "Engineering",
						"desc":               "Engineering team",
						"status":             "Active",
						"push_enabled":       false,
						"sms_enabled":        false,
						"voice_enabled":      false,
						"mobile_otp_enabled": false,
					},
					{
						"group_id":           "group-2",
						"name":               "Security",
						"desc":               "Security team",
						"status":             "Active",
						"push_enabled":       false,
						"sms_enabled":        false,
						"voice_enabled":      false,
						"mobile_otp_enabled": false,
					},
				},
			})
			return

		case "/admin/v2/groups/group-1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"stat": "OK",
				"response": []map[string]interface{}{
					{"user_id": "user-1", "username": "user-1"},
				},
			})
			return

		case "/admin/v2/groups/group-2/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"stat": "OK",
				"response": []map[string]interface{}{
					{"user_id": "user-2", "username": "user-2"},
				},
			})
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewDuoProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":             server.URL,
		"integration_key": "ikey",
		"secret_key":      "skey",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

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

	if rowsByTable["duo_users"] != 301 {
		t.Fatalf("duo_users rows = %d, want 301", rowsByTable["duo_users"])
	}
	if rowsByTable["duo_groups"] != 2 {
		t.Fatalf("duo_groups rows = %d, want 2", rowsByTable["duo_groups"])
	}
	if rowsByTable["duo_group_memberships"] != 2 {
		t.Fatalf("duo_group_memberships rows = %d, want 2", rowsByTable["duo_group_memberships"])
	}
}

func TestDuoProviderSync_IgnoresPermissionDeniedMembershipEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !duoAuthHeaderLooksValid(req.Header.Get("Authorization"), "ikey") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.URL.Path {
		case "/admin/v1/users":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"stat":     "OK",
				"metadata": map[string]interface{}{},
				"response": []map[string]interface{}{duoTestUsers(1, 1)[0]},
			})
			return

		case "/admin/v1/groups":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"stat": "OK",
				"response": []map[string]interface{}{
					{"group_id": "group-1", "name": "Engineering", "status": "Active"},
					{"group_id": "group-2", "name": "Security", "status": "Active"},
				},
			})
			return

		case "/admin/v2/groups/group-1/users":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"stat":"FAIL","message":"forbidden"}`))
			return

		case "/admin/v2/groups/group-2/users":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"stat":"FAIL","message":"not found"}`))
			return

		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	provider := NewDuoProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":             server.URL,
		"integration_key": "ikey",
		"secret_key":      "skey",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

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

	if rowsByTable["duo_users"] != 1 {
		t.Fatalf("duo_users rows = %d, want 1", rowsByTable["duo_users"])
	}
	if rowsByTable["duo_groups"] != 2 {
		t.Fatalf("duo_groups rows = %d, want 2", rowsByTable["duo_groups"])
	}
	if rowsByTable["duo_group_memberships"] != 0 {
		t.Fatalf("duo_group_memberships rows = %d, want 0", rowsByTable["duo_group_memberships"])
	}
}

func TestDuoProviderRequest_RejectsCrossHostURL(t *testing.T) {
	t.Parallel()

	provider := NewDuoProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"url":             "https://api-123.duosecurity.com",
		"integration_key": "ikey",
		"secret_key":      "skey",
	}); err != nil {
		t.Fatalf("configure failed: %v", err)
	}

	_, err := provider.request(context.Background(), http.MethodGet, "https://evil.example.com/admin/v1/users", map[string]string{
		"limit": "1",
	})
	if err == nil {
		t.Fatal("expected cross-host URL rejection")
		return
	}
	if !strings.Contains(err.Error(), "host mismatch") {
		t.Fatalf("expected host mismatch error, got %v", err)
	}
}

func TestDuoAuthorizationHeader_MatchesDocumentationExample(t *testing.T) {
	t.Parallel()

	date := "Tue, 21 Aug 2012 17:29:18 -0000"
	encodedParams := duoEncodeParams(map[string]string{
		"realname": "First Last",
		"username": "root",
	})
	authorization := duoAuthorizationHeader(
		date,
		http.MethodPost,
		"api-xxxxxxxx.duosecurity.com",
		"/admin/v1/users",
		encodedParams,
		"DIWJ8X6AEYOR5OMC6TQ1",
		"Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep",
	)

	const expected = "Basic RElXSjhYNkFFWU9SNU9NQzZUUTE6YzFlZjQzNzY3YzNlYjNiMzI1OGRiZGRjYTZmOGQwOTQxZTA4NWI5Mg=="
	if authorization != expected {
		t.Fatalf("authorization mismatch:\n got: %s\nwant: %s", authorization, expected)
	}
}

func duoAuthHeaderLooksValid(value string, expectedIKey string) bool {
	if !strings.HasPrefix(value, "Basic ") {
		return false
	}
	encoded := strings.TrimSpace(strings.TrimPrefix(value, "Basic "))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	if parts[0] != expectedIKey {
		return false
	}
	if len(parts[1]) != 40 {
		return false
	}
	for _, ch := range parts[1] {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func duoTestUsers(count int, start int) []map[string]interface{} {
	users := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		id := start + i
		users = append(users, map[string]interface{}{
			"user_id":     "user-" + strconv.Itoa(id),
			"username":    "user-" + strconv.Itoa(id),
			"email":       "user" + strconv.Itoa(id) + "@example.com",
			"realname":    "User " + strconv.Itoa(id),
			"firstname":   "User",
			"lastname":    strconv.Itoa(id),
			"status":      "active",
			"is_enrolled": true,
			"created":     1704067200,
			"last_login":  1706659200,
		})
	}
	return users
}
