package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSlackListAllUsersRejectsPaginationLoop(t *testing.T) {
	provider := NewSlackProvider()
	provider.token = "token"
	provider.apiURL = "https://slack.example.com"
	provider.client = &http.Client{Transport: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/users.list" {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
			"ok":      true,
			"members": []map[string]interface{}{{"id": "user-1"}},
			"response_metadata": map[string]interface{}{
				"next_cursor": "repeat-token",
			},
		})
	})}

	_, err := provider.listAllUsers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestRipplingListAllRejectsPaginationLoop(t *testing.T) {
	provider := NewRipplingProvider()
	provider.apiToken = "token"
	provider.apiURL = "https://api.rippling.example.com"
	provider.client = &http.Client{Transport: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/platform/api/employees" {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
			"data":        []map[string]interface{}{{"id": "emp-1"}},
			"next_cursor": "repeat-token",
		})
	})}

	_, err := provider.listAll(context.Background(), "/platform/api/employees?employment_status=ACTIVE")
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestGoogleWorkspaceListAllRejectsPaginationLoop(t *testing.T) {
	provider := NewGoogleWorkspaceProvider()
	provider.client = &http.Client{Transport: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/admin/directory/v1/users" {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
			"users": []map[string]interface{}{
				{"id": "user-1", "primaryEmail": "user-1@example.com"},
			},
			"nextPageToken": "repeat-token",
		})
	})}

	_, err := provider.listAll(context.Background(), "https://admin.googleapis.com/admin/directory/v1/users", map[string]string{
		"domain": "example.com",
	}, "users")
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestIntuneListAllRejectsPaginationLoop(t *testing.T) {
	provider := NewIntuneProvider()
	provider.accessToken = "token"
	provider.tokenExpiry = time.Now().Add(time.Hour)
	provider.client = &http.Client{Transport: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1.0/devices" {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
			"value":           []map[string]interface{}{{"id": "device-1"}},
			"@odata.nextLink": "https://graph.microsoft.com/v1.0/devices?$skiptoken=repeat",
		})
	})}

	_, err := provider.listAll(context.Background(), "/v1.0/devices")
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestEntraListAllRejectsPaginationLoop(t *testing.T) {
	provider := NewEntraIDProvider()
	provider.accessToken = "token"
	provider.tokenExpiry = time.Now().Add(time.Hour)
	provider.client = &http.Client{Transport: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1.0/users" {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
			"value":           []map[string]interface{}{{"id": "user-1"}},
			"@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=repeat",
		})
	})}

	_, err := provider.listAll(context.Background(), "/v1.0/users")
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestKandjiListAllResultsRejectsPaginationLoop(t *testing.T) {
	provider := NewKandjiProvider()
	provider.apiToken = "token"
	provider.apiURL = "https://tenant.kandji.example.com"
	provider.client = &http.Client{Transport: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/audit/events" {
			t.Fatalf("unexpected path %q", req.URL.Path)
		}
		return jsonHTTPResponse(http.StatusOK, map[string]interface{}{
			"results": []map[string]interface{}{{"id": "evt-1"}},
			"next":    "?cursor=repeat-token",
		})
	})}

	_, err := provider.listAllResults(context.Background(), "/audit/events?limit=500")
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}

func TestOktaRequestAllRejectsPaginationLoop(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", "<"+server.URL+"/api/v1/users>; rel=\"next\"")
		_, _ = w.Write([]byte(`[{"id":"user-1"}]`))
	}))
	defer server.Close()

	provider := newTLSTestOktaProvider(t, server)
	_, err := provider.requestAll(context.Background(), "/api/v1/users")
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("expected pagination loop error, got %v", err)
	}
}
