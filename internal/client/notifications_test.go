package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListNotifiers_SendsPathAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/notifications/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "10" {
			t.Fatalf("expected limit=10, got %q", got)
		}
		if got := r.URL.Query().Get("offset"); got != "20" {
			t.Fatalf("expected offset=20, got %q", got)
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"notifiers": []string{"slack", "pagerduty"},
			"count":     2,
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	notifiers, err := c.ListNotifiers(context.Background(), 10, 20)
	if err != nil {
		t.Fatalf("list notifiers: %v", err)
	}
	if len(notifiers) != 2 || notifiers[0] != "slack" || notifiers[1] != "pagerduty" {
		t.Fatalf("unexpected notifiers: %#v", notifiers)
	}
}

func TestTestNotifications_SendsPayloadAndParsesResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/notifications/test" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req["message"] != "hello" {
			t.Fatalf("expected message hello, got %#v", req["message"])
		}
		if req["severity"] != "critical" {
			t.Fatalf("expected severity critical, got %#v", req["severity"])
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "sent",
		})
	}))
	defer server.Close()

	c, err := New(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	resp, err := c.TestNotifications(context.Background(), "hello", "critical")
	if err != nil {
		t.Fatalf("test notifications: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Status != "sent" {
		t.Fatalf("expected status sent, got %q", resp.Status)
	}
}
