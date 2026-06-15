package cloudflare

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
	if got := source.Spec().GetId(); got != "cloudflare" {
		t.Fatalf("Spec().Id = %q, want cloudflare", got)
	}
}

func TestReadMemberUsesAccountPathParamAndResultList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.EscapedPath(); got != "/accounts/account-1/members" {
			t.Fatalf("request path = %q, want /accounts/account-1/members", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": []map[string]any{{
				"id":     "member-1",
				"status": "accepted",
				"user": map[string]any{
					"email": "alice@example.com",
				},
			}},
		})
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.inner.AllowLoopbackBaseURL = true
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{
		"account_id": "account-1",
		"base_url":   server.URL,
		"family":     "member",
		"tenant_id":  "writer",
		"token":      "token-1",
	}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "cloudflare.member" {
		t.Fatalf("Kind = %q, want cloudflare.member", event.Kind)
	}
	if got := event.Attributes["member_id"]; got != "member-1" {
		t.Fatalf("member_id = %q, want member-1", got)
	}
	if got := event.Attributes["account_id"]; got != "account-1" {
		t.Fatalf("account_id = %q, want account-1", got)
	}
	if got := event.Attributes["email"]; got != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", got)
	}
}
