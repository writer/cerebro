package tailscale

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
	if got := source.Spec().GetId(); got != "tailscale" {
		t.Fatalf("Spec().Id = %q, want tailscale", got)
	}
}

func TestReadTailscaleCoreInventoryKinds(t *testing.T) {
	aclResponse := map[string]any{
		"groups":    map[string]any{"group:eng": []string{"alice@writer.com", "bob@writer.com"}},
		"tagOwners": map[string]any{"tag:prod": []string{"group:eng"}},
		"grants":    []map[string]any{{"id": "grant-1", "src": []string{"group:eng"}, "dst": []string{"tag:prod:443"}, "disabled": false}},
	}
	for _, tt := range []struct {
		name     string
		family   string
		kind     string
		path     string
		response map[string]any
		want     map[string]string
	}{
		{
			name:     "tailnet",
			family:   "tailnet",
			kind:     "tailscale.tailnet",
			path:     "/tailnet/writer.com/settings",
			response: map[string]any{"devicesApprovalOn": false, "usersApprovalOn": true, "networkFlowLoggingOn": true, "regionalRoutingOn": false, "maxKeyDurationDays": 90},
			want:     map[string]string{"tailnet": "writer.com", "devices_approval_on": "false", "users_approval_on": "true", "regional_routing_on": "false", "max_key_duration_days": "90"},
		},
		{
			name:     "user",
			family:   "user",
			kind:     "tailscale.user",
			path:     "/tailnet/-/users",
			response: map[string]any{"users": []map[string]any{{"id": "user-1", "loginName": "alice@writer.com", "role": "admin", "status": "active", "type": "member"}}},
			want:     map[string]string{"user_id": "user-1", "login_name": "alice@writer.com", "role": "admin", "type": "member"},
		},
		{
			name:     "device",
			family:   "device",
			kind:     "tailscale.device",
			path:     "/tailnet/-/devices",
			response: map[string]any{"devices": []map[string]any{{"id": "device-1", "nodeId": "node-1", "name": "laptop", "os": "macOS", "user": "alice@writer.com", "authorized": true, "keyExpiryDisabled": false, "tags": []string{"tag:prod"}}}},
			want:     map[string]string{"device_id": "device-1", "node_id": "node-1", "user_id": "alice@writer.com", "authorized": "true", "key_expiry_disabled": "false", "tags": "tag:prod"},
		},
		{
			name:     "service",
			family:   "service",
			kind:     "tailscale.service",
			path:     "/tailnet/-/services",
			response: map[string]any{"services": []map[string]any{{"id": "service-1", "name": "api", "tags": []string{"tag:prod"}}}},
			want:     map[string]string{"service_id": "service-1", "name": "api", "tags": "tag:prod"},
		},
		{
			name:     "group",
			family:   "group",
			kind:     "tailscale.group",
			path:     "/tailnet/-/acl",
			response: aclResponse,
			want:     map[string]string{"group_id": "group:eng", "members": "alice@writer.com,bob@writer.com"},
		},
		{
			name:     "tag",
			family:   "tag",
			kind:     "tailscale.tag",
			path:     "/tailnet/-/acl",
			response: aclResponse,
			want:     map[string]string{"tag_id": "tag:prod", "owners": "group:eng"},
		},
		{
			name:     "grant",
			family:   "grant",
			kind:     "tailscale.grant",
			path:     "/tailnet/-/acl",
			response: aclResponse,
			want:     map[string]string{"grant_id": "grant-1", "sources": "group:eng", "destinations": "tag:prod:443"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.EscapedPath(); got != tt.path {
					t.Fatalf("request path = %q, want %s", got, tt.path)
				}
				_ = json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			source, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			source.inner.AllowLoopbackBaseURL = true
			config := map[string]string{"base_url": server.URL, "family": tt.family, "tenant_id": "writer", "tailnet": "writer.com", "token": "token-1"}
			pull, err := source.Read(context.Background(), sourcecdk.NewConfig(config), nil)
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if len(pull.Events) != 1 {
				t.Fatalf("len(Events) = %d, want 1", len(pull.Events))
			}
			event := pull.Events[0]
			if event.Kind != tt.kind {
				t.Fatalf("Kind = %q, want %q", event.Kind, tt.kind)
			}
			for key, value := range tt.want {
				if got := event.Attributes[key]; got != value {
					t.Fatalf("attribute %q = %q, want %q", key, got, value)
				}
			}
		})
	}
}
