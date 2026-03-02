package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractOktaAdminID(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected string
	}{
		{
			name:     "user.id",
			input:    map[string]interface{}{"user": map[string]interface{}{"id": "user-1"}},
			expected: "user-1",
		},
		{
			name:     "assignee.id",
			input:    map[string]interface{}{"assignee": map[string]interface{}{"id": "user-2"}},
			expected: "user-2",
		},
		{
			name:     "user_id",
			input:    map[string]interface{}{"user_id": "user-3"},
			expected: "user-3",
		},
		{
			name:     "id",
			input:    map[string]interface{}{"id": "user-4"},
			expected: "user-4",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractOktaAdminID(tc.input); got != tc.expected {
				t.Errorf("extractOktaAdminID() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestExtractOktaPolicyAppIDs(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected []string
	}{
		{
			name: "conditions.apps.include strings",
			input: map[string]interface{}{
				"conditions": map[string]interface{}{
					"apps": map[string]interface{}{
						"include": []interface{}{"app-1", "app-2"},
					},
				},
			},
			expected: []string{"app-1", "app-2"},
		},
		{
			name: "conditions.app.include objects",
			input: map[string]interface{}{
				"conditions": map[string]interface{}{
					"app": map[string]interface{}{
						"include": []interface{}{map[string]interface{}{"id": "app-3"}},
					},
				},
			},
			expected: []string{"app-3"},
		},
		{
			name: "conditions.apps.include string slice",
			input: map[string]interface{}{
				"conditions": map[string]interface{}{
					"apps": map[string]interface{}{
						"include": []string{"app-4", "app-5"},
					},
				},
			},
			expected: []string{"app-4", "app-5"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractOktaPolicyAppIDs(tc.input)
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("extractOktaPolicyAppIDs() = %v, want %v", got, tc.expected)
			}
		})
	}
}

func TestExtractOktaAppTarget(t *testing.T) {
	tests := []struct {
		name          string
		input         interface{}
		expectedID    string
		expectedLabel string
	}{
		{
			name: "target list with appinstance",
			input: []interface{}{
				map[string]interface{}{"type": "User", "id": "user-1"},
				map[string]interface{}{"type": "AppInstance", "id": "app-1", "display_name": "Salesforce"},
			},
			expectedID:    "app-1",
			expectedLabel: "Salesforce",
		},
		{
			name:          "single app object",
			input:         map[string]interface{}{"type": "application", "id": "app-2", "alternate_id": "jira"},
			expectedID:    "app-2",
			expectedLabel: "jira",
		},
		{
			name:          "unsupported target type",
			input:         []interface{}{map[string]interface{}{"type": "User", "id": "user-1"}},
			expectedID:    "",
			expectedLabel: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, label := extractOktaAppTarget(tc.input)
			if id != tc.expectedID || label != tc.expectedLabel {
				t.Fatalf("extractOktaAppTarget() = (%q, %q), want (%q, %q)", id, label, tc.expectedID, tc.expectedLabel)
			}
		})
	}
}

func TestNormalizeOktaLogExtractsTargetApp(t *testing.T) {
	log := map[string]interface{}{
		"uuid":      "evt-1",
		"eventType": "user.authentication.sso",
		"actor": map[string]interface{}{
			"id":   "user-1",
			"type": "User",
		},
		"target": []interface{}{
			map[string]interface{}{"type": "User", "id": "user-1"},
			map[string]interface{}{"type": "AppInstance", "id": "app-1", "displayName": "Salesforce"},
		},
	}

	normalized := normalizeOktaLog(log)
	if got := asString(normalized["target_app_id"]); got != "app-1" {
		t.Fatalf("target_app_id = %q, want app-1", got)
	}
	if got := asString(normalized["target_app_label"]); got != "Salesforce" {
		t.Fatalf("target_app_label = %q, want Salesforce", got)
	}
}

func TestOktaRequestWithResponse_RetryOn429(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("rate limited"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer server.Close()

	okta := &OktaProvider{
		apiToken: "token",
		client:   server.Client(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	body, _, err := okta.requestWithResponse(ctx, server.URL)
	if err != nil {
		t.Fatalf("requestWithResponse() error = %v", err)
	}
	if string(body) != "[]" {
		t.Fatalf("requestWithResponse() body = %q, want []", string(body))
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("requestWithResponse() calls = %d, want 2", got)
	}
}
