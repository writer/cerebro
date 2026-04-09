package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type notificationsCLIState struct {
	message  string
	severity string
	output   string
}

func snapshotNotificationsCLIState() notificationsCLIState {
	return notificationsCLIState{
		message:  testMessage,
		severity: testSeverity,
		output:   testOutput,
	}
}

func restoreNotificationsCLIState(state notificationsCLIState) {
	testMessage = state.message
	testSeverity = state.severity
	testOutput = state.output
}

func TestRunNotificationsTest_APIModeJSON(t *testing.T) {
	state := snapshotNotificationsCLIState()
	t.Cleanup(func() { restoreNotificationsCLIState(state) })

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		switch r.URL.Path {
		case "/api/v1/notifications/":
			if r.Method != http.MethodGet {
				t.Fatalf("expected GET, got %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"notifiers": []string{"slack", "pagerduty"},
				"count":     2,
			})
		case "/api/v1/notifications/test":
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if req["message"] != "hello from test" {
				t.Fatalf("unexpected message payload: %#v", req["message"])
			}
			if req["severity"] != "critical" {
				t.Fatalf("unexpected severity payload: %#v", req["severity"])
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "sent"})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAPI))
	t.Setenv(envCLIAPIURL, server.URL)

	testMessage = "hello from test"
	testSeverity = "critical"
	testOutput = FormatJSON

	output := captureStdout(t, func() {
		if err := runNotificationsTest(notificationsTestCmd, nil); err != nil {
			t.Fatalf("runNotificationsTest failed: %v", err)
		}
	})

	if requestCount != 2 {
		t.Fatalf("expected two API requests, got %d", requestCount)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		t.Fatalf("decode output: %v (output=%s)", err, output)
	}
	if success, _ := payload["success"].(bool); !success {
		t.Fatalf("expected success=true payload, got %#v", payload)
	}
	if payload["count"].(float64) != 2 {
		t.Fatalf("expected count=2, got %v", payload["count"])
	}
}

func TestRunNotificationsTest_AutoModeFallbacksToDirectOnTransportError(t *testing.T) {
	state := snapshotNotificationsCLIState()
	t.Cleanup(func() { restoreNotificationsCLIState(state) })

	originalDirectFn := runNotificationsTestDirectFn
	t.Cleanup(func() { runNotificationsTestDirectFn = originalDirectFn })

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, "http://127.0.0.1:1")

	called := false
	runNotificationsTestDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	if err := runNotificationsTest(notificationsTestCmd, nil); err != nil {
		t.Fatalf("expected direct fallback success, got error: %v", err)
	}
	if !called {
		t.Fatal("expected direct fallback function to be called")
	}
}

func TestRunNotificationsTest_AutoModeDoesNotFallbackOnUnauthorized(t *testing.T) {
	state := snapshotNotificationsCLIState()
	t.Cleanup(func() { restoreNotificationsCLIState(state) })

	originalDirectFn := runNotificationsTestDirectFn
	t.Cleanup(func() { runNotificationsTestDirectFn = originalDirectFn })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","code":"unauthorized"}`))
	}))
	defer server.Close()

	t.Setenv(envCLIExecutionMode, string(cliExecutionModeAuto))
	t.Setenv(envCLIAPIURL, server.URL)

	called := false
	runNotificationsTestDirectFn = func(cmd *cobra.Command, args []string) error {
		called = true
		return nil
	}

	err := runNotificationsTest(notificationsTestCmd, nil)
	if err == nil {
		t.Fatal("expected error when API responds unauthorized")
		return
	}
	if !strings.Contains(err.Error(), "list notification channels via api") {
		t.Fatalf("expected api failure context, got %v", err)
	}
	if called {
		t.Fatal("did not expect direct fallback on unauthorized response")
	}
}
