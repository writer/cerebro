package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrowdStrikeAuthenticateRetriesReplayableBody(t *testing.T) {
	var attempts atomic.Int32
	requestBodies := make([]string, 0, 2)
	provider := &CrowdStrikeProvider{
		BaseProvider: NewBaseProvider("crowdstrike", ProviderTypeEndpoint),
		clientID:     "client-id",
		clientSecret: "client-secret",
		baseURL:      "https://api.crowdstrike.example",
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &providerResilientTransport{
				base: providerRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					body, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					requestBodies = append(requestBodies, string(body))
					switch attempts.Add(1) {
					case 1:
						return &http.Response{
							StatusCode: http.StatusServiceUnavailable,
							Body:       io.NopCloser(strings.NewReader("retry me")),
						}, nil
					case 2:
						return &http.Response{
							StatusCode: http.StatusCreated,
							Body:       io.NopCloser(strings.NewReader(`{"access_token":"token","expires_in":300}`)),
						}, nil
					default:
						return nil, context.Canceled
					}
				}),
				options: ProviderHTTPClientOptions{
					Provider:                "crowdstrike",
					RetryAttempts:           2,
					RetryBackoff:            time.Millisecond,
					RetryMaxBackoff:         time.Millisecond,
					CircuitFailureThreshold: 5,
					CircuitOpenTimeout:      time.Minute,
				},
				circuit: newProviderCircuitBreaker("crowdstrike", 5, time.Minute),
				sleep:   func(context.Context, time.Duration) error { return nil },
			},
		},
	}

	token, err := provider.authenticate(context.Background())
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if token != "token" {
		t.Fatalf("token = %q, want token", token)
	}
	if attempts.Load() != 2 {
		t.Fatalf("attempts = %d, want 2", attempts.Load())
	}
	if len(requestBodies) != 2 {
		t.Fatalf("request body count = %d, want 2", len(requestBodies))
	}
	for i, body := range requestBodies {
		if body != "client_id=client-id&client_secret=client-secret" {
			t.Fatalf("request body %d = %q", i+1, body)
		}
	}
}

func TestCrowdStrikeProviderSync_MaterializesEndpointTables(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/oauth2/token":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"access_token":"token","expires_in":300}`)
		case "/devices/queries/devices/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{"resources": []string{"device-1"}})
		case "/devices/entities/devices/v2":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resources": []map[string]any{{
					"device_id":     "device-1",
					"hostname":      "host-1",
					"platform_name": "Mac",
					"os_version":    "14.4",
					"agent_version": "7.0.0",
					"last_seen":     "2026-04-14T10:00:00Z",
					"status":        "normal",
					"tags":          []string{"corp"},
				}},
			})
		case "/detects/queries/detects/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{"resources": []string{"det-1"}})
		case "/detects/entities/summaries/GET/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resources": []map[string]any{{
					"detection_id": "det-1",
					"device_id":    "device-1",
					"severity":     5,
					"status":       "new",
					"tactic":       "execution",
					"technique":    "t1059",
					"description":  "Suspicious activity",
					"created_at":   "2026-04-14T10:30:00Z",
				}},
			})
		case "/spotlight/combined/vulnerabilities/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"resources": []map[string]any{{
					"aid":         "device-1",
					"cve":         "CVE-2026-1111",
					"app_name":    "Chrome",
					"app_version": "1.2.4",
					"severity":    "high",
					"status":      "open",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewCrowdStrikeProvider()
	if err := provider.Configure(context.Background(), map[string]interface{}{
		"client_id":     "client-id",
		"client_secret": "client-secret",
		"base_url":      server.URL,
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
	for _, table := range []string{
		"crowdstrike_hosts",
		"crowdstrike_detections",
		"crowdstrike_vulnerabilities",
	} {
		if got := rowsByTable[table]; got != 1 {
			t.Fatalf("%s rows = %d, want 1", table, got)
		}
	}
}
