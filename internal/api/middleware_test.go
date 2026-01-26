package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*http.Request)
		expected string
	}{
		{
			name: "Bearer token",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer test-key-123")
			},
			expected: "test-key-123",
		},
		{
			name: "X-API-Key header",
			setup: func(r *http.Request) {
				r.Header.Set("X-API-Key", "header-key-456")
			},
			expected: "header-key-456",
		},
		{
			name:     "No key",
			setup:    func(r *http.Request) {},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/test", nil)
			tt.setup(r)

			key := extractAPIKey(r)
			if key != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, key)
			}
		})
	}
}

func TestAPIKeyAuth(t *testing.T) {
	cfg := AuthConfig{
		Enabled: true,
		APIKeys: map[string]string{
			"valid-key": "user-1",
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := GetUserID(r.Context())
		w.Write([]byte(userID))
	})

	middleware := APIKeyAuth(cfg)(handler)

	tests := []struct {
		name       string
		path       string
		apiKey     string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "Valid key",
			path:       "/api/v1/test",
			apiKey:     "valid-key",
			wantStatus: http.StatusOK,
			wantBody:   "user-1",
		},
		{
			name:       "Invalid key",
			path:       "/api/v1/test",
			apiKey:     "invalid-key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Missing key",
			path:       "/api/v1/test",
			apiKey:     "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Health endpoint - no auth required",
			path:       "/health",
			apiKey:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Ready endpoint - no auth required",
			path:       "/ready",
			apiKey:     "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.path, nil)
			if tt.apiKey != "" {
				r.Header.Set("Authorization", "Bearer "+tt.apiKey)
			}

			w := httptest.NewRecorder()
			middleware.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}

			if tt.wantBody != "" && w.Body.String() != tt.wantBody {
				t.Errorf("expected body '%s', got '%s'", tt.wantBody, w.Body.String())
			}
		})
	}
}

func TestAPIKeyAuthDisabled(t *testing.T) {
	cfg := AuthConfig{
		Enabled: false,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := APIKeyAuth(cfg)(handler)

	r := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()
	middleware.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200 when auth disabled, got %d", w.Code)
	}
}
