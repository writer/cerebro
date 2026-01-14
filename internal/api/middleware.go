package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

// APIError represents a structured API error response
type APIError struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIError{
		Error: message,
		Code:  code,
	})
}

type contextKey string

const (
	contextKeyAPIKey contextKey = "api_key"
	contextKeyUserID contextKey = "user_id"
)

type AuthConfig struct {
	APIKeys map[string]string // key -> user_id mapping
	Enabled bool
}

func APIKeyAuth(cfg AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Skip auth for health endpoints
			if r.URL.Path == "/health" || r.URL.Path == "/ready" {
				next.ServeHTTP(w, r)
				return
			}

			apiKey := extractAPIKey(r)
			if apiKey == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing_api_key", "API key is required")
				return
			}

			userID, valid := validateAPIKey(cfg.APIKeys, apiKey)
			if !valid {
				writeJSONError(w, http.StatusUnauthorized, "invalid_api_key", "API key is invalid or expired")
				return
			}

			ctx := context.WithValue(r.Context(), contextKeyAPIKey, apiKey)
			ctx = context.WithValue(ctx, contextKeyUserID, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractAPIKey(r *http.Request) string {
	// Check Authorization header
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Check X-API-Key header
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// Check query parameter (not recommended but supported)
	if key := r.URL.Query().Get("api_key"); key != "" {
		return key
	}

	return ""
}

func validateAPIKey(keys map[string]string, key string) (string, bool) {
	for k, userID := range keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			return userID, true
		}
	}
	return "", false
}

func GetUserID(ctx context.Context) string {
	if v := ctx.Value(contextKeyUserID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func GetAPIKey(ctx context.Context) string {
	if v := ctx.Value(contextKeyAPIKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// CORS middleware
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			allowed := false
			for _, o := range allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
