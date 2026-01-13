package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

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
				http.Error(w, `{"error":"missing api key"}`, http.StatusUnauthorized)
				return
			}

			userID, valid := validateAPIKey(cfg.APIKeys, apiKey)
			if !valid {
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
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
		return v.(string)
	}
	return ""
}

func GetAPIKey(ctx context.Context) string {
	if v := ctx.Value(contextKeyAPIKey); v != nil {
		return v.(string)
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
