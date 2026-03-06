package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/auth"
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

			if isPublicEndpoint(r.URL.Path) {
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

// SecurityHeaders adds standard response headers to reduce common web attack surface.
func SecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "no-referrer")

			if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
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

// MaxBodySize limits the size of request bodies to prevent denial of service
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DefaultMaxBodySize is 10MB
const DefaultMaxBodySize = 10 * 1024 * 1024

// RBACMiddleware enforces role-based access control on API routes.
// It maps HTTP method + path prefix to required permissions and checks
// the authenticated user has the necessary role.
func RBACMiddleware(rbac *auth.RBAC) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublicEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			userID := GetUserID(r.Context())
			if userID == "" {
				next.ServeHTTP(w, r)
				return
			}

			requiredPerm := routePermission(r.Method, r.URL.Path)
			if requiredPerm == "" {
				next.ServeHTTP(w, r)
				return
			}

			if !rbac.HasPermission(r.Context(), userID, requiredPerm) {
				writeJSONError(w, http.StatusForbidden, "forbidden",
					"insufficient permissions: requires "+requiredPerm)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isPublicEndpoint(path string) bool {
	return path == "/health" || path == "/ready" ||
		path == "/metrics" || path == "/docs" ||
		path == "/openapi.yaml"
}

// routePermission maps an HTTP method + path to the required RBAC permission.
func routePermission(method, path string) string {
	isWrite := method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH"
	isExport := strings.Contains(path, "/export")

	switch {
	case strings.HasPrefix(path, "/api/v1/findings"):
		if isWrite {
			return "findings:write"
		}
		return "findings:read"
	case strings.HasPrefix(path, "/api/v1/policies"):
		if isWrite {
			return "policies:write"
		}
		return "policies:read"
	case strings.HasPrefix(path, "/api/v1/assets"),
		strings.HasPrefix(path, "/api/v1/tables"),
		strings.HasPrefix(path, "/api/v1/query"):
		return "assets:read"
	case strings.HasPrefix(path, "/api/v1/compliance"),
		strings.HasPrefix(path, "/api/v1/reports"):
		if isExport {
			return "compliance:export"
		}
		return "compliance:read"
	case strings.HasPrefix(path, "/api/v1/agents"):
		if isWrite {
			return "agents:write"
		}
		return "agents:read"
	case strings.HasPrefix(path, "/api/v1/tickets"):
		if isWrite {
			return "tickets:write"
		}
		return "tickets:read"
	case strings.HasPrefix(path, "/api/v1/runtime"):
		if isWrite {
			return "runtime:write"
		}
		return "runtime:read"
	case strings.HasPrefix(path, "/api/v1/graph"),
		strings.HasPrefix(path, "/api/v1/attack-paths"),
		strings.HasPrefix(path, "/api/v1/lineage"):
		if isWrite {
			return "graph:write"
		}
		return "graph:read"
	case strings.HasPrefix(path, "/api/v1/incidents"),
		strings.HasPrefix(path, "/api/v1/identity"),
		strings.HasPrefix(path, "/api/v1/threatintel"),
		strings.HasPrefix(path, "/api/v1/audit"):
		if isWrite {
			return "findings:write"
		}
		return "findings:read"
	case strings.HasPrefix(path, "/api/v1/providers"),
		strings.HasPrefix(path, "/api/v1/webhooks"),
		strings.HasPrefix(path, "/api/v1/scheduler"),
		strings.HasPrefix(path, "/api/v1/notifications"),
		strings.HasPrefix(path, "/api/v1/remediation"),
		strings.HasPrefix(path, "/api/v1/scan"),
		strings.HasPrefix(path, "/api/v1/telemetry"):
		return "admin:users"
	case strings.HasPrefix(path, "/api/v1/rbac"),
		strings.HasPrefix(path, "/api/v1/admin"):
		return "admin:users"
	case strings.HasPrefix(path, "/api/v1"):
		if isWrite {
			return "admin:users"
		}
		return "findings:read"
	default:
		return ""
	}
}

// CORS middleware
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed := false
			allowAny := false
			for _, o := range allowedOrigins {
				if o == "*" {
					allowAny = true
					allowed = true
					break
				}
				if o == origin {
					allowed = true
					break
				}
			}

			if allowed {
				if allowAny {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
				w.Header().Add("Vary", "Origin")
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			if r.Method == "OPTIONS" {
				if !allowed {
					writeJSONError(w, http.StatusForbidden, "forbidden_origin", "origin not allowed")
					return
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
