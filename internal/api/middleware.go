package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/evalops/cerebro/internal/auth"
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
	contextKeyTenant contextKey = "tenant_id"
)

type AuthConfig struct {
	APIKeys        map[string]string        // key -> user_id mapping
	APIKeyProvider func() map[string]string // optional dynamic key source
	Enabled        bool
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

			apiKey, err := extractAPIKeyStrict(r)
			if err != nil {
				switch {
				case errors.Is(err, errMalformedAuthorizationHeader):
					writeJSONError(w, http.StatusUnauthorized, "invalid_authorization_header", "Authorization header must use the format 'Bearer <token>'")
				case errors.Is(err, errConflictingAPICredentials):
					writeJSONError(w, http.StatusUnauthorized, "conflicting_api_credentials", "Authorization and X-API-Key credentials must match when both are provided")
				default:
					writeJSONError(w, http.StatusUnauthorized, "invalid_api_key", "API key is invalid or expired")
				}
				return
			}
			if apiKey == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing_api_key", "API key is required")
				return
			}

			keys := cfg.APIKeys
			if cfg.APIKeyProvider != nil {
				dynamicKeys := cfg.APIKeyProvider()
				if len(dynamicKeys) > 0 || len(keys) == 0 {
					keys = dynamicKeys
				}
			}

			userID, valid := validateAPIKey(keys, apiKey)
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

var (
	errMalformedAuthorizationHeader = errors.New("malformed authorization header")
	errConflictingAPICredentials    = errors.New("conflicting api credentials")
)

func extractAPIKeyStrict(r *http.Request) (string, error) {
	authKey, hasAuth, err := bearerTokenFromAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return "", err
	}

	headerKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	hasHeaderKey := headerKey != ""

	if hasAuth && hasHeaderKey {
		if subtle.ConstantTimeCompare([]byte(authKey), []byte(headerKey)) != 1 {
			return "", errConflictingAPICredentials
		}
		return authKey, nil
	}
	if hasAuth {
		return authKey, nil
	}
	if hasHeaderKey {
		return headerKey, nil
	}
	return "", nil
}

func bearerTokenFromAuthorization(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, nil
	}

	parts := strings.Fields(raw)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", false, errMalformedAuthorizationHeader
	}

	return parts[1], true, nil
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

func GetTenantID(ctx context.Context) string {
	if v := ctx.Value(contextKeyTenant); v != nil {
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
			if user, ok := rbac.GetUser(userID); ok && strings.TrimSpace(user.TenantID) != "" {
				ctx := context.WithValue(r.Context(), contextKeyTenant, user.TenantID)
				r = r.WithContext(ctx)
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
		path == "/metrics" ||
		path == "/docs" ||
		path == "/openapi.yaml"
}

func isRateLimitBypassEndpoint(path string) bool {
	return path == "/health" || path == "/ready" ||
		path == "/docs" ||
		path == "/openapi.yaml"
}

// routePermission maps an HTTP method + path to the required RBAC permission.
func routePermission(method, path string) string {
	isWrite := method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH"
	isExport := strings.Contains(path, "/export")

	switch {
	case strings.HasPrefix(path, "/api/v1/platform/graph"):
		return "platform.graph.read"
	case strings.HasPrefix(path, "/api/v1/platform/intelligence"):
		if isWrite && strings.Contains(path, "/runs") {
			return "platform.intelligence.run"
		}
		return "platform.intelligence.read"
	case strings.HasPrefix(path, "/api/v1/platform/jobs"):
		return "platform.jobs.read"
	case strings.HasPrefix(path, "/api/v1/platform/knowledge"):
		return "platform.knowledge.write"
	case strings.HasPrefix(path, "/api/v1/platform/workflows"):
		return "platform.workflow.write"
	case strings.HasPrefix(path, "/api/v1/security/analyses"):
		if isWrite {
			return "security.analyses.run"
		}
		return "security.analyses.read"
	case strings.HasPrefix(path, "/api/v1/org/expertise"):
		return "org.expertise.read"
	case strings.HasPrefix(path, "/api/v1/org/team-recommendations"):
		return "org.team.recommend"
	case strings.HasPrefix(path, "/api/v1/org/reorg-simulations"):
		return "org.reorg.simulate"
	case strings.HasPrefix(path, "/api/v1/org"):
		return "org.intelligence.read"
	case strings.HasPrefix(path, "/api/v1/findings"):
		if isWrite {
			return "security.findings.manage"
		}
		return "security.findings.read"
	case strings.HasPrefix(path, "/api/v1/policies"):
		if isWrite {
			return "security.policies.manage"
		}
		return "security.policies.read"
	case strings.HasPrefix(path, "/api/v1/assets"),
		strings.HasPrefix(path, "/api/v1/tables"),
		strings.HasPrefix(path, "/api/v1/query"):
		return "security.assets.read"
	case strings.HasPrefix(path, "/api/v1/compliance"),
		strings.HasPrefix(path, "/api/v1/reports"):
		if isExport {
			return "security.compliance.export"
		}
		return "security.compliance.read"
	case strings.HasPrefix(path, "/api/v1/agents"):
		if isWrite {
			return "agents:write"
		}
		return "agents:read"
	case strings.HasPrefix(path, "/api/v1/tickets"):
		if isWrite {
			return "security.tickets.manage"
		}
		return "security.tickets.read"
	case strings.HasPrefix(path, "/api/v1/runtime"):
		if isWrite {
			return "security.runtime.write"
		}
		return "security.runtime.read"
	case strings.HasPrefix(path, "/api/v1/graph"),
		strings.HasPrefix(path, "/api/v1/attack-paths"),
		strings.HasPrefix(path, "/api/v1/lineage"):
		switch {
		case strings.HasPrefix(path, "/api/v1/attack-paths"),
			strings.Contains(path, "/attack-paths"),
			strings.Contains(path, "/blast-radius"),
			strings.Contains(path, "/cascading-blast-radius"),
			strings.Contains(path, "/reverse-access"),
			strings.Contains(path, "/effective-permissions"),
			strings.Contains(path, "/compare-permissions"),
			strings.Contains(path, "/privilege-escalation"),
			strings.Contains(path, "/toxic-combinations"),
			strings.Contains(path, "/chokepoints"),
			strings.Contains(path, "/impact-analysis"):
			if isWrite {
				return "security.analyses.run"
			}
			return "security.analyses.read"
		case strings.Contains(path, "/identity/resolve"),
			strings.Contains(path, "/identity/split"),
			strings.Contains(path, "/identity/review"):
			return "platform.identity.review"
		case strings.Contains(path, "/schema/register"):
			return "platform.schema.manage"
		case strings.Contains(path, "/schema"):
			return "platform.schema.read"
		case strings.Contains(path, "/simulate"),
			strings.Contains(path, "/evaluate-change"):
			return "platform.simulation.run"
		case strings.Contains(path, "/write/claim"):
			return "platform.knowledge.write"
		case strings.Contains(path, "/write/decision"),
			strings.Contains(path, "/write/outcome"),
			strings.Contains(path, "/actuate/recommendation"):
			return "platform.workflow.write"
		case strings.Contains(path, "/intelligence/"):
			return "platform.intelligence.read"
		case strings.Contains(path, "/diff"),
			strings.Contains(path, "/query"),
			strings.Contains(path, "/stats"),
			strings.Contains(path, "/ingest/"),
			strings.Contains(path, "/identity/calibration"):
			return "platform.graph.read"
		case isWrite:
			return "platform.graph.write"
		default:
			return "platform.graph.read"
		}
	case strings.HasPrefix(path, "/api/v1/incidents"):
		if isWrite {
			return "security.incidents.manage"
		}
		return "security.incidents.read"
	case strings.HasPrefix(path, "/api/v1/identity"):
		if isWrite {
			return "security.identity.manage"
		}
		return "security.identity.read"
	case strings.HasPrefix(path, "/api/v1/threatintel"):
		if isWrite {
			return "security.threat.manage"
		}
		return "security.threat.read"
	case strings.HasPrefix(path, "/api/v1/audit"):
		return "admin.audit.read"
	case strings.HasPrefix(path, "/api/v1/providers"),
		strings.HasPrefix(path, "/api/v1/sync"):
		return "admin.providers.manage"
	case strings.HasPrefix(path, "/api/v1/webhooks"):
		return "admin.webhooks.manage"
	case strings.HasPrefix(path, "/api/v1/scheduler"):
		return "admin.scheduler.manage"
	case strings.HasPrefix(path, "/api/v1/notifications"):
		return "admin.notifications.manage"
	case strings.HasPrefix(path, "/api/v1/admin"),
		strings.HasPrefix(path, "/api/v1/scan"),
		strings.HasPrefix(path, "/api/v1/telemetry"),
		strings.HasPrefix(path, "/api/v1/remediation"):
		if isWrite {
			return "admin.operations.manage"
		}
		return "admin.operations.read"
	case strings.HasPrefix(path, "/api/v1/rbac/permissions"),
		strings.HasPrefix(path, "/api/v1/rbac/roles"):
		return "admin.rbac.roles.manage"
	case strings.HasPrefix(path, "/api/v1/rbac/users"):
		if strings.Contains(path, "/roles") {
			return "admin.rbac.roles.manage"
		}
		return "admin.rbac.users.manage"
	case strings.HasPrefix(path, "/api/v1/rbac/tenants"),
		strings.HasPrefix(path, "/api/v1/rbac"):
		return "admin.rbac.users.manage"
	case strings.HasPrefix(path, "/api/v1"):
		if isWrite {
			return "admin.operations.manage"
		}
		return "security.findings.read"
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
