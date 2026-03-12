package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/apiauth"
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
	contextKeyAPIKey           contextKey = "api_key"
	contextKeyUserID           contextKey = "user_id"
	contextKeyTenant           contextKey = "tenant_id"
	contextKeyCredentialID     contextKey = "api_credential_id"
	contextKeyCredentialKind   contextKey = "api_credential_kind"
	contextKeyCredentialName   contextKey = "api_credential_name"
	contextKeyCredentialScopes contextKey = "api_credential_scopes"
	contextKeyClientID         contextKey = "api_client_id"
	contextKeyTraceparent      contextKey = "traceparent"
)

type AuthConfig struct {
	APIKeys              map[string]string             // key -> user_id mapping
	APIKeyProvider       func() map[string]string      // optional dynamic key source
	Credentials          map[string]apiauth.Credential // key -> credential mapping
	CredentialProvider   func() map[string]apiauth.Credential
	CredentialLookup     func(string) (apiauth.Credential, bool)
	AuthorizationServers []string
	Enabled              bool
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
					writeAPIAuthError(w, r, http.StatusUnauthorized, "invalid_authorization_header", "Authorization header must use the format 'Bearer <token>'")
				case errors.Is(err, errConflictingAPICredentials):
					writeAPIAuthError(w, r, http.StatusUnauthorized, "conflicting_api_credentials", "Authorization and X-API-Key credentials must match when both are provided")
				default:
					writeAPIAuthError(w, r, http.StatusUnauthorized, "invalid_api_key", "API key is invalid or expired")
				}
				return
			}
			if apiKey == "" {
				writeAPIAuthError(w, r, http.StatusUnauthorized, "missing_api_key", "API key is required")
				return
			}

			credential, valid := lookupAuthCredential(cfg, apiKey)
			if !valid {
				writeAPIAuthError(w, r, http.StatusUnauthorized, "invalid_api_key", "API key is invalid or expired")
				return
			}

			ctx := context.WithValue(r.Context(), contextKeyAPIKey, apiKey)
			ctx = context.WithValue(ctx, contextKeyUserID, credential.UserID)
			ctx = context.WithValue(ctx, contextKeyCredentialID, credential.ID)
			ctx = context.WithValue(ctx, contextKeyCredentialKind, credential.Kind)
			ctx = context.WithValue(ctx, contextKeyCredentialName, credential.Name)
			ctx = context.WithValue(ctx, contextKeyCredentialScopes, append([]string(nil), credential.Scopes...))
			ctx = context.WithValue(ctx, contextKeyClientID, credential.ClientID)
			if traceparent := strings.TrimSpace(r.Header.Get("traceparent")); traceparent != "" {
				ctx = context.WithValue(ctx, contextKeyTraceparent, traceparent)
			}
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

func lookupAuthCredential(cfg AuthConfig, key string) (apiauth.Credential, bool) {
	if cfg.CredentialLookup != nil {
		if credential, ok := cfg.CredentialLookup(key); ok {
			return credential, true
		}
	}

	credentials := cfg.Credentials
	if cfg.CredentialProvider != nil {
		dynamicCredentials := cfg.CredentialProvider()
		if len(dynamicCredentials) > 0 || len(credentials) == 0 {
			credentials = dynamicCredentials
		}
	}
	if len(credentials) > 0 {
		return apiauth.LookupCredential(credentials, key)
	}

	keys := cfg.APIKeys
	if cfg.APIKeyProvider != nil {
		dynamicKeys := cfg.APIKeyProvider()
		if len(dynamicKeys) > 0 || len(keys) == 0 {
			keys = dynamicKeys
		}
	}
	credentials = make(map[string]apiauth.Credential, len(keys))
	for candidate, userID := range keys {
		credentials[candidate] = apiauth.DefaultCredentialForAPIKey(candidate, userID)
	}
	return apiauth.LookupCredential(credentials, key)
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

func GetAPICredentialID(ctx context.Context) string {
	if v := ctx.Value(contextKeyCredentialID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func GetAPICredentialKind(ctx context.Context) string {
	if v := ctx.Value(contextKeyCredentialKind); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func GetAPICredentialName(ctx context.Context) string {
	if v := ctx.Value(contextKeyCredentialName); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func GetAPICredentialScopes(ctx context.Context) []string {
	if v := ctx.Value(contextKeyCredentialScopes); v != nil {
		if scopes, ok := v.([]string); ok {
			return append([]string(nil), scopes...)
		}
	}
	return nil
}

func GetAPIClientID(ctx context.Context) string {
	if v := ctx.Value(contextKeyClientID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func GetTraceparent(ctx context.Context) string {
	if v := ctx.Value(contextKeyTraceparent); v != nil {
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
			if !credentialAllowsPermission(GetAPICredentialScopes(r.Context()), requiredPerm) {
				writeCredentialScopeError(w, r, requiredPerm)
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
		path == "/openapi.yaml" ||
		path == "/.well-known/oauth-protected-resource"
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
	case strings.HasPrefix(path, "/api/v1/admin/agent-sdk/credentials"):
		return "sdk.admin"
	case strings.HasPrefix(path, "/api/v1/agent-sdk/tools"):
		if strings.HasSuffix(path, ":call") || strings.HasSuffix(path, "/call") {
			return "sdk.invoke"
		}
		return "sdk.schema.read"
	case strings.HasPrefix(path, "/api/v1/agent-sdk/schema"):
		return "sdk.schema.read"
	case strings.HasPrefix(path, "/api/v1/agent-sdk/context"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/report"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/quality"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/leverage"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/templates"):
		return "sdk.context.read"
	case strings.HasPrefix(path, "/api/v1/agent-sdk/check"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/simulate"):
		return "sdk.enforcement.run"
	case strings.HasPrefix(path, "/api/v1/agent-sdk/observations"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/claims"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/decisions"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/outcomes"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/annotations"),
		strings.HasPrefix(path, "/api/v1/agent-sdk/identity/resolve"):
		return "sdk.worldmodel.write"
	case strings.HasPrefix(path, "/api/v1/mcp"):
		return "sdk.invoke"
	case isWrite && path == "/api/v1/platform/graph/diffs":
		return "platform.graph.write"
	case strings.HasPrefix(path, "/api/v1/platform/graph"):
		return "platform.graph.read"
	case strings.HasPrefix(path, "/api/v1/status"):
		return "platform.graph.read"
	case strings.HasPrefix(path, "/api/v1/platform/entities"):
		return "platform.graph.read"
	case strings.HasPrefix(path, "/api/v1/platform/intelligence"):
		if isWrite && strings.Contains(path, "/runs") {
			return "platform.intelligence.run"
		}
		return "platform.intelligence.read"
	case strings.HasPrefix(path, "/api/v1/platform/jobs"):
		return "platform.jobs.read"
	case strings.HasPrefix(path, "/api/v1/platform/knowledge"):
		if isWrite {
			return "platform.knowledge.write"
		}
		return "platform.knowledge.read"
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

func credentialAllowsPermission(scopes []string, requiredPermission string) bool {
	requiredPermission = strings.TrimSpace(requiredPermission)
	if requiredPermission == "" {
		return true
	}
	if len(scopes) == 0 {
		return true
	}
	for _, scope := range scopes {
		if auth.PermissionImplies(scope, requiredPermission) {
			return true
		}
	}
	return false
}

func writeCredentialScopeError(w http.ResponseWriter, r *http.Request, requiredPermission string) {
	if requiresProtectedResourceMetadata(r.URL.Path) {
		w.Header().Set("WWW-Authenticate", buildProtectedResourceChallenge(r, "", requiredPermission))
	}
	writeJSONError(w, http.StatusForbidden, "insufficient_scope", "credential scope does not allow "+strings.TrimSpace(requiredPermission))
}

func writeAPIAuthError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	if requiresProtectedResourceMetadata(r.URL.Path) {
		w.Header().Set("WWW-Authenticate", buildProtectedResourceChallenge(r, "", ""))
	}
	writeJSONError(w, status, code, message)
}

func requiresProtectedResourceMetadata(path string) bool {
	return strings.HasPrefix(path, "/api/v1/agent-sdk") || strings.HasPrefix(path, "/api/v1/mcp")
}

func buildProtectedResourceChallenge(r *http.Request, realm, requiredScope string) string {
	parts := make([]string, 0, 4)
	if scope := strings.TrimSpace(requiredScope); scope != "" {
		parts = append(parts, `error="insufficient_scope"`, `scope="`+scope+`"`)
	}
	if realm = strings.TrimSpace(realm); realm != "" {
		parts = append(parts, `realm="`+realm+`"`)
	} else {
		parts = append(parts, `realm="cerebro-agent-sdk"`)
	}
	parts = append(parts, `resource_metadata="`+protectedResourceMetadataURL(r)+`"`)
	return "Bearer " + strings.Join(parts, ", ")
}

func protectedResourceMetadataURL(r *http.Request) string {
	scheme := "http"
	if r != nil {
		if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
			scheme = "https"
		} else if r.TLS != nil {
			scheme = "https"
		}
		if host := strings.TrimSpace(r.Host); host != "" {
			return scheme + "://" + host + "/.well-known/oauth-protected-resource"
		}
	}
	return "/.well-known/oauth-protected-resource"
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
