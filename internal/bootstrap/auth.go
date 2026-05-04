package bootstrap

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/writer/cerebro/internal/config"
)

var errTenantForbidden = errors.New("tenant forbidden")

type authContextKey struct{}

type authPrincipal struct {
	Name     string
	TenantID string
}

type authContext struct {
	cfg       config.AuthConfig
	principal authPrincipal
}

func authMiddleware(cfg config.AuthConfig, next http.Handler) http.Handler {
	if !cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		principal, ok := authenticateRequest(cfg, r)
		if !ok {
			writeAuthError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if tenantID := requestTenantHint(r); tenantID != "" && !tenantAllowed(cfg, principal, tenantID) {
			writeAuthError(w, http.StatusForbidden, "tenant forbidden")
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, authContext{cfg: cfg, principal: principal})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authInterceptor(cfg config.AuthConfig) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if cfg.Enabled {
				if err := authorizeProtoTenant(ctx, cfg, req.Any()); err != nil {
					return nil, err
				}
			}
			return next(ctx, req)
		}
	})
}

func isPublicPath(path string) bool {
	switch path {
	case "/health", "/healthz", "/openapi.yaml":
		return true
	default:
		return false
	}
}

func authenticateRequest(cfg config.AuthConfig, r *http.Request) (authPrincipal, bool) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Cerebro-API-Key"))
	}
	if token == "" {
		return authPrincipal{}, false
	}
	for _, key := range cfg.APIKeys {
		if constantTimeEqual(token, key.Key) {
			return authPrincipal{Name: key.Principal, TenantID: key.TenantID}, true
		}
	}
	return authPrincipal{}, false
}

func bearerToken(header string) string {
	parts := strings.Fields(strings.TrimSpace(header))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func constantTimeEqual(a string, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func requestTenantHint(r *http.Request) string {
	if tenantID := strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant")); tenantID != "" {
		return tenantID
	}
	if tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id")); tenantID != "" {
		return tenantID
	}
	return ""
}

func authorizeProtoTenant(ctx context.Context, cfg config.AuthConfig, message any) error {
	protoMessage, ok := message.(proto.Message)
	if !ok || protoMessage == nil {
		return nil
	}
	auth, _ := ctx.Value(authContextKey{}).(authContext)
	for _, tenantID := range protoTenantIDs(protoMessage) {
		if !tenantAllowed(cfg, auth.principal, tenantID) {
			return connect.NewError(connect.CodePermissionDenied, nil)
		}
	}
	return nil
}

func authorizeHTTPRequestTenant(ctx context.Context, message proto.Message) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok {
		return nil
	}
	for _, tenantID := range protoTenantIDs(message) {
		if !tenantAllowed(auth.cfg, auth.principal, tenantID) {
			return errTenantForbidden
		}
	}
	return nil
}

func authorizeSourceConfigTenant(ctx context.Context, sourceConfig map[string]string) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok {
		return nil
	}
	if tenantID := strings.TrimSpace(sourceConfig["tenant_id"]); tenantID != "" && !tenantAllowed(auth.cfg, auth.principal, tenantID) {
		return errTenantForbidden
	}
	return nil
}

func tenantAllowed(cfg config.AuthConfig, principal authPrincipal, tenantID string) bool {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return true
	}
	if principal.TenantID != "" {
		return tenantID == principal.TenantID
	}
	if len(cfg.AllowedTenants) == 0 {
		return true
	}
	for _, allowed := range cfg.AllowedTenants {
		if tenantID == allowed {
			return true
		}
	}
	return false
}

func protoTenantIDs(message proto.Message) []string {
	seen := map[string]struct{}{}
	var tenants []string
	collectProtoTenantIDs(message.ProtoReflect(), seen, &tenants)
	return tenants
}

func collectProtoTenantIDs(message protoreflect.Message, seen map[string]struct{}, tenants *[]string) {
	if !message.IsValid() {
		return
	}
	fields := message.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		value := message.Get(field)
		if field.IsList() {
			list := value.List()
			for j := 0; j < list.Len(); j++ {
				collectProtoValueTenantIDs(field, list.Get(j), seen, tenants)
			}
			continue
		}
		if field.IsMap() || !message.Has(field) {
			continue
		}
		collectProtoValueTenantIDs(field, value, seen, tenants)
	}
}

func collectProtoValueTenantIDs(field protoreflect.FieldDescriptor, value protoreflect.Value, seen map[string]struct{}, tenants *[]string) {
	if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
		collectProtoTenantIDs(value.Message(), seen, tenants)
		return
	}
	if field.Name() != "tenant_id" || field.Kind() != protoreflect.StringKind {
		return
	}
	tenantID := strings.TrimSpace(value.String())
	if tenantID == "" {
		return
	}
	if _, ok := seen[tenantID]; ok {
		return
	}
	seen[tenantID] = struct{}{}
	*tenants = append(*tenants, tenantID)
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
