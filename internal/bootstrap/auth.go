package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourceconfig"
)

var errTenantForbidden = errors.New("tenant forbidden")
var errScopeForbidden = errors.New("scope forbidden")

type authContextKey struct{}

type authPrincipal struct {
	Name           string
	TenantID       string
	CredentialID   string
	ClientID       string
	AllowedTenants []string
	Scopes         []string
	Groups         []string
	Capability     bool
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
		auth := authContext{cfg: cfg, principal: principal}
		if err := authorizeHTTPRequestScope(auth, r); err != nil {
			writeAuthError(w, http.StatusForbidden, "scope forbidden")
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, auth)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authInterceptor(cfg config.AuthConfig) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if cfg.Enabled {
				if err := authorizeConnectProcedureScope(ctx, req.Spec().Procedure); err != nil {
					return nil, connect.NewError(connect.CodePermissionDenied, nil)
				}
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
	for _, credential := range cfg.APICredentials {
		if apiCredentialMatches(token, credential) {
			return authPrincipal{
				Name:           credential.Principal,
				TenantID:       credential.TenantID,
				CredentialID:   credential.ID,
				ClientID:       credential.ClientID,
				AllowedTenants: credential.AllowedTenants,
				Scopes:         credential.Scopes,
			}, true
		}
	}
	if principal, ok := authenticateCapabilityToken(cfg, token, time.Now()); ok {
		return principal, true
	}
	return authPrincipal{}, false
}

func apiCredentialMatches(token string, credential config.APICredential) bool {
	if credential.Key != "" && constantTimeEqual(token, credential.Key) {
		return true
	}
	if credential.KeySHA256 == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return constantTimeEqual(hex.EncodeToString(sum[:]), strings.ToLower(credential.KeySHA256))
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

func authenticateCapabilityToken(cfg config.AuthConfig, token string, now time.Time) (authPrincipal, bool) {
	if len(cfg.CapabilityTokenSecrets) == 0 || strings.Count(token, ".") != 2 {
		return authPrincipal{}, false
	}
	parts := strings.Split(token, ".")
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return authPrincipal{}, false
	}
	if !validCapabilitySignature([]byte(signingInput), signature, cfg.CapabilityTokenSecrets) {
		return authPrincipal{}, false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return authPrincipal{}, false
	}
	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Algorithm != "HS256" {
		return authPrincipal{}, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return authPrincipal{}, false
	}
	var claims capabilityClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return authPrincipal{}, false
	}
	if claims.ExpiresAt <= 0 || !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return authPrincipal{}, false
	}
	if claims.IssuedAt > 0 && now.Add(5*time.Minute).Before(time.Unix(claims.IssuedAt, 0)) {
		return authPrincipal{}, false
	}
	if cfg.CapabilityTokenAudience != "" && strings.TrimSpace(claims.Audience) != cfg.CapabilityTokenAudience {
		return authPrincipal{}, false
	}
	scopes := normalizeAuthList(claims.Scopes)
	allowedTenants := normalizeAuthList(claims.AllowedTenants)
	tenantID := strings.TrimSpace(claims.TenantID)
	if len(scopes) == 0 {
		return authPrincipal{}, false
	}
	if tenantID == "" && len(allowedTenants) == 0 {
		return authPrincipal{}, false
	}
	return authPrincipal{
		Name:           strings.TrimSpace(claims.Subject),
		TenantID:       tenantID,
		CredentialID:   strings.TrimSpace(claims.CredentialID),
		ClientID:       strings.TrimSpace(claims.ClientID),
		AllowedTenants: allowedTenants,
		Scopes:         scopes,
		Groups:         normalizeAuthList(claims.Groups),
		Capability:     true,
	}, true
}

type capabilityClaims struct {
	Audience       string   `json:"aud"`
	Subject        string   `json:"sub"`
	ExpiresAt      int64    `json:"exp"`
	IssuedAt       int64    `json:"iat,omitempty"`
	CredentialID   string   `json:"credential_id,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	TenantID       string   `json:"tenant_id,omitempty"`
	AllowedTenants []string `json:"allowed_tenants,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	Groups         []string `json:"groups,omitempty"`
}

func validCapabilitySignature(signingInput []byte, signature []byte, secrets []string) bool {
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(signingInput)
		if hmac.Equal(signature, mac.Sum(nil)) {
			return true
		}
	}
	return false
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
	for _, tenantID := range protoTenantIDs(message) {
		if err := authorizeTenantID(ctx, tenantID); err != nil {
			return err
		}
	}
	return nil
}

func authorizeSourceConfigTenant(ctx context.Context, sourceConfig map[string]string) error {
	return authorizeTenantID(ctx, sourceConfig["tenant_id"])
}

func authorizeKnowledgeTenant(ctx context.Context, metadata map[string]any, ids ...string) error {
	if err := authorizeTenantID(ctx, tenantIDFromMetadata(metadata)); err != nil {
		return err
	}
	for _, id := range ids {
		if err := authorizeCerebroURNTenant(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func authorizeCerebroURNTenant(ctx context.Context, urn string) error {
	return authorizeTenantID(ctx, tenantIDFromCerebroURN(urn))
}

func authorizeTenantScopeRequired(ctx context.Context, tenantID string) error {
	if hasTenantScopedAuth(ctx) && strings.TrimSpace(tenantID) == "" {
		return errTenantForbidden
	}
	return authorizeTenantID(ctx, tenantID)
}

func authorizeTenantID(ctx context.Context, tenantID string) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		if len(auth.principal.AllowedTenants) > 0 {
			return errTenantForbidden
		}
		return nil
	}
	if !tenantAllowed(auth.cfg, auth.principal, tenantID) {
		return errTenantForbidden
	}
	return nil
}

const scopeCosmoSecurityRead = "cerebro.cosmo.security.read"

func authorizeHTTPRequestScope(auth authContext, r *http.Request) error {
	if !principalScopeRestricted(auth.principal) || isConnectProcedurePath(r.URL.Path) {
		return nil
	}
	scope := scopeForHTTPRequest(r)
	return authorizePrincipalScope(auth.principal, scope)
}

func authorizeConnectProcedureScope(ctx context.Context, procedure string) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok || !principalScopeRestricted(auth.principal) {
		return nil
	}
	return authorizePrincipalScope(auth.principal, scopeForConnectProcedure(procedure))
}

func authorizePrincipalScope(principal authPrincipal, required string) error {
	if required == "" || !containsAuthValue(principal.Scopes, required) {
		return errScopeForbidden
	}
	if required == scopeCosmoSecurityRead && principal.Capability && !containsAuthValue(principal.Groups, "security") {
		return errScopeForbidden
	}
	return nil
}

func principalScopeRestricted(principal authPrincipal) bool {
	return len(principal.Scopes) > 0
}

func isConnectProcedurePath(path string) bool {
	return strings.HasPrefix(path, "/cerebro.v1.BootstrapService/")
}

func scopeForHTTPRequest(r *http.Request) string {
	if r.Method != http.MethodGet {
		return ""
	}
	path := strings.TrimSpace(r.URL.Path)
	switch {
	case path == "/sources", path == "/reports", path == "/finding-rules":
		return scopeCosmoSecurityRead
	case path == "/source-runtimes" || strings.HasPrefix(path, "/source-runtimes/"):
		return scopeCosmoSecurityRead
	case strings.HasPrefix(path, "/findings/"):
		return scopeCosmoSecurityRead
	case strings.HasPrefix(path, "/finding-evaluation-runs/"), strings.HasPrefix(path, "/finding-evidence/"):
		return scopeCosmoSecurityRead
	case strings.HasPrefix(path, "/grc/"):
		return scopeCosmoSecurityRead
	case path == "/platform/graph/neighborhood", path == "/graph/neighborhood":
		return scopeCosmoSecurityRead
	case strings.HasPrefix(path, "/platform/graph/impact/"), strings.HasPrefix(path, "/graph/impact/"):
		return scopeCosmoSecurityRead
	case path == "/platform/graph/aws-public-endpoint-insights":
		return scopeCosmoSecurityRead
	case path == "/platform/graph/ingest-health", path == "/graph/ingest-health":
		return scopeCosmoSecurityRead
	case path == "/platform/graph/ingest-runs", strings.HasPrefix(path, "/platform/graph/ingest-runs/"):
		return scopeCosmoSecurityRead
	case path == "/graph/ingest-runs", strings.HasPrefix(path, "/graph/ingest-runs/"):
		return scopeCosmoSecurityRead
	case strings.HasPrefix(path, "/report-runs/"):
		return scopeCosmoSecurityRead
	default:
		return ""
	}
}

func scopeForConnectProcedure(procedure string) string {
	switch procedure {
	case cerebrov1connect.BootstrapServiceGetVersionProcedure,
		cerebrov1connect.BootstrapServiceCheckHealthProcedure,
		cerebrov1connect.BootstrapServiceListSourcesProcedure,
		cerebrov1connect.BootstrapServiceListReportDefinitionsProcedure,
		cerebrov1connect.BootstrapServiceListFindingRulesProcedure,
		cerebrov1connect.BootstrapServiceGetReportRunProcedure,
		cerebrov1connect.BootstrapServiceGetSourceRuntimeProcedure,
		cerebrov1connect.BootstrapServiceListClaimsProcedure,
		cerebrov1connect.BootstrapServiceListFindingsProcedure,
		cerebrov1connect.BootstrapServiceGetFindingProcedure,
		cerebrov1connect.BootstrapServiceListFindingEvaluationRunsProcedure,
		cerebrov1connect.BootstrapServiceGetFindingEvaluationRunProcedure,
		cerebrov1connect.BootstrapServiceListFindingEvidenceProcedure,
		cerebrov1connect.BootstrapServiceGetFindingEvidenceProcedure,
		cerebrov1connect.BootstrapServiceGetEntityNeighborhoodProcedure,
		cerebrov1connect.BootstrapServiceGetGraphIngestRunProcedure,
		cerebrov1connect.BootstrapServiceListGraphIngestRunsProcedure,
		cerebrov1connect.BootstrapServiceCheckGraphIngestHealthProcedure:
		return scopeCosmoSecurityRead
	default:
		return ""
	}
}

func tenantIDFromMetadata(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}
	value, ok := metadata["tenant_id"]
	if !ok {
		return ""
	}
	tenantID, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(tenantID)
}

func tenantIDFromCerebroURN(urn string) string {
	parts := strings.SplitN(strings.TrimSpace(urn), ":", 5)
	if len(parts) < 5 || parts[0] != "urn" || parts[1] != "cerebro" {
		return ""
	}
	return strings.TrimSpace(parts[2])
}

func hasAuthContext(ctx context.Context) bool {
	_, ok := ctx.Value(authContextKey{}).(authContext)
	return ok
}

func hasTenantScopedAuth(ctx context.Context) bool {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	return ok && principalHasTenantScope(auth.principal)
}

func requiresTenantFilter(ctx context.Context) bool {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	return ok && strings.TrimSpace(auth.principal.TenantID) == "" && (len(auth.principal.AllowedTenants) > 0 || len(auth.cfg.AllowedTenants) > 0)
}

func principalHasTenantScope(principal authPrincipal) bool {
	return strings.TrimSpace(principal.TenantID) != "" || len(principal.AllowedTenants) > 0
}

func tenantAllowed(cfg config.AuthConfig, principal authPrincipal, tenantID string) bool {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return len(principal.AllowedTenants) == 0
	}
	if principal.TenantID != "" {
		return tenantID == principal.TenantID
	}
	if len(principal.AllowedTenants) > 0 {
		return containsAuthValue(principal.AllowedTenants, tenantID)
	}
	if len(cfg.AllowedTenants) == 0 {
		return true
	}
	return containsAuthValue(cfg.AllowedTenants, tenantID)
}

func containsAuthValue(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func normalizeAuthList(values []string) []string {
	seen := map[string]struct{}{}
	var normalized []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
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
		if field.IsMap() {
			mapping := value.Map()
			mapping.Range(func(key protoreflect.MapKey, mapValue protoreflect.Value) bool {
				collectProtoMapTenantIDs(field, key, mapValue, seen, tenants)
				return true
			})
			continue
		}
		if !message.Has(field) {
			continue
		}
		collectProtoValueTenantIDs(field, value, seen, tenants)
	}
}

func collectProtoMapTenantIDs(field protoreflect.FieldDescriptor, key protoreflect.MapKey, value protoreflect.Value, seen map[string]struct{}, tenants *[]string) {
	valueField := field.MapValue()
	if valueField.Kind() == protoreflect.MessageKind || valueField.Kind() == protoreflect.GroupKind {
		if field.MapKey().Kind() == protoreflect.StringKind && key.String() == "tenant_id" {
			appendTenantID(protoStringValue(value.Message()), seen, tenants)
		}
		collectProtoTenantIDs(value.Message(), seen, tenants)
		return
	}
	if field.MapKey().Kind() != protoreflect.StringKind || key.String() != "tenant_id" || valueField.Kind() != protoreflect.StringKind {
		return
	}
	appendTenantID(value.String(), seen, tenants)
}

func collectProtoValueTenantIDs(field protoreflect.FieldDescriptor, value protoreflect.Value, seen map[string]struct{}, tenants *[]string) {
	if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
		collectProtoTenantIDs(value.Message(), seen, tenants)
		return
	}
	if field.Kind() != protoreflect.StringKind {
		return
	}
	switch field.Name() {
	case "tenant_id":
		appendTenantID(value.String(), seen, tenants)
	case "root_urn", "decision_id", "target_ids", "evidence_ids", "action_ids":
		appendTenantID(tenantIDFromCerebroURN(value.String()), seen, tenants)
	}
}

func protoStringValue(message protoreflect.Message) string {
	if !message.IsValid() {
		return ""
	}
	field := message.Descriptor().Fields().ByName("string_value")
	if field == nil || field.Kind() != protoreflect.StringKind || !message.Has(field) {
		return ""
	}
	return message.Get(field).String()
}

func appendTenantID(rawTenantID string, seen map[string]struct{}, tenants *[]string) {
	tenantID := strings.TrimSpace(rawTenantID)
	if tenantID == "" {
		return
	}
	if sourceconfig.IsSecretReference(tenantID) {
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
