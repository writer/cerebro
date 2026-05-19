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
	"net"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/telemetry"
)

var errTenantForbidden = errors.New("tenant forbidden")
var errScopeForbidden = errors.New("scope forbidden")

type authContextKey struct{}
type accessAuditContextKey struct{}

type accessAuditResult struct {
	ConnectCode string
}

type authPrincipal struct {
	Name           string
	TenantID       string
	CredentialID   string
	ClientID       string
	AuthMode       string
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
		started := time.Now()
		recorder := &accessAuditResponseWriter{ResponseWriter: w}
		auditResult := &accessAuditResult{}
		principal := authPrincipal{}
		outcome := "denied"
		denialReason := ""
		defer func() {
			status := recorder.Status()
			finalOutcome, finalDenialReason := accessAuditOutcome(status, outcome, denialReason, auditResult.ConnectCode)
			emitAccessAuditEvent(r, principal, status, time.Since(started), finalOutcome, finalDenialReason, auditResult.ConnectCode)
		}()
		principal, ok := authenticateRequest(cfg, r)
		if !ok {
			denialReason = "unauthenticated"
			writeAuthError(recorder, http.StatusUnauthorized, "unauthorized")
			return
		}
		if tenantID := requestTenantHint(r); tenantID != "" && !tenantAllowed(cfg, principal, tenantID) {
			denialReason = "tenant_forbidden"
			writeAuthError(recorder, http.StatusForbidden, "tenant forbidden")
			return
		}
		auth := authContext{cfg: cfg, principal: principal}
		if err := authorizeHTTPRequestScope(auth, r); err != nil {
			denialReason = "scope_forbidden"
			writeAuthError(recorder, http.StatusForbidden, "scope forbidden")
			return
		}
		outcome = "allowed"
		ctx := context.WithValue(r.Context(), authContextKey{}, auth)
		ctx = context.WithValue(ctx, accessAuditContextKey{}, auditResult)
		next.ServeHTTP(recorder, r.WithContext(ctx))
	})
}

func authInterceptor(cfg config.AuthConfig) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if cfg.Enabled {
				if err := authorizeConnectProcedureScope(ctx, req.Spec().Procedure); err != nil {
					connectErr := connect.NewError(connect.CodePermissionDenied, nil)
					recordConnectAccessAuditResult(ctx, connectErr)
					return nil, connectErr
				}
				if err := authorizeProtoTenant(ctx, cfg, req.Any()); err != nil {
					recordConnectAccessAuditResult(ctx, err)
					return nil, err
				}
			}
			response, err := next(ctx, req)
			recordConnectAccessAuditResult(ctx, err)
			return response, err
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
			return authPrincipal{Name: key.Principal, TenantID: key.TenantID, AuthMode: "api_key"}, true
		}
	}
	for _, credential := range cfg.APICredentials {
		if apiCredentialMatches(token, credential) {
			return authPrincipal{
				Name:           credential.Principal,
				TenantID:       credential.TenantID,
				CredentialID:   credential.ID,
				ClientID:       credential.ClientID,
				AuthMode:       "api_credential",
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
		AuthMode:       "capability_token",
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
	if tenantID := strings.TrimSpace(tenantID); tenantID != "" && !tenantAllowed(auth.cfg, auth.principal, tenantID) {
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

func tenantAllowedByContext(ctx context.Context, tenantID string) bool {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	return !ok || tenantAllowed(auth.cfg, auth.principal, tenantID)
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

type accessAuditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *accessAuditResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *accessAuditResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *accessAuditResponseWriter) Status() int {
	if w == nil || w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *accessAuditResponseWriter) Unwrap() http.ResponseWriter {
	if w == nil {
		return nil
	}
	return w.ResponseWriter
}

func recordConnectAccessAuditResult(ctx context.Context, err error) {
	if err == nil {
		return
	}
	result, _ := ctx.Value(accessAuditContextKey{}).(*accessAuditResult)
	if result == nil {
		return
	}
	result.ConnectCode = strings.ToLower(connect.CodeOf(err).String())
}

func emitAccessAuditEvent(r *http.Request, principal authPrincipal, status int, duration time.Duration, outcome string, denialReason string, connectCode string) {
	if r == nil {
		return
	}
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "outcome", Value: outcome},
		telemetry.Field{Key: "status", Value: status},
		telemetry.Field{Key: "method", Value: r.Method},
		telemetry.Field{Key: "route", Value: accessAuditRoute(r)},
		telemetry.Field{Key: "duration_ms", Value: duration.Milliseconds()},
	)
	if remoteIP := accessAuditRemoteIP(r.RemoteAddr); remoteIP != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "remote_ip", Value: remoteIP})
	}
	if tenantID := firstNonEmpty(requestTenantHint(r), principal.TenantID); tenantID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "tenant_id", Value: tenantID})
	}
	if principal.Name != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "principal", Value: principal.Name})
	}
	if tenantHint := requestTenantHint(r); tenantHint != "" && principal.TenantID != "" && principal.TenantID != tenantHint {
		attrs = attrs.WithField(telemetry.Field{Key: "principal_tenant_id", Value: principal.TenantID})
	}
	if principal.AuthMode != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "auth_mode", Value: principal.AuthMode})
	}
	if principal.CredentialID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "credential_id", Value: principal.CredentialID})
	}
	if principal.ClientID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "client_id", Value: principal.ClientID})
	}
	if procedure := accessAuditConnectProcedure(r.URL.Path); procedure != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "connect_procedure", Value: procedure})
	}
	if connectCode != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "connect_code", Value: connectCode})
	}
	if denialReason != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "denial_reason", Value: denialReason})
	}
	telemetry.Event(r.Context(), "cerebro.api.access", attrs)
}

func accessAuditOutcome(status int, outcome string, denialReason string, connectCode string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(connectCode)) {
	case "":
	case "unauthenticated":
		return "denied", firstNonEmpty(denialReason, "unauthenticated")
	case "permission_denied":
		return "denied", firstNonEmpty(denialReason, "authorization_failed")
	case "internal", "unavailable", "unknown", "data_loss":
		return "error", denialReason
	default:
		return "rejected", denialReason
	}
	switch status {
	case http.StatusUnauthorized:
		return "denied", firstNonEmpty(denialReason, "unauthenticated")
	case http.StatusForbidden:
		return "denied", firstNonEmpty(denialReason, "authorization_failed")
	default:
		if status >= 500 {
			return "error", denialReason
		}
		if status >= 400 {
			return "rejected", denialReason
		}
		return outcome, denialReason
	}
}

func accessAuditRemoteIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return strings.Trim(host, "[]")
	}
	if parsed := net.ParseIP(remoteAddr); parsed != nil {
		return parsed.String()
	}
	return ""
}

func accessAuditRoute(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "unknown"
	}
	path := strings.TrimSpace(r.URL.Path)
	if isConnectProcedurePath(path) {
		return "/cerebro.v1.BootstrapService/{Procedure}"
	}
	if pattern := strings.TrimSpace(r.Pattern); pattern != "" {
		if strings.Contains(pattern, " ") {
			return pattern
		}
		return strings.TrimSpace(r.Method + " " + pattern)
	}
	return fallbackAccessAuditRoute(r.Method, path)
}

func accessAuditConnectProcedure(path string) string {
	if !isConnectProcedurePath(path) {
		return ""
	}
	procedure := "/" + strings.Trim(path, "/")
	if _, ok := knownAccessAuditConnectProcedures[procedure]; !ok {
		return "unknown"
	}
	return strings.TrimPrefix(procedure, "/")
}

var knownAccessAuditConnectProcedures = map[string]struct{}{
	cerebrov1connect.BootstrapServiceGetVersionProcedure:                        {},
	cerebrov1connect.BootstrapServiceCheckHealthProcedure:                       {},
	cerebrov1connect.BootstrapServiceListReportDefinitionsProcedure:             {},
	cerebrov1connect.BootstrapServiceListFindingRulesProcedure:                  {},
	cerebrov1connect.BootstrapServiceRunReportProcedure:                         {},
	cerebrov1connect.BootstrapServiceGetReportRunProcedure:                      {},
	cerebrov1connect.BootstrapServiceListSourcesProcedure:                       {},
	cerebrov1connect.BootstrapServiceCheckSourceProcedure:                       {},
	cerebrov1connect.BootstrapServiceDiscoverSourceProcedure:                    {},
	cerebrov1connect.BootstrapServiceReadSourceProcedure:                        {},
	cerebrov1connect.BootstrapServicePutSourceRuntimeProcedure:                  {},
	cerebrov1connect.BootstrapServiceGetSourceRuntimeProcedure:                  {},
	cerebrov1connect.BootstrapServiceSyncSourceRuntimeProcedure:                 {},
	cerebrov1connect.BootstrapServiceWriteClaimsProcedure:                       {},
	cerebrov1connect.BootstrapServiceListClaimsProcedure:                        {},
	cerebrov1connect.BootstrapServiceListFindingsProcedure:                      {},
	cerebrov1connect.BootstrapServiceGetFindingProcedure:                        {},
	cerebrov1connect.BootstrapServiceResolveFindingProcedure:                    {},
	cerebrov1connect.BootstrapServiceSuppressFindingProcedure:                   {},
	cerebrov1connect.BootstrapServiceAssignFindingProcedure:                     {},
	cerebrov1connect.BootstrapServiceSetFindingDueDateProcedure:                 {},
	cerebrov1connect.BootstrapServiceAddFindingNoteProcedure:                    {},
	cerebrov1connect.BootstrapServiceLinkFindingTicketProcedure:                 {},
	cerebrov1connect.BootstrapServiceListFindingEvaluationRunsProcedure:         {},
	cerebrov1connect.BootstrapServiceGetFindingEvaluationRunProcedure:           {},
	cerebrov1connect.BootstrapServiceListFindingEvidenceProcedure:               {},
	cerebrov1connect.BootstrapServiceGetFindingEvidenceProcedure:                {},
	cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingRulesProcedure: {},
	cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingsProcedure:     {},
	cerebrov1connect.BootstrapServiceWriteDecisionProcedure:                     {},
	cerebrov1connect.BootstrapServiceWriteActionProcedure:                       {},
	cerebrov1connect.BootstrapServiceWriteOutcomeProcedure:                      {},
	cerebrov1connect.BootstrapServiceReplayWorkflowEventsProcedure:              {},
	cerebrov1connect.BootstrapServiceGetEntityNeighborhoodProcedure:             {},
	cerebrov1connect.BootstrapServiceRunGraphIngestRuntimeProcedure:             {},
	cerebrov1connect.BootstrapServiceGetGraphIngestRunProcedure:                 {},
	cerebrov1connect.BootstrapServiceListGraphIngestRunsProcedure:               {},
	cerebrov1connect.BootstrapServiceCheckGraphIngestHealthProcedure:            {},
}

func fallbackAccessAuditRoute(method string, path string) string {
	prefix := strings.TrimSpace(method) + " "
	switch {
	case path == "/sources":
		return prefix + "/sources"
	case strings.HasPrefix(path, "/sources/"):
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 3 {
			switch parts[2] {
			case "check", "discover", "read":
				return prefix + "/sources/{sourceID}/" + parts[2]
			default:
				return prefix + "/sources/{sourceID}/{subresource}"
			}
		}
	case path == "/source-runtimes":
		return prefix + "/source-runtimes"
	case strings.HasPrefix(path, "/source-runtimes/"):
		return prefix + fallbackRuntimeRoute(path)
	case path == "/reports":
		return prefix + "/reports"
	case strings.HasPrefix(path, "/report-runs/"):
		return prefix + "/report-runs/{runID}"
	case path == "/finding-rules":
		return prefix + "/finding-rules"
	case strings.HasPrefix(path, "/findings/"):
		return prefix + fallbackFindingRoute(path)
	case strings.HasPrefix(path, "/finding-evaluation-runs/"):
		return prefix + "/finding-evaluation-runs/{runID}"
	case strings.HasPrefix(path, "/finding-evidence/"):
		return prefix + "/finding-evidence/{evidenceID}"
	case strings.HasPrefix(path, "/grc/entities/") && strings.HasSuffix(path, "/impact"):
		return prefix + "/grc/entities/{entityID}/impact"
	case strings.HasPrefix(path, "/grc/audit-packets/"):
		return prefix + "/grc/audit-packets/{packetID}"
	case strings.HasPrefix(path, "/grc/"):
		switch path {
		case "/grc/dashboard", "/grc/findings", "/grc/controls", "/grc/evidence":
			return prefix + path
		default:
			return prefix + "/grc/{subresource}"
		}
	case strings.HasPrefix(path, "/platform/graph/ingest-runs/"):
		return prefix + "/platform/graph/ingest-runs/{runID}"
	case strings.HasPrefix(path, "/graph/ingest-runs/"):
		return prefix + "/graph/ingest-runs/{runID}"
	case isKnownStaticAccessPath(path):
		return prefix + path
	}
	return prefix + "unmatched"
}

func fallbackRuntimeRoute(path string) string {
	suffix := strings.TrimPrefix(path, "/source-runtimes/")
	if !strings.Contains(suffix, "/") {
		return "/source-runtimes/{runtimeID}"
	}
	parts := strings.SplitN(suffix, "/", 2)
	switch parts[1] {
	case "sync", "graph-ingest-runs", "claims", "findings", "finding-evidence", "finding-evaluation-runs":
		return "/source-runtimes/{runtimeID}/" + parts[1]
	case "finding-rules/evaluate":
		return "/source-runtimes/{runtimeID}/finding-rules/evaluate"
	case "findings/evaluate":
		return "/source-runtimes/{runtimeID}/findings/evaluate"
	default:
		return "/source-runtimes/{runtimeID}/{subresource}"
	}
}

func fallbackFindingRoute(path string) string {
	suffix := strings.TrimPrefix(path, "/findings/")
	if !strings.Contains(suffix, "/") {
		return "/findings/{findingID}"
	}
	parts := strings.SplitN(suffix, "/", 2)
	switch parts[1] {
	case "resolve", "suppress", "assign", "due", "notes", "tickets":
		return "/findings/{findingID}/" + parts[1]
	default:
		return "/findings/{findingID}/{subresource}"
	}
}

func isKnownStaticAccessPath(path string) bool {
	switch path {
	case "/platform/knowledge/decisions",
		"/platform/knowledge/actions",
		"/platform/knowledge/actions/recommendation",
		"/graph/actuate/recommendation",
		"/platform/knowledge/outcomes",
		"/graph/write/outcome",
		"/platform/workflow/replay",
		"/platform/graph/neighborhood",
		"/graph/neighborhood",
		"/platform/graph/impact/package",
		"/graph/impact/package",
		"/platform/graph/impact/asset",
		"/graph/impact/asset",
		"/platform/graph/aws-public-endpoint-insights",
		"/platform/graph/ingest-health",
		"/graph/ingest-health",
		"/platform/graph/ingest-runs",
		"/graph/ingest-runs":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
