package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/writer/cerebro/gen/cerebro/v1/cerebrov1connect"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/deviceauth"
	"github.com/writer/cerebro/internal/deviceauth/risk"
	"github.com/writer/cerebro/internal/sourceconfig"
	"github.com/writer/cerebro/internal/telemetry"
)

var errTenantForbidden = errors.New("tenant forbidden")
var errScopeForbidden = errors.New("scope forbidden")

type authContextKey struct{}
type accessAuditContextKey struct{}

type accessAuditResult struct {
	ConnectCode       string
	RequestedTenantID string
}

type authPrincipal struct {
	Name           string
	TenantID       string
	CredentialID   string
	ClientID       string
	AuthMode       string
	TokenResource  string
	AllowedTenants []string
	Scopes         []string
	Groups         []string
	Capability     bool
	DeviceID       string
	HardwareUUID   string
	// AssuranceLevel is "hardware" or "software" for device principals.
	AssuranceLevel string
	// RiskScore / RiskLevel are populated by the risk pipeline during
	// authentication for device principals. Both are zero / "" for non-
	// device principals.
	RiskScore int
	RiskLevel string
}

type authContext struct {
	cfg            config.AuthConfig
	principal      authPrincipal
	deviceVerifier *deviceauth.JWTVerifier
	dpopVerifier   *deviceauth.DPoPVerifier
	riskScorer     *risk.Scorer
	observations   risk.ObservationStore
}

// AuthDependencies carries the optional verifiers/scorers the auth pipeline
// uses for device JWT authentication. All fields are optional; the
// middleware degrades gracefully when nil (DPoP not enforced; risk scoring
// disabled).
type AuthDependencies struct {
	DeviceVerifier *deviceauth.JWTVerifier
	DPoPVerifier   *deviceauth.DPoPVerifier
	RiskScorer     *risk.Scorer
	Observations   risk.ObservationStore
}

func authMiddleware(cfg config.AuthConfig, deps AuthDependencies, next http.Handler) http.Handler {
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
		auditResult := &accessAuditResult{RequestedTenantID: requestTenantHint(r)}
		origin := resolveRequestOrigin(r, cfg.RequestOrigin)
		principal := authPrincipal{}
		outcome := "denied"
		denialReason := ""
		defer func() {
			status := recorder.Status()
			finalOutcome, finalDenialReason := accessAuditOutcome(status, outcome, denialReason, auditResult.ConnectCode)
			emitAccessAuditEvent(r, origin, principal, status, time.Since(started), finalOutcome, finalDenialReason, auditResult)
		}()
		if isUnauthenticatedDevicePath(r.URL.Path) {
			outcome = "allowed"
			ctx := context.WithValue(r.Context(), accessAuditContextKey{}, auditResult)
			next.ServeHTTP(recorder, r.WithContext(ctx))
			return
		}
		var deviceJKT string
		var presentedToken string
		principal, deviceJKT, presentedToken, ok := authenticateRequest(cfg, deps.DeviceVerifier, r)
		if !ok {
			denialReason = "unauthenticated"
			writeAuthErrorForRequest(recorder, r, cfg, http.StatusUnauthorized, "unauthorized")
			return
		}
		if deviceJKT != "" {
			if err := verifyDPoPHeader(deps.DPoPVerifier, r, origin.PublicURL, deviceJKT, presentedToken); err != nil {
				denialReason = "dpop_invalid"
				if errors.Is(err, deviceauth.ErrDPoPVerifierUnavailable) {
					denialReason = "dpop_unavailable"
				}
				writeDeviceAuthServiceError(recorder, err)
				return
			}
		}
		if principal.AuthMode == "device_jwt" && deps.RiskScorer != nil {
			scoreSig := risk.Signal{
				DeviceID:  principal.DeviceID,
				TenantID:  principal.TenantID,
				RemoteIP:  net.ParseIP(origin.ClientIP),
				UserAgent: r.Header.Get("User-Agent"),
				Method:    r.Method,
				Path:      r.URL.Path,
				Now:       time.Now(),
			}
			if deps.Observations != nil {
				if obs, found := deps.Observations.Get(r.Context(), principal.DeviceID); found {
					scoreSig.PriorObservation = obs
				}
			}
			decision := deps.RiskScorer.Score(r.Context(), scoreSig)
			principal.Scopes = decision.FilterScopes(principal.Scopes)
			principal.RiskScore = decision.Score
			principal.RiskLevel = decision.Level
		}
		if err := authorizeTokenResource(cfg, principal, r); err != nil {
			denialReason = "resource_forbidden"
			writeAuthErrorForRequest(recorder, r, cfg, http.StatusUnauthorized, "unauthorized")
			return
		}
		if tenantID := auditResult.RequestedTenantID; tenantID != "" && !tenantAllowed(cfg, principal, tenantID) {
			denialReason = "tenant_forbidden"
			writeAuthErrorForRequest(recorder, r, cfg, http.StatusForbidden, "tenant forbidden")
			return
		}
		auth := authContext{
			cfg:            cfg,
			principal:      principal,
			deviceVerifier: deps.DeviceVerifier,
			dpopVerifier:   deps.DPoPVerifier,
			riskScorer:     deps.RiskScorer,
			observations:   deps.Observations,
		}
		if err := authorizeHTTPRequestScope(auth, r); err != nil {
			denialReason = "scope_forbidden"
			writeAuthErrorForRequest(recorder, r, cfg, http.StatusForbidden, "scope forbidden")
			return
		}
		outcome = "allowed"
		ctx := context.WithValue(r.Context(), authContextKey{}, auth)
		ctx = context.WithValue(ctx, accessAuditContextKey{}, auditResult)
		next.ServeHTTP(recorder, r.WithContext(ctx))
	})
}

// verifyDPoPHeader inspects the DPoP request header (RFC 9449 §4) when the
// authenticated device JWT carries a cnf.jkt claim. The proof must be a
// valid DPoP+JWT, htm/htu must match the request, and the JWK thumbprint
// must equal the expected jkt that was bound at enroll time.
func verifyDPoPHeader(verifier *deviceauth.DPoPVerifier, r *http.Request, publicURL string, expectedJKT string, accessToken string) error {
	if verifier == nil {
		return deviceauth.ErrDPoPVerifierUnavailable
	}
	proof := strings.TrimSpace(r.Header.Get("DPoP"))
	if proof == "" {
		return deviceauth.ErrDPoPMissing
	}
	if strings.TrimSpace(publicURL) == "" && r != nil {
		publicURL = resolveRequestOrigin(r, config.RequestOriginConfig{}).PublicURL
	}
	res, err := verifier.Verify(proof, r.Method, publicURL, accessToken)
	if err != nil {
		return err
	}
	if res.JKT != expectedJKT {
		return deviceauth.ErrDPoPJKTMismatch
	}
	return nil
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
	case "/health", "/healthz", "/livez", "/openapi.yaml":
		return true
	case "/.well-known/device-jwks.json":
		return true
	case oauthProtectedResourceMetadataPath, oauthProtectedResourceMetadataMCPPath, oauthAuthorizationServerMetadataPath:
		return true
	case oauthAuthorizePath, oauthCallbackPath, oauthTokenPath, oauthRevokePath, oauthRegisterPath:
		return true
	default:
		return false
	}
}

func isUnauthenticatedDevicePath(path string) bool {
	switch path {
	case "/platform/devices/enroll", "/platform/devices/token":
		return true
	default:
		return false
	}
}

func authenticateRequest(cfg config.AuthConfig, deviceVerifier *deviceauth.JWTVerifier, r *http.Request) (authPrincipal, string, string, bool) {
	token := bearerToken(r.Header.Get("Authorization"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Cerebro-API-Key"))
	}
	if token == "" {
		return authPrincipal{}, "", "", false
	}
	for _, credential := range cfg.APICredentials {
		if !apiCredentialAcceptsBearer(credential) {
			continue
		}
		if apiCredentialMatches(token, credential) {
			return authPrincipal{
				Name:           credential.Principal,
				TenantID:       credential.TenantID,
				CredentialID:   credential.ID,
				ClientID:       credential.ClientID,
				AuthMode:       "api_credential",
				AllowedTenants: credential.AllowedTenants,
				Scopes:         credential.Scopes,
			}, "", token, true
		}
	}
	for _, key := range cfg.APIKeys {
		if constantTimeEqual(token, key.Key) {
			return authPrincipal{Name: key.Principal, TenantID: key.TenantID, AuthMode: "api_key"}, "", token, true
		}
	}
	if principal, ok := authenticateCapabilityToken(cfg, token, time.Now()); ok {
		return principal, "", token, true
	}
	if principal, jkt, ok := authenticateDeviceToken(deviceVerifier, token); ok {
		return principal, jkt, token, true
	}
	return authPrincipal{}, "", "", false
}

func apiCredentialAcceptsBearer(credential config.APICredential) bool {
	switch strings.TrimSpace(credential.Kind) {
	case "oauth_client", "client_credentials":
		return false
	default:
		return true
	}
}

// authenticateDeviceToken verifies an EdDSA device JWT issued by the
// internal/deviceauth Service. It returns the principal, the cnf.jkt
// thumbprint when the token was minted DPoP-bound (empty otherwise), and
// a success flag.
func authenticateDeviceToken(verifier *deviceauth.JWTVerifier, token string) (authPrincipal, string, bool) {
	if verifier == nil {
		return authPrincipal{}, "", false
	}
	verified, err := verifier.Verify(token)
	if err != nil {
		return authPrincipal{}, "", false
	}
	return authPrincipal{
		Name:           "device:" + verified.DeviceID,
		TenantID:       verified.TenantID,
		AuthMode:       "device_jwt",
		Scopes:         verified.Scopes,
		DeviceID:       verified.DeviceID,
		HardwareUUID:   verified.HardwareUUID,
		AssuranceLevel: verified.AssuranceLevel,
	}, verified.DPoPJKT, true
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
		KeyID     string `json:"kid,omitempty"`
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
		TokenResource:  strings.TrimSpace(claims.Resource),
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
	Resource       string   `json:"resource,omitempty"`
	TenantID       string   `json:"tenant_id,omitempty"`
	AllowedTenants []string `json:"allowed_tenants,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	JWTID          string   `json:"jti,omitempty"`
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

func issueCapabilityToken(cfg config.AuthConfig, claims capabilityClaims, ttl time.Duration, now time.Time) (string, error) {
	if len(cfg.CapabilityTokenSecrets) == 0 {
		return "", fmt.Errorf("capability token secret is required")
	}
	secret := strings.TrimSpace(cfg.CapabilityTokenSecrets[0])
	if secret == "" {
		return "", fmt.Errorf("capability token secret is empty")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	claims.IssuedAt = now.UTC().Unix()
	claims.ExpiresAt = now.UTC().Add(ttl).Unix()
	if strings.TrimSpace(claims.Audience) == "" {
		claims.Audience = cfg.CapabilityTokenAudience
	}
	if strings.TrimSpace(claims.JWTID) == "" {
		jti, err := randomTokenID()
		if err != nil {
			return "", err
		}
		claims.JWTID = jti
	}
	headerBytes, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": "0"})
	if err != nil {
		return "", fmt.Errorf("marshal capability token header: %w", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal capability token claims: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature, nil
}

func randomTokenID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
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
		recordAccessAuditRequestedTenant(ctx, tenantID)
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

func effectiveTenantFilter(ctx context.Context, requestedTenantID string) (string, error) {
	tenantID := strings.TrimSpace(requestedTenantID)
	if tenantID == "" {
		if auth, ok := ctx.Value(authContextKey{}).(authContext); ok {
			tenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if tenantID == "" && requiresTenantFilter(ctx) {
		return "", errTenantForbidden
	}
	if err := authorizeTenantID(ctx, tenantID); err != nil {
		return "", err
	}
	return tenantID, nil
}

func authorizeTenantID(ctx context.Context, tenantID string) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok {
		return nil
	}
	tenantID = strings.TrimSpace(tenantID)
	recordAccessAuditRequestedTenant(ctx, tenantID)
	if tenantID != "" && !tenantAllowed(auth.cfg, auth.principal, tenantID) {
		return errTenantForbidden
	}
	return nil
}

func authorizeFindingCandidatePromotion(ctx context.Context) error {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok {
		return nil
	}
	return authorizePrincipalScope(auth.principal, scopeFindingCandidatePromote)
}

const (
	scopeCosmoSecurityRead       = "cerebro.cosmo.security.read"
	scopeFindingCandidatePromote = "cerebro.finding_candidates.promote"
	scopeRuntimeResponseWrite    = "cerebro.runtime_response.write"
)

func authorizeHTTPRequestScope(auth authContext, r *http.Request) error {
	if !principalScopeRestricted(auth.principal) || isConnectProcedurePath(r.URL.Path) {
		return nil
	}
	scope := scopeForHTTPRequest(r)
	return authorizePrincipalScope(auth.principal, scope)
}

func authorizeTokenResource(cfg config.AuthConfig, principal authPrincipal, r *http.Request) error {
	if strings.TrimSpace(principal.TokenResource) == "" {
		return nil
	}
	if !tokenResourceAllowedForRequest(cfg, r, principal.TokenResource) {
		return errScopeForbidden
	}
	return nil
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

func hasRuntimeResponseTrustedScope(ctx context.Context) bool {
	auth, ok := ctx.Value(authContextKey{}).(authContext)
	if !ok || !principalScopeRestricted(auth.principal) {
		return true
	}
	return containsAuthValue(auth.principal.Scopes, scopeRuntimeResponseWrite)
}

func principalScopeRestricted(principal authPrincipal) bool {
	return len(principal.Scopes) > 0
}

func isConnectProcedurePath(path string) bool {
	return strings.HasPrefix(path, "/cerebro.v1.BootstrapService/")
}

func scopeForHTTPRequest(r *http.Request) string {
	return httpRoutePolicyForRequest(r).Scope
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
		cerebrov1connect.BootstrapServiceListFindingCandidatesProcedure,
		cerebrov1connect.BootstrapServiceGetFindingCandidateProcedure,
		cerebrov1connect.BootstrapServiceListFindingEvaluationRunsProcedure,
		cerebrov1connect.BootstrapServiceGetFindingEvaluationRunProcedure,
		cerebrov1connect.BootstrapServiceListFindingEvidenceProcedure,
		cerebrov1connect.BootstrapServiceGetFindingEvidenceProcedure,
		cerebrov1connect.BootstrapServiceGetEntityNeighborhoodProcedure,
		cerebrov1connect.BootstrapServiceGetGraphIngestRunProcedure,
		cerebrov1connect.BootstrapServiceListGraphIngestRunsProcedure,
		cerebrov1connect.BootstrapServiceCheckGraphIngestHealthProcedure:
		return scopeCosmoSecurityRead
	case cerebrov1connect.BootstrapServicePromoteFindingCandidateProcedure,
		cerebrov1connect.BootstrapServiceRejectFindingCandidateProcedure:
		return scopeFindingCandidatePromote
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
	if (status == http.StatusUnauthorized || status == http.StatusForbidden) && w.Header().Get("WWW-Authenticate") == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writeAuthErrorForRequest(w http.ResponseWriter, r *http.Request, cfg config.AuthConfig, status int, message string) {
	if cfg.MCPOAuth.Enabled && r != nil && r.URL != nil && r.URL.Path == mcpEndpointPath && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		challenge := `Bearer resource_metadata="` + mcpOAuthResourceMetadataURL(r, cfg) + `", scope="` + scopeCosmoSecurityRead + `"`
		if status == http.StatusForbidden {
			challenge += `, error="insufficient_scope", error_description="MCP access requires the ` + scopeCosmoSecurityRead + ` scope"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	writeAuthError(w, status, message)
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

func (w *accessAuditResponseWriter) Flush() {
	if w == nil {
		return
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
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

func recordAccessAuditRequestedTenant(ctx context.Context, tenantID string) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" || sourceconfig.IsSecretReference(tenantID) {
		return
	}
	result, _ := ctx.Value(accessAuditContextKey{}).(*accessAuditResult)
	if result == nil {
		return
	}
	result.RequestedTenantID = mergeAccessAuditTenantID(result.RequestedTenantID, tenantID)
}

func mergeAccessAuditTenantID(existing string, tenantID string) string {
	existing = strings.TrimSpace(existing)
	tenantID = strings.TrimSpace(tenantID)
	if existing == "" {
		return tenantID
	}
	if tenantID == "" || existing == tenantID {
		return existing
	}
	return "multiple"
}

func emitAccessAuditEvent(r *http.Request, origin requestOrigin, principal authPrincipal, status int, duration time.Duration, outcome string, denialReason string, auditResult *accessAuditResult) {
	if r == nil {
		return
	}
	if auditResult == nil {
		auditResult = &accessAuditResult{}
	}
	route := accessAuditRoute(r)
	operation := accessAuditOperation(r, route)
	effectiveStatusCode := accessAuditEffectiveStatusCode(status, auditResult.ConnectCode)
	attrs := telemetry.Attrs(
		telemetry.Field{Key: "outcome", Value: outcome},
		telemetry.Field{Key: "status", Value: status},
		telemetry.Field{Key: "status_code", Value: status},
		telemetry.Field{Key: "effective_status_code", Value: effectiveStatusCode},
		telemetry.Field{Key: "method", Value: r.Method},
		telemetry.Field{Key: "route", Value: route},
		telemetry.Field{Key: "operation_family", Value: operation.Family},
		telemetry.Field{Key: "operation_type", Value: operation.Type},
		telemetry.Field{Key: "duration_ms", Value: duration.Milliseconds()},
	)
	if remoteIP := strings.TrimSpace(origin.RemoteIP); remoteIP != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "remote_ip", Value: remoteIP})
	}
	if clientIP := strings.TrimSpace(origin.ClientIP); clientIP != "" && clientIP != strings.TrimSpace(origin.RemoteIP) {
		attrs = attrs.WithField(telemetry.Field{Key: "client_ip", Value: clientIP})
	}
	if requestID := accessAuditRequestID(r); requestID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "request_id", Value: requestID})
	}
	if operation.SensitiveAction {
		attrs = attrs.WithField(telemetry.Field{Key: "sensitive_action", Value: true})
	}
	requestedTenantID := firstNonEmpty(auditResult.RequestedTenantID, requestTenantHint(r))
	principalTenantID := strings.TrimSpace(principal.TenantID)
	if tenantID := firstNonEmpty(requestedTenantID, principalTenantID); tenantID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "tenant_id", Value: tenantID})
	}
	if effectiveTenantID := firstNonEmpty(principalTenantID, requestedTenantID); effectiveTenantID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "effective_tenant_id", Value: effectiveTenantID})
	}
	if requestedTenantID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "requested_tenant_id", Value: requestedTenantID})
	}
	if principalTenantID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "principal_tenant_id", Value: principalTenantID})
	}
	if requestedTenantID != "" && principalTenantID != "" && requestedTenantID != principalTenantID {
		attrs = attrs.WithField(telemetry.Field{Key: "tenant_mismatch", Value: true})
	}
	if principal.Name != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "principal", Value: principal.Name})
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
	if principal.DeviceID != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "device_id", Value: principal.DeviceID})
	}
	if principal.AssuranceLevel != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "assurance_level", Value: principal.AssuranceLevel})
	}
	if principal.RiskLevel != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "risk_level", Value: principal.RiskLevel})
		attrs = attrs.WithField(telemetry.Field{Key: "risk_score", Value: principal.RiskScore})
	}
	if auditResult.ConnectCode != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "connect_code", Value: auditResult.ConnectCode})
	}
	if denialReason != "" {
		attrs = attrs.WithField(telemetry.Field{Key: "denial_reason", Value: denialReason})
	}
	telemetry.Event(r.Context(), "cerebro.api.access", attrs)
}

func accessAuditEffectiveStatusCode(status int, connectCode string) int {
	switch strings.ToLower(strings.TrimSpace(connectCode)) {
	case "":
		return status
	case "unauthenticated":
		return http.StatusUnauthorized
	case "permission_denied":
		return http.StatusForbidden
	case "aborted", "already_exists", "failed_precondition":
		return http.StatusConflict
	case "invalid_argument", "out_of_range":
		return http.StatusBadRequest
	case "not_found":
		return http.StatusNotFound
	case "unavailable":
		return http.StatusServiceUnavailable
	case "internal", "unknown", "data_loss":
		return http.StatusInternalServerError
	default:
		if status >= 400 {
			return status
		}
		return http.StatusInternalServerError
	}
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

func accessAuditClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	remoteIP := net.ParseIP(accessAuditRemoteIP(r.RemoteAddr))
	if remoteIP == nil || !accessAuditTrustsForwardedFor(remoteIP) {
		return ""
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue
		}
		if accessAuditTrustsForwardedFor(ip) {
			continue
		}
		return ip.String()
	}
	return ""
}

func accessAuditTrustsForwardedFor(remoteIP net.IP) bool {
	return remoteIP != nil && (remoteIP.IsLoopback() || remoteIP.IsPrivate() || remoteIP.IsLinkLocalUnicast())
}

func accessAuditRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, header := range []string{"X-Request-ID", "X-Correlation-ID"} {
		if requestID := sanitizeAccessAuditIdentifier(r.Header.Get(header)); requestID != "" {
			return requestID
		}
	}
	if traceID := accessAuditAWSRootTraceID(r.Header.Get("X-Amzn-Trace-Id")); traceID != "" {
		return traceID
	}
	if traceID := accessAuditW3CTraceID(r.Header.Get("Traceparent")); traceID != "" {
		return traceID
	}
	return ""
}

func accessAuditAWSRootTraceID(header string) string {
	for _, part := range strings.Split(header, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && key == "Root" {
			return sanitizeAccessAuditIdentifier(value)
		}
	}
	return ""
}

func accessAuditW3CTraceID(header string) string {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) < 2 {
		return ""
	}
	return sanitizeAccessAuditIdentifier(parts[1])
}

func sanitizeAccessAuditIdentifier(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 128 {
		return ""
	}
	for _, ch := range raw {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		switch ch {
		case '-', '_', '.', ':', '/', '=':
			continue
		default:
			return ""
		}
	}
	return raw
}

type accessAuditOperationInfo struct {
	Family          string
	Type            string
	SensitiveAction bool
}

func accessAuditOperation(r *http.Request, route string) accessAuditOperationInfo {
	if r == nil {
		return accessAuditOperationInfo{Family: "unknown", Type: "unknown"}
	}
	procedure := accessAuditConnectProcedure(r.URL.Path)
	if procedure != "" {
		return accessAuditOperationInfo{
			Family:          accessAuditConnectFamily(procedure),
			Type:            accessAuditConnectOperationType(procedure),
			SensitiveAction: accessAuditConnectSensitiveAction(procedure),
		}
	}
	operationType := accessAuditHTTPOperationType(r.Method)
	if route == "GET /api/v1/mcp" || route == "POST /api/v1/mcp" {
		operationType = "read"
	}
	return accessAuditOperationInfo{
		Family:          accessAuditRouteFamily(route),
		Type:            operationType,
		SensitiveAction: operationType == "write" || accessAuditRouteUsesSourceSecret(route),
	}
}

func accessAuditHTTPOperationType(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "read"
	case "":
		return "unknown"
	default:
		return "write"
	}
}

func accessAuditConnectOperationType(procedure string) string {
	name := accessAuditProcedureName(procedure)
	switch {
	case strings.HasPrefix(name, "Get"),
		strings.HasPrefix(name, "List"),
		strings.HasPrefix(name, "Check"),
		strings.HasPrefix(name, "Read"),
		strings.HasPrefix(name, "Discover"):
		return "read"
	default:
		return "write"
	}
}

func accessAuditConnectSensitiveAction(procedure string) bool {
	if accessAuditConnectOperationType(procedure) == "write" {
		return true
	}
	switch accessAuditProcedureName(procedure) {
	case "CheckSource", "DiscoverSource", "ReadSource":
		return true
	default:
		return false
	}
}

func accessAuditConnectFamily(procedure string) string {
	name := accessAuditProcedureName(procedure)
	switch {
	case strings.Contains(name, "SourceRuntime"):
		return "source_runtime"
	case strings.Contains(name, "Source"):
		return "source"
	case strings.Contains(name, "Report"):
		return "report"
	case strings.Contains(name, "FindingEvaluation"):
		return "finding_evaluation"
	case strings.Contains(name, "FindingEvidence"):
		return "finding_evidence"
	case strings.Contains(name, "Finding"):
		return "finding"
	case strings.Contains(name, "Graph"), strings.Contains(name, "EntityNeighborhood"):
		return "graph"
	case strings.Contains(name, "Decision"), strings.Contains(name, "Action"), strings.Contains(name, "Outcome"), strings.Contains(name, "Workflow"):
		return "workflow"
	case strings.Contains(name, "Claim"):
		return "claim"
	case strings.Contains(name, "Health"), strings.Contains(name, "Version"):
		return "health"
	default:
		return "connect"
	}
}

func accessAuditRouteFamily(route string) string {
	route = strings.TrimSpace(route)
	switch {
	case strings.Contains(route, "/platform/devices"), strings.Contains(route, "/.well-known/device-jwks"):
		return "device"
	case strings.Contains(route, "/platform/telemetry"):
		return "telemetry"
	case strings.Contains(route, "/source-runtimes"):
		return "source_runtime"
	case strings.Contains(route, "/sources"):
		return "source"
	case strings.Contains(route, "/report-runs"), strings.Contains(route, "/reports"):
		return "report"
	case strings.Contains(route, "/finding-evaluation-runs"):
		return "finding_evaluation"
	case strings.Contains(route, "/finding-evidence"):
		return "finding_evidence"
	case strings.Contains(route, "/finding-rules"), strings.Contains(route, "/finding-candidates"), strings.Contains(route, "/findings"), strings.Contains(route, "/vulnerability-findings"):
		return "finding"
	case strings.Contains(route, "/grc/"):
		return "grc"
	case strings.Contains(route, "/platform/knowledge"):
		return "platform_knowledge"
	case strings.Contains(route, "/platform/workflow"):
		return "workflow"
	case strings.Contains(route, "/platform/graph"):
		return "graph"
	case strings.Contains(route, "/api/v1/mcp"):
		return "mcp"
	case route == "":
		return "unknown"
	default:
		return "other"
	}
}

func accessAuditRouteUsesSourceSecret(route string) bool {
	return strings.HasSuffix(route, "/check") || strings.HasSuffix(route, "/discover") || strings.HasSuffix(route, "/read")
}

func accessAuditProcedureName(procedure string) string {
	procedure = strings.TrimSpace(procedure)
	if index := strings.LastIndex(procedure, "/"); index >= 0 {
		return procedure[index+1:]
	}
	return procedure
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
	cerebrov1connect.BootstrapServiceGetVersionProcedure:                             {},
	cerebrov1connect.BootstrapServiceCheckHealthProcedure:                            {},
	cerebrov1connect.BootstrapServiceListReportDefinitionsProcedure:                  {},
	cerebrov1connect.BootstrapServiceListFindingRulesProcedure:                       {},
	cerebrov1connect.BootstrapServiceRunReportProcedure:                              {},
	cerebrov1connect.BootstrapServiceGetReportRunProcedure:                           {},
	cerebrov1connect.BootstrapServiceListSourcesProcedure:                            {},
	cerebrov1connect.BootstrapServiceCheckSourceProcedure:                            {},
	cerebrov1connect.BootstrapServiceDiscoverSourceProcedure:                         {},
	cerebrov1connect.BootstrapServiceReadSourceProcedure:                             {},
	cerebrov1connect.BootstrapServicePutSourceRuntimeProcedure:                       {},
	cerebrov1connect.BootstrapServiceGetSourceRuntimeProcedure:                       {},
	cerebrov1connect.BootstrapServiceSyncSourceRuntimeProcedure:                      {},
	cerebrov1connect.BootstrapServiceWriteClaimsProcedure:                            {},
	cerebrov1connect.BootstrapServiceListClaimsProcedure:                             {},
	cerebrov1connect.BootstrapServiceListFindingsProcedure:                           {},
	cerebrov1connect.BootstrapServiceGetFindingProcedure:                             {},
	cerebrov1connect.BootstrapServiceListFindingCandidatesProcedure:                  {},
	cerebrov1connect.BootstrapServiceGetFindingCandidateProcedure:                    {},
	cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingCandidatesProcedure: {},
	cerebrov1connect.BootstrapServicePromoteFindingCandidateProcedure:                {},
	cerebrov1connect.BootstrapServiceRejectFindingCandidateProcedure:                 {},
	cerebrov1connect.BootstrapServiceResolveFindingProcedure:                         {},
	cerebrov1connect.BootstrapServiceSuppressFindingProcedure:                        {},
	cerebrov1connect.BootstrapServiceAssignFindingProcedure:                          {},
	cerebrov1connect.BootstrapServiceSetFindingDueDateProcedure:                      {},
	cerebrov1connect.BootstrapServiceAddFindingNoteProcedure:                         {},
	cerebrov1connect.BootstrapServiceLinkFindingTicketProcedure:                      {},
	cerebrov1connect.BootstrapServiceListFindingEvaluationRunsProcedure:              {},
	cerebrov1connect.BootstrapServiceGetFindingEvaluationRunProcedure:                {},
	cerebrov1connect.BootstrapServiceListFindingEvidenceProcedure:                    {},
	cerebrov1connect.BootstrapServiceGetFindingEvidenceProcedure:                     {},
	cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingRulesProcedure:      {},
	cerebrov1connect.BootstrapServiceEvaluateSourceRuntimeFindingsProcedure:          {},
	cerebrov1connect.BootstrapServiceWriteDecisionProcedure:                          {},
	cerebrov1connect.BootstrapServiceWriteActionProcedure:                            {},
	cerebrov1connect.BootstrapServiceWriteOutcomeProcedure:                           {},
	cerebrov1connect.BootstrapServiceReplayWorkflowEventsProcedure:                   {},
	cerebrov1connect.BootstrapServiceGetEntityNeighborhoodProcedure:                  {},
	cerebrov1connect.BootstrapServiceRunGraphIngestRuntimeProcedure:                  {},
	cerebrov1connect.BootstrapServiceGetGraphIngestRunProcedure:                      {},
	cerebrov1connect.BootstrapServiceListGraphIngestRunsProcedure:                    {},
	cerebrov1connect.BootstrapServiceCheckGraphIngestHealthProcedure:                 {},
}

func fallbackAccessAuditRoute(method string, path string) string {
	prefix := strings.TrimSpace(method) + " "
	switch {
	case path == "/api/v1/mcp":
		return prefix + "/api/v1/mcp"
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
	case strings.HasPrefix(path, "/finding-candidates/"):
		return prefix + fallbackFindingCandidateRoute(path)
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
		case "/grc/dashboard", "/grc/ask", "/grc/findings", "/grc/controls", "/grc/evidence":
			return prefix + path
		default:
			return prefix + "/grc/{subresource}"
		}
	case strings.HasPrefix(path, "/platform/graph/ingest-runs/"):
		return prefix + "/platform/graph/ingest-runs/{runID}"
	case path == "/endpoint-vulnerability-findings":
		return prefix + "/endpoint-vulnerability-findings"
	case strings.HasPrefix(path, "/platform/endpoints/") && strings.HasSuffix(path, "/vulnerability-findings"):
		return prefix + "/platform/endpoints/{deviceKey}/vulnerability-findings"
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
	case "sync", "graph-ingest-runs", "claims", "findings", "finding-candidates", "finding-evidence", "finding-evaluation-runs":
		return "/source-runtimes/{runtimeID}/" + parts[1]
	case "finding-rules/evaluate":
		return "/source-runtimes/{runtimeID}/finding-rules/evaluate"
	case "finding-candidates/evaluate":
		return "/source-runtimes/{runtimeID}/finding-candidates/evaluate"
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

func fallbackFindingCandidateRoute(path string) string {
	suffix := strings.TrimPrefix(path, "/finding-candidates/")
	if !strings.Contains(suffix, "/") {
		return "/finding-candidates/{candidateID}"
	}
	parts := strings.SplitN(suffix, "/", 2)
	switch parts[1] {
	case "promote", "reject":
		return "/finding-candidates/{candidateID}/" + parts[1]
	default:
		return "/finding-candidates/{candidateID}/{subresource}"
	}
}

func isKnownStaticAccessPath(path string) bool {
	return httpRouteStaticAccessPathKnown(path)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
