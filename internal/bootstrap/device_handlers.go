package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/deviceauth"
	"github.com/writer/cerebro/internal/deviceauth/attestation"
	"github.com/writer/cerebro/internal/deviceauth/risk"
	"github.com/writer/cerebro/internal/endpointtelemetry"
)

// buildDeviceAuthService wires the deviceauth.Service against the configured
// store and signing-key material. It returns nil if the surface is disabled
// or the runtime dependencies are missing.
func buildDeviceAuthService(cfg config.DeviceAuthConfig, store deviceauth.Store, dpop *deviceauth.DPoPVerifier, scorer *risk.Scorer, observations risk.ObservationStore) (*deviceauth.Service, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if store == nil {
		return nil, errors.New("device-auth requires a configured state store")
	}
	signingKeys := make([]deviceauth.SigningKey, 0, len(cfg.SigningKeys))
	for _, key := range cfg.SigningKeys {
		pub, err := deviceauth.DecodePEMPublicKey(key.PublicPEM)
		if err != nil {
			return nil, fmt.Errorf("device-auth public key %q: %w", key.KID, err)
		}
		entry := deviceauth.SigningKey{KID: key.KID, Public: pub}
		if key.PrivatePEM != "" {
			priv, err := deviceauth.DecodePEMPrivateKey(key.PrivatePEM)
			if err != nil {
				return nil, fmt.Errorf("device-auth private key %q: %w", key.KID, err)
			}
			entry.Private = priv
		}
		signingKeys = append(signingKeys, entry)
	}
	currentKID := strings.TrimSpace(cfg.CurrentKID)
	if currentKID == "" {
		return nil, errors.New("device-auth current kid is required")
	}
	signingKeys = orderCurrentFirst(signingKeys, currentKID)
	if len(signingKeys[0].Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("device-auth current kid %q is missing private_pem; external/KMS signing is not supported by this bootstrap path", currentKID)
	}
	signer, err := deviceauth.NewLocalSigner(signingKeys)
	if err != nil {
		return nil, fmt.Errorf("device-auth signer: %w", err)
	}
	verifyKeys := make([]deviceauth.SigningKey, 0, len(signingKeys))
	for _, key := range signingKeys {
		verifyKeys = append(verifyKeys, deviceauth.SigningKey{KID: key.KID, Public: key.Public})
	}
	keyset := &deviceauth.KeySet{Keys: verifyKeys}
	issuer, err := deviceauth.NewJWTIssuer(deviceauth.IssuerConfig{
		Issuer:    cfg.Issuer,
		Audience:  cfg.Audience,
		AccessTTL: cfg.AccessTTL,
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("device-auth issuer: %w", err)
	}
	verifier, err := deviceauth.NewJWTVerifier(deviceauth.VerifierConfig{
		Issuer:    cfg.Issuer,
		Audience:  cfg.Audience,
		ClockSkew: cfg.ClockSkew,
	}, keyset)
	if err != nil {
		return nil, fmt.Errorf("device-auth verifier: %w", err)
	}
	registry, err := buildAttestationRegistry(cfg)
	if err != nil {
		return nil, fmt.Errorf("device-auth attestation: %w", err)
	}
	return deviceauth.NewService(deviceauth.ServiceConfig{
		Issuer:            cfg.Issuer,
		Audience:          cfg.Audience,
		AccessTTL:         cfg.AccessTTL,
		RefreshTTL:        cfg.RefreshTTL,
		BootstrapTokenTTL: cfg.BootstrapTokenTTL,
		IdempotencyTTL:    cfg.IdempotencyTTL,
		ClockSkew:         cfg.ClockSkew,
		Attestations:      registry,
		DPoP:              dpop,
		Risk:              scorer,
		Observations:      observations,
	}, store, issuer, verifier, keyset)
}

// buildAttestationRegistry constructs the attestation registry from
// configuration. When the operator has not configured Apple or TPM
// verifiers, the registry runs in non-required mode -- enroll requests
// without an attestation statement get a software-assurance result, but
// still need device_key or an existing binding before refresh tokens are
// issued.
func buildAttestationRegistry(cfg config.DeviceAuthConfig) (*attestation.Registry, error) {
	verifiers := make([]attestation.Verifier, 0, 2)
	if cfg.Attestation.Apple.TeamID != "" && len(cfg.Attestation.Apple.BundleIDs) > 0 {
		v, err := attestation.NewAppleAppAttestVerifier(attestation.AppleConfig{
			TeamID:    cfg.Attestation.Apple.TeamID,
			BundleIDs: cfg.Attestation.Apple.BundleIDs,
		})
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, v)
	}
	if cfg.Attestation.Required && len(verifiers) == 0 {
		return nil, errors.New("required attestation has no configured verifier backend")
	}
	return attestation.NewRegistry(cfg.Attestation.Required, verifiers...), nil
}

func orderCurrentFirst(keys []deviceauth.SigningKey, currentKID string) []deviceauth.SigningKey {
	out := make([]deviceauth.SigningKey, 0, len(keys))
	for _, key := range keys {
		if key.KID == currentKID {
			out = append([]deviceauth.SigningKey{key}, out...)
		} else {
			out = append(out, key)
		}
	}
	return out
}

type deviceAuthHTTPHandler struct {
	service      *deviceauth.Service
	enrollLimit  *deviceauth.TokenBucket
	tokenLimit   *deviceauth.TokenBucket
	originConfig config.RequestOriginConfig
	now          func() time.Time
}

func newDeviceAuthHTTPHandler(service *deviceauth.Service, cfg config.DeviceAuthConfig, originConfig config.RequestOriginConfig) *deviceAuthHTTPHandler {
	return &deviceAuthHTTPHandler{
		service:      service,
		enrollLimit:  deviceauth.NewTokenBucket(cfg.EnrollPerIPRatePerSecond, cfg.EnrollPerIPBurst),
		tokenLimit:   deviceauth.NewTokenBucket(cfg.TokenPerDeviceRatePerSecond, cfg.TokenPerDeviceBurst),
		originConfig: originConfig,
		now:          time.Now,
	}
}

type enrollRequestBody struct {
	BootstrapToken string `json:"bootstrap_token"`
	HardwareUUID   string `json:"hardware_uuid"`
	SerialNumber   string `json:"serial_number,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	OSType         string `json:"os_type,omitempty"`
	OSVersion      string `json:"os_version,omitempty"`
	AgentVersion   string `json:"agent_version,omitempty"`
	// Attestation is the base64-encoded device-bound proof: an Apple App
	// Attest CBOR attestationObject on macOS or a TPM 2.0 quote bundle on
	// Windows. Required when CEREBRO_DEVICE_AUTH_ATTESTATION_REQUIRED=true.
	Attestation string `json:"attestation,omitempty"`
	// DeviceKey is the agent-supplied public JWK that the agent will sign
	// DPoP proofs with. It is required unless verified attestation or an
	// existing device record supplies the binding. cnf.jkt on the access
	// token is set to the RFC 7638 thumbprint of this key, and every
	// refresh and DPoP-protected resource call must carry a proof signed by
	// the matching private key. Allowed kty/crv values: EC P-256, EC
	// P-384, OKP Ed25519. RSA is rejected. Maximum encoded size: 4 KiB.
	DeviceKey json.RawMessage `json:"device_key,omitempty"`
}

type tokenResponseBody struct {
	AccessToken       string   `json:"access_token"`
	TokenType         string   `json:"token_type"`
	ExpiresIn         int64    `json:"expires_in"`
	RefreshToken      string   `json:"refresh_token,omitempty"`
	RefreshExpires    string   `json:"refresh_expires_at,omitempty"`
	Scopes            []string `json:"scopes"`
	DeviceID          string   `json:"device_id,omitempty"`
	AssuranceLevel    string   `json:"assurance_level,omitempty"`
	AttestationVendor string   `json:"attestation_vendor,omitempty"`
	RiskScore         int      `json:"risk_score,omitempty"`
	RiskLevel         string   `json:"risk_level,omitempty"`
}

type tokenRequestBody struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
}

type bootstrapTokenRequestBody struct {
	HardwareUUID string   `json:"hardware_uuid"`
	TenantID     string   `json:"tenant_id,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	TTLSeconds   int64    `json:"ttl_seconds,omitempty"`
}

type bootstrapTokenResponseBody struct {
	TokenID   string `json:"token_id"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type revokeRequestBody struct {
	Reason string `json:"reason,omitempty"`
}

func (h *deviceAuthHTTPHandler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		writeDeviceAuthError(w, http.StatusServiceUnavailable, "device_auth_disabled", "device-auth is not enabled")
		return
	}
	origin := resolveRequestOrigin(r, h.originConfig)
	clientIP := firstNonEmpty(origin.ClientIP, "unknown")
	if !h.enrollLimit.Allow(clientIP) {
		writeDeviceAuthError(w, http.StatusTooManyRequests, "rate_limited", "too many enrollment attempts")
		return
	}
	var body enrollRequestBody
	if err := readJSONRequest(r, &body); err != nil {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	response, err := h.service.Enroll(r.Context(), deviceauth.EnrollRequest{
		BootstrapToken: body.BootstrapToken,
		HardwareUUID:   body.HardwareUUID,
		SerialNumber:   body.SerialNumber,
		Hostname:       body.Hostname,
		OSType:         body.OSType,
		OSVersion:      body.OSVersion,
		AgentVersion:   body.AgentVersion,
		Attestation:    body.Attestation,
		DeviceJWK:      body.DeviceKey,
		RemoteIP:       net.ParseIP(clientIP),
	})
	if err != nil {
		writeDeviceAuthServiceError(w, err)
		return
	}
	setNoStoreHeaders(w)
	writeJSON(w, http.StatusOK, tokenResponseBody{
		AccessToken:       response.AccessToken,
		TokenType:         response.TokenType,
		ExpiresIn:         int64(time.Until(response.AccessExpires).Seconds()),
		RefreshToken:      response.RefreshToken,
		RefreshExpires:    response.RefreshExpires.UTC().Format(time.RFC3339),
		Scopes:            response.Scopes,
		DeviceID:          response.DeviceID,
		AssuranceLevel:    response.AssuranceLevel,
		AttestationVendor: response.AttestationVendor,
	})
}

// setNoStoreHeaders sets the response headers required by RFC 6749 §5.1 for
// any endpoint that returns a token. The headers also defeat any
// well-meaning intermediate cache that might otherwise hold an access /
// refresh token long enough to leak it across requests.
func setNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
}

func (h *deviceAuthHTTPHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		writeDeviceAuthError(w, http.StatusServiceUnavailable, "device_auth_disabled", "device-auth is not enabled")
		return
	}
	var body tokenRequestBody
	if err := readJSONRequest(r, &body); err != nil {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	origin := resolveRequestOrigin(r, h.originConfig)
	requestIP := firstNonEmpty(origin.ClientIP, "unknown")
	limitKey := requestIP
	if deviceKey, err := h.service.RefreshTokenRateLimitKey(r.Context(), body.RefreshToken); err == nil && deviceKey != "" {
		limitKey = deviceKey
	}
	if !h.tokenLimit.Allow(limitKey) {
		writeDeviceAuthError(w, http.StatusTooManyRequests, "rate_limited", "too many token requests")
		return
	}
	dpopProof := strings.TrimSpace(r.Header.Get("DPoP"))
	response, err := h.service.IssueToken(r.Context(), deviceauth.TokenRequest{
		GrantType:    body.GrantType,
		RefreshToken: body.RefreshToken,
		DPoPProof:    dpopProof,
		HTTPMethod:   r.Method,
		HTTPURL:      origin.PublicURL,
		RemoteIP:     net.ParseIP(requestIP),
	})
	if err != nil {
		writeDeviceAuthServiceError(w, err)
		return
	}
	setNoStoreHeaders(w)
	writeJSON(w, http.StatusOK, tokenResponseBody{
		AccessToken:    response.AccessToken,
		TokenType:      response.TokenType,
		ExpiresIn:      int64(time.Until(response.AccessExpires).Seconds()),
		RefreshToken:   response.RefreshToken,
		RefreshExpires: response.RefreshExpires.UTC().Format(time.RFC3339),
		Scopes:         response.Scopes,
		RiskScore:      response.RiskScore,
		RiskLevel:      response.RiskLevel,
	})
}

func (h *deviceAuthHTTPHandler) handleIssueBootstrapToken(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		writeDeviceAuthError(w, http.StatusServiceUnavailable, "device_auth_disabled", "device-auth is not enabled")
		return
	}
	var body bootstrapTokenRequestBody
	if err := readJSONRequest(r, &body); err != nil {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tenantID := strings.TrimSpace(body.TenantID)
	if tenantID == "" {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
			tenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if tenantID == "" {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", "tenant_id is required")
		return
	}
	if err := authorizeTenantID(r.Context(), tenantID); err != nil {
		writeDeviceAuthError(w, http.StatusForbidden, "tenant_forbidden", err.Error())
		return
	}
	ttl := time.Duration(body.TTLSeconds) * time.Second
	issuedBy := principalNameFromContext(r)
	response, err := h.service.IssueBootstrapToken(r.Context(), deviceauth.IssueBootstrapTokenRequest{
		HardwareUUID: body.HardwareUUID,
		TenantID:     tenantID,
		Scopes:       body.Scopes,
		TTL:          ttl,
		IssuedBy:     issuedBy,
	})
	if err != nil {
		writeDeviceAuthServiceError(w, err)
		return
	}
	setNoStoreHeaders(w)
	writeJSON(w, http.StatusCreated, bootstrapTokenResponseBody{
		TokenID:   response.TokenID,
		Token:     response.Token,
		ExpiresAt: response.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *deviceAuthHTTPHandler) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		writeDeviceAuthError(w, http.StatusServiceUnavailable, "device_auth_disabled", "device-auth is not enabled")
		return
	}
	deviceID := strings.TrimSpace(r.PathValue("deviceID"))
	if deviceID == "" {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", "device_id is required")
		return
	}
	var body revokeRequestBody
	if r.ContentLength > 0 {
		if err := readJSONRequest(r, &body); err != nil {
			writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
	}
	device, err := h.service.LookupDevice(r.Context(), deviceID)
	if err != nil {
		writeDeviceAuthServiceError(w, err)
		return
	}
	if err := authorizeTenantScopeRequired(r.Context(), device.TenantID); err != nil {
		writeDeviceAuthServiceError(w, deviceauth.ErrDeviceNotFound)
		return
	}
	if err := h.service.Revoke(r.Context(), deviceID, body.Reason); err != nil {
		writeDeviceAuthServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "device_id": deviceID})
}

func (h *deviceAuthHTTPHandler) handleIngestTelemetry(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.service == nil {
		writeDeviceAuthError(w, http.StatusServiceUnavailable, "device_auth_disabled", "device-auth is not enabled")
		return
	}
	auth, ok := r.Context().Value(authContextKey{}).(authContext)
	if !ok || strings.TrimSpace(auth.principal.DeviceID) == "" {
		writeDeviceAuthError(w, http.StatusForbidden, "device_required", "telemetry ingest requires a device JWT")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, deviceauth.MaxIngestBodyBytes+1))
	if err != nil {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(body) > deviceauth.MaxIngestBodyBytes {
		writeDeviceAuthError(w, http.StatusRequestEntityTooLarge, "request_too_large", "telemetry body exceeds limit")
		return
	}
	if err := validateTelemetryBody(body); err != nil {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if _, err := endpointtelemetry.Normalize(body, endpointtelemetry.Principal{
		TenantID:     auth.principal.TenantID,
		DeviceID:     auth.principal.DeviceID,
		HardwareUUID: auth.principal.HardwareUUID,
	}, time.Now()); err != nil {
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_telemetry", err.Error())
		return
	}
	idempotencyKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	result, err := h.service.IngestTelemetry(r.Context(), deviceauth.IngestPayload{
		DeviceID:       auth.principal.DeviceID,
		IdempotencyKey: idempotencyKey,
		Body:           body,
	})
	if err != nil {
		writeDeviceAuthServiceError(w, err)
		return
	}
	if result.Cached {
		w.Header().Set("Idempotent-Replayed", "true")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.Status)
	_, _ = w.Write(result.Body)
}

func validateTelemetryBody(body []byte) error {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("telemetry body must be a JSON object: %w", err)
	}
	if payload == nil {
		return errors.New("telemetry body must be a JSON object")
	}
	return nil
}

func (h *deviceAuthHTTPHandler) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	if h == nil || h.service == nil {
		writeDeviceAuthError(w, http.StatusServiceUnavailable, "device_auth_disabled", "device-auth is not enabled")
		return
	}
	doc := deviceauth.EncodeJWKS(h.service.KeySet())
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(doc)
}

func readJSONRequest(r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, deviceauth.MaxIngestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	return nil
}

func writeDeviceAuthError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": message})
}

func writeDeviceAuthServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, deviceauth.ErrInvalidRequest):
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case errors.Is(err, deviceauth.ErrBootstrapTokenNotFound),
		errors.Is(err, deviceauth.ErrBootstrapTokenConsumed),
		errors.Is(err, deviceauth.ErrBootstrapTokenExpired),
		errors.Is(err, deviceauth.ErrBootstrapTokenMismatch):
		writeDeviceAuthError(w, http.StatusUnauthorized, "invalid_bootstrap_token", err.Error())
	case errors.Is(err, deviceauth.ErrRefreshNotFound),
		errors.Is(err, deviceauth.ErrRefreshExpired):
		writeDeviceAuthError(w, http.StatusUnauthorized, "invalid_refresh_token", err.Error())
	case errors.Is(err, deviceauth.ErrRefreshReplay):
		writeDeviceAuthError(w, http.StatusUnauthorized, "refresh_token_replayed", err.Error())
	case errors.Is(err, deviceauth.ErrDeviceNotFound):
		writeDeviceAuthError(w, http.StatusNotFound, "device_not_found", err.Error())
	case errors.Is(err, deviceauth.ErrDeviceInactive):
		writeDeviceAuthError(w, http.StatusForbidden, "device_inactive", err.Error())
	case errors.Is(err, deviceauth.ErrIdempotencyConflict):
		writeDeviceAuthError(w, http.StatusConflict, "idempotency_conflict", err.Error())
	case errors.Is(err, attestation.ErrAttestationRequired):
		writeDeviceAuthError(w, http.StatusBadRequest, "attestation_required", err.Error())
	case errors.Is(err, attestation.ErrUnsupportedFormat):
		writeDeviceAuthError(w, http.StatusBadRequest, "unsupported_attestation", err.Error())
	case errors.Is(err, attestation.ErrInvalidStatement),
		errors.Is(err, attestation.ErrChainInvalid),
		errors.Is(err, attestation.ErrNonceMismatch),
		errors.Is(err, attestation.ErrKeyIDMismatch),
		errors.Is(err, attestation.ErrUnsupportedVendor):
		writeDeviceAuthError(w, http.StatusBadRequest, "invalid_attestation", err.Error())
	case errors.Is(err, deviceauth.ErrDPoPMissing):
		writeDeviceAuthError(w, http.StatusUnauthorized, "dpop_required", err.Error())
	case errors.Is(err, deviceauth.ErrDPoPVerifierUnavailable):
		writeDeviceAuthError(w, http.StatusServiceUnavailable, "dpop_unavailable", err.Error())
	case errors.Is(err, deviceauth.ErrDPoPMalformed),
		errors.Is(err, deviceauth.ErrDPoPInvalidHeader),
		errors.Is(err, deviceauth.ErrDPoPInvalidJWK):
		writeDeviceAuthError(w, http.StatusUnauthorized, "dpop_malformed", err.Error())
	case errors.Is(err, deviceauth.ErrDPoPInvalidSignature),
		errors.Is(err, deviceauth.ErrDPoPMismatch),
		errors.Is(err, deviceauth.ErrDPoPExpired),
		errors.Is(err, deviceauth.ErrDPoPFromFuture),
		errors.Is(err, deviceauth.ErrDPoPMissingJTI),
		errors.Is(err, deviceauth.ErrDPoPReplay),
		errors.Is(err, deviceauth.ErrDPoPJKTMismatch):
		writeDeviceAuthError(w, http.StatusUnauthorized, "dpop_invalid", err.Error())
	default:
		writeDeviceAuthError(w, http.StatusInternalServerError, "internal_error", "device-auth internal error")
	}
}

func remoteIPForRateLimit(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	return firstNonEmpty(resolveRequestOrigin(r, config.RequestOriginConfig{}).ClientIP, "unknown")
}

func principalNameFromContext(r *http.Request) string {
	if r == nil {
		return ""
	}
	auth, ok := r.Context().Value(authContextKey{}).(authContext)
	if !ok {
		return ""
	}
	return strings.TrimSpace(auth.principal.Name)
}
