// Package identitysso serves the /platform/identity routes that back web
// console SSO: connections, policy, sessions, SCIM tokens, the SCIM 2.0
// protocol, and directory views. Domain rules live in internal/identitysso.
package identitysso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

const (
	// TenantHeader optionally selects the tenant when tenant_id is not in the query.
	TenantHeader = "X-Cerebro-Tenant"
	// SCIMTokenHeader carries the raw SCIM bearer token forwarded by the web server.
	SCIMTokenHeader = "X-Cerebro-SCIM-Token" //nolint:gosec // Header name, not a credential value.
	// DefaultTenantID is used when neither the request nor the principal selects a tenant.
	DefaultTenantID = "default"

	maxBodyBytes      = 1 << 20
	maxListLimit      = 500
	defaultListLimit  = 100
	maxQueryLength    = 256
	sessionListLimit  = 500
	errorCodeNotFound = "not_found"
)

var (
	errStoreUnavailable = errors.New("identity_store_unavailable")
	errTenantForbidden  = errors.New("tenant_forbidden")
)

// TenantResolver returns the authorized tenant for a requested tenant ID. Any
// error it returns is treated as an authorization failure.
type TenantResolver func(context.Context, string) (string, error)

// ActorResolver returns the authenticated principal's display identity.
type ActorResolver func(context.Context) string

// Handler serves the /platform/identity routes.
type Handler struct {
	store     ports.IdentitySSOStore
	resolve   TenantResolver
	actor     ActorResolver
	now       func() time.Time
	bootstrap *sso.Bootstrap
}

// NewHandler builds a handler from the optional IdentitySSOStore capability.
// A missing capability returns 503 from every route.
func NewHandler(store ports.StateStore, resolve TenantResolver, actor ActorResolver) Handler {
	ssoStore, _ := store.(ports.IdentitySSOStore)
	if ssoStore != nil {
		if value := reflect.ValueOf(ssoStore); value.Kind() == reflect.Pointer && value.IsNil() {
			ssoStore = nil
		}
	}
	return Handler{store: ssoStore, resolve: resolve, actor: actor, now: func() time.Time { return time.Now().UTC() }}
}

// WithBootstrap marks the stack-configured connection and policy as managed so
// admin writes cannot drift them from configuration.
func (h Handler) WithBootstrap(bootstrap *sso.Bootstrap) Handler {
	h.bootstrap = bootstrap
	return h
}

func (h Handler) clock() time.Time {
	if h.now == nil {
		return time.Now().UTC()
	}
	return h.now().UTC()
}

func (h Handler) tenant(r *http.Request) (string, error) {
	if h.store == nil {
		return "", errStoreUnavailable
	}
	requested := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	header := strings.TrimSpace(r.Header.Get(TenantHeader))
	if requested != "" && header != "" && requested != header {
		return "", errTenantForbidden
	}
	if requested == "" {
		requested = header
	}
	tenantID := requested
	if h.resolve != nil {
		resolved, err := h.resolve(r.Context(), requested)
		if err != nil {
			return "", fmt.Errorf("%w: %w", errTenantForbidden, err)
		}
		tenantID = strings.TrimSpace(resolved)
	}
	if tenantID == "" {
		tenantID = DefaultTenantID
	}
	return tenantID, nil
}

func (h Handler) actorFor(ctx context.Context, fallback string) string {
	if fallback = strings.TrimSpace(fallback); fallback != "" {
		return fallback
	}
	if h.actor != nil {
		return strings.TrimSpace(h.actor(ctx))
	}
	return ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, r.Body, maxBodyBytes), maxBodyBytes+1))
	if err != nil {
		return sso.Invalid("request body is too large or unreadable")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return sso.Invalid("request body must be valid JSON")
	}
	return nil
}

type errorBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

func writeError(w http.ResponseWriter, err error) {
	status, body := errorResponse(err)
	writeJSON(w, status, body)
}

func errorResponse(err error) (int, errorBody) {
	switch {
	case errors.Is(err, sso.ErrInvalid):
		return http.StatusBadRequest, errorBody{Error: strings.TrimPrefix(err.Error(), sso.ErrInvalid.Error()+": ")}
	case errors.Is(err, ports.ErrSSOConnectionLimit):
		return http.StatusBadRequest, errorBody{Error: fmt.Sprintf("at most %d connections are allowed", sso.MaxConnections)}
	case errors.Is(err, errTenantForbidden):
		return http.StatusForbidden, errorBody{Error: errTenantForbidden.Error()}
	case errors.Is(err, ports.ErrSSOConnectionNotFound), errors.Is(err, ports.ErrSSOSessionNotFound),
		errors.Is(err, ports.ErrSCIMTokenNotFound), errors.Is(err, ports.ErrDirectoryUserNotFound),
		errors.Is(err, ports.ErrDirectoryGroupNotFound):
		return http.StatusNotFound, errorBody{Error: errorCodeNotFound}
	case errors.Is(err, ports.ErrSSODomainConflict):
		return http.StatusConflict, errorBody{Error: "domain_in_use", Detail: strings.TrimPrefix(err.Error(), ports.ErrSSODomainConflict.Error()+": ")}
	case errors.Is(err, sso.ErrConnectionNotTested), errors.Is(err, sso.ErrNoActiveConnection),
		errors.Is(err, sso.ErrConnectionInactive), errors.Is(err, sso.ErrLastActiveEnforced), errors.Is(err, sso.ErrJITDisabled):
		return http.StatusConflict, errorBody{Error: conflictCode(err)}
	case errors.Is(err, sso.ErrBootstrapManaged):
		return http.StatusConflict, errorBody{Error: sso.ErrBootstrapManaged.Error(), Detail: "managed by stack configuration"}
	case errors.Is(err, ports.ErrSSOSessionExists):
		return http.StatusConflict, errorBody{Error: "session_exists"}
	case errors.Is(err, ports.ErrDirectoryConflict):
		return http.StatusConflict, errorBody{Error: "directory_conflict"}
	case errors.Is(err, errStoreUnavailable):
		return http.StatusServiceUnavailable, errorBody{Error: errStoreUnavailable.Error()}
	default:
		return http.StatusInternalServerError, errorBody{Error: "internal_error"}
	}
}

func conflictCode(err error) string {
	for _, candidate := range []error{sso.ErrConnectionNotTested, sso.ErrNoActiveConnection, sso.ErrConnectionInactive, sso.ErrLastActiveEnforced, sso.ErrJITDisabled} {
		if errors.Is(err, candidate) {
			return candidate.Error()
		}
	}
	return "conflict"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeEncoded(w, status, "application/json", value)
}

func writeEncoded(w http.ResponseWriter, status int, contentType string, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}
