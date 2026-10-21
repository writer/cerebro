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
	// SCIMTokenHeader carries the raw SCIM bearer token forwarded by the web server.
	SCIMTokenHeader = "X-Cerebro-SCIM-Token" //nolint:gosec // Header name, not a credential value.
	// DefaultTenantID is used when the calling credential carries no tenant.
	DefaultTenantID = "default"

	maxBodyBytes      = 1 << 20
	maxListLimit      = 500
	defaultListLimit  = 100
	maxQueryLength    = 256
	sessionListLimit  = 500
	errorCodeNotFound = "not_found"
)

var (
	// errStoreUnavailable maps to 404 so callers can tell a deployment without
	// identity SSO apart from a transient outage.
	errStoreUnavailable = errors.New("identity_sso_unavailable")
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
// A missing capability returns 404 identity_sso_unavailable from every route.
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
	// The identity API always acts on the calling credential's own tenant.
	// Request selectors (tenant_id, X-Cerebro-Tenant) are ignored so a value
	// forwarded from a browser or IdP cannot point admin, session, or SCIM
	// calls at a different store partition.
	tenantID := ""
	if h.resolve != nil {
		resolved, err := h.resolve(r.Context(), "")
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

// principal returns the authenticated caller. Body-supplied actors are kept
// separately as on-behalf-of values and never replace it.
func (h Handler) principal(ctx context.Context) string {
	if h.actor == nil {
		return ""
	}
	return strings.TrimSpace(h.actor(ctx))
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

// errorBody carries a stable machine code in Code. Error repeats the code,
// except for 400 responses where it holds the validation message.
type errorBody struct {
	Error  string `json:"error"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

func codeBody(code string) errorBody {
	return errorBody{Error: code, Code: code}
}

func writeError(w http.ResponseWriter, err error) {
	status, body := errorResponse(err)
	writeJSON(w, status, body)
}

// codedErrors map to their own Error() text as the response code.
var codedErrors = []struct {
	err    error
	status int
}{
	{sso.ErrConnectionNotTested, http.StatusConflict},
	{sso.ErrNoActiveConnection, http.StatusConflict},
	{sso.ErrConnectionInactive, http.StatusConflict},
	{sso.ErrLastActiveEnforced, http.StatusConflict},
	{sso.ErrJITDisabled, http.StatusConflict},
	{sso.ErrSubjectMismatch, http.StatusConflict},
	{ports.ErrSAMLAssertionReplayed, http.StatusConflict},
	{sso.ErrUserInactive, http.StatusForbidden},
	{sso.ErrUserDeprovisioned, http.StatusForbidden},
	{sso.ErrDomainNotAllowed, http.StatusForbidden},
	{errTenantForbidden, http.StatusForbidden},
	{errStoreUnavailable, http.StatusNotFound},
}

func errorResponse(err error) (int, errorBody) {
	for _, coded := range codedErrors {
		if errors.Is(err, coded.err) {
			return coded.status, codeBody(coded.err.Error())
		}
	}
	switch {
	case errors.Is(err, sso.ErrInvalid):
		return http.StatusBadRequest, errorBody{Error: strings.TrimPrefix(err.Error(), sso.ErrInvalid.Error()+": "), Code: "invalid_request"}
	case errors.Is(err, ports.ErrSSOConnectionLimit):
		return http.StatusBadRequest, errorBody{Error: fmt.Sprintf("at most %d connections are allowed", sso.MaxConnections), Code: "connection_limit"}
	case errors.Is(err, ports.ErrSSOConnectionNotFound), errors.Is(err, ports.ErrSSOSessionNotFound),
		errors.Is(err, ports.ErrSCIMTokenNotFound), errors.Is(err, ports.ErrDirectoryUserNotFound),
		errors.Is(err, ports.ErrDirectoryGroupNotFound):
		return http.StatusNotFound, codeBody(errorCodeNotFound)
	case errors.Is(err, ports.ErrSSODomainConflict):
		body := codeBody("domain_in_use")
		body.Detail = strings.TrimPrefix(err.Error(), ports.ErrSSODomainConflict.Error()+": ")
		return http.StatusConflict, body
	case errors.Is(err, sso.ErrBootstrapManaged):
		body := codeBody(sso.ErrBootstrapManaged.Error())
		body.Detail = "managed by stack configuration"
		return http.StatusConflict, body
	case errors.Is(err, ports.ErrSSOSessionExists):
		return http.StatusConflict, codeBody("session_exists")
	case errors.Is(err, ports.ErrDirectoryConflict):
		return http.StatusConflict, codeBody("directory_conflict")
	default:
		return http.StatusInternalServerError, codeBody("internal_error")
	}
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
