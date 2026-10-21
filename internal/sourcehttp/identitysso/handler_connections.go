package identitysso

import (
	"context"
	"errors"
	"net/http"
	"strings"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

type connectionsResponse struct {
	Connections []connectionView `json:"connections"`
}

// connectionView adds response-only fields to a stored connection.
type connectionView struct {
	ports.SSOConnection
	Managed bool `json:"managed"`
}

func (h Handler) view(conn ports.SSOConnection) connectionView {
	return connectionView{SSOConnection: conn, Managed: h.bootstrap.ManagesConnection(conn.TenantID, conn.ID)}
}

func (h Handler) refuseManaged(tenantID string, connectionID string) error {
	if h.bootstrap.ManagesConnection(tenantID, connectionID) {
		return sso.ErrBootstrapManaged
	}
	return nil
}

// ListConnections serves GET /platform/identity/sso/connections.
func (h Handler) ListConnections(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	connections, err := h.store.ListSSOConnections(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	views := make([]connectionView, 0, len(connections))
	for _, conn := range connections {
		views = append(views, h.view(conn))
	}
	writeJSON(w, http.StatusOK, connectionsResponse{Connections: views})
}

// CreateConnection serves POST /platform/identity/sso/connections.
func (h Handler) CreateConnection(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var input sso.ConnectionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	conn, err := sso.NormalizeConnectionInput(input)
	if err != nil {
		writeError(w, err)
		return
	}
	id, err := sso.NewID("conn")
	if err != nil {
		writeError(w, err)
		return
	}
	if conn, err = sso.PrepareCreate(conn, id, h.clock()); err != nil {
		writeError(w, err)
		return
	}
	conn.TenantID = tenantID
	conn.UpdatedBy = h.principal(r.Context())
	if err := h.store.PutSSOConnection(r.Context(), &conn, sso.MaxConnections); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, h.view(conn))
}

// GetConnection serves GET /platform/identity/sso/connections/{connectionID}.
func (h Handler) GetConnection(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	conn, err := h.loadConnection(r.Context(), tenantID, r.PathValue("connectionID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(*conn))
}

// UpdateConnection serves PUT /platform/identity/sso/connections/{connectionID}.
// The merge, the enforced-lockout check, and session revocation run in the
// store under the tenant's connection lock.
func (h Handler) UpdateConnection(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	connectionID, err := connectionIDFrom(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.refuseManaged(tenantID, connectionID); err != nil {
		writeError(w, err)
		return
	}
	var input sso.ConnectionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	normalized, err := sso.NormalizeConnectionInput(input)
	if err != nil {
		writeError(w, err)
		return
	}
	now := h.clock()
	principal := h.principal(r.Context())
	updated, err := h.store.UpdateSSOConnection(r.Context(), tenantID, connectionID, sso.MaxConnections, func(previous ports.SSOConnection) (ports.SSOConnectionUpdate, error) {
		next, err := sso.PrepareUpdate(previous, normalized, now)
		if err != nil {
			return ports.SSOConnectionUpdate{}, err
		}
		next.UpdatedBy = principal
		return ports.SSOConnectionUpdate{Connection: next, RevokeSessions: sso.ConnectionChangeRevokesSessions(previous, next)}, nil
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(*updated))
}

// DeleteConnection serves DELETE /platform/identity/sso/connections/{connectionID}.
func (h Handler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	connectionID, err := connectionIDFrom(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.refuseManaged(tenantID, connectionID); err != nil {
		writeError(w, err)
		return
	}
	if err := h.store.DeleteSSOConnection(r.Context(), tenantID, connectionID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RecordTestResult serves POST /platform/identity/sso/connections/{connectionID}/test-result.
func (h Handler) RecordTestResult(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	connectionID, err := connectionIDFrom(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var input sso.TestResultInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	now := h.clock()
	principal := h.principal(r.Context())
	updated, err := h.store.UpdateSSOConnection(r.Context(), tenantID, connectionID, sso.MaxConnections, func(current ports.SSOConnection) (ports.SSOConnectionUpdate, error) {
		next, err := sso.ApplyTestResult(current, input, principal, now)
		return ports.SSOConnectionUpdate{Connection: next}, err
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(*updated))
}

// GetPolicy serves GET /platform/identity/sso/policy.
func (h Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	policy, err := h.effectivePolicy(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

// PutPolicy serves PUT /platform/identity/sso/policy. The store refuses to
// enforce SSO without an active connection inside the tenant's lock.
func (h Handler) PutPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var input ports.SSOPolicy
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	input.UpdatedOnBehalfOf = input.UpdatedBy
	input.UpdatedBy = h.principal(r.Context())
	policy, err := sso.NormalizePolicy(input)
	if err != nil {
		writeError(w, err)
		return
	}
	if !policy.Enforced && h.bootstrap.EnforcesPolicy(tenantID) {
		writeError(w, sso.ErrBootstrapManaged)
		return
	}
	policy.TenantID = tenantID
	policy.UpdatedAt = h.clock()
	if err := h.store.PutSSOPolicy(r.Context(), &policy); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func connectionIDFrom(r *http.Request) (string, error) {
	id := strings.TrimSpace(r.PathValue("connectionID"))
	if !sso.ValidResourceID(id) {
		return "", ports.ErrSSOConnectionNotFound
	}
	return id, nil
}

func (h Handler) loadConnection(ctx context.Context, tenantID string, rawID string) (*ports.SSOConnection, error) {
	id := strings.TrimSpace(rawID)
	if !sso.ValidResourceID(id) {
		return nil, ports.ErrSSOConnectionNotFound
	}
	return h.store.GetSSOConnection(ctx, tenantID, id)
}

func (h Handler) effectivePolicy(ctx context.Context, tenantID string) (ports.SSOPolicy, error) {
	policy, err := h.store.GetSSOPolicy(ctx, tenantID)
	if errors.Is(err, ports.ErrSSOPolicyNotFound) {
		return sso.DefaultPolicy(), nil
	}
	if err != nil {
		return ports.SSOPolicy{}, err
	}
	return *policy, nil
}
