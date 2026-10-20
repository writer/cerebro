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
	conn.UpdatedBy = h.actorFor(r.Context(), conn.UpdatedBy)
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
func (h Handler) UpdateConnection(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	previous, err := h.loadConnection(r.Context(), tenantID, r.PathValue("connectionID"))
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.refuseManaged(tenantID, previous.ID); err != nil {
		writeError(w, err)
		return
	}
	var input sso.ConnectionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	next, err := sso.NormalizeConnectionInput(input)
	if err != nil {
		writeError(w, err)
		return
	}
	if next, err = sso.PrepareUpdate(*previous, next, h.clock()); err != nil {
		writeError(w, err)
		return
	}
	if previous.Status == sso.StatusActive && next.Status != sso.StatusActive {
		if err := h.guardEnforcedLockout(r.Context(), tenantID, previous.ID, &next); err != nil {
			writeError(w, err)
			return
		}
	}
	next.UpdatedBy = h.actorFor(r.Context(), next.UpdatedBy)
	if err := h.store.PutSSOConnection(r.Context(), &next, sso.MaxConnections); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(next))
}

// DeleteConnection serves DELETE /platform/identity/sso/connections/{connectionID}.
func (h Handler) DeleteConnection(w http.ResponseWriter, r *http.Request) {
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
	if err := h.refuseManaged(tenantID, conn.ID); err != nil {
		writeError(w, err)
		return
	}
	if conn.Status == sso.StatusActive {
		if err := h.guardEnforcedLockout(r.Context(), tenantID, conn.ID, nil); err != nil {
			writeError(w, err)
			return
		}
	}
	if err := h.store.DeleteSSOConnection(r.Context(), tenantID, conn.ID); err != nil {
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
	conn, err := h.loadConnection(r.Context(), tenantID, r.PathValue("connectionID"))
	if err != nil {
		writeError(w, err)
		return
	}
	var input sso.TestResultInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	input.Actor = h.actorFor(r.Context(), input.Actor)
	next, err := sso.ApplyTestResult(*conn, input, h.clock())
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.store.PutSSOConnection(r.Context(), &next, sso.MaxConnections); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.view(next))
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

// PutPolicy serves PUT /platform/identity/sso/policy.
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
	policy, err := sso.NormalizePolicy(input)
	if err != nil {
		writeError(w, err)
		return
	}
	if !policy.Enforced && h.bootstrap.EnforcesPolicy(tenantID) {
		writeError(w, sso.ErrBootstrapManaged)
		return
	}
	if policy.Enforced {
		active, err := h.hasActiveConnection(r.Context(), tenantID)
		if err != nil {
			writeError(w, err)
			return
		}
		if !active {
			writeError(w, sso.ErrNoActiveConnection)
			return
		}
	}
	policy.TenantID = tenantID
	policy.UpdatedAt = h.clock()
	policy.UpdatedBy = h.actorFor(r.Context(), policy.UpdatedBy)
	if err := h.store.PutSSOPolicy(r.Context(), &policy); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
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

func (h Handler) hasActiveConnection(ctx context.Context, tenantID string) (bool, error) {
	connections, err := h.store.ListSSOConnections(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, conn := range connections {
		if conn.Status == sso.StatusActive {
			return true, nil
		}
	}
	return false, nil
}

// guardEnforcedLockout refuses a change that would leave an enforced tenant
// with no active connection, which would lock every console user out until
// break-glass is used.
func (h Handler) guardEnforcedLockout(ctx context.Context, tenantID string, connectionID string, next *ports.SSOConnection) error {
	policy, err := h.effectivePolicy(ctx, tenantID)
	if err != nil || !policy.Enforced {
		return err
	}
	connections, err := h.store.ListSSOConnections(ctx, tenantID)
	if err != nil {
		return err
	}
	if sso.LeavesNoActiveConnection(connections, connectionID, next) {
		return sso.ErrLastActiveEnforced
	}
	return nil
}
