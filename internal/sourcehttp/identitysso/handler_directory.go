package identitysso

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

type directoryUsersResponse struct {
	Users []sso.DirectoryUserView `json:"users"`
}

type directoryGroupsResponse struct {
	Groups []sso.DirectoryGroupView `json:"groups"`
}

func parseLimit(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultListLimit, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, sso.Invalid("limit must be a positive integer")
	}
	return min(value, maxListLimit), nil
}

// ListDirectoryUsers serves GET /platform/identity/directory/users.
func (h Handler) ListDirectoryUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if len(query) > maxQueryLength {
		writeError(w, sso.Invalid("query is too long"))
		return
	}
	limit, err := parseLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, err)
		return
	}
	users, _, err := h.store.ListDirectoryUsers(r.Context(), ports.DirectoryUserQuery{TenantID: tenantID, Search: query, Limit: limit})
	if err != nil {
		writeError(w, err)
		return
	}
	views := make([]sso.DirectoryUserView, 0, len(users))
	for _, user := range users {
		views = append(views, sso.NewDirectoryUserView(user))
	}
	writeJSON(w, http.StatusOK, directoryUsersResponse{Users: views})
}

// ListDirectoryGroups serves GET /platform/identity/directory/groups.
func (h Handler) ListDirectoryGroups(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	groups, _, err := h.store.ListDirectoryGroups(r.Context(), ports.DirectoryGroupQuery{TenantID: tenantID, Limit: maxListLimit})
	if err != nil {
		writeError(w, err)
		return
	}
	views := make([]sso.DirectoryGroupView, 0, len(groups))
	for _, group := range groups {
		views = append(views, sso.NewDirectoryGroupView(group))
	}
	writeJSON(w, http.StatusOK, directoryGroupsResponse{Groups: views})
}

// LookupDirectoryUser serves GET /platform/identity/directory/users/lookup.
func (h Handler) LookupDirectoryUser(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	connectionID := strings.TrimSpace(r.URL.Query().Get("connectionId"))
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if !sso.ValidResourceID(connectionID) {
		writeError(w, sso.Invalid("connectionId is required"))
		return
	}
	if err := sso.CheckText("email", email, sso.MaxEmailLength, true); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.findUserByEmail(r.Context(), tenantID, connectionID, email)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sso.NewDirectoryUserView(*user))
}

// UpsertJITUser serves POST /platform/identity/directory/users/jit. It records
// a login for an existing user, or creates a just-in-time user when the
// connection allows it. Inactive users are returned unchanged.
func (h Handler) UpsertJITUser(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var input sso.JITUserInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	if input, err = sso.NormalizeJITInput(input); err != nil {
		writeError(w, err)
		return
	}
	conn, err := h.store.GetSSOConnection(r.Context(), tenantID, input.ConnectionID)
	if err != nil {
		writeError(w, err)
		return
	}
	user, status, err := h.upsertJIT(r.Context(), *conn, input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, status, sso.NewDirectoryUserView(user))
}

func (h Handler) upsertJIT(ctx context.Context, conn ports.SSOConnection, input sso.JITUserInput) (ports.DirectoryUser, int, error) {
	for attempt := 0; attempt < 2; attempt++ {
		existing, err := h.findUserByEmail(ctx, conn.TenantID, conn.ID, input.Email)
		switch {
		case err == nil:
			if !existing.Active {
				return *existing, http.StatusOK, nil
			}
			updated := sso.ApplyJITLogin(*existing, input, h.clock())
			if err := h.store.UpdateDirectoryUser(ctx, &updated); err != nil {
				return ports.DirectoryUser{}, 0, err
			}
			return updated, http.StatusOK, nil
		case !errors.Is(err, ports.ErrDirectoryUserNotFound):
			return ports.DirectoryUser{}, 0, err
		case !conn.JITProvisioning:
			return ports.DirectoryUser{}, 0, sso.ErrJITDisabled
		}
		id, err := sso.NewID("usr")
		if err != nil {
			return ports.DirectoryUser{}, 0, err
		}
		user := sso.NewJITUser(conn.TenantID, id, input, h.clock())
		err = h.store.CreateDirectoryUser(ctx, &user)
		if err == nil {
			return user, http.StatusCreated, nil
		}
		if !errors.Is(err, ports.ErrDirectoryConflict) {
			return ports.DirectoryUser{}, 0, err
		}
		// A concurrent login or SCIM push created the user; retry as an update.
	}
	return ports.DirectoryUser{}, 0, ports.ErrDirectoryConflict
}

// findUserByEmail returns the connection's user whose email or userName
// matches, preferring SCIM-provisioned users over just-in-time users.
func (h Handler) findUserByEmail(ctx context.Context, tenantID string, connectionID string, email string) (*ports.DirectoryUser, error) {
	users, _, err := h.store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, ConnectionID: connectionID, Email: email, Limit: 10})
	if err != nil {
		return nil, err
	}
	var match *ports.DirectoryUser
	for i := range users {
		if match == nil || (users[i].Source == sso.DirectorySourceSCIM && match.Source != sso.DirectorySourceSCIM) {
			match = &users[i]
		}
	}
	if match == nil {
		return nil, ports.ErrDirectoryUserNotFound
	}
	return match, nil
}
