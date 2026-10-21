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

// maxMatchCandidates bounds the users a login lookup considers per key.
const maxMatchCandidates = 20

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
// An optional subject query parameter prefers the user bound to that subject.
// Deprovisioned users are not found.
func (h Handler) LookupDirectoryUser(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	connectionID := strings.TrimSpace(r.URL.Query().Get("connectionId"))
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if !sso.ValidResourceID(connectionID) {
		writeError(w, sso.Invalid("connectionId is required"))
		return
	}
	if err := sso.CheckText("email", email, sso.MaxEmailLength, true); err != nil {
		writeError(w, err)
		return
	}
	if err := sso.CheckText("subject", subject, sso.MaxSubjectLength, false); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.matchDirectoryUser(r.Context(), tenantID, connectionID, subject, email)
	if err != nil {
		writeError(w, err)
		return
	}
	if user == nil || user.DeletedAt != nil {
		writeError(w, ports.ErrDirectoryUserNotFound)
		return
	}
	writeJSON(w, http.StatusOK, sso.NewDirectoryUserView(*user))
}

// UpsertJITUser serves POST /platform/identity/directory/users/jit. It records
// a login for an existing user, or creates a just-in-time user when the
// connection allows it. Deprovisioned and inactive users are refused with 403,
// and a user bound to a different subject on the connection with 409.
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
		existing, err := h.matchDirectoryUser(ctx, conn.TenantID, conn.ID, input.Subject, input.Email)
		if err != nil {
			return ports.DirectoryUser{}, 0, err
		}
		if existing != nil {
			if err := sso.CheckLoginUser(*existing, input.Subject); err != nil {
				return ports.DirectoryUser{}, 0, err
			}
			now := h.clock()
			updated, err := h.store.MutateDirectoryUser(ctx, conn.TenantID, conn.ID, existing.ID, func(user *ports.DirectoryUser) error {
				return sso.ApplyJITLogin(user, input, now)
			})
			if errors.Is(err, ports.ErrDirectoryUserNotFound) {
				continue
			}
			if err != nil {
				return ports.DirectoryUser{}, 0, err
			}
			return *updated, http.StatusOK, nil
		}
		if !conn.JITProvisioning {
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

// matchDirectoryUser returns the connection's user a login belongs to, found
// by subject binding or by email, including deprovisioned tombstones so callers
// can refuse them. It returns nil when no user matches.
func (h Handler) matchDirectoryUser(ctx context.Context, tenantID string, connectionID string, subject string, email string) (*ports.DirectoryUser, error) {
	var candidates []ports.DirectoryUser
	if subject != "" {
		users, _, err := h.store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, ConnectionID: connectionID, Subject: subject, IncludeDeleted: true, Limit: maxMatchCandidates})
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, users...)
	}
	if email != "" {
		users, _, err := h.store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: tenantID, ConnectionID: connectionID, Email: email, IncludeDeleted: true, Limit: maxMatchCandidates})
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, users...)
	}
	match := sso.MatchDirectoryUser(candidates, subject, email)
	if match == nil {
		return nil, nil
	}
	user := *match
	return &user, nil
}
