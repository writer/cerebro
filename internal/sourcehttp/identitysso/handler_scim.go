package identitysso

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

// scimCaller is the tenant and connection a SCIM token is bound to.
type scimCaller struct {
	tenantID     string
	connectionID string
}

func writeSCIM(w http.ResponseWriter, status int, value any) {
	writeEncoded(w, status, sso.SCIMContentType, value)
}

func writeSCIMError(w http.ResponseWriter, err error) {
	if scimErr, ok := sso.AsSCIMError(err); ok {
		writeSCIM(w, scimErr.Status, sso.NewSCIMErrorBody(scimErr))
		return
	}
	status, body := errorResponse(err)
	scimErr := &sso.SCIMError{Status: status, Detail: body.Error}
	switch {
	case errors.Is(err, ports.ErrDirectoryConflict):
		scimErr.SCIMType = sso.SCIMTypeUniqueness
		scimErr.Detail = "a resource with the same unique attribute already exists"
	case status == http.StatusNotFound:
		scimErr.Detail = "resource not found"
	}
	writeSCIM(w, status, sso.NewSCIMErrorBody(scimErr))
}

var errSCIMUnauthorized = &sso.SCIMError{Status: http.StatusUnauthorized, Detail: "a valid SCIM bearer token is required"}

// authenticateSCIM validates the forwarded SCIM token and returns the tenant
// and connection it is bound to.
func (h Handler) authenticateSCIM(r *http.Request) (scimCaller, error) {
	tenantID, err := h.tenant(r)
	if err != nil {
		return scimCaller{}, err
	}
	raw := strings.TrimSpace(r.Header.Get(SCIMTokenHeader))
	if len(raw) > 7 && strings.EqualFold(raw[:7], "bearer ") {
		raw = strings.TrimSpace(raw[7:])
	}
	if !strings.HasPrefix(raw, sso.SCIMTokenPrefix) || len(raw) > 256 {
		return scimCaller{}, errSCIMUnauthorized
	}
	hash := sso.HashToken(raw)
	token, err := h.store.GetSCIMTokenByHash(r.Context(), tenantID, hash)
	if err != nil {
		if errors.Is(err, ports.ErrSCIMTokenNotFound) {
			return scimCaller{}, errSCIMUnauthorized
		}
		return scimCaller{}, err
	}
	if subtle.ConstantTimeCompare([]byte(token.TokenHash), []byte(hash)) != 1 {
		return scimCaller{}, errSCIMUnauthorized
	}
	now := h.clock()
	if token.LastUsedAt == nil || now.Sub(*token.LastUsedAt) >= sso.SCIMTokenTouchInterval {
		if err := h.store.TouchSCIMToken(r.Context(), tenantID, token.ID, now); err != nil {
			return scimCaller{}, err
		}
	}
	return scimCaller{tenantID: tenantID, connectionID: token.ConnectionID}, nil
}

func (h Handler) scimRoute(next func(http.ResponseWriter, *http.Request, scimCaller)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := h.authenticateSCIM(r)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		next(w, r, caller)
	}
}

func decodeSCIM(w http.ResponseWriter, r *http.Request, target any) error {
	body, err := io.ReadAll(io.LimitReader(http.MaxBytesReader(w, r.Body, maxBodyBytes), maxBodyBytes+1))
	if err != nil {
		return sso.NewSCIMBadRequest(sso.SCIMTypeInvalidSyntax, "request body is too large or unreadable")
	}
	if err := json.Unmarshal(body, target); err != nil {
		return sso.NewSCIMBadRequest(sso.SCIMTypeInvalidSyntax, "request body must be valid JSON")
	}
	return nil
}

// SCIMServiceProviderConfig serves GET .../scim/v2/ServiceProviderConfig.
func (h Handler) SCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, _ *http.Request, _ scimCaller) {
		writeSCIM(w, http.StatusOK, sso.ServiceProviderConfig())
	})(w, r)
}

// SCIMResourceTypes serves GET .../scim/v2/ResourceTypes.
func (h Handler) SCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, _ *http.Request, _ scimCaller) {
		types := sso.ResourceTypes()
		writeSCIM(w, http.StatusOK, sso.NewSCIMListResponse(types, len(types), sso.SCIMPage{StartIndex: 1, Count: len(types)}))
	})(w, r)
}

// SCIMSchemas serves GET .../scim/v2/Schemas.
func (h Handler) SCIMSchemas(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, _ *http.Request, _ scimCaller) {
		schemas := sso.Schemas()
		writeSCIM(w, http.StatusOK, sso.NewSCIMListResponse(schemas, len(schemas), sso.SCIMPage{StartIndex: 1, Count: len(schemas)}))
	})(w, r)
}

// SCIMListUsers serves GET .../scim/v2/Users.
func (h Handler) SCIMListUsers(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(h.scimListUsers)(w, r)
}

func (h Handler) scimListUsers(w http.ResponseWriter, r *http.Request, caller scimCaller) {
	query := r.URL.Query()
	filter, err := sso.ParseSCIMFilter(query.Get("filter"), sso.SCIMFilterAttrUserName)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	page, err := sso.ParseSCIMPage(query.Get("startIndex"), query.Get("count"))
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	request := ports.DirectoryUserQuery{TenantID: caller.tenantID, ConnectionID: caller.connectionID, Offset: page.StartIndex - 1, Limit: page.Count}
	if filter != nil {
		request.UserName = filter.Value
	}
	users, total, err := h.store.ListDirectoryUsers(r.Context(), request)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	resources := make([]sso.SCIMUser, 0, len(users))
	for _, user := range users {
		resources = append(resources, sso.NewSCIMUser(user))
	}
	writeSCIM(w, http.StatusOK, sso.NewSCIMListResponse(resources, total, page))
}

// SCIMCreateUser serves POST .../scim/v2/Users. A just-in-time user with the
// same userName is adopted as SCIM-managed instead of conflicting, and a
// deprovisioned tombstone with the same userName is revived.
func (h Handler) SCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(h.scimCreateUser)(w, r)
}

func (h Handler) scimCreateUser(w http.ResponseWriter, r *http.Request, caller scimCaller) {
	var in sso.SCIMUser
	if err := decodeSCIM(w, r, &in); err != nil {
		writeSCIMError(w, err)
		return
	}
	if in.Active == nil {
		active := true
		in.Active = &active
	}
	now := h.clock()
	user, err := sso.ApplySCIMUser(ports.DirectoryUser{TenantID: caller.tenantID, ConnectionID: caller.connectionID, Source: sso.DirectorySourceSCIM, CreatedAt: now, UpdatedAt: now}, in)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	existing, _, err := h.store.ListDirectoryUsers(r.Context(), ports.DirectoryUserQuery{TenantID: caller.tenantID, ConnectionID: caller.connectionID, UserName: user.UserName, IncludeDeleted: true, Limit: 1})
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	if len(existing) == 0 {
		if user.ID, err = sso.NewID("usr"); err != nil {
			writeSCIMError(w, err)
			return
		}
		if err := h.store.CreateDirectoryUser(r.Context(), &user); err != nil {
			writeSCIMError(w, err)
			return
		}
		h.writeSCIMUser(w, r, caller, user.ID, http.StatusCreated)
		return
	}
	var before ports.DirectoryUser
	adopted, err := h.store.MutateDirectoryUser(r.Context(), caller.tenantID, caller.connectionID, existing[0].ID, func(current *ports.DirectoryUser) error {
		if current.DeletedAt == nil && current.Source != sso.DirectorySourceJIT {
			return ports.ErrDirectoryConflict
		}
		before = *current
		next, err := sso.ApplySCIMUser(*current, in)
		if err != nil {
			return err
		}
		sso.AdoptSCIMUser(&next, now)
		*current = next
		return nil
	})
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	if !adopted.Active {
		if err := h.revokeUserSessions(r.Context(), caller, before, *adopted); err != nil {
			writeSCIMError(w, err)
			return
		}
	}
	h.writeSCIMUser(w, r, caller, adopted.ID, http.StatusCreated)
}

// SCIMGetUser serves GET .../scim/v2/Users/{userID}.
func (h Handler) SCIMGetUser(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		h.writeSCIMUser(w, r, caller, r.PathValue("userID"), http.StatusOK)
	})(w, r)
}

// SCIMReplaceUser serves PUT .../scim/v2/Users/{userID}.
func (h Handler) SCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		var in sso.SCIMUser
		if err := decodeSCIM(w, r, &in); err != nil {
			writeSCIMError(w, err)
			return
		}
		h.mutateSCIMUser(w, r, caller, func(user ports.DirectoryUser) (ports.DirectoryUser, error) {
			return sso.ApplySCIMUser(user, in)
		})
	})(w, r)
}

// SCIMPatchUser serves PATCH .../scim/v2/Users/{userID}.
func (h Handler) SCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		var patch sso.SCIMPatchRequest
		if err := decodeSCIM(w, r, &patch); err != nil {
			writeSCIMError(w, err)
			return
		}
		h.mutateSCIMUser(w, r, caller, func(user ports.DirectoryUser) (ports.DirectoryUser, error) {
			return sso.ApplySCIMUserPatch(user, patch)
		})
	})(w, r)
}

// mutateSCIMUser applies a SCIM change to the locked current user, so a stale
// read can never reactivate a user that was deactivated concurrently.
func (h Handler) mutateSCIMUser(w http.ResponseWriter, r *http.Request, caller scimCaller, mutate func(ports.DirectoryUser) (ports.DirectoryUser, error)) {
	id := strings.TrimSpace(r.PathValue("userID"))
	if !sso.ValidResourceID(id) {
		writeSCIMError(w, ports.ErrDirectoryUserNotFound)
		return
	}
	now := h.clock()
	var before ports.DirectoryUser
	next, err := h.store.MutateDirectoryUser(r.Context(), caller.tenantID, caller.connectionID, id, func(current *ports.DirectoryUser) error {
		if current.DeletedAt != nil {
			return ports.ErrDirectoryUserNotFound
		}
		before = *current
		updated, err := mutate(*current)
		if err != nil {
			return err
		}
		sso.AdoptSCIMUser(&updated, now)
		*current = updated
		return nil
	})
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	if !next.Active {
		if err := h.revokeUserSessions(r.Context(), caller, before, *next); err != nil {
			writeSCIMError(w, err)
			return
		}
	}
	h.writeSCIMUser(w, r, caller, next.ID, http.StatusOK)
}

// SCIMDeleteUser serves DELETE .../scim/v2/Users/{userID}. The user is kept as
// an inactive tombstone, hidden from SCIM, so a later just-in-time login
// cannot recreate it, and its sessions on the connection are revoked.
func (h Handler) SCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		id := strings.TrimSpace(r.PathValue("userID"))
		if !sso.ValidResourceID(id) {
			writeSCIMError(w, ports.ErrDirectoryUserNotFound)
			return
		}
		before, err := h.store.TombstoneDirectoryUser(r.Context(), caller.tenantID, caller.connectionID, id, h.clock())
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		if err := h.revokeUserSessions(r.Context(), caller, *before); err != nil {
			writeSCIMError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})(w, r)
}

// revokeUserSessions revokes the sessions on the caller's connection that
// belong to any version of a user.
func (h Handler) revokeUserSessions(ctx context.Context, caller scimCaller, users ...ports.DirectoryUser) error {
	match := ports.SSOSessionMatch{ConnectionID: caller.connectionID}
	for _, user := range users {
		match = sso.AddUserToSessionMatch(match, user)
	}
	if len(match.Subjects) == 0 && len(match.Emails) == 0 {
		return nil
	}
	_, err := h.store.RevokeSSOSessions(ctx, caller.tenantID, match, h.clock())
	return err
}

// revokeMemberSessions revokes the sessions of group members whose roles may
// have changed.
func (h Handler) revokeMemberSessions(ctx context.Context, caller scimCaller, userIDs []string) error {
	if len(userIDs) == 0 {
		return nil
	}
	users, _, err := h.store.ListDirectoryUsers(ctx, ports.DirectoryUserQuery{TenantID: caller.tenantID, ConnectionID: caller.connectionID, IDs: userIDs, IncludeDeleted: true, Limit: len(userIDs)})
	if err != nil {
		return err
	}
	return h.revokeUserSessions(ctx, caller, users...)
}

func (h Handler) scimUser(ctx context.Context, caller scimCaller, rawID string) (*ports.DirectoryUser, error) {
	id := strings.TrimSpace(rawID)
	if !sso.ValidResourceID(id) {
		return nil, ports.ErrDirectoryUserNotFound
	}
	return h.store.GetDirectoryUser(ctx, caller.tenantID, caller.connectionID, id)
}

func (h Handler) writeSCIMUser(w http.ResponseWriter, r *http.Request, caller scimCaller, id string, status int) {
	user, err := h.scimUser(r.Context(), caller, id)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	writeSCIM(w, status, sso.NewSCIMUser(*user))
}

// SCIMListGroups serves GET .../scim/v2/Groups.
func (h Handler) SCIMListGroups(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		query := r.URL.Query()
		filter, err := sso.ParseSCIMFilter(query.Get("filter"), sso.SCIMFilterAttrDisplayName)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		page, err := sso.ParseSCIMPage(query.Get("startIndex"), query.Get("count"))
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		request := ports.DirectoryGroupQuery{TenantID: caller.tenantID, ConnectionID: caller.connectionID, Offset: page.StartIndex - 1, Limit: page.Count}
		if filter != nil {
			request.DisplayName = filter.Value
		}
		groups, total, err := h.store.ListDirectoryGroups(r.Context(), request)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		includeMembers := !excludesMembers(query.Get("excludedAttributes"))
		resources := make([]sso.SCIMGroup, 0, len(groups))
		for _, group := range groups {
			resources = append(resources, sso.NewSCIMGroup(group, includeMembers))
		}
		writeSCIM(w, http.StatusOK, sso.NewSCIMListResponse(resources, total, page))
	})(w, r)
}

func excludesMembers(raw string) bool {
	for _, attr := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(attr), "members") {
			return true
		}
	}
	return false
}

// SCIMCreateGroup serves POST .../scim/v2/Groups.
func (h Handler) SCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		var in sso.SCIMGroup
		if err := decodeSCIM(w, r, &in); err != nil {
			writeSCIMError(w, err)
			return
		}
		now := h.clock()
		group, err := sso.ApplySCIMGroup(ports.DirectoryGroup{TenantID: caller.tenantID, ConnectionID: caller.connectionID, CreatedAt: now, UpdatedAt: now}, in)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		if group.ID, err = sso.NewID("grp"); err != nil {
			writeSCIMError(w, err)
			return
		}
		if err := h.store.CreateDirectoryGroup(r.Context(), &group); err != nil {
			writeSCIMError(w, err)
			return
		}
		if err := h.revokeMemberSessions(r.Context(), caller, group.MemberIDs); err != nil {
			writeSCIMError(w, err)
			return
		}
		h.writeSCIMGroup(w, r, caller, group.ID, http.StatusCreated)
	})(w, r)
}

// SCIMGetGroup serves GET .../scim/v2/Groups/{groupID}.
func (h Handler) SCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		h.writeSCIMGroup(w, r, caller, r.PathValue("groupID"), http.StatusOK)
	})(w, r)
}

// SCIMReplaceGroup serves PUT .../scim/v2/Groups/{groupID}.
func (h Handler) SCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		var in sso.SCIMGroup
		if err := decodeSCIM(w, r, &in); err != nil {
			writeSCIMError(w, err)
			return
		}
		h.mutateSCIMGroup(w, r, caller, func(group ports.DirectoryGroup) (ports.DirectoryGroup, error) {
			return sso.ApplySCIMGroup(group, in)
		})
	})(w, r)
}

// SCIMPatchGroup serves PATCH .../scim/v2/Groups/{groupID}.
func (h Handler) SCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		var patch sso.SCIMPatchRequest
		if err := decodeSCIM(w, r, &patch); err != nil {
			writeSCIMError(w, err)
			return
		}
		h.mutateSCIMGroup(w, r, caller, func(group ports.DirectoryGroup) (ports.DirectoryGroup, error) {
			return sso.ApplySCIMGroupPatch(group, patch)
		})
	})(w, r)
}

// mutateSCIMGroup applies a SCIM change to the locked current group, so a
// stale read can never restore a removed member, and revokes the sessions of
// members whose roles may have changed.
func (h Handler) mutateSCIMGroup(w http.ResponseWriter, r *http.Request, caller scimCaller, mutate func(ports.DirectoryGroup) (ports.DirectoryGroup, error)) {
	id := strings.TrimSpace(r.PathValue("groupID"))
	if !sso.ValidResourceID(id) {
		writeSCIMError(w, ports.ErrDirectoryGroupNotFound)
		return
	}
	now := h.clock()
	var before ports.DirectoryGroup
	next, err := h.store.MutateDirectoryGroup(r.Context(), caller.tenantID, caller.connectionID, id, func(current *ports.DirectoryGroup) error {
		before = *current
		before.MemberIDs = slices.Clone(current.MemberIDs)
		updated, err := mutate(*current)
		if err != nil {
			return err
		}
		updated.UpdatedAt = now
		*current = updated
		return nil
	})
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	if err := h.revokeMemberSessions(r.Context(), caller, sso.AffectedGroupMembers(before, *next)); err != nil {
		writeSCIMError(w, err)
		return
	}
	h.writeSCIMGroup(w, r, caller, next.ID, http.StatusOK)
}

// SCIMDeleteGroup serves DELETE .../scim/v2/Groups/{groupID} and revokes the
// sessions of its members.
func (h Handler) SCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	h.scimRoute(func(w http.ResponseWriter, r *http.Request, caller scimCaller) {
		id := strings.TrimSpace(r.PathValue("groupID"))
		if !sso.ValidResourceID(id) {
			writeSCIMError(w, ports.ErrDirectoryGroupNotFound)
			return
		}
		deleted, err := h.store.DeleteDirectoryGroup(r.Context(), caller.tenantID, caller.connectionID, id)
		if err != nil {
			writeSCIMError(w, err)
			return
		}
		if err := h.revokeMemberSessions(r.Context(), caller, deleted.MemberIDs); err != nil {
			writeSCIMError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})(w, r)
}

func (h Handler) scimGroup(ctx context.Context, caller scimCaller, rawID string) (*ports.DirectoryGroup, error) {
	id := strings.TrimSpace(rawID)
	if !sso.ValidResourceID(id) {
		return nil, ports.ErrDirectoryGroupNotFound
	}
	return h.store.GetDirectoryGroup(ctx, caller.tenantID, caller.connectionID, id)
}

func (h Handler) writeSCIMGroup(w http.ResponseWriter, r *http.Request, caller scimCaller, id string, status int) {
	group, err := h.scimGroup(r.Context(), caller, id)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	writeSCIM(w, status, sso.NewSCIMGroup(*group, true))
}
