package identitysso

import (
	"errors"
	"net/http"
	"strings"
	"time"

	sso "github.com/writer/cerebro/internal/identitysso"
	"github.com/writer/cerebro/internal/ports"
)

type sessionsResponse struct {
	Sessions []sso.SessionSummary `json:"sessions"`
}

type revokedResponse struct {
	Revoked int `json:"revoked"`
}

// CreateSession serves POST /platform/identity/sessions. The connection must be
// active, and a matching directory user must be active, not deprovisioned, and
// bound to the session subject. Sessions carrying an admin role are capped at
// sso.AdminSessionMaxLifetime.
func (h Handler) CreateSession(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var input sso.SessionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	now := h.clock()
	session, err := sso.NormalizeSessionInput(input, now)
	if err != nil {
		writeError(w, err)
		return
	}
	conn, err := h.store.GetSSOConnection(r.Context(), tenantID, session.ConnectionID)
	if err != nil {
		writeError(w, err)
		return
	}
	if conn.Status != sso.StatusActive {
		writeError(w, sso.ErrConnectionInactive)
		return
	}
	user, err := h.matchDirectoryUser(r.Context(), tenantID, conn.ID, session.Subject, session.Email)
	if err != nil {
		writeError(w, err)
		return
	}
	if user != nil {
		if err := sso.CheckLoginUser(*user, session.Subject); err != nil {
			writeError(w, err)
			return
		}
	}
	policy, err := h.effectivePolicy(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	sso.CapSessionLifetime(&session, policy)
	if session.ID, err = sso.NewID("sess"); err != nil {
		writeError(w, err)
		return
	}
	session.TenantID = tenantID
	if err := h.store.CreateSSOSession(r.Context(), &session); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sso.NewSessionView(session))
}

// GetSession serves GET /platform/identity/sessions/{tokenHash}. Missing,
// expired, revoked, and idle-expired sessions all return 404, as do sessions
// whose connection is no longer active or whose directory user is inactive or
// deprovisioned.
func (h Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	tokenHash := strings.TrimSpace(r.PathValue("tokenHash"))
	if !sso.ValidTokenHash(tokenHash) {
		writeError(w, ports.ErrSSOSessionNotFound)
		return
	}
	session, err := h.store.GetSSOSession(r.Context(), tenantID, tokenHash)
	if err != nil {
		writeError(w, err)
		return
	}
	now := h.clock()
	if !sso.SessionActive(*session, now) {
		writeError(w, ports.ErrSSOSessionNotFound)
		return
	}
	if sso.SessionNeedsTouch(*session, now) {
		if err := h.store.TouchSSOSession(r.Context(), tenantID, tokenHash, now); err != nil {
			writeError(w, err)
			return
		}
		session.LastSeenAt = now
	}
	writeJSON(w, http.StatusOK, sso.NewSessionView(*session))
}

// DeleteSession serves DELETE /platform/identity/sessions/{tokenHash}. It is
// idempotent so logout always succeeds.
func (h Handler) DeleteSession(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	tokenHash := strings.TrimSpace(r.PathValue("tokenHash"))
	if !sso.ValidTokenHash(tokenHash) {
		writeError(w, sso.Invalid("tokenHash must be a lowercase hex sha256 digest"))
		return
	}
	if err := h.store.DeleteSSOSession(r.Context(), tenantID, tokenHash); err != nil && !errors.Is(err, ports.ErrSSOSessionNotFound) {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListSessions serves GET /platform/identity/sessions?subject= (or ?email=).
// The value matches a session's subject exactly or its email
// case-insensitively; when it is omitted every live session is listed.
func (h Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if subject == "" {
		subject = strings.TrimSpace(r.URL.Query().Get("email"))
	}
	if len(subject) > sso.MaxSubjectLength {
		writeError(w, sso.Invalid("subject is too long"))
		return
	}
	now := h.clock()
	sessions, err := h.store.ListSSOSessions(r.Context(), tenantID, subject, now, sessionListLimit)
	if err != nil {
		writeError(w, err)
		return
	}
	summaries := make([]sso.SessionSummary, 0, len(sessions))
	for _, session := range sessions {
		if sso.SessionActive(session, now) {
			summaries = append(summaries, sso.NewSessionSummary(session))
		}
	}
	writeJSON(w, http.StatusOK, sessionsResponse{Sessions: summaries})
}

// RevokeSessions serves DELETE /platform/identity/sessions?subject= or ?email=.
// subject matches a session's subject exactly or its email case-insensitively;
// email matches only the session email, case-insensitively.
func (h Handler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	var match ports.SSOSessionMatch
	switch {
	case subject != "" && email != "":
		writeError(w, sso.Invalid("use either subject or email, not both"))
		return
	case email != "":
		if err := sso.CheckText("email", email, sso.MaxEmailLength, true); err != nil {
			writeError(w, err)
			return
		}
		match.Emails = []string{strings.ToLower(email)}
	default:
		if err := sso.CheckText("subject", subject, sso.MaxSubjectLength, true); err != nil {
			writeError(w, err)
			return
		}
		match.Subjects = []string{subject}
		match.Emails = []string{strings.ToLower(subject)}
	}
	revoked, err := h.store.RevokeSSOSessions(r.Context(), tenantID, match, h.clock())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revokedResponse{Revoked: revoked})
}

type scimTokenView struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Prefix            string     `json:"prefix"`
	ConnectionID      string     `json:"connectionId"`
	CreatedAt         time.Time  `json:"createdAt"`
	CreatedBy         string     `json:"createdBy"`
	CreatedOnBehalfOf string     `json:"createdOnBehalfOf,omitempty"`
	LastUsedAt        *time.Time `json:"lastUsedAt,omitempty"`
}

type scimTokenCreated struct {
	scimTokenView
	Token string `json:"token"`
}

type scimTokensResponse struct {
	Tokens []scimTokenView `json:"tokens"`
}

type scimTokenInput struct {
	Name         string `json:"name"`
	ConnectionID string `json:"connectionId"`
	CreatedBy    string `json:"createdBy"`
}

func newSCIMTokenView(token ports.SCIMToken) scimTokenView {
	return scimTokenView{
		ID:                token.ID,
		Name:              token.Name,
		Prefix:            token.Prefix,
		ConnectionID:      token.ConnectionID,
		CreatedAt:         token.CreatedAt.UTC(),
		CreatedBy:         token.CreatedBy,
		CreatedOnBehalfOf: token.CreatedOnBehalfOf,
		LastUsedAt:        token.LastUsedAt,
	}
}

// ListSCIMTokens serves GET /platform/identity/scim/tokens.
func (h Handler) ListSCIMTokens(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	tokens, err := h.store.ListSCIMTokens(r.Context(), tenantID)
	if err != nil {
		writeError(w, err)
		return
	}
	views := make([]scimTokenView, 0, len(tokens))
	for _, token := range tokens {
		views = append(views, newSCIMTokenView(token))
	}
	writeJSON(w, http.StatusOK, scimTokensResponse{Tokens: views})
}

// CreateSCIMToken serves POST /platform/identity/scim/tokens. The raw token is
// returned once and only its hash is stored.
func (h Handler) CreateSCIMToken(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var input scimTokenInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	name := strings.TrimSpace(input.Name)
	if err := sso.CheckText("name", name, sso.MaxNameLength, true); err != nil {
		writeError(w, err)
		return
	}
	onBehalfOf := strings.TrimSpace(input.CreatedBy)
	if err := sso.CheckText("createdBy", onBehalfOf, sso.MaxShortTextLength, false); err != nil {
		writeError(w, err)
		return
	}
	conn, err := h.loadConnection(r.Context(), tenantID, input.ConnectionID)
	if err != nil {
		if errors.Is(err, ports.ErrSSOConnectionNotFound) {
			writeError(w, sso.Invalid("connectionId does not name an existing connection"))
			return
		}
		writeError(w, err)
		return
	}
	raw, hash, prefix, err := sso.NewSCIMToken()
	if err != nil {
		writeError(w, err)
		return
	}
	id, err := sso.NewID("scim")
	if err != nil {
		writeError(w, err)
		return
	}
	token := ports.SCIMToken{
		TenantID:          tenantID,
		ID:                id,
		ConnectionID:      conn.ID,
		Name:              name,
		Prefix:            prefix,
		TokenHash:         hash,
		CreatedAt:         h.clock(),
		CreatedBy:         h.principal(r.Context()),
		CreatedOnBehalfOf: onBehalfOf,
	}
	if err := h.store.CreateSCIMToken(r.Context(), &token); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, scimTokenCreated{scimTokenView: newSCIMTokenView(token), Token: raw})
}

// DeleteSCIMToken serves DELETE /platform/identity/scim/tokens/{tokenID}.
func (h Handler) DeleteSCIMToken(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	id := strings.TrimSpace(r.PathValue("tokenID"))
	if !sso.ValidResourceID(id) {
		writeError(w, ports.ErrSCIMTokenNotFound)
		return
	}
	if err := h.store.DeleteSCIMToken(r.Context(), tenantID, id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type samlAssertionConsumed struct {
	Consumed bool `json:"consumed"`
}

// ConsumeSAMLAssertion serves POST /platform/identity/saml/assertions. It
// records a verified assertion once; a second use of the same assertion ID on
// the connection, or of the same request ID in the tenant, returns 409
// assertion_replayed.
func (h Handler) ConsumeSAMLAssertion(w http.ResponseWriter, r *http.Request) {
	tenantID, err := h.tenant(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var input sso.SAMLAssertionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	use, err := sso.NormalizeSAMLAssertion(input, h.clock())
	if err != nil {
		writeError(w, err)
		return
	}
	use.TenantID = tenantID
	if err := h.store.ConsumeSAMLAssertion(r.Context(), use); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, samlAssertionConsumed{Consumed: true})
}
