package identitysso

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/authz"
	"github.com/writer/cerebro/internal/ports"
)

const (
	// SessionTouchInterval bounds how often a session read bumps lastSeenAt.
	SessionTouchInterval = time.Minute
	// SCIMTokenTouchInterval bounds how often SCIM token use bumps lastUsedAt.
	SCIMTokenTouchInterval = time.Minute
	// SCIMTokenPrefix marks Cerebro SCIM bearer tokens.
	SCIMTokenPrefix = "cscim_"
	// AdminSessionMaxLifetime caps sessions that carry an admin role,
	// regardless of the tenant policy lifetime.
	AdminSessionMaxLifetime = 12 * time.Hour

	scimTokenDisplayPrefixLength = len(SCIMTokenPrefix) + 6
	sessionHashPrefixLength      = 8
	maxSessionRoles              = 50
	maxUserAgentLength           = 512
	maxSubjectLength             = 512
	maxEmailLength               = 320
	expirySkew                   = time.Minute
)

// SessionInput is the request body for creating a session.
type SessionInput struct {
	TokenHash          string    `json:"tokenHash"`
	ConnectionID       string    `json:"connectionId"`
	Subject            string    `json:"subject"`
	Email              string    `json:"email"`
	Name               string    `json:"name"`
	Groups             []string  `json:"groups"`
	Roles              []string  `json:"roles"`
	ExpiresAt          time.Time `json:"expiresAt"`
	IdleTimeoutMinutes int       `json:"idleTimeoutMinutes"`
	UserAgent          string    `json:"userAgent"`
	IPHash             string    `json:"ipHash"`
}

// SessionView is the wire shape for one session. It never carries the token hash.
type SessionView struct {
	ID                 string    `json:"id"`
	ConnectionID       string    `json:"connectionId"`
	Subject            string    `json:"subject"`
	Email              string    `json:"email"`
	Name               string    `json:"name"`
	Groups             []string  `json:"groups"`
	Roles              []string  `json:"roles"`
	CreatedAt          time.Time `json:"createdAt"`
	LastSeenAt         time.Time `json:"lastSeenAt"`
	ExpiresAt          time.Time `json:"expiresAt"`
	IdleTimeoutMinutes int       `json:"idleTimeoutMinutes"`
}

// SessionSummary is the admin list shape. TokenHashPrefix is at most 8 characters.
type SessionSummary struct {
	SessionView
	TokenHashPrefix string `json:"tokenHashPrefix"`
	UserAgent       string `json:"userAgent,omitempty"`
}

// NormalizeSessionInput validates a session create request.
func NormalizeSessionInput(input SessionInput, now time.Time) (ports.SSOSession, error) {
	var session ports.SSOSession
	session.TokenHash = strings.TrimSpace(input.TokenHash)
	if !ValidTokenHash(session.TokenHash) {
		return session, invalid("tokenHash must be a lowercase hex sha256 digest")
	}
	session.ConnectionID = strings.TrimSpace(input.ConnectionID)
	if !ValidResourceID(session.ConnectionID) {
		return session, invalid("connectionId is invalid")
	}
	session.Subject = strings.TrimSpace(input.Subject)
	if err := checkText("subject", session.Subject, maxSubjectLength, true); err != nil {
		return session, err
	}
	session.Email = strings.TrimSpace(input.Email)
	if err := checkText("email", session.Email, maxEmailLength, false); err != nil {
		return session, err
	}
	session.Name = strings.TrimSpace(input.Name)
	if err := checkText("name", session.Name, maxShortTextLength, false); err != nil {
		return session, err
	}
	var err error
	if session.Groups, err = normalizeStringList("groups", input.Groups, maxSessionClaimValues, maxShortTextLength); err != nil {
		return session, err
	}
	if len(input.Roles) > maxSessionRoles {
		return session, invalid("roles allows at most %d entries", maxSessionRoles)
	}
	session.Roles = make([]string, 0, len(input.Roles))
	for _, role := range input.Roles {
		role = strings.ToLower(strings.TrimSpace(role))
		if !authz.IsKnownRole(role) {
			return session, invalid("roles contains unknown role %q", role)
		}
		if !containsString(session.Roles, role) {
			session.Roles = append(session.Roles, role)
		}
	}
	if input.IdleTimeoutMinutes < MinIdleMinutes || input.IdleTimeoutMinutes > MaxIdleMinutes {
		return session, invalid("idleTimeoutMinutes must be between %d and %d", MinIdleMinutes, MaxIdleMinutes)
	}
	session.IdleTimeoutMinutes = input.IdleTimeoutMinutes
	if input.ExpiresAt.IsZero() || !input.ExpiresAt.After(now) {
		return session, invalid("expiresAt must be in the future")
	}
	if input.ExpiresAt.After(now.Add(MaxLifetimeMinutes*time.Minute + expirySkew)) {
		return session, invalid("expiresAt exceeds the maximum session lifetime")
	}
	session.ExpiresAt = input.ExpiresAt.UTC()
	session.UserAgent = truncate(strings.ToValidUTF8(strings.TrimSpace(input.UserAgent), ""), maxUserAgentLength)
	session.IPHash = strings.TrimSpace(input.IPHash)
	if session.IPHash != "" {
		if err := checkToken("ipHash", session.IPHash, 128); err != nil {
			return session, err
		}
	}
	session.CreatedAt = now
	session.LastSeenAt = now
	return session, nil
}

// CapSessionLifetime limits a session to the policy lifetime and idle timeout
// from its creation, and a session that carries an admin role to at most
// min(policy lifetime, AdminSessionMaxLifetime). The caller's values can only
// shorten a session, never extend it past policy.
func CapSessionLifetime(session *ports.SSOSession, policy ports.SSOPolicy) {
	if policy.SessionIdleTimeoutMinutes > 0 && session.IdleTimeoutMinutes > policy.SessionIdleTimeoutMinutes {
		session.IdleTimeoutMinutes = policy.SessionIdleTimeoutMinutes
	}
	limit := time.Duration(policy.SessionMaxLifetimeMinutes) * time.Minute
	if authz.HasAdminRole(session.Roles) && (limit <= 0 || limit > AdminSessionMaxLifetime) {
		limit = AdminSessionMaxLifetime
	}
	if limit <= 0 {
		return
	}
	if latest := session.CreatedAt.Add(limit).UTC(); session.ExpiresAt.After(latest) {
		session.ExpiresAt = latest
	}
}

// SessionActive reports whether a session still authenticates at now.
func SessionActive(session ports.SSOSession, now time.Time) bool {
	if session.RevokedAt != nil || !now.Before(session.ExpiresAt) {
		return false
	}
	idle := time.Duration(session.IdleTimeoutMinutes) * time.Minute
	return now.Sub(session.LastSeenAt) <= idle
}

// SessionNeedsTouch reports whether lastSeenAt should be bumped.
func SessionNeedsTouch(session ports.SSOSession, now time.Time) bool {
	return now.Sub(session.LastSeenAt) >= SessionTouchInterval
}

// NewSessionView converts a stored session to its wire shape.
func NewSessionView(session ports.SSOSession) SessionView {
	return SessionView{
		ID:                 session.ID,
		ConnectionID:       session.ConnectionID,
		Subject:            session.Subject,
		Email:              session.Email,
		Name:               session.Name,
		Groups:             nonNil(session.Groups),
		Roles:              nonNil(session.Roles),
		CreatedAt:          session.CreatedAt.UTC(),
		LastSeenAt:         session.LastSeenAt.UTC(),
		ExpiresAt:          session.ExpiresAt.UTC(),
		IdleTimeoutMinutes: session.IdleTimeoutMinutes,
	}
}

// NewSessionSummary converts a stored session to the admin list shape.
func NewSessionSummary(session ports.SSOSession) SessionSummary {
	return SessionSummary{
		SessionView:     NewSessionView(session),
		TokenHashPrefix: truncate(session.TokenHash, sessionHashPrefixLength),
		UserAgent:       session.UserAgent,
	}
}

// HashToken returns the lowercase hex SHA-256 digest of a raw bearer token.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// NewSCIMToken generates a SCIM bearer token. It returns the raw token (shown
// to the admin once), its storage hash, and a short display prefix.
func NewSCIMToken() (raw string, hash string, prefix string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("generate scim token: %w", err)
	}
	raw = SCIMTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashToken(raw), raw[:scimTokenDisplayPrefixLength], nil
}

// NewID returns a random URL-safe identifier such as conn_0123456789abcdef.
func NewID(prefix string) (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate %s id: %w", prefix, err)
	}
	return prefix + "_" + hex.EncodeToString(buf), nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return strings.ToValidUTF8(value[:limit], "")
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
