package ports

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrSSOConnectionNotFound indicates that a tenant has no SSO connection with the requested ID.
	ErrSSOConnectionNotFound = errors.New("sso connection not found")
	// ErrSSODomainConflict indicates that an email domain is already routed to another connection.
	ErrSSODomainConflict = errors.New("sso domain already routed to another connection")
	// ErrSSOConnectionLimit indicates that a tenant already has the maximum number of connections.
	ErrSSOConnectionLimit = errors.New("sso connection limit reached")
	// ErrSSOPolicyNotFound indicates that a tenant has not saved an SSO policy.
	ErrSSOPolicyNotFound = errors.New("sso policy not found")
	// ErrSSOSessionNotFound indicates that no session exists for a token hash.
	ErrSSOSessionNotFound = errors.New("sso session not found")
	// ErrSSOSessionExists indicates that a session already exists for a token hash.
	ErrSSOSessionExists = errors.New("sso session already exists")
	// ErrSCIMTokenNotFound indicates that no SCIM token matches the request.
	ErrSCIMTokenNotFound = errors.New("scim token not found")
	// ErrDirectoryUserNotFound indicates that no directory user matches the request.
	ErrDirectoryUserNotFound = errors.New("directory user not found")
	// ErrDirectoryGroupNotFound indicates that no directory group matches the request.
	ErrDirectoryGroupNotFound = errors.New("directory group not found")
	// ErrDirectoryConflict indicates a duplicate userName or group displayName within a connection.
	ErrDirectoryConflict = errors.New("directory resource already exists")
	// ErrSSONoActiveConnection indicates that enforcing SSO was refused because
	// the tenant has no active connection.
	ErrSSONoActiveConnection = errors.New("no_active_connection")
	// ErrSSOLastActiveConnection indicates that a connection change was refused
	// because it would leave an enforced tenant with no active connection.
	ErrSSOLastActiveConnection = errors.New("last_active_connection")
	// ErrSAMLAssertionReplayed indicates that a SAML assertion or the login
	// request it answers was already consumed.
	ErrSAMLAssertionReplayed = errors.New("assertion_replayed")
)

// SSOStatusActive is the connection status that can authenticate users.
const SSOStatusActive = "active"

// SSOConnection is one tenant-scoped identity provider connection used by the
// web console. Fields ending in Ref hold secret references, never secret values.
type SSOConnection struct {
	TenantID        string            `json:"-"`
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Protocol        string            `json:"protocol"`
	Status          string            `json:"status"`
	Domains         []string          `json:"domains"`
	OIDC            *SSOOIDCConfig    `json:"oidc,omitempty"`
	SAML            *SSOSAMLConfig    `json:"saml,omitempty"`
	RoleMappings    []SSORoleMapping  `json:"roleMappings"`
	DefaultRoles    []string          `json:"defaultRoles"`
	JITProvisioning bool              `json:"jitProvisioning"`
	LastTest        *SSOConnectionRun `json:"lastTest,omitempty"`
	CreatedAt       time.Time         `json:"createdAt"`
	UpdatedAt       time.Time         `json:"updatedAt"`
	// UpdatedBy is the authenticated principal that wrote the connection.
	UpdatedBy string `json:"updatedBy"`
	// UpdatedOnBehalfOf is the caller-asserted end user the principal acted for.
	UpdatedOnBehalfOf string `json:"updatedOnBehalfOf,omitempty"`
}

// SSOOIDCConfig configures an OpenID Connect identity provider.
type SSOOIDCConfig struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"clientId"`
	ClientSecretRef string   `json:"clientSecretRef"`
	Scopes          []string `json:"scopes"`
	GroupsClaim     string   `json:"groupsClaim"`
	// TrustEmailClaim declares the IdP authoritative for the email claim, so
	// logins are accepted without email_verified=true.
	TrustEmailClaim bool `json:"trustEmailClaim"`
}

// SSOSAMLConfig configures a SAML 2.0 identity provider.
type SSOSAMLConfig struct {
	IDPEntityID          string   `json:"idpEntityId"`
	IDPSSOURL            string   `json:"idpSsoUrl"`
	IDPCertificates      []string `json:"idpCertificates"`
	IDPMetadataURL       string   `json:"idpMetadataUrl,omitempty"`
	WantAssertionsSigned bool     `json:"wantAssertionsSigned"`
	EmailAttribute       string   `json:"emailAttribute"`
	NameAttribute        string   `json:"nameAttribute"`
	GroupsAttribute      string   `json:"groupsAttribute"`
	NameIDFormat         string   `json:"nameIdFormat"`
}

// SSORoleMapping grants Cerebro roles to members of one IdP group.
type SSORoleMapping struct {
	Group string   `json:"group"`
	Roles []string `json:"roles"`
}

// SSOConnectionRun records the most recent admin test login for a connection.
type SSOConnectionRun struct {
	At time.Time `json:"at"`
	OK bool      `json:"ok"`
	// Actor is the authenticated principal that recorded the result.
	Actor string `json:"actor"`
	// OnBehalfOf is the caller-asserted admin who ran the test login.
	OnBehalfOf string `json:"onBehalfOf,omitempty"`
	Detail     string `json:"detail"`
}

// SSOPolicy is the tenant singleton controlling console SSO enforcement.
type SSOPolicy struct {
	TenantID                  string    `json:"-"`
	Enforced                  bool      `json:"enforced"`
	SessionMaxLifetimeMinutes int       `json:"sessionMaxLifetimeMinutes"`
	SessionIdleTimeoutMinutes int       `json:"sessionIdleTimeoutMinutes"`
	UpdatedAt                 time.Time `json:"updatedAt,omitzero"`
	// UpdatedBy is the authenticated principal that wrote the policy.
	UpdatedBy string `json:"updatedBy,omitempty"`
	// UpdatedOnBehalfOf is the caller-asserted end user the principal acted for.
	UpdatedOnBehalfOf string `json:"updatedOnBehalfOf,omitempty"`
}

// SSOSession is one server-side console session keyed by the SHA-256 hash of
// the opaque cookie token. The raw token is never stored.
type SSOSession struct {
	TenantID           string
	ID                 string
	TokenHash          string
	ConnectionID       string
	Subject            string
	Email              string
	Name               string
	Groups             []string
	Roles              []string
	UserAgent          string
	IPHash             string
	CreatedAt          time.Time
	LastSeenAt         time.Time
	ExpiresAt          time.Time
	IdleTimeoutMinutes int
	RevokedAt          *time.Time
}

// SSOSessionMatch selects sessions that belong to one user. A session matches
// when its subject equals any Subjects entry or its email equals any Emails
// entry case-insensitively. A non-empty ConnectionID restricts the match to
// sessions created through that connection.
type SSOSessionMatch struct {
	ConnectionID string
	Subjects     []string
	Emails       []string
}

// SSOConnectionUpdate is the result of a connection mutation. RevokeSessions
// revokes every live session of the connection in the same transaction.
type SSOConnectionUpdate struct {
	Connection     SSOConnection
	RevokeSessions bool
}

// SAMLAssertionUse records one consumed SAML assertion. The assertion ID is
// unique per connection and the request ID is unique per tenant until
// ExpiresAt.
type SAMLAssertionUse struct {
	TenantID     string
	ConnectionID string
	AssertionID  string
	RequestID    string
	ConsumedAt   time.Time
	ExpiresAt    time.Time
}

// SCIMToken is a SCIM bearer token bound to one SSO connection. Only the
// SHA-256 hash of the token is stored.
type SCIMToken struct {
	TenantID     string
	ID           string
	ConnectionID string
	Name         string
	Prefix       string
	TokenHash    string
	CreatedAt    time.Time
	// CreatedBy is the authenticated principal that created the token.
	CreatedBy string
	// CreatedOnBehalfOf is the caller-asserted end user the principal acted for.
	CreatedOnBehalfOf string
	LastUsedAt        *time.Time
}

// DirectoryUser is a console user provisioned through SCIM or created just in
// time at first login. Subject is the IdP subject bound to the user on its
// connection at first login. DeletedAt marks a SCIM-deleted tombstone, which
// stays inactive and is hidden from SCIM and admin listings.
type DirectoryUser struct {
	TenantID     string
	ID           string
	ConnectionID string
	Source       string
	UserName     string
	ExternalID   string
	Subject      string
	Email        string
	DisplayName  string
	GivenName    string
	FamilyName   string
	Active       bool
	JITGroups    []string
	Groups       []DirectoryGroupRef
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
	DeletedAt    *time.Time
}

// DirectoryGroupRef names one group a directory user belongs to.
type DirectoryGroupRef struct {
	ID          string
	DisplayName string
}

// DirectoryGroup is a SCIM-provisioned group and its member user IDs.
type DirectoryGroup struct {
	TenantID     string
	ID           string
	ConnectionID string
	DisplayName  string
	ExternalID   string
	MemberIDs    []string
	MemberCount  int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// DirectoryUserQuery filters directory users. Empty ConnectionID lists users
// across every connection in the tenant. Tombstoned users are excluded unless
// IncludeDeleted is set. Non-empty IDs restricts the result to those user IDs.
type DirectoryUserQuery struct {
	TenantID       string
	ConnectionID   string
	UserName       string
	Email          string
	Subject        string
	Search         string
	IDs            []string
	IncludeDeleted bool
	Offset         int
	Limit          int
}

// DirectoryGroupQuery filters directory groups. Empty ConnectionID lists
// groups across every connection in the tenant.
type DirectoryGroupQuery struct {
	TenantID     string
	ConnectionID string
	DisplayName  string
	Offset       int
	Limit        int
}

// SSOConnectionStore persists SSO connections and the tenant SSO policy.
// Every connection and policy write runs under one per-tenant lock and checks
// that an enforced tenant keeps at least one active connection inside that
// lock, returning ErrSSOLastActiveConnection or ErrSSONoActiveConnection.
type SSOConnectionStore interface {
	ListSSOConnections(ctx context.Context, tenantID string) ([]SSOConnection, error)
	GetSSOConnection(ctx context.Context, tenantID string, connectionID string) (*SSOConnection, error)
	// PutSSOConnection inserts or replaces a connection. It enforces tenant-wide
	// domain uniqueness and the connection limit atomically.
	PutSSOConnection(ctx context.Context, connection *SSOConnection, maxConnections int) error
	// UpdateSSOConnection loads the stored connection under the tenant lock,
	// applies mutate, and writes the result in the same transaction, so
	// concurrent writers never overwrite each other with stale reads.
	UpdateSSOConnection(ctx context.Context, tenantID string, connectionID string, maxConnections int, mutate func(SSOConnection) (SSOConnectionUpdate, error)) (*SSOConnection, error)
	// DeleteSSOConnection removes a connection plus its sessions, SCIM tokens,
	// and directory records.
	DeleteSSOConnection(ctx context.Context, tenantID string, connectionID string) error
	GetSSOPolicy(ctx context.Context, tenantID string) (*SSOPolicy, error)
	PutSSOPolicy(ctx context.Context, policy *SSOPolicy) error
}

// SSOSessionStore persists server-side console sessions.
type SSOSessionStore interface {
	CreateSSOSession(ctx context.Context, session *SSOSession) error
	// GetSSOSession loads a session by token hash, including expired or revoked
	// rows. It returns ErrSSOSessionNotFound unless the session's connection is
	// active and the directory user the session belongs to, when one exists, is
	// active and not deleted. The checks run in one query.
	GetSSOSession(ctx context.Context, tenantID string, tokenHash string) (*SSOSession, error)
	TouchSSOSession(ctx context.Context, tenantID string, tokenHash string, seenAt time.Time) error
	DeleteSSOSession(ctx context.Context, tenantID string, tokenHash string) error
	ListSSOSessions(ctx context.Context, tenantID string, subject string, now time.Time, limit int) ([]SSOSession, error)
	RevokeSSOSessions(ctx context.Context, tenantID string, match SSOSessionMatch, revokedAt time.Time) (int, error)
}

// SCIMTokenStore persists hashed SCIM bearer tokens.
type SCIMTokenStore interface {
	CreateSCIMToken(ctx context.Context, token *SCIMToken) error
	ListSCIMTokens(ctx context.Context, tenantID string) ([]SCIMToken, error)
	GetSCIMTokenByHash(ctx context.Context, tenantID string, tokenHash string) (*SCIMToken, error)
	TouchSCIMToken(ctx context.Context, tenantID string, tokenID string, usedAt time.Time) error
	DeleteSCIMToken(ctx context.Context, tenantID string, tokenID string) error
}

// DirectoryStore persists SCIM and just-in-time directory users and groups.
// Updates go through the Mutate methods, which lock the row, apply the change
// to the current value, and write it back in one transaction.
type DirectoryStore interface {
	ListDirectoryUsers(ctx context.Context, query DirectoryUserQuery) ([]DirectoryUser, int, error)
	// GetDirectoryUser loads one user. Tombstoned users are not found.
	GetDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string) (*DirectoryUser, error)
	CreateDirectoryUser(ctx context.Context, user *DirectoryUser) error
	// MutateDirectoryUser locks a user (including a tombstone), applies mutate,
	// and writes the result. A mutate error aborts the write.
	MutateDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string, mutate func(*DirectoryUser) error) (*DirectoryUser, error)
	// TombstoneDirectoryUser marks a user deleted and inactive and removes its
	// group memberships. It returns the user as it was before the change.
	TombstoneDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string, deletedAt time.Time) (*DirectoryUser, error)
	ListDirectoryGroups(ctx context.Context, query DirectoryGroupQuery) ([]DirectoryGroup, int, error)
	GetDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string) (*DirectoryGroup, error)
	CreateDirectoryGroup(ctx context.Context, group *DirectoryGroup) error
	// MutateDirectoryGroup locks a group, applies mutate to it and its current
	// member IDs, and writes the result. A mutate error aborts the write.
	MutateDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string, mutate func(*DirectoryGroup) error) (*DirectoryGroup, error)
	// DeleteDirectoryGroup removes a group and returns it with the member IDs
	// it had when it was deleted.
	DeleteDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string) (*DirectoryGroup, error)
}

// SAMLReplayStore records consumed SAML assertions.
type SAMLReplayStore interface {
	// ConsumeSAMLAssertion atomically records an assertion. It returns
	// ErrSAMLAssertionReplayed when the assertion ID was already consumed for
	// the connection or the request ID was already consumed for the tenant.
	ConsumeSAMLAssertion(ctx context.Context, use SAMLAssertionUse) error
}

// IdentitySSOStore is the full web console SSO state capability. State stores
// implement it as an optional capability discovered via type assertion.
type IdentitySSOStore interface {
	SSOConnectionStore
	SSOSessionStore
	SCIMTokenStore
	DirectoryStore
	SAMLReplayStore
}
