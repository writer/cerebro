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
)

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
	UpdatedBy       string            `json:"updatedBy"`
}

// SSOOIDCConfig configures an OpenID Connect identity provider.
type SSOOIDCConfig struct {
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"clientId"`
	ClientSecretRef string   `json:"clientSecretRef"`
	Scopes          []string `json:"scopes"`
	GroupsClaim     string   `json:"groupsClaim"`
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
	At     time.Time `json:"at"`
	OK     bool      `json:"ok"`
	Actor  string    `json:"actor"`
	Detail string    `json:"detail"`
}

// SSOPolicy is the tenant singleton controlling console SSO enforcement.
type SSOPolicy struct {
	TenantID                  string    `json:"-"`
	Enforced                  bool      `json:"enforced"`
	SessionMaxLifetimeMinutes int       `json:"sessionMaxLifetimeMinutes"`
	SessionIdleTimeoutMinutes int       `json:"sessionIdleTimeoutMinutes"`
	UpdatedAt                 time.Time `json:"updatedAt,omitzero"`
	UpdatedBy                 string    `json:"updatedBy,omitempty"`
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
// entry case-insensitively.
type SSOSessionMatch struct {
	Subjects []string
	Emails   []string
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
	CreatedBy    string
	LastUsedAt   *time.Time
}

// DirectoryUser is a console user provisioned through SCIM or created just in
// time at first login.
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
// across every connection in the tenant.
type DirectoryUserQuery struct {
	TenantID     string
	ConnectionID string
	UserName     string
	Email        string
	Search       string
	Offset       int
	Limit        int
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
type SSOConnectionStore interface {
	ListSSOConnections(ctx context.Context, tenantID string) ([]SSOConnection, error)
	GetSSOConnection(ctx context.Context, tenantID string, connectionID string) (*SSOConnection, error)
	// PutSSOConnection inserts or replaces a connection. It enforces tenant-wide
	// domain uniqueness and the connection limit atomically.
	PutSSOConnection(ctx context.Context, connection *SSOConnection, maxConnections int) error
	// DeleteSSOConnection removes a connection plus its sessions, SCIM tokens,
	// and directory records.
	DeleteSSOConnection(ctx context.Context, tenantID string, connectionID string) error
	GetSSOPolicy(ctx context.Context, tenantID string) (*SSOPolicy, error)
	PutSSOPolicy(ctx context.Context, policy *SSOPolicy) error
}

// SSOSessionStore persists server-side console sessions.
type SSOSessionStore interface {
	CreateSSOSession(ctx context.Context, session *SSOSession) error
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
type DirectoryStore interface {
	ListDirectoryUsers(ctx context.Context, query DirectoryUserQuery) ([]DirectoryUser, int, error)
	GetDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string) (*DirectoryUser, error)
	CreateDirectoryUser(ctx context.Context, user *DirectoryUser) error
	UpdateDirectoryUser(ctx context.Context, user *DirectoryUser) error
	DeleteDirectoryUser(ctx context.Context, tenantID string, connectionID string, userID string) error
	ListDirectoryGroups(ctx context.Context, query DirectoryGroupQuery) ([]DirectoryGroup, int, error)
	GetDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string) (*DirectoryGroup, error)
	CreateDirectoryGroup(ctx context.Context, group *DirectoryGroup) error
	UpdateDirectoryGroup(ctx context.Context, group *DirectoryGroup) error
	DeleteDirectoryGroup(ctx context.Context, tenantID string, connectionID string, groupID string) error
}

// IdentitySSOStore is the full web console SSO state capability. State stores
// implement it as an optional capability discovered via type assertion.
type IdentitySSOStore interface {
	SSOConnectionStore
	SSOSessionStore
	SCIMTokenStore
	DirectoryStore
}
