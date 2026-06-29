package ports

import (
	"context"
	"time"
)

// IdentityOrganization is a product organization Cerebro can authorize and show
// in the console. TenantID remains the enforcement boundary; OrgID is the
// operator-facing organization key inside that tenant.
type IdentityOrganization struct {
	OrgID        string
	TenantID     string
	Name         string
	Slug         string
	Domain       string
	Provider     string
	Source       string
	ExternalID   string
	UserCount    int
	LastSyncedAt time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IdentityUser is a product user associated with a Cerebro organization.
type IdentityUser struct {
	UserID       string
	TenantID     string
	OrgID        string
	Subject      string
	Email        string
	DisplayName  string
	Status       string
	Provider     string
	Source       string
	Roles        []string
	Groups       []string
	LastSeenAt   time.Time
	LastSyncedAt time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type IdentityOrganizationFilter struct {
	TenantID string
	OrgID    string
	Query    string
	Limit    uint32
}

type IdentityUserFilter struct {
	TenantID string
	OrgID    string
	UserID   string
	Query    string
	Limit    uint32
}

// IdentityDirectoryStore persists users and organizations learned from auth
// flows or operator-configured identity sources.
type IdentityDirectoryStore interface {
	StateStore
	UpsertIdentityOrganization(context.Context, *IdentityOrganization) error
	UpsertIdentityUser(context.Context, *IdentityUser) error
	ListIdentityOrganizations(context.Context, IdentityOrganizationFilter) ([]*IdentityOrganization, error)
	ListIdentityUsers(context.Context, IdentityUserFilter) ([]*IdentityUser, error)
}
