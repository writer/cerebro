package ports

import (
	"context"
	"errors"
	"time"
)

var ErrCustomDashboardNotFound = errors.New("custom dashboard not found")

type CustomDashboard struct {
	ID             string
	TenantID       string
	OrganizationID string
	WorkspaceID    string
	OwnerUserID    string
	Name           string
	Description    string
	Visibility     string
	SchemaVersion  int
	LayoutJSON     string
	WidgetsJSON    string
	FiltersJSON    string
	CreatedBy      string
	UpdatedBy      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ArchivedAt     time.Time
}

type CustomDashboardFilter struct {
	TenantID       string
	OrganizationID string
	WorkspaceID    string
	OwnerUserID    string
	// ViewerUserID, when set, restricts private dashboards to the viewer so
	// visibility is enforced in the query rather than only in memory after a
	// LIMIT has already been applied.
	ViewerUserID    string
	IncludeArchived bool
	Limit           uint32
}

type CustomDashboardStore interface {
	PutCustomDashboard(context.Context, *CustomDashboard) error
	GetCustomDashboard(context.Context, string) (*CustomDashboard, error)
	ListCustomDashboards(context.Context, CustomDashboardFilter) ([]*CustomDashboard, error)
	DeleteCustomDashboard(context.Context, string) error
}
