package ports

import (
	"context"
	"errors"
	"time"
)

// ErrComplianceFrameworkSettingsNotFound indicates that a tenant has not saved
// a framework selection yet.
var ErrComplianceFrameworkSettingsNotFound = errors.New("compliance framework settings not found")

// ComplianceFrameworkSettings records which built-in compliance frameworks a
// tenant measures its findings against. Framework names are canonical catalog
// names because finding control refs join on framework_name.
type ComplianceFrameworkSettings struct {
	TenantID          string    `json:"tenant_id"`
	EnabledFrameworks []string  `json:"enabled_frameworks"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
}

// ComplianceFrameworkSettingsStore persists tenant-scoped framework selections.
// State stores implement it as an optional capability discovered via type
// assertion.
type ComplianceFrameworkSettingsStore interface {
	PutComplianceFrameworkSettings(context.Context, *ComplianceFrameworkSettings) error
	GetComplianceFrameworkSettings(context.Context, string) (*ComplianceFrameworkSettings, error)
}
