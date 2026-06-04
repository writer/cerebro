package ports

import (
	"context"
	"errors"
	"time"
)

var ErrRuntimeBlocklistEntryNotFound = errors.New("runtime blocklist entry not found")

type RuntimeBlocklistEntry struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Type        string            `json:"type"`
	Value       string            `json:"value"`
	Reason      string            `json:"reason,omitempty"`
	Source      string            `json:"source,omitempty"`
	SourceJobID string            `json:"source_job_id,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	RevokedAt   time.Time         `json:"revoked_at,omitempty"`
}

type RuntimeBlocklistFilter struct {
	TenantID       string
	Type           string
	IncludeRevoked bool
	Limit          uint32
}

type RuntimeBlocklistStore interface {
	StateStore
	PutRuntimeBlocklistEntry(context.Context, RuntimeBlocklistEntry) (*RuntimeBlocklistEntry, error)
	ListRuntimeBlocklistEntries(context.Context, RuntimeBlocklistFilter) ([]*RuntimeBlocklistEntry, error)
	RevokeRuntimeBlocklistEntry(context.Context, string, string) (*RuntimeBlocklistEntry, error)
}
