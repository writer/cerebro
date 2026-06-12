package ports

import (
	"context"
	"time"
)

const (
	GRCInventoryScopeStateIn  = "in_scope"
	GRCInventoryScopeStateOut = "out_of_scope"
)

type GRCInventoryScopeRecord struct {
	TenantID   string            `json:"tenant_id"`
	AssetURN   string            `json:"asset_urn"`
	SourceID   string            `json:"source_id,omitempty"`
	ScopeState string            `json:"scope_state"`
	Reason     string            `json:"reason,omitempty"`
	UpdatedBy  string            `json:"updated_by,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type GRCInventoryScopeFilter struct {
	TenantID   string
	AssetURNs  []string
	SourceID   string
	ScopeState string
	Limit      uint32
}

type GRCInventoryScopeStore interface {
	StateStore
	UpsertGRCInventoryScope(context.Context, GRCInventoryScopeRecord) (*GRCInventoryScopeRecord, error)
	ListGRCInventoryScopes(context.Context, GRCInventoryScopeFilter) ([]*GRCInventoryScopeRecord, error)
}
