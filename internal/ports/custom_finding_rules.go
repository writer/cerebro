package ports

import (
	"context"
	"errors"
	"time"
)

// ErrCustomFindingRuleNotFound indicates that a tenant has no saved custom
// rule with the requested ID.
var ErrCustomFindingRuleNotFound = errors.New("custom finding rule not found")

// CustomFindingRule is one operator-authored PolicyFindingRule document.
// Document holds canonical YAML that has already passed DSL validation.
type CustomFindingRule struct {
	TenantID  string    `json:"tenant_id"`
	ID        string    `json:"id"`
	Document  string    `json:"document"`
	CreatedBy string    `json:"created_by,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// CustomFindingRuleStore persists tenant-scoped custom rule documents. State
// stores implement it as an optional capability discovered via type assertion.
type CustomFindingRuleStore interface {
	ListCustomFindingRules(context.Context, string) ([]CustomFindingRule, error)
	GetCustomFindingRule(context.Context, string, string) (*CustomFindingRule, error)
	PutCustomFindingRule(context.Context, *CustomFindingRule) error
	DeleteCustomFindingRule(context.Context, string, string) error
}
