package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var _ ports.CustomFindingRuleStore = (*Store)(nil)

const maxCustomFindingRulesPerTenant = 1000

var ensureCustomFindingRulesStatements = []string{
	`CREATE TABLE IF NOT EXISTS custom_finding_rules (
  tenant_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  document TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, rule_id)
)`,
}

const customFindingRuleColumns = `tenant_id, rule_id, document, created_by, updated_by, created_at, updated_at`

func (s *Store) ensureCustomFindingRulesTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.settings.customFindingRules, "custom finding rules", ensureCustomFindingRulesStatements)
}

// ListCustomFindingRules returns one tenant's custom rules ordered by ID.
func (s *Store) ListCustomFindingRules(ctx context.Context, tenantID string) ([]ports.CustomFindingRule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("custom finding rule tenant_id is required")
	}
	if err := s.ensureCustomFindingRulesTable(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- column list and limit are fixed constants; tenant remains parameterized.
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM custom_finding_rules WHERE tenant_id = $1 ORDER BY rule_id LIMIT %d", customFindingRuleColumns, maxCustomFindingRulesPerTenant), tenantID)
	if err != nil {
		return nil, fmt.Errorf("list custom finding rules for tenant %q: %w", tenantID, err)
	}
	defer func() { _ = rows.Close() }()
	rules := []ports.CustomFindingRule{}
	for rows.Next() {
		rule, err := scanCustomFindingRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan custom finding rule: %w", err)
		}
		rules = append(rules, *rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list custom finding rules for tenant %q: %w", tenantID, err)
	}
	return rules, nil
}

// GetCustomFindingRule loads one custom rule.
func (s *Store) GetCustomFindingRule(ctx context.Context, tenantID string, ruleID string) (*ports.CustomFindingRule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	ruleID = strings.TrimSpace(ruleID)
	if tenantID == "" || ruleID == "" {
		return nil, errors.New("custom finding rule tenant_id and id are required")
	}
	if err := s.ensureCustomFindingRulesTable(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- column list is a fixed constant; identifiers remain parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM custom_finding_rules WHERE tenant_id = $1 AND rule_id = $2", customFindingRuleColumns), tenantID, ruleID)
	rule, err := scanCustomFindingRule(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrCustomFindingRuleNotFound, ruleID)
		}
		return nil, fmt.Errorf("query custom finding rule %q: %w", ruleID, err)
	}
	return rule, nil
}

// PutCustomFindingRule upserts one custom rule, preserving its creator.
func (s *Store) PutCustomFindingRule(ctx context.Context, rule *ports.CustomFindingRule) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if rule == nil {
		return errors.New("custom finding rule is required")
	}
	tenantID := strings.TrimSpace(rule.TenantID)
	ruleID := strings.TrimSpace(rule.ID)
	if tenantID == "" || ruleID == "" {
		return errors.New("custom finding rule tenant_id and id are required")
	}
	if strings.TrimSpace(rule.Document) == "" {
		return errors.New("custom finding rule document is required")
	}
	if err := s.ensureCustomFindingRulesTable(ctx); err != nil {
		return err
	}
	updatedBy := strings.TrimSpace(rule.UpdatedBy)
	createdBy := firstNonEmptyPostgres(strings.TrimSpace(rule.CreatedBy), updatedBy)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO custom_finding_rules (tenant_id, rule_id, document, created_by, updated_by)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, rule_id) DO UPDATE SET
  document = EXCLUDED.document,
  updated_by = EXCLUDED.updated_by,
  updated_at = NOW()`, tenantID, ruleID, rule.Document, createdBy, updatedBy); err != nil {
		return fmt.Errorf("upsert custom finding rule %q: %w", ruleID, err)
	}
	return nil
}

// DeleteCustomFindingRule removes one custom rule.
func (s *Store) DeleteCustomFindingRule(ctx context.Context, tenantID string, ruleID string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	tenantID = strings.TrimSpace(tenantID)
	ruleID = strings.TrimSpace(ruleID)
	if tenantID == "" || ruleID == "" {
		return errors.New("custom finding rule tenant_id and id are required")
	}
	if err := s.ensureCustomFindingRulesTable(ctx); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM custom_finding_rules WHERE tenant_id = $1 AND rule_id = $2`, tenantID, ruleID)
	if err != nil {
		return fmt.Errorf("delete custom finding rule %q: %w", ruleID, err)
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return fmt.Errorf("%w: %s", ports.ErrCustomFindingRuleNotFound, ruleID)
	}
	return nil
}

func scanCustomFindingRule(row scanner) (*ports.CustomFindingRule, error) {
	var rule ports.CustomFindingRule
	var createdAt sql.NullTime
	var updatedAt sql.NullTime
	if err := row.Scan(&rule.TenantID, &rule.ID, &rule.Document, &rule.CreatedBy, &rule.UpdatedBy, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	if createdAt.Valid {
		rule.CreatedAt = createdAt.Time.UTC()
	}
	if updatedAt.Valid {
		rule.UpdatedAt = updatedAt.Time.UTC()
	}
	return &rule, nil
}
