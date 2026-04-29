package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var ensureProjectionStatements = []string{
	`CREATE TABLE IF NOT EXISTS entities (
  urn TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  label TEXT NOT NULL,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS entities_tenant_type_idx ON entities (tenant_id, entity_type)`,
	`CREATE TABLE IF NOT EXISTS entity_links (
  from_urn TEXT NOT NULL,
  relation TEXT NOT NULL,
  to_urn TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (from_urn, relation, to_urn)
)`,
	`CREATE INDEX IF NOT EXISTS entity_links_tenant_relation_idx ON entity_links (tenant_id, relation)`,
}

// UpsertProjectedEntity persists one normalized entity in the current-state store.
func (s *Store) UpsertProjectedEntity(ctx context.Context, entity *ports.ProjectedEntity) error {
	if entity == nil {
		return errors.New("projected entity is required")
	}
	urn := strings.TrimSpace(entity.URN)
	if urn == "" {
		return errors.New("projected entity urn is required")
	}
	tenantID := strings.TrimSpace(entity.TenantID)
	if tenantID == "" {
		return errors.New("projected entity tenant id is required")
	}
	sourceID := strings.TrimSpace(entity.SourceID)
	if sourceID == "" {
		return errors.New("projected entity source id is required")
	}
	entityType := strings.TrimSpace(entity.EntityType)
	if entityType == "" {
		return errors.New("projected entity type is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return err
	}
	attributesJSON, err := projectionAttributesJSON(entity.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected entity attributes: %w", err)
	}
	label := strings.TrimSpace(entity.Label)
	if label == "" {
		label = urn
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO entities (urn, tenant_id, source_id, entity_type, label, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (urn)
DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  source_id = EXCLUDED.source_id,
  entity_type = EXCLUDED.entity_type,
  label = EXCLUDED.label,
  attributes_json = entities.attributes_json || EXCLUDED.attributes_json,
  updated_at = NOW()`, urn, tenantID, sourceID, entityType, label, attributesJSON); err != nil {
		return fmt.Errorf("upsert projected entity %q: %w", urn, err)
	}
	return nil
}

// UpsertProjectedLink persists one normalized link in the current-state store.
func (s *Store) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	if link == nil {
		return errors.New("projected link is required")
	}
	fromURN := strings.TrimSpace(link.FromURN)
	if fromURN == "" {
		return errors.New("projected link from urn is required")
	}
	toURN := strings.TrimSpace(link.ToURN)
	if toURN == "" {
		return errors.New("projected link to urn is required")
	}
	relation := strings.TrimSpace(link.Relation)
	if relation == "" {
		return errors.New("projected link relation is required")
	}
	tenantID := strings.TrimSpace(link.TenantID)
	if tenantID == "" {
		return errors.New("projected link tenant id is required")
	}
	sourceID := strings.TrimSpace(link.SourceID)
	if sourceID == "" {
		return errors.New("projected link source id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return err
	}
	attributesJSON, err := projectionAttributesJSON(link.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected link attributes: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (from_urn, relation, to_urn)
DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  source_id = EXCLUDED.source_id,
  attributes_json = EXCLUDED.attributes_json,
  updated_at = NOW()`, fromURN, relation, toURN, tenantID, sourceID, attributesJSON); err != nil {
		return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

func (s *Store) ensureProjectionTables(ctx context.Context) error {
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.projectionTablesReady {
		return nil
	}
	for _, statement := range ensureProjectionStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure projection tables: %w", err)
		}
	}
	s.projectionTablesReady = true
	return nil
}

func projectionAttributesJSON(attributes map[string]string) (string, error) {
	if len(attributes) == 0 {
		return `{}`, nil
	}
	payload, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}
