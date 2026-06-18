package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const defaultProjectionCleanupLimit = 1000

var ensureProjectionStatements = []string{
	`CREATE TABLE IF NOT EXISTS entities (
  urn TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  entity_type TEXT NOT NULL,
  label TEXT NOT NULL,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS entities_tenant_type_idx ON entities (tenant_id, entity_type)`,
	`ALTER TABLE entities ADD COLUMN IF NOT EXISTS runtime_id TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS entities_tenant_runtime_idx ON entities (tenant_id, runtime_id)`,
	`CREATE INDEX IF NOT EXISTS entities_runtime_evidence_source_event_idx ON entities (tenant_id, runtime_id, (attributes_json ->> 'source_event_id')) WHERE entity_type = 'runtime.evidence'`,
	`CREATE TABLE IF NOT EXISTS entity_links (
  from_urn TEXT NOT NULL,
  relation TEXT NOT NULL,
  to_urn TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (from_urn, relation, to_urn)
)`,
	`CREATE INDEX IF NOT EXISTS entity_links_tenant_relation_idx ON entity_links (tenant_id, relation)`,
	`CREATE INDEX IF NOT EXISTS entity_links_to_urn_idx ON entity_links (to_urn)`,
	`ALTER TABLE entity_links ADD COLUMN IF NOT EXISTS runtime_id TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS entity_links_tenant_runtime_idx ON entity_links (tenant_id, runtime_id)`,
}

func projectedEntityUpsertSQL() string {
	return `
INSERT INTO entities (urn, tenant_id, source_id, runtime_id, entity_type, label, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
ON CONFLICT (urn)
DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  source_id = EXCLUDED.source_id,
  runtime_id = CASE WHEN EXCLUDED.runtime_id <> '' THEN EXCLUDED.runtime_id ELSE entities.runtime_id END,
  entity_type = EXCLUDED.entity_type,
  label = CASE WHEN EXCLUDED.label = EXCLUDED.urn THEN entities.label ELSE EXCLUDED.label END,
  attributes_json = entities.attributes_json || EXCLUDED.attributes_json,
  updated_at = NOW()`
}

func projectedLinkUpsertSQL() string {
	return `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, source_id, runtime_id, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
ON CONFLICT (from_urn, relation, to_urn)
DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  source_id = EXCLUDED.source_id,
  runtime_id = CASE WHEN EXCLUDED.runtime_id <> '' THEN EXCLUDED.runtime_id ELSE entity_links.runtime_id END,
  attributes_json = entity_links.attributes_json || EXCLUDED.attributes_json,
  updated_at = NOW()`
}

func projectedLinkDeleteSQL() string {
	return `
DELETE FROM entity_links
WHERE from_urn = $1 AND relation = $2 AND to_urn = $3`
}

func projectedEntityLinkDeleteSQL() string {
	return `
DELETE FROM entity_links
WHERE from_urn = $1 OR to_urn = $1`
}

func projectedEntityDeleteSQL() string {
	return `
DELETE FROM entities
WHERE urn = $1`
}

func projectedEntityGetSQL() string {
	return `
SELECT urn, tenant_id, source_id, runtime_id, entity_type, label, attributes_json
FROM entities
WHERE urn = $1`
}

func projectedRuntimeEvidenceBySourceEventSQL() string {
	return `
SELECT urn, tenant_id, source_id, runtime_id, entity_type, label, attributes_json
FROM entities
WHERE tenant_id = $1
  AND entity_type = 'runtime.evidence'
  AND (runtime_id = $2 OR attributes_json ->> 'source_runtime_id' = $2)
  AND attributes_json ->> 'source_event_id' = $3
ORDER BY updated_at DESC, urn
LIMIT 1`
}

func projectedEntityCleanupSQL(request ports.ProjectionCleanupRequest) (string, []any, error) {
	conditions, args, scoped := projectedEntityCleanupConditions(request)
	if !scoped {
		return "", nil, errors.New("projection cleanup scope is required")
	}
	limit := request.Limit
	if limit == 0 {
		limit = defaultProjectionCleanupLimit
	}
	args = append(args, limit)
	limitPlaceholder := len(args)
	query := fmt.Sprintf(`
WITH victims AS (
  SELECT e.urn
  FROM entities e
  WHERE %s
  ORDER BY e.urn
  LIMIT $%d
),
matched_links AS (
  SELECT COUNT(DISTINCT (l.from_urn, l.relation, l.to_urn)) AS count
  FROM entity_links l
  JOIN victims v ON l.from_urn = v.urn OR l.to_urn = v.urn
)
`, strings.Join(conditions, " AND "), limitPlaceholder)
	if request.DryRun {
		return query + `
SELECT
  (SELECT COUNT(*) FROM victims) AS entities_matched,
  (SELECT count FROM matched_links) AS links_matched,
  0 AS entities_deleted,
  0 AS links_deleted`, args, nil
	}
	query += `
,
deleted_links AS (
  DELETE FROM entity_links l
  USING victims v
  WHERE l.from_urn = v.urn OR l.to_urn = v.urn
  RETURNING 1
),
deleted_entities AS (
  DELETE FROM entities e
  USING victims v
  WHERE e.urn = v.urn
  RETURNING 1
)
SELECT
  (SELECT COUNT(*) FROM deleted_entities) AS entities_matched,
  (SELECT count FROM matched_links) AS links_matched,
  (SELECT COUNT(*) FROM deleted_entities) AS entities_deleted,
  (SELECT COUNT(*) FROM deleted_links) AS links_deleted`
	return query, args, nil
}

func projectedEntityCleanupConditions(request ports.ProjectionCleanupRequest) ([]string, []any, bool) {
	conditions := []string{}
	args := []any{}
	scoped := false
	addStringCondition := func(column string, value string) {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			return
		}
		args = append(args, normalized)
		conditions = append(conditions, fmt.Sprintf("e.%s = $%d", column, len(args)))
		scoped = true
	}
	addStringCondition("tenant_id", request.TenantID)
	addStringCondition("source_id", request.SourceID)
	addStringCondition("runtime_id", request.RuntimeID)
	if findingID := strings.TrimSpace(request.FindingID); findingID != "" {
		args = append(args, findingID)
		conditions = append(conditions, fmt.Sprintf("e.attributes_json ->> 'finding_id' = $%d", len(args)))
		scoped = true
	}
	if entityTypes := normalizeProjectionCleanupValues(request.EntityTypes); len(entityTypes) != 0 {
		placeholders := make([]string, 0, len(entityTypes))
		for _, entityType := range entityTypes {
			args = append(args, entityType)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
		}
		conditions = append(conditions, fmt.Sprintf("e.entity_type IN (%s)", strings.Join(placeholders, ", ")))
		scoped = true
	}
	if urnPrefixes := normalizeProjectionCleanupValues(request.URNPrefixes); len(urnPrefixes) != 0 {
		prefixConditions := make([]string, 0, len(urnPrefixes))
		for _, urnPrefix := range urnPrefixes {
			args = append(args, urnPrefix)
			prefixConditions = append(prefixConditions, fmt.Sprintf("LEFT(e.urn, LENGTH($%d)) = $%d", len(args), len(args)))
		}
		conditions = append(conditions, "("+strings.Join(prefixConditions, " OR ")+")")
		scoped = true
	}
	if request.OnlyIsolated && strings.TrimSpace(request.FindingID) == "" {
		conditions = append(conditions, "NOT EXISTS (SELECT 1 FROM entity_links l WHERE l.from_urn = e.urn OR l.to_urn = e.urn)")
	}
	return conditions, args, scoped
}

func projectedEndpointOwnerIDLinkCleanupSQL(request ports.ProjectionLinkCleanupRequest) (string, []any, error) {
	conditions, replacementConditions, args, stalePrefixes, replacementPrefixes, err := projectedEndpointOwnerIDLinkCleanupConditions(request)
	if err != nil {
		return "", nil, err
	}
	suffixCondition := projectedEndpointOwnerIDReplacementSuffixCondition(stalePrefixes, replacementPrefixes, &args)
	args = append(args, requestLimit(request.Limit))
	limitPlaceholder := len(args)
	victims := fmt.Sprintf(`
WITH victims AS (
  SELECT DISTINCT l.from_urn, l.relation, l.to_urn
  FROM entity_links l
  JOIN entities e ON e.urn = l.from_urn
  WHERE %s
    AND EXISTS (
      SELECT 1
      FROM entity_links replacement
      WHERE replacement.from_urn = l.from_urn
        AND replacement.tenant_id = l.tenant_id
        AND replacement.relation = 'has_identifier'
        AND %s
        AND %s
    )
  ORDER BY l.from_urn, l.relation, l.to_urn
  LIMIT $%d
)`, strings.Join(conditions, " AND "), strings.Join(replacementConditions, " AND "), suffixCondition, limitPlaceholder)
	if request.DryRun {
		return victims + `
SELECT COUNT(*) AS links_matched, 0 AS links_deleted
FROM victims`, args, nil
	}
	return victims + `
, deleted_links AS (
  DELETE FROM entity_links l
  USING victims v
  WHERE l.from_urn = v.from_urn AND l.relation = v.relation AND l.to_urn = v.to_urn
  RETURNING 1
)
SELECT
  (SELECT COUNT(*) FROM victims) AS links_matched,
  (SELECT COUNT(*) FROM deleted_links) AS links_deleted`, args, nil
}

func projectedEndpointOwnerIDLinkCleanupConditions(request ports.ProjectionLinkCleanupRequest) ([]string, []string, []any, []string, []string, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, nil, nil, nil, nil, errors.New("tenant_id is required for endpoint owner-id link cleanup")
	}
	sources := endpointOwnerIDCleanupSources(request.SourceID)
	if len(sources) == 0 {
		return nil, nil, nil, nil, nil, errors.New("unsupported endpoint owner-id cleanup source")
	}
	stalePrefixes, replacementPrefixes := endpointOwnerIDCleanupPrefixes(tenantID, sources)
	args := []any{tenantID}
	conditions := []string{
		"l.tenant_id = $1",
		"e.tenant_id = $1",
		"e.entity_type IN ('kolide.device', 'kandji.device')",
		"l.relation IN ('owned_by', 'represents_identity', 'has_identifier')",
		projectedPrefixCondition("l.to_urn", stalePrefixes, &args),
	}
	sourcePlaceholders := make([]string, 0, len(sources))
	for _, source := range sources {
		args = append(args, source)
		sourcePlaceholders = append(sourcePlaceholders, fmt.Sprintf("$%d", len(args)))
	}
	conditions = append(conditions,
		fmt.Sprintf("l.source_id IN (%s)", strings.Join(sourcePlaceholders, ", ")),
		fmt.Sprintf("e.source_id IN (%s)", strings.Join(sourcePlaceholders, ", ")),
	)
	replacementConditions := []string{fmt.Sprintf("replacement.source_id IN (%s)", strings.Join(sourcePlaceholders, ", "))}
	if runtimeID := strings.TrimSpace(request.RuntimeID); runtimeID != "" {
		args = append(args, runtimeID)
		conditions = append(conditions, fmt.Sprintf("l.runtime_id = $%d", len(args)))
	}
	return conditions, replacementConditions, args, stalePrefixes, replacementPrefixes, nil
}

func projectedEndpointOwnerIDReplacementSuffixCondition(stalePrefixes []string, replacementPrefixes []string, args *[]any) string {
	pairs := make([]string, 0, len(stalePrefixes)*len(replacementPrefixes))
	for _, stalePrefix := range stalePrefixes {
		for _, replacementPrefix := range replacementPrefixes {
			*args = append(*args, stalePrefix)
			stalePlaceholder := len(*args)
			*args = append(*args, replacementPrefix)
			replacementPlaceholder := len(*args)
			pairs = append(pairs, fmt.Sprintf("(LEFT(l.to_urn, LENGTH($%[1]d)) = $%[1]d AND LEFT(replacement.to_urn, LENGTH($%[2]d)) = $%[2]d AND SUBSTRING(l.to_urn FROM LENGTH($%[1]d) + 1) = SUBSTRING(replacement.to_urn FROM LENGTH($%[2]d) + 1))", stalePlaceholder, replacementPlaceholder))
		}
	}
	if len(pairs) == 0 {
		return "FALSE"
	}
	return "(" + strings.Join(pairs, " OR ") + ")"
}

func projectedPrefixCondition(column string, prefixes []string, args *[]any) string {
	conditions := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		*args = append(*args, prefix)
		placeholder := len(*args)
		conditions = append(conditions, fmt.Sprintf("LEFT(%s, LENGTH($%d)) = $%d", column, placeholder, placeholder))
	}
	if len(conditions) == 0 {
		return "FALSE"
	}
	return "(" + strings.Join(conditions, " OR ") + ")"
}

func endpointOwnerIDCleanupSources(sourceID string) []string {
	source := strings.ToLower(strings.TrimSpace(sourceID))
	switch source {
	case "":
		return []string{"kolide", "kandji"}
	case "kolide", "kandji":
		return []string{source}
	default:
		return nil
	}
}

func endpointOwnerIDCleanupPrefixes(tenantID string, sources []string) ([]string, []string) {
	stalePrefixes := []string{
		fmt.Sprintf("urn:cerebro:%s:identity:login:", tenantID),
		fmt.Sprintf("urn:cerebro:%s:identifier:login:", tenantID),
	}
	replacementPrefixes := make([]string, 0, len(sources)*2)
	for _, source := range sources {
		replacementPrefixes = append(replacementPrefixes,
			fmt.Sprintf("urn:cerebro:%s:endpoint_identifier:%s_owner_id:", tenantID, source),
			fmt.Sprintf("urn:cerebro:%s:endpoint_identifier:%s_user_id:", tenantID, source),
		)
	}
	return stalePrefixes, replacementPrefixes
}

func requestLimit(limit uint32) uint32 {
	if limit == 0 {
		return defaultProjectionCleanupLimit
	}
	return limit
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
	if err := ports.ValidateProjectedEntityTenantScope(entity); err != nil {
		return err
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
	if _, err := s.db.ExecContext(ctx, projectedEntityUpsertSQL(), urn, tenantID, sourceID, strings.TrimSpace(entity.RuntimeID), entityType, label, attributesJSON); err != nil {
		return fmt.Errorf("upsert projected entity %q: %w", urn, err)
	}
	return nil
}

// GetProjectedEntity reads one normalized current-state entity by URN.
func (s *Store) GetProjectedEntity(ctx context.Context, urn string) (*ports.ProjectedEntity, error) {
	normalizedURN := strings.TrimSpace(urn)
	if normalizedURN == "" {
		return nil, errors.New("projected entity urn is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return nil, err
	}
	entity := &ports.ProjectedEntity{}
	var attributesRaw []byte
	err := s.db.QueryRowContext(ctx, projectedEntityGetSQL(), normalizedURN).Scan(
		&entity.URN,
		&entity.TenantID,
		&entity.SourceID,
		&entity.RuntimeID,
		&entity.EntityType,
		&entity.Label,
		&attributesRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get projected entity %q: %w", normalizedURN, err)
	}
	if len(attributesRaw) != 0 {
		if err := json.Unmarshal(attributesRaw, &entity.Attributes); err != nil {
			return nil, fmt.Errorf("decode projected entity attributes %q: %w", normalizedURN, err)
		}
	}
	if entity.Attributes == nil {
		entity.Attributes = map[string]string{}
	}
	return entity, nil
}

// GetProjectedRuntimeEvidenceBySourceEvent reads a runtime evidence entity by
// the stable source event identity used for EvidenceCAS idempotency checks.
func (s *Store) GetProjectedRuntimeEvidenceBySourceEvent(ctx context.Context, tenantID string, sourceRuntimeID string, sourceEventID string) (*ports.ProjectedEntity, error) {
	normalizedTenantID := strings.TrimSpace(tenantID)
	if normalizedTenantID == "" {
		return nil, errors.New("projected runtime evidence tenant_id is required")
	}
	normalizedSourceRuntimeID := strings.TrimSpace(sourceRuntimeID)
	if normalizedSourceRuntimeID == "" {
		return nil, errors.New("projected runtime evidence source_runtime_id is required")
	}
	normalizedSourceEventID := strings.TrimSpace(sourceEventID)
	if normalizedSourceEventID == "" {
		return nil, errors.New("projected runtime evidence source_event_id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return nil, err
	}
	entity := &ports.ProjectedEntity{}
	var attributesRaw []byte
	err := s.db.QueryRowContext(ctx, projectedRuntimeEvidenceBySourceEventSQL(), normalizedTenantID, normalizedSourceRuntimeID, normalizedSourceEventID).Scan(
		&entity.URN,
		&entity.TenantID,
		&entity.SourceID,
		&entity.RuntimeID,
		&entity.EntityType,
		&entity.Label,
		&attributesRaw,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get projected runtime evidence by source event: %w", err)
	}
	if len(attributesRaw) != 0 {
		if err := json.Unmarshal(attributesRaw, &entity.Attributes); err != nil {
			return nil, fmt.Errorf("decode projected runtime evidence attributes: %w", err)
		}
	}
	if entity.Attributes == nil {
		entity.Attributes = map[string]string{}
	}
	return entity, nil
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
	if err := ports.ValidateProjectedLinkTenantScope(link); err != nil {
		return err
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
	if _, err := s.db.ExecContext(ctx, projectedLinkUpsertSQL(), fromURN, relation, toURN, tenantID, sourceID, strings.TrimSpace(link.RuntimeID), attributesJSON); err != nil {
		return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

// DeleteProjectedLink removes one normalized link from the current-state store.
func (s *Store) DeleteProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
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
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, projectedLinkDeleteSQL(), fromURN, relation, toURN); err != nil {
		return fmt.Errorf("delete projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

// DeleteProjectedEntity removes one normalized entity and any current-state links that reference it.
func (s *Store) DeleteProjectedEntity(ctx context.Context, urn string) error {
	normalizedURN := strings.TrimSpace(urn)
	if normalizedURN == "" {
		return errors.New("projected entity urn is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin projected entity delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, projectedEntityLinkDeleteSQL(), normalizedURN); err != nil {
		return fmt.Errorf("delete projected entity links %q: %w", normalizedURN, err)
	}
	if _, err := tx.ExecContext(ctx, projectedEntityDeleteSQL(), normalizedURN); err != nil {
		return fmt.Errorf("delete projected entity %q: %w", normalizedURN, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit projected entity delete %q: %w", normalizedURN, err)
	}
	return nil
}

// CleanupProjectedEntities removes projected entities matching a scoped cleanup request.
func (s *Store) CleanupProjectedEntities(ctx context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	if s == nil || s.db == nil {
		return ports.ProjectionCleanupResult{}, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return ports.ProjectionCleanupResult{}, err
	}
	query, args, err := projectedEntityCleanupSQL(request)
	if err != nil {
		return ports.ProjectionCleanupResult{}, err
	}
	var result ports.ProjectionCleanupResult
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.EntitiesMatched, &result.LinksMatched, &result.EntitiesDeleted, &result.LinksDeleted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ports.ProjectionCleanupResult{}, nil
		}
		return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
	}
	return result, nil
}

// CleanupEndpointOwnerIDLinks removes stale endpoint owner_id/user_id canonical identity links.
func (s *Store) CleanupEndpointOwnerIDLinks(ctx context.Context, request ports.ProjectionLinkCleanupRequest) (ports.ProjectionLinkCleanupResult, error) {
	if s == nil || s.db == nil {
		return ports.ProjectionLinkCleanupResult{}, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	query, args, err := projectedEndpointOwnerIDLinkCleanupSQL(request)
	if err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	var result ports.ProjectionLinkCleanupResult
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&result.LinksMatched, &result.LinksDeleted); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ports.ProjectionLinkCleanupResult{}, nil
		}
		return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
	}
	return result, nil
}

func (s *Store) ensureProjectionTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.projectionTablesReady, "projection", ensureProjectionStatements)
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

func normalizeProjectionCleanupValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}
