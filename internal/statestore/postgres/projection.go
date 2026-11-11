package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/projectionmeta"
)

const defaultProjectionCleanupLimit = 1000

// errProjectionAssertionMigrationScopeRequired guards
// CountProjectedLinksMissingAssertions/MigrateProjectedLinkAssertions
// against an unbounded, tenant-less scan.
var errProjectionAssertionMigrationScopeRequired = errors.New("tenant_id and relations are required for projected link assertion migration")

// ensureProjectionStatements is applied through ensureStatements, which is
// idempotent on databases that already have the old tables: every
// statement here is IF NOT EXISTS/ADD COLUMN IF NOT EXISTS, so re-running it
// against a pre-F06 schema only adds the new assertion table and the two
// new entity_links columns without touching existing rows.
//
// F06: entity_links alone cannot preserve two independent source/runtime
// assertions of the same (from_urn, relation, to_urn) edge, because its
// primary key collapses them into one last-writer row. entity_link_assertions
// adds a second table keyed by (from_urn, relation, to_urn, tenant_id,
// source_id, runtime_id) so every assertion survives independently; the
// entity_links row becomes a materialized view of whichever assertion
// currently wins (see reconcileProjectedLink), identified by
// assertion_managed. Pre-existing entity_links rows default to
// assertion_managed = false (no assertion ever backs them): they are
// legacy facts that predate this model and are never rehydrated or
// deleted by assertion-based reconciliation; see
// CountProjectedLinksMissingAssertions and MigrateProjectedLinkAssertions
// for the bounded, conservative migration/quarantine policy that covers
// them without inventing provenance.
var ensureProjectionStatements = []string{
	`CREATE TABLE IF NOT EXISTS entities (
  urn TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  application_workspace_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  entity_type TEXT NOT NULL,
  label TEXT NOT NULL,
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS entities_tenant_type_idx ON entities (tenant_id, entity_type)`,
	`ALTER TABLE entities ADD COLUMN IF NOT EXISTS application_workspace_id TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS entities_tenant_workspace_type_idx ON entities (tenant_id, application_workspace_id, entity_type)`,
	`ALTER TABLE entities ADD COLUMN IF NOT EXISTS runtime_id TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS entities_tenant_runtime_idx ON entities (tenant_id, runtime_id)`,
	`CREATE INDEX IF NOT EXISTS entities_runtime_evidence_source_event_idx ON entities (tenant_id, runtime_id, (attributes_json ->> 'source_event_id')) WHERE entity_type = 'runtime.evidence'`,
	`CREATE TABLE IF NOT EXISTS entity_links (
  from_urn TEXT NOT NULL,
  relation TEXT NOT NULL,
  to_urn TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  application_workspace_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (from_urn, relation, to_urn)
)`,
	`CREATE INDEX IF NOT EXISTS entity_links_tenant_relation_idx ON entity_links (tenant_id, relation)`,
	`ALTER TABLE entity_links ADD COLUMN IF NOT EXISTS application_workspace_id TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS entity_links_tenant_workspace_relation_idx ON entity_links (tenant_id, application_workspace_id, relation)`,
	`CREATE INDEX IF NOT EXISTS entity_links_to_urn_idx ON entity_links (to_urn)`,
	`ALTER TABLE entity_links ADD COLUMN IF NOT EXISTS runtime_id TEXT NOT NULL DEFAULT ''`,
	`CREATE INDEX IF NOT EXISTS entity_links_tenant_runtime_idx ON entity_links (tenant_id, runtime_id)`,
	`ALTER TABLE entity_links ADD COLUMN IF NOT EXISTS assertion_managed BOOLEAN NOT NULL DEFAULT false`,
	`ALTER TABLE entity_links ADD COLUMN IF NOT EXISTS assertion_quarantined BOOLEAN NOT NULL DEFAULT false`,
	`CREATE INDEX IF NOT EXISTS entity_links_unmanaged_idx ON entity_links (tenant_id, relation) WHERE NOT assertion_managed`,
	`CREATE TABLE IF NOT EXISTS entity_link_assertions (
  from_urn TEXT NOT NULL,
  relation TEXT NOT NULL,
  to_urn TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  application_workspace_id TEXT NOT NULL DEFAULT '',
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  attributes_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (from_urn, relation, to_urn, tenant_id, source_id, runtime_id)
)`,
	`CREATE INDEX IF NOT EXISTS entity_link_assertions_logical_idx ON entity_link_assertions (from_urn, relation, to_urn, tenant_id)`,
	`CREATE INDEX IF NOT EXISTS entity_link_assertions_to_urn_idx ON entity_link_assertions (to_urn)`,
	`CREATE INDEX IF NOT EXISTS entity_link_assertions_tenant_scope_idx ON entity_link_assertions (tenant_id, source_id, runtime_id)`,
	`CREATE TABLE IF NOT EXISTS link_set_observations (
  owner_urn TEXT NOT NULL,
  relation TEXT NOT NULL,
  outgoing BOOLEAN NOT NULL,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  observation_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (owner_urn, relation, outgoing, tenant_id, source_id, runtime_id)
)`,
}

// projectedLinkAssertionUpsertSQL upserts one independent (tenant, source,
// runtime) assertion of a logical link. Unlike the old entity_links upsert,
// no cross-tenant/workspace conflict guard is needed here: the primary key
// already scopes each row to exactly one writer, so two different
// tenants/sources/runtimes asserting the "same" (from_urn, relation, to_urn)
// triple simply get independent rows rather than colliding. The shared
// logical entity_links row's own tenant/workspace conflict guard is
// enforced by reconcileProjectedLink instead.
func projectedLinkAssertionUpsertSQL() string {
	return `
INSERT INTO entity_link_assertions (from_urn, relation, to_urn, tenant_id, application_workspace_id, source_id, runtime_id, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
ON CONFLICT (from_urn, relation, to_urn, tenant_id, source_id, runtime_id)
DO UPDATE SET
  application_workspace_id = CASE WHEN EXCLUDED.application_workspace_id <> '' THEN EXCLUDED.application_workspace_id ELSE entity_link_assertions.application_workspace_id END,
  attributes_json = entity_link_assertions.attributes_json || EXCLUDED.attributes_json,
  updated_at = NOW()`
}

func projectedEntityGetSQL() string {
	return `
SELECT urn, tenant_id, application_workspace_id, source_id, runtime_id, entity_type, label, attributes_json
FROM entities
WHERE urn = $1`
}

func projectedRuntimeEvidenceBySourceEventSQL() string {
	return `
SELECT urn, tenant_id, application_workspace_id, source_id, runtime_id, entity_type, label, attributes_json
FROM entities
WHERE tenant_id = $1
  AND entity_type = 'runtime.evidence'
  AND (runtime_id = $2 OR attributes_json ->> 'source_runtime_id' = $2)
  AND attributes_json ->> 'source_event_id' = $3
ORDER BY updated_at DESC, urn
LIMIT 1`
}

// projectedEntityCleanupCandidatesSQL selects only the candidate entity
// URNs matching a scoped cleanup request. Deletion itself (assertion
// retraction, logical-link reconciliation, and isolated-entity removal) is
// orchestrated in Go by CleanupProjectedEntities so it can keep
// entity_link_assertions and entity_links consistent instead of a single
// opaque multi-table SQL statement.
func projectedEntityCleanupCandidatesSQL(request ports.ProjectionCleanupRequest) (string, []any, error) {
	conditions, args, scoped := projectedEntityCleanupConditions(request)
	if !scoped {
		return "", nil, errors.New("projection cleanup scope is required")
	}
	limit := request.Limit
	if limit == 0 {
		limit = defaultProjectionCleanupLimit
	}
	tenantID := strings.TrimSpace(request.TenantID)
	sourceID := strings.TrimSpace(request.SourceID)
	runtimeID := strings.TrimSpace(request.RuntimeID)
	orderBy := "e.urn"
	if tenantID != "" && sourceID != "" {
		// GraphReview issue 3: an entity a quarantined legacy row keeps
		// alive, or one another source/runtime's own coverage keeps
		// alive, can never be deleted by this exact pass regardless of
		// how many times it is reselected. Ordering those candidates
		// after the ones this pass can actually finish keeps bounded
		// pagination (a small limit especially) making real progress
		// instead of reselecting the same permanently-blocked entity
		// forever while reporting it as "matched" either way.
		args = append(args, tenantID, sourceID, runtimeID)
		n1, n2, n3 := len(args)-2, len(args)-1, len(args)
		orderBy = fmt.Sprintf(`(
  EXISTS (
    SELECT 1 FROM entity_links l
    WHERE (l.from_urn = e.urn OR l.to_urn = e.urn)
      AND (l.assertion_quarantined OR l.tenant_id <> $%d OR l.source_id <> $%d OR l.runtime_id <> $%d)
  )
  OR EXISTS (
    SELECT 1 FROM entity_link_assertions a
    WHERE (a.from_urn = e.urn OR a.to_urn = e.urn)
      AND (a.tenant_id <> $%d OR a.source_id <> $%d OR a.runtime_id <> $%d)
  )
), e.urn`, n1, n2, n3, n1, n2, n3)
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT e.urn
FROM entities e
WHERE %s
ORDER BY %s
LIMIT $%d`, strings.Join(conditions, " AND "), orderBy, len(args))
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
		conditions = append(conditions,
			"NOT EXISTS (SELECT 1 FROM entity_links l WHERE l.from_urn = e.urn OR l.to_urn = e.urn)",
			"NOT EXISTS (SELECT 1 FROM entity_link_assertions a WHERE a.from_urn = e.urn OR a.to_urn = e.urn)",
		)
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
	// l now denotes entity_link_assertions (the per-source/runtime
	// assertion rows), not the shared entity_links logical row: deleting
	// a stale assertion must never remove another source/runtime's
	// coverage of the same logical edge. The replacement join still
	// checks the materialized entity_links view, since that is "does a
	// replacement identifier currently exist" regardless of assertion
	// bookkeeping detail.
	victims := fmt.Sprintf(`
WITH victims AS (
  SELECT DISTINCT l.from_urn, l.relation, l.to_urn, l.tenant_id, l.source_id, l.runtime_id
  FROM entity_link_assertions l
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
  ORDER BY l.from_urn, l.relation, l.to_urn, l.source_id, l.runtime_id
  LIMIT $%d
)`, strings.Join(conditions, " AND "), strings.Join(replacementConditions, " AND "), suffixCondition, limitPlaceholder)
	if request.DryRun {
		return victims + `
SELECT COUNT(*) AS links_matched, 0 AS links_deleted
FROM victims`, args, nil
	}
	return victims + `
DELETE FROM entity_link_assertions l
USING victims v
WHERE l.from_urn = v.from_urn AND l.relation = v.relation AND l.to_urn = v.to_urn
  AND l.tenant_id = v.tenant_id AND l.source_id = v.source_id AND l.runtime_id = v.runtime_id
RETURNING v.from_urn, v.relation, v.to_urn, v.tenant_id`, args, nil
}

// projectedEndpointOwnerIDLinkCleanupSelectSQL is the read-only planning
// counterpart of projectedEndpointOwnerIDLinkCleanupSQL's victims CTE
// (GraphReview issue 1/2): used to plan and lock the exact victim rows
// before any DELETE, so the subsequent mutation can be restricted to
// exactly what was planned and locked rather than re-matching the same
// broad WHERE clause a concurrent writer could also match in between.
func projectedEndpointOwnerIDLinkCleanupSelectSQL(request ports.ProjectionLinkCleanupRequest) (string, []any, error) {
	conditions, replacementConditions, args, stalePrefixes, replacementPrefixes, err := projectedEndpointOwnerIDLinkCleanupConditions(request)
	if err != nil {
		return "", nil, err
	}
	suffixCondition := projectedEndpointOwnerIDReplacementSuffixCondition(stalePrefixes, replacementPrefixes, &args)
	args = append(args, requestLimit(request.Limit))
	limitPlaceholder := len(args)
	query := fmt.Sprintf(`
SELECT DISTINCT l.from_urn, l.relation, l.to_urn, l.tenant_id, l.source_id, l.runtime_id
FROM entity_link_assertions l
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
ORDER BY l.from_urn, l.relation, l.to_urn, l.source_id, l.runtime_id
LIMIT $%d`, strings.Join(conditions, " AND "), strings.Join(replacementConditions, " AND "), suffixCondition, limitPlaceholder)
	return query, args, nil
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

// UpsertProjectedEntity persists one normalized entity in the current-state
// store, applying Contract G's G1 semantics:
//   - entity.CreateOnly creates the entity only when absent; when it is
//     already present, nothing changes (not even typed source/runtime
//     ownership, label, or attributes), and a workspace mismatch is not an
//     error.
//   - A stale strict-precedence observation (projectionmeta.StaleStrictObservation)
//     against an existing entity changes nothing at all.
//   - An accepted observation merges attributes per key, then deletes each
//     entity.RetractedAttributes key absent from the incoming Attributes. A
//     key present in Attributes is never removed.
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
	runtimeID := strings.TrimSpace(entity.RuntimeID)
	label := strings.TrimSpace(entity.Label)
	if label == "" {
		label = urn
	}
	workspaceID, err := ports.ValidateApplicationWorkspaceScope(tenantID, entity.ApplicationWorkspaceID)
	if err != nil {
		return err
	}
	attributesJSON, err := projectionAttributesJSON(entity.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected entity attributes: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin upsert projected entity %q: %w", urn, err)
	}
	defer func() { _ = tx.Rollback() }()

	insertResult, err := tx.ExecContext(ctx, `
INSERT INTO entities (urn, tenant_id, application_workspace_id, source_id, runtime_id, entity_type, label, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
ON CONFLICT (urn) DO NOTHING`, urn, tenantID, workspaceID, sourceID, runtimeID, entityType, label, attributesJSON)
	if err != nil {
		return fmt.Errorf("upsert projected entity %q: %w", urn, err)
	}
	if inserted, rowsErr := insertResult.RowsAffected(); rowsErr == nil && inserted == 1 {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit projected entity %q: %w", urn, err)
		}
		return nil
	}
	if entity.CreateOnly {
		// The entity already existed: CreateOnly changes nothing, and a
		// pre-existing entity under a different workspace is not a
		// conflict to report.
		return nil
	}

	var existingTenantID, existingWorkspaceID, existingLabel string
	var existingAttrsRaw []byte
	if err := tx.QueryRowContext(ctx, `
SELECT tenant_id, application_workspace_id, label, attributes_json
FROM entities WHERE urn = $1 FOR UPDATE`, urn).Scan(&existingTenantID, &existingWorkspaceID, &existingLabel, &existingAttrsRaw); err != nil {
		return fmt.Errorf("load projected entity %q: %w", urn, err)
	}
	if existingTenantID != "" && existingTenantID != tenantID {
		return fmt.Errorf("%w: projected entity %q", ports.ErrApplicationWorkspaceConflict, urn)
	}
	if existingWorkspaceID != "" && workspaceID != "" && existingWorkspaceID != workspaceID {
		return fmt.Errorf("%w: projected entity %q", ports.ErrApplicationWorkspaceConflict, urn)
	}
	existingAttrs, err := projectionAttributesFromJSONRaw(existingAttrsRaw)
	if err != nil {
		return fmt.Errorf("decode projected entity %q attributes: %w", urn, err)
	}
	if projectionmeta.StaleStrictObservation(existingAttrs, entity.Attributes) {
		// A stale strict-precedence observation changes nothing at all,
		// including retractions and typed owner fields.
		return nil
	}
	mergedAttributes := ports.ApplyRetractedAttributes(mergeProjectionAttributes(existingAttrs, entity.Attributes), entity.Attributes, entity.RetractedAttributes)
	mergedJSON, err := projectionAttributesJSON(mergedAttributes)
	if err != nil {
		return fmt.Errorf("marshal projected entity %q attributes: %w", urn, err)
	}
	newWorkspaceID := existingWorkspaceID
	if newWorkspaceID == "" {
		newWorkspaceID = workspaceID
	}
	newLabel := existingLabel
	if label != urn {
		newLabel = label
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE entities
SET tenant_id = $2, application_workspace_id = $3, source_id = $4,
    runtime_id = CASE WHEN $5 <> '' THEN $5 ELSE runtime_id END,
    entity_type = $6, label = $7, attributes_json = $8::jsonb, updated_at = NOW()
WHERE urn = $1`, urn, tenantID, newWorkspaceID, sourceID, runtimeID, entityType, newLabel, mergedJSON); err != nil {
		return fmt.Errorf("update projected entity %q: %w", urn, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit projected entity %q: %w", urn, err)
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
		&entity.ApplicationWorkspaceID,
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
		&entity.ApplicationWorkspaceID,
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

// UpsertProjectedLink persists one independent (tenant, source, runtime)
// assertion of a link (Contract/F06) and reconciles the shared logical
// entity_links row from whichever assertion currently survives, so
// retracting or replaying one source/runtime's assertion never affects
// another's.
func (s *Store) UpsertProjectedLink(ctx context.Context, link *ports.ProjectedLink) error {
	fromURN, toURN, relation, tenantID, sourceID, err := validateProjectedLinkForPostgres(link)
	if err != nil {
		return err
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return err
	}
	runtimeID := strings.TrimSpace(link.RuntimeID)
	workspaceID, err := ports.ValidateApplicationWorkspaceScope(tenantID, link.ApplicationWorkspaceID)
	if err != nil {
		return err
	}
	attributesJSON, err := projectionAttributesJSON(link.Attributes)
	if err != nil {
		return fmt.Errorf("marshal projected link attributes: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	defer func() { _ = tx.Rollback() }()

	// GraphReview issue 2: acquire the logical-link advisory lock before
	// the assertion row INSERT/UPDATE below, matching every other
	// assertion writer (reconcileProjectedLink, replaceProjectedLinkSet).
	// Taking the row lock first and the advisory lock only afterward (in
	// reconcileProjectedLink) let a concurrent lock-first caller for the
	// same row form a 40P01 cycle.
	if err := lockProjectedLinkKey(ctx, tx, tenantID, projectedLinkIdentity{fromURN: fromURN, relation: relation, toURN: toURN}); err != nil {
		return fmt.Errorf("lock projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	if _, err := tx.ExecContext(ctx, projectedLinkAssertionUpsertSQL(), fromURN, relation, toURN, tenantID, workspaceID, sourceID, runtimeID, attributesJSON); err != nil {
		return fmt.Errorf("upsert projected link assertion %q %q %q: %w", fromURN, relation, toURN, err)
	}
	if err := reconcileProjectedLink(ctx, tx, fromURN, relation, toURN, tenantID, workspaceID); err != nil {
		return fmt.Errorf("upsert projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

func validateProjectedLinkForPostgres(link *ports.ProjectedLink) (fromURN string, toURN string, relation string, tenantID string, sourceID string, err error) {
	if link == nil {
		return "", "", "", "", "", errors.New("projected link is required")
	}
	fromURN = strings.TrimSpace(link.FromURN)
	if fromURN == "" {
		return "", "", "", "", "", errors.New("projected link from urn is required")
	}
	toURN = strings.TrimSpace(link.ToURN)
	if toURN == "" {
		return "", "", "", "", "", errors.New("projected link to urn is required")
	}
	relation = strings.TrimSpace(link.Relation)
	if relation == "" {
		return "", "", "", "", "", errors.New("projected link relation is required")
	}
	tenantID = strings.TrimSpace(link.TenantID)
	if tenantID == "" {
		return "", "", "", "", "", errors.New("projected link tenant id is required")
	}
	sourceID = strings.TrimSpace(link.SourceID)
	if sourceID == "" {
		return "", "", "", "", "", errors.New("projected link source id is required")
	}
	if err := ports.ValidateProjectedLinkTenantScope(link); err != nil {
		return "", "", "", "", "", err
	}
	return fromURN, toURN, relation, tenantID, sourceID, nil
}

// postgresLinkAssertion is one loaded (source_id, runtime_id) assertion row
// of a logical link, used to pick the surviving assertion that materializes
// the logical entity_links row.
type postgresLinkAssertion struct {
	sourceID       string
	runtimeID      string
	workspaceID    string
	attributesJSON string
}

// projectedLinkIdentity identifies one logical link affected by a retraction
// or cleanup pass, queued for reconcileProjectedLink.
type projectedLinkIdentity struct {
	fromURN  string
	relation string
	toURN    string
}

// loadProjectedLinkAssertions loads every surviving (tenant, source,
// runtime) assertion of one logical link, scoped to tenantID (the tenant
// the caller is writing under): a different tenant's assertions of a
// colliding provider-native URN pair are never considered.
func loadProjectedLinkAssertions(ctx context.Context, tx *sql.Tx, fromURN string, relation string, toURN string, tenantID string) ([]postgresLinkAssertion, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT source_id, runtime_id, application_workspace_id, attributes_json
FROM entity_link_assertions
WHERE from_urn = $1 AND relation = $2 AND to_urn = $3 AND tenant_id = $4`, fromURN, relation, toURN, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load projected link assertions %q %q %q: %w", fromURN, relation, toURN, err)
	}
	defer func() { _ = rows.Close() }()
	var assertions []postgresLinkAssertion
	for rows.Next() {
		var a postgresLinkAssertion
		var attrsRaw []byte
		if err := rows.Scan(&a.sourceID, &a.runtimeID, &a.workspaceID, &attrsRaw); err != nil {
			return nil, fmt.Errorf("scan projected link assertion %q %q %q: %w", fromURN, relation, toURN, err)
		}
		a.attributesJSON = string(attrsRaw)
		assertions = append(assertions, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return assertions, nil
}

// collectProjectionRows runs query and scans every row with scan, closing the
// rows before it returns so the caller can keep using the same transaction.
func collectProjectionRows[T any](ctx context.Context, tx *sql.Tx, query string, args []any, scan func(*sql.Rows) (T, error)) ([]T, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var items []T
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// projectedLinkAdvisoryLockSQL serializes every transaction that reconciles
// the same logical link's entity_links row (see reconcileProjectedLink)
// behind a transaction-scoped Postgres advisory lock, keyed by a hash of
// (tenant, from_urn, relation, to_urn). Without it, two concurrent
// transactions asserting the very first (previously unseen) assertion of
// the same edge from different source/runtimes can both observe no
// entity_links row under READ COMMITTED and both attempt the plain
// INSERT: one succeeds and the other fails on the primary-key unique
// violation, rolling back its otherwise-valid independent assertion. The
// lock is released automatically at transaction end (_xact_), so it never
// outlives the commit/rollback that reconciled the row.
const projectedLinkAdvisoryLockSQL = `SELECT pg_advisory_xact_lock(hashtext('cerebro_projected_link'), hashtext($1))`

// projectedLinkLockKey builds the advisory-lock key for one logical link.
// It intentionally excludes source_id/runtime_id: the lock must exclude
// every writer of this logical key, not just one assertion scope. "|" is
// safe here (never NUL, unlike some other keys in this package) because
// the key is sent to Postgres as a TEXT query parameter.
func projectedLinkLockKey(tenantID string, fromURN string, relation string, toURN string) string {
	return strings.Join([]string{tenantID, fromURN, relation, toURN}, "|")
}

// sortProjectedLinkIdentities orders logical links deterministically so
// that every transaction touching several of them (replaceProjectedLinkSet,
// CleanupProjectedEntities, CleanupEndpointOwnerIDLinks) acquires their
// reconcileProjectedLink advisory locks in the same relative order,
// preventing a circular-wait deadlock between two such transactions whose
// affected sets overlap.
func sortProjectedLinkIdentities(keys []projectedLinkIdentity) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].fromURN != keys[j].fromURN {
			return keys[i].fromURN < keys[j].fromURN
		}
		if keys[i].relation != keys[j].relation {
			return keys[i].relation < keys[j].relation
		}
		return keys[i].toURN < keys[j].toURN
	})
}

// lockProjectedLinkKey acquires reconcileProjectedLink's transaction-scoped
// advisory lock for one logical link key directly, without the rest of
// reconcileProjectedLink's materialization logic. Callers that must lock a
// whole planned set of keys up front, in one deterministic global order,
// before any retraction/assertion mutation (R03/R05) use this; the lock is
// reentrant, so reconcileProjectedLink's own later call for the same key is
// a no-op.
func lockProjectedLinkKey(ctx context.Context, tx *sql.Tx, tenantID string, key projectedLinkIdentity) error {
	if _, err := tx.ExecContext(ctx, projectedLinkAdvisoryLockSQL, projectedLinkLockKey(tenantID, key.fromURN, key.relation, key.toURN)); err != nil {
		return fmt.Errorf("lock projected link %q %q %q: %w", key.fromURN, key.relation, key.toURN, err)
	}
	return nil
}

// dedupeProjectedLinkIdentities drops duplicate logical link keys while
// preserving first-seen order, so a caller merging several candidate lists
// (R03/R05 planning) locks and reconciles each affected key exactly once.
func dedupeProjectedLinkIdentities(keys []projectedLinkIdentity) []projectedLinkIdentity {
	seen := make(map[projectedLinkIdentity]struct{}, len(keys))
	deduped := make([]projectedLinkIdentity, 0, len(keys))
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, key)
	}
	return deduped
}

// reconcileProjectedLink materializes entity_links from whichever
// entity_link_assertions rows still cover (fromURN, relation, toURN) under
// tenantID: the logical row survives iff at least one assertion remains,
// independent of which assertion was written or retracted last (F06).
//
// A pre-existing logical row that predates the assertion model
// (assertion_managed = false) is never rehydrated or deleted here: its
// last-writer tenant/source/runtime/attributes cannot prove no other
// runtime also asserted the same fact, so overwriting it would risk
// inventing provenance or silently erasing a legacy fact. A new
// conflicting assertion only raises assertion_quarantined so the conflict
// is measurable (CountProjectedLinksMissingAssertions); real coverage for
// such rows requires the bounded MigrateProjectedLinkAssertions quarantine
// plus a full projection rebuild, matching the Neo4j store's policy.
func reconcileProjectedLink(ctx context.Context, tx *sql.Tx, fromURN string, relation string, toURN string, tenantID string, workspaceIDHint string) error {
	if err := lockProjectedLinkKey(ctx, tx, tenantID, projectedLinkIdentity{fromURN: fromURN, relation: relation, toURN: toURN}); err != nil {
		return err
	}

	var existingTenantID, existingWorkspaceID string
	var assertionManaged bool
	logicalExists := true
	err := tx.QueryRowContext(ctx, `
SELECT tenant_id, application_workspace_id, assertion_managed
FROM entity_links
WHERE from_urn = $1 AND relation = $2 AND to_urn = $3
FOR UPDATE`, fromURN, relation, toURN).Scan(&existingTenantID, &existingWorkspaceID, &assertionManaged)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		logicalExists = false
	case err != nil:
		return fmt.Errorf("load projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	if logicalExists {
		if existingTenantID != "" && existingTenantID != tenantID {
			return fmt.Errorf("%w: projected link %q %q %q", ports.ErrApplicationWorkspaceConflict, fromURN, relation, toURN)
		}
		if existingWorkspaceID != "" && workspaceIDHint != "" && existingWorkspaceID != workspaceIDHint {
			return fmt.Errorf("%w: projected link %q %q %q", ports.ErrApplicationWorkspaceConflict, fromURN, relation, toURN)
		}
	}

	assertions, err := loadProjectedLinkAssertions(ctx, tx, fromURN, relation, toURN, tenantID)
	if err != nil {
		return err
	}

	if logicalExists && !assertionManaged {
		if len(assertions) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE entity_links SET assertion_quarantined = true, updated_at = NOW()
WHERE from_urn = $1 AND relation = $2 AND to_urn = $3 AND NOT assertion_quarantined`, fromURN, relation, toURN); err != nil {
			return fmt.Errorf("quarantine projected link %q %q %q: %w", fromURN, relation, toURN, err)
		}
		return nil
	}

	if len(assertions) == 0 {
		if !logicalExists {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM entity_links WHERE from_urn = $1 AND relation = $2 AND to_urn = $3`, fromURN, relation, toURN); err != nil {
			return fmt.Errorf("delete projected link %q %q %q: %w", fromURN, relation, toURN, err)
		}
		return nil
	}

	survivor := selectPostgresLinkSurvivor(assertions)
	newWorkspaceID := workspaceIDHint
	switch {
	case logicalExists && existingWorkspaceID != "":
		newWorkspaceID = existingWorkspaceID
	case newWorkspaceID == "":
		newWorkspaceID = survivor.workspaceID
	}

	if !logicalExists {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO entity_links (from_urn, relation, to_urn, tenant_id, application_workspace_id, source_id, runtime_id, attributes_json, assertion_managed, assertion_quarantined)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, true, false)`,
			fromURN, relation, toURN, tenantID, newWorkspaceID, survivor.sourceID, survivor.runtimeID, survivor.attributesJSON); err != nil {
			return fmt.Errorf("create projected link %q %q %q: %w", fromURN, relation, toURN, err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE entity_links
SET tenant_id = $4, application_workspace_id = $5, source_id = $6, runtime_id = $7, attributes_json = $8::jsonb,
    assertion_managed = true, assertion_quarantined = false, updated_at = NOW()
WHERE from_urn = $1 AND relation = $2 AND to_urn = $3`,
		fromURN, relation, toURN, tenantID, newWorkspaceID, survivor.sourceID, survivor.runtimeID, survivor.attributesJSON); err != nil {
		return fmt.Errorf("update projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

// selectPostgresLinkSurvivor picks the surviving assertion among candidates
// still covering a logical link: the newest parseable `at` wins, a present
// `at` beats a missing/unparseable one, and ties break deterministically on
// (source_id, runtime_id, attributes_json), mirroring the Neo4j store's
// RELATION_ASSERTION survivor rule.
func selectPostgresLinkSurvivor(assertions []postgresLinkAssertion) postgresLinkAssertion {
	survivor := assertions[0]
	for _, candidate := range assertions[1:] {
		if postgresLinkAssertionPreferred(candidate, survivor) {
			survivor = candidate
		}
	}
	return survivor
}

func postgresLinkAssertionPreferred(a postgresLinkAssertion, b postgresLinkAssertion) bool {
	aAt, aOK := postgresLinkAssertionObservedAt(a)
	bAt, bOK := postgresLinkAssertionObservedAt(b)
	switch {
	case aOK && bOK && !aAt.Equal(bAt):
		return aAt.After(bAt)
	case aOK && !bOK:
		return true
	case !aOK && bOK:
		return false
	}
	if a.sourceID != b.sourceID {
		return a.sourceID < b.sourceID
	}
	if a.runtimeID != b.runtimeID {
		return a.runtimeID < b.runtimeID
	}
	return a.attributesJSON < b.attributesJSON
}

func postgresLinkAssertionObservedAt(a postgresLinkAssertion) (time.Time, bool) {
	attrs, err := projectionAttributesFromJSONRaw([]byte(a.attributesJSON))
	if err != nil {
		return time.Time{}, false
	}
	at := strings.TrimSpace(attrs["at"])
	if at == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// DeleteProjectedLink retracts one source-runtime assertion when tenant and
// source provenance are present; the shared logical link survives until its
// last assertion is removed (F06). A blank runtime is an exact
// blank-runtime identity, not a wildcard. An identity-less delete (missing
// tenant or source) is a fail-closed no-op: it can never choose which
// assertion to retract, and never removes a legacy uncovered logical row.
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
	tenantID := strings.TrimSpace(link.TenantID)
	sourceID := strings.TrimSpace(link.SourceID)
	runtimeID := strings.TrimSpace(link.RuntimeID)
	if tenantID == "" || sourceID == "" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	defer func() { _ = tx.Rollback() }()
	// GraphReview issue 2: lock before the assertion row DELETE below.
	if err := lockProjectedLinkKey(ctx, tx, tenantID, projectedLinkIdentity{fromURN: fromURN, relation: relation, toURN: toURN}); err != nil {
		return fmt.Errorf("lock projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM entity_link_assertions
WHERE from_urn = $1 AND relation = $2 AND to_urn = $3 AND tenant_id = $4 AND source_id = $5 AND runtime_id = $6`,
		fromURN, relation, toURN, tenantID, sourceID, runtimeID)
	if err != nil {
		return fmt.Errorf("delete projected link assertion %q %q %q: %w", fromURN, relation, toURN, err)
	}
	if deleted, rowsErr := result.RowsAffected(); rowsErr == nil && deleted == 0 {
		return nil
	}
	if err := reconcileProjectedLink(ctx, tx, fromURN, relation, toURN, tenantID, ""); err != nil {
		return fmt.Errorf("delete projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete projected link %q %q %q: %w", fromURN, relation, toURN, err)
	}
	return nil
}

// DeleteProjectedEntity removes only an isolated entity: one with no
// remaining materialized link (entity_links) and no remaining assertion
// (entity_link_assertions) in either direction. The identity-less API
// cannot safely choose among source-runtime assertions, so shared or
// legacy graph facts must be retracted through their scoped link APIs
// first (F06).
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
	if _, err := s.db.ExecContext(ctx, `
DELETE FROM entities e
WHERE e.urn = $1
  AND NOT EXISTS (SELECT 1 FROM entity_links l WHERE l.from_urn = e.urn OR l.to_urn = e.urn)
  AND NOT EXISTS (SELECT 1 FROM entity_link_assertions a WHERE a.from_urn = e.urn OR a.to_urn = e.urn)`, normalizedURN); err != nil {
		return fmt.Errorf("delete projected entity %q: %w", normalizedURN, err)
	}
	return nil
}

// CleanupProjectedEntities removes only this request's tenant/source/runtime
// scoped assertions (when fully scoped), reconciles the logical links that
// retraction affects, and deletes a candidate entity only when no logical
// link or assertion still references it (F06): another source/runtime's
// coverage of a shared entity or edge is never swept away by this pass.
//
// R03: deployed pre-F06 state can still carry a logical entity_links row
// whose own recorded tenant/source/runtime exactly matches this request's
// scope but has no entity_link_assertions coverage at all
// (assertion_managed = false), because it predates the assertion table.
// Upgrading the schema alone never retroactively asserts it, so without
// this step the row's own already-recorded (trustworthy) provenance
// survives every retraction pass forever and blocks entity deletion.
// Before retracting, this migrates exactly those rows — never a row the
// store already quarantined for conflicting provenance from another
// writer — into a real assertion scoped to their own recorded tenant/
// source/runtime, so the retraction below then removes them the same way
// it removes any other assertion in scope.
func (s *Store) CleanupProjectedEntities(ctx context.Context, request ports.ProjectionCleanupRequest) (ports.ProjectionCleanupResult, error) {
	if s == nil || s.db == nil {
		return ports.ProjectionCleanupResult{}, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return ports.ProjectionCleanupResult{}, err
	}
	candidateQuery, candidateArgs, err := projectedEntityCleanupCandidatesSQL(request)
	if err != nil {
		return ports.ProjectionCleanupResult{}, err
	}
	tenantID := strings.TrimSpace(request.TenantID)
	sourceID := strings.TrimSpace(request.SourceID)
	runtimeID := strings.TrimSpace(request.RuntimeID)
	assertionScopeComplete := tenantID != "" && sourceID != ""

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	urns, err := queryProjectedEntityCleanupCandidates(ctx, tx, candidateQuery, candidateArgs)
	if err != nil {
		return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
	}
	result := ports.ProjectionCleanupResult{EntitiesMatched: uint32FromInt(len(urns))}
	if len(urns) == 0 {
		return result, nil
	}

	if request.DryRun {
		if assertionScopeComplete {
			matched, err := countProjectedEntityCleanupAssertions(ctx, tx, urns, tenantID, sourceID, runtimeID)
			if err != nil {
				return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
			}
			result.LinksMatched = matched
			migratable, err := countLegacyProjectedLinkMigrationCandidates(ctx, tx, urns, tenantID, sourceID, runtimeID)
			if err != nil {
				return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
			}
			result.LinksMigrated = migratable
		}
		return result, nil
	}

	if assertionScopeComplete {
		// Plan every logical link key this pass can touch — legacy
		// entity_links rows whose own recorded provenance exactly
		// matches this scope (migration candidates, above) and this
		// scope's already-existing assertions — and lock all of them,
		// in one deterministic global order, before any mutation. A
		// legacy row needs two sequential state transitions (quarantine-
		// free legacy -> assertion-managed -> fully retracted); planning
		// and locking the full set up front keeps that two-step sequence
		// from acquiring its locks out of order against a concurrent
		// transaction retracting/asserting the overlapping keys in
		// reverse (R05's deadlock).
		legacyCandidates, err := selectLegacyProjectedLinkMigrationCandidates(ctx, tx, urns, tenantID, sourceID, runtimeID)
		if err != nil {
			return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
		}
		existingAssertions, err := selectProjectedEntityCleanupAssertionKeys(ctx, tx, urns, tenantID, sourceID, runtimeID)
		if err != nil {
			return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
		}
		planned := dedupeProjectedLinkIdentities(append(append([]projectedLinkIdentity{}, legacyCandidates...), existingAssertions...))
		sortProjectedLinkIdentities(planned)
		for _, key := range planned {
			if err := lockProjectedLinkKey(ctx, tx, tenantID, key); err != nil {
				return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
			}
		}

		migrated, err := migrateLegacyProjectedLinksForCleanup(ctx, tx, urns, tenantID, sourceID, runtimeID)
		if err != nil {
			return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
		}
		result.LinksMigrated = migrated

		deleted, err := deleteProjectedEntityCleanupAssertions(ctx, tx, planned, tenantID, sourceID, runtimeID)
		if err != nil {
			return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
		}
		for _, key := range planned {
			if err := reconcileProjectedLink(ctx, tx, key.fromURN, key.relation, key.toURN, tenantID, ""); err != nil {
				return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
			}
		}
		result.LinksMatched = deleted
		result.LinksDeleted = deleted
	}

	deletedEntities, err := deleteIsolatedProjectedEntities(ctx, tx, urns)
	if err != nil {
		return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
	}
	result.EntitiesDeleted = deletedEntities

	if err := tx.Commit(); err != nil {
		return ports.ProjectionCleanupResult{}, fmt.Errorf("cleanup projected entities: %w", err)
	}
	return result, nil
}

// selectLegacyProjectedLinkMigrationCandidates finds entity_links rows
// touching the cleanup's candidate urns whose own recorded tenant/source/
// runtime exactly matches this cleanup request's scope but that have
// never had any entity_link_assertions coverage (R03): deployed pre-F06
// state. A row the store already quarantined (a conflicting assertion
// from a different writer arrived since) is excluded; its provenance is
// no longer unambiguous enough to migrate automatically, so it is
// reported (still matched, never deleted) instead of silently retired.
func selectLegacyProjectedLinkMigrationCandidates(ctx context.Context, tx *sql.Tx, urns []string, tenantID string, sourceID string, runtimeID string) ([]projectedLinkIdentity, error) {
	return collectProjectionRows(ctx, tx, `
SELECT from_urn, relation, to_urn
FROM entity_links
WHERE (from_urn = ANY($1::text[]) OR to_urn = ANY($1::text[]))
  AND tenant_id = $2 AND source_id = $3 AND runtime_id = $4
  AND NOT assertion_managed AND NOT assertion_quarantined`,
		[]any{pgTextArray(urns), tenantID, sourceID, runtimeID},
		func(rows *sql.Rows) (projectedLinkIdentity, error) {
			var key projectedLinkIdentity
			err := rows.Scan(&key.fromURN, &key.relation, &key.toURN)
			return key, err
		})
}

// selectProjectedEntityCleanupAssertionKeys loads the logical link keys
// already covered by this exact tenant/source/runtime scope's own
// entity_link_assertions rows touching the cleanup's candidate urns,
// before any retraction (R05 planning).
func selectProjectedEntityCleanupAssertionKeys(ctx context.Context, tx *sql.Tx, urns []string, tenantID string, sourceID string, runtimeID string) ([]projectedLinkIdentity, error) {
	return collectProjectionRows(ctx, tx, `
SELECT from_urn, relation, to_urn
FROM entity_link_assertions
WHERE (from_urn = ANY($1::text[]) OR to_urn = ANY($1::text[]))
  AND tenant_id = $2 AND source_id = $3 AND runtime_id = $4`,
		[]any{pgTextArray(urns), tenantID, sourceID, runtimeID},
		func(rows *sql.Rows) (projectedLinkIdentity, error) {
			var key projectedLinkIdentity
			err := rows.Scan(&key.fromURN, &key.relation, &key.toURN)
			return key, err
		})
}

// countLegacyProjectedLinkMigrationCandidates previews how many legacy
// rows a non-dry-run pass would migrate, without mutating anything.
func countLegacyProjectedLinkMigrationCandidates(ctx context.Context, tx *sql.Tx, urns []string, tenantID string, sourceID string, runtimeID string) (uint32, error) {
	var count int64
	err := tx.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM entity_links
WHERE (from_urn = ANY($1::text[]) OR to_urn = ANY($1::text[]))
  AND tenant_id = $2 AND source_id = $3 AND runtime_id = $4
  AND NOT assertion_managed AND NOT assertion_quarantined`, pgTextArray(urns), tenantID, sourceID, runtimeID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return uint32FromInt64(count), nil
}

// migrateLegacyProjectedLinksForCleanup converts every entity_links row
// matched by selectLegacyProjectedLinkMigrationCandidates into a real
// entity_link_assertions row scoped to its own already-recorded tenant/
// source/runtime, then flips that logical row's assertion_managed flag:
// the migrated row's own existing tenant/workspace/source/runtime/
// attributes already equal what the new assertion carries, so no other
// column changes and no ownership is invented. The caller must already
// hold every migrated key's advisory lock (R05 planning) before calling
// this.
func migrateLegacyProjectedLinksForCleanup(ctx context.Context, tx *sql.Tx, urns []string, tenantID string, sourceID string, runtimeID string) (uint32, error) {
	var migrated int64
	err := tx.QueryRowContext(ctx, `
WITH migrated AS (
  INSERT INTO entity_link_assertions (from_urn, relation, to_urn, tenant_id, application_workspace_id, source_id, runtime_id, attributes_json)
  SELECT from_urn, relation, to_urn, tenant_id, application_workspace_id, source_id, runtime_id, attributes_json
  FROM entity_links
  WHERE (from_urn = ANY($1::text[]) OR to_urn = ANY($1::text[]))
    AND tenant_id = $2 AND source_id = $3 AND runtime_id = $4
    AND NOT assertion_managed AND NOT assertion_quarantined
  ON CONFLICT (from_urn, relation, to_urn, tenant_id, source_id, runtime_id) DO NOTHING
  RETURNING from_urn, relation, to_urn
), flipped AS (
  UPDATE entity_links l
  SET assertion_managed = true, updated_at = NOW()
  FROM migrated m
  WHERE l.from_urn = m.from_urn AND l.relation = m.relation AND l.to_urn = m.to_urn
  RETURNING 1
)
SELECT count(*) FROM flipped`, pgTextArray(urns), tenantID, sourceID, runtimeID).Scan(&migrated)
	if err != nil {
		return 0, fmt.Errorf("migrate legacy projected links: %w", err)
	}
	return uint32FromInt64(migrated), nil
}

func queryProjectedEntityCleanupCandidates(ctx context.Context, tx *sql.Tx, query string, args []any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var urns []string
	for rows.Next() {
		var urn string
		if err := rows.Scan(&urn); err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, rows.Err()
}

func countProjectedEntityCleanupAssertions(ctx context.Context, tx *sql.Tx, urns []string, tenantID string, sourceID string, runtimeID string) (uint32, error) {
	var count int64
	err := tx.QueryRowContext(ctx, `
SELECT COUNT(DISTINCT (from_urn, relation, to_urn))
FROM entity_link_assertions
WHERE (from_urn = ANY($1::text[]) OR to_urn = ANY($1::text[]))
  AND tenant_id = $2 AND source_id = $3 AND runtime_id = $4`, pgTextArray(urns), tenantID, sourceID, runtimeID).Scan(&count)
	if err != nil {
		return 0, err
	}
	return uint32FromInt64(count), nil
}

// deleteProjectedEntityCleanupAssertions retracts exactly the given
// already-locked planned keys' entity_link_assertions rows (GraphReview
// issue 1): restricting the DELETE to the planned set, rather than a
// broad tenant/source/runtime/urn WHERE clause, guarantees it can never
// also sweep up a different, concurrently-asserted key that was never
// part of the plan and therefore never reconciled.
func deleteProjectedEntityCleanupAssertions(ctx context.Context, tx *sql.Tx, planned []projectedLinkIdentity, tenantID string, sourceID string, runtimeID string) (uint32, error) {
	if len(planned) == 0 {
		return 0, nil
	}
	fromURNs := make([]string, len(planned))
	relations := make([]string, len(planned))
	toURNs := make([]string, len(planned))
	for i, key := range planned {
		fromURNs[i] = key.fromURN
		relations[i] = key.relation
		toURNs[i] = key.toURN
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM entity_link_assertions a
USING unnest($1::text[], $2::text[], $3::text[]) AS p(from_urn, relation, to_urn)
WHERE a.from_urn = p.from_urn AND a.relation = p.relation AND a.to_urn = p.to_urn
  AND a.tenant_id = $4 AND a.source_id = $5 AND a.runtime_id = $6`,
		pgTextArray(fromURNs), pgTextArray(relations), pgTextArray(toURNs), tenantID, sourceID, runtimeID)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return uint32FromInt64(deleted), nil
}

func deleteIsolatedProjectedEntities(ctx context.Context, tx *sql.Tx, urns []string) (uint32, error) {
	result, err := tx.ExecContext(ctx, `
DELETE FROM entities e
WHERE e.urn = ANY($1::text[])
  AND NOT EXISTS (SELECT 1 FROM entity_links l WHERE l.from_urn = e.urn OR l.to_urn = e.urn)
  AND NOT EXISTS (SELECT 1 FROM entity_link_assertions a WHERE a.from_urn = e.urn OR a.to_urn = e.urn)`, pgTextArray(urns))
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return uint32FromInt64(deleted), nil
}

// pgTextArray normalizes a Go string slice for use as a text[] query
// argument; the pgx driver this store opens ("pgx") maps a []string
// argument directly onto a Postgres array.
func pgTextArray(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// CleanupEndpointOwnerIDLinks removes stale endpoint owner_id/user_id
// canonical identity assertions once a replacement identifier exists,
// reconciling each affected logical link so another source/runtime's
// coverage of the same logical edge survives (F06).
func (s *Store) CleanupEndpointOwnerIDLinks(ctx context.Context, request ports.ProjectionLinkCleanupRequest) (ports.ProjectionLinkCleanupResult, error) {
	if s == nil || s.db == nil {
		return ports.ProjectionLinkCleanupResult{}, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	if request.DryRun {
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
	selectQuery, selectArgs, err := projectedEndpointOwnerIDLinkCleanupSelectSQL(request)
	if err != nil {
		return ports.ProjectionLinkCleanupResult{}, err
	}
	tenantID := strings.TrimSpace(request.TenantID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Plan the exact victim rows (GraphReview issue 1/2) before any lock
	// or mutation.
	victims, err := collectProjectionRows(ctx, tx, selectQuery, selectArgs, func(rows *sql.Rows) (projectedEndpointOwnerIDCleanupVictim, error) {
		var v projectedEndpointOwnerIDCleanupVictim
		err := rows.Scan(&v.fromURN, &v.relation, &v.toURN, &v.tenantID, &v.sourceID, &v.runtimeID)
		return v, err
	})
	if err != nil {
		return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
	}
	if len(victims) == 0 {
		if err := tx.Commit(); err != nil {
			return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
		}
		return ports.ProjectionLinkCleanupResult{}, nil
	}
	planned := make([]projectedLinkIdentity, 0, len(victims))
	for _, v := range victims {
		planned = append(planned, projectedLinkIdentity{fromURN: v.fromURN, relation: v.relation, toURN: v.toURN})
	}
	planned = dedupeProjectedLinkIdentities(planned)
	sortProjectedLinkIdentities(planned)
	for _, key := range planned {
		if err := lockProjectedLinkKey(ctx, tx, tenantID, key); err != nil {
			return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
		}
	}
	// Restrict the DELETE to exactly the planned, now-locked victim rows
	// (GraphReview issue 1): a concurrent writer asserting a different
	// key in between planning and this delete can never be swept up.
	deleted, err := deleteProjectedEndpointOwnerIDCleanupVictims(ctx, tx, victims)
	if err != nil {
		return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
	}
	for _, key := range planned {
		if err := reconcileProjectedLink(ctx, tx, key.fromURN, key.relation, key.toURN, tenantID, ""); err != nil {
			return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return ports.ProjectionLinkCleanupResult{}, fmt.Errorf("cleanup endpoint owner-id links: %w", err)
	}
	return ports.ProjectionLinkCleanupResult{LinksMatched: deleted, LinksDeleted: deleted}, nil
}

// projectedEndpointOwnerIDCleanupVictim is one planned
// entity_link_assertions row to retract, carrying the full composite key
// (including source_id/runtime_id, which the shared projectedLinkIdentity
// intentionally omits) so the restricted DELETE can match it exactly.
type projectedEndpointOwnerIDCleanupVictim struct {
	fromURN, relation, toURN      string
	tenantID, sourceID, runtimeID string
}

// deleteProjectedEndpointOwnerIDCleanupVictims retracts exactly the given
// already-locked planned victim rows.
func deleteProjectedEndpointOwnerIDCleanupVictims(ctx context.Context, tx *sql.Tx, victims []projectedEndpointOwnerIDCleanupVictim) (uint32, error) {
	if len(victims) == 0 {
		return 0, nil
	}
	fromURNs := make([]string, len(victims))
	relations := make([]string, len(victims))
	toURNs := make([]string, len(victims))
	tenantIDs := make([]string, len(victims))
	sourceIDs := make([]string, len(victims))
	runtimeIDs := make([]string, len(victims))
	for i, v := range victims {
		fromURNs[i] = v.fromURN
		relations[i] = v.relation
		toURNs[i] = v.toURN
		tenantIDs[i] = v.tenantID
		sourceIDs[i] = v.sourceID
		runtimeIDs[i] = v.runtimeID
	}
	result, err := tx.ExecContext(ctx, `
DELETE FROM entity_link_assertions a
USING unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
  AS p(from_urn, relation, to_urn, tenant_id, source_id, runtime_id)
WHERE a.from_urn = p.from_urn AND a.relation = p.relation AND a.to_urn = p.to_urn
  AND a.tenant_id = p.tenant_id AND a.source_id = p.source_id AND a.runtime_id = p.runtime_id`,
		pgTextArray(fromURNs), pgTextArray(relations), pgTextArray(toURNs),
		pgTextArray(tenantIDs), pgTextArray(sourceIDs), pgTextArray(runtimeIDs))
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return uint32FromInt64(deleted), nil
}

// CountProjectedLinksMissingAssertions reports entity_links rows in scope
// that are not backed by any entity_link_assertions coverage: either
// because the row predates the assertion model (assertion_managed = false)
// or, in principle, because its last assertion was removed without the
// logical row being reconciled. Callers can use a non-zero count as a
// migration coverage gate before trusting assertion-based deletion for a
// tenant/relation scope (F06).
func (s *Store) CountProjectedLinksMissingAssertions(ctx context.Context, tenantID string, relations []string) (uint32, error) {
	tenantID = strings.TrimSpace(tenantID)
	relations = normalizeProjectionCleanupValues(relations)
	if tenantID == "" || len(relations) == 0 {
		return 0, errProjectionAssertionMigrationScopeRequired
	}
	if s == nil || s.db == nil {
		return 0, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return 0, err
	}
	var missing int64
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM entity_links l
WHERE l.tenant_id = $1
  AND l.relation = ANY($2::text[])
  AND (
    NOT l.assertion_managed
    OR NOT EXISTS (
      SELECT 1 FROM entity_link_assertions a
      WHERE a.from_urn = l.from_urn AND a.relation = l.relation AND a.to_urn = l.to_urn AND a.tenant_id = l.tenant_id
    )
  )`, tenantID, pgTextArray(relations)).Scan(&missing)
	if err != nil {
		return 0, fmt.Errorf("count projected links missing assertions: %w", err)
	}
	return uint32FromInt64(missing), nil
}

// MigrateProjectedLinkAssertions quarantines legacy entity_links rows that
// predate the assertion model: their last-writer source/runtime cannot
// prove no other runtime also asserted the same fact, so this bounded pass
// only flags them (assertion_quarantined = true) rather than inventing
// assertion_managed coverage. Only a clean graph rebuild (re-projecting
// every source) can establish complete, trustworthy assertion coverage for
// them, matching the Neo4j store's policy (F06).
func (s *Store) MigrateProjectedLinkAssertions(ctx context.Context, request ports.ProjectionAssertionMigrationRequest) (ports.ProjectionAssertionMigrationResult, error) {
	tenantID := strings.TrimSpace(request.TenantID)
	relations := normalizeProjectionCleanupValues(request.Relations)
	if tenantID == "" || len(relations) == 0 {
		return ports.ProjectionAssertionMigrationResult{}, errProjectionAssertionMigrationScopeRequired
	}
	if s == nil || s.db == nil {
		return ports.ProjectionAssertionMigrationResult{}, errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return ports.ProjectionAssertionMigrationResult{}, err
	}
	limit := request.Limit
	if limit == 0 {
		limit = defaultProjectionCleanupLimit
	}
	candidateQuery := `
SELECT from_urn, relation, to_urn
FROM entity_links
WHERE tenant_id = $1 AND relation = ANY($2::text[]) AND NOT assertion_managed
ORDER BY from_urn, relation, to_urn
LIMIT $3`
	if request.DryRun {
		var matched int64
		if err := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM (%s) candidates`, candidateQuery), tenantID, pgTextArray(relations), limit).Scan(&matched); err != nil {
			return ports.ProjectionAssertionMigrationResult{}, fmt.Errorf("migrate projected link assertions: %w", err)
		}
		return ports.ProjectionAssertionMigrationResult{LinksMatched: uint32FromInt64(matched), LinksQuarantined: uint32FromInt64(matched)}, nil
	}
	var quarantined int64
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(`
WITH candidates AS (%s), quarantined AS (
UPDATE entity_links l
SET assertion_quarantined = true, updated_at = NOW()
FROM candidates c
WHERE l.from_urn = c.from_urn AND l.relation = c.relation AND l.to_urn = c.to_urn
RETURNING 1
)
SELECT count(*) FROM quarantined`, candidateQuery), tenantID, pgTextArray(relations), limit).Scan(&quarantined); err != nil {
		return ports.ProjectionAssertionMigrationResult{}, fmt.Errorf("migrate projected link assertions: %w", err)
	}
	return ports.ProjectionAssertionMigrationResult{LinksMatched: uint32FromInt64(quarantined), LinksQuarantined: uint32FromInt64(quarantined)}, nil
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

func uint32FromInt64(value int64) uint32 {
	if value < 0 {
		return 0
	}
	if value > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(value) // #nosec G115 -- bounds checked above.
}

func uint32FromInt(value int) uint32 {
	return uint32FromInt64(int64(value))
}

// ReplaceProjectedLinkSets applies each guarded link set (Contract C9) in
// its own transaction. Unlike the old last-writer entity_links row, a set's
// narrowing or authoritative-empty retraction now removes only this exact
// (tenant, source, runtime) scope's own entity_link_assertions rows for the
// set's (owner, relation, direction) — found by the assertion's own
// identity columns, not any separately cached ownership set — so a
// different source/runtime's assertion of the exact same logical link is
// never touched (F06). An Incomplete set (G1) carries no links: it only
// advances the scope's Observation guard and never retracts or asserts
// anything.
func (s *Store) ReplaceProjectedLinkSets(ctx context.Context, sets []*ports.ProjectedLinkSet) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureProjectionTables(ctx); err != nil {
		return err
	}
	for _, set := range sets {
		if err := s.replaceProjectedLinkSet(ctx, set); err != nil {
			return err
		}
	}
	return nil
}

// maxLinkSetPlanAttempts bounds how many times replaceProjectedLinkSet may
// replan after detecting a concurrent writer asserted a new key in the
// same scope between planning and verification (GraphReview issue 1): a
// bounded plan-validation retry, never a late lock acquired out of order.
const maxLinkSetPlanAttempts = 5

func (s *Store) replaceProjectedLinkSet(ctx context.Context, set *ports.ProjectedLinkSet) error {
	ownerURN, relation, tenantID, sourceID, runtimeID, prepared, err := validateProjectedLinkSetForPostgres(set)
	if err != nil {
		return err
	}
	if err := ports.ValidateProjectedLinkSetEndpoints(set); err != nil {
		return err
	}
	observationJSON, err := projectionAttributesJSON(set.Observation)
	if err != nil {
		return fmt.Errorf("marshal link set %q %q observation: %w", ownerURN, relation, err)
	}
	for range maxLinkSetPlanAttempts {
		retry, err := s.attemptReplaceProjectedLinkSet(ctx, set, ownerURN, relation, tenantID, sourceID, runtimeID, prepared, observationJSON)
		if err != nil {
			return err
		}
		if !retry {
			return nil
		}
	}
	return fmt.Errorf("replace link set %q %q: scope assertions kept changing concurrently after %d planning attempts", ownerURN, relation, maxLinkSetPlanAttempts)
}

// attemptReplaceProjectedLinkSet runs one bounded planning attempt in its
// own transaction. It returns retry=true (the transaction has already
// rolled back) when a concurrent writer asserted or retracted a key in
// this exact scope between planning and verification, so the caller must
// replan from a fresh read rather than acquire a lock out of order
// (GraphReview issue 1).
func (s *Store) attemptReplaceProjectedLinkSet(ctx context.Context, set *ports.ProjectedLinkSet, ownerURN string, relation string, tenantID string, sourceID string, runtimeID string, prepared []*ports.ProjectedLink, observationJSON string) (retry bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin link set replacement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var storedObservationRaw []byte
	if err := tx.QueryRowContext(ctx, `
INSERT INTO link_set_observations (owner_urn, relation, outgoing, tenant_id, source_id, runtime_id, observation_json)
VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb)
ON CONFLICT (owner_urn, relation, outgoing, tenant_id, source_id, runtime_id) DO UPDATE SET owner_urn = EXCLUDED.owner_urn
RETURNING observation_json`, ownerURN, relation, set.Outgoing, tenantID, sourceID, runtimeID).Scan(&storedObservationRaw); err != nil {
		return false, fmt.Errorf("load link set %q %q observation marker: %w", ownerURN, relation, err)
	}
	storedObservation, err := projectionAttributesFromJSONRaw(storedObservationRaw)
	if err != nil {
		return false, fmt.Errorf("decode link set %q %q observation marker: %w", ownerURN, relation, err)
	}
	if projectionmeta.CompareObservations(storedObservation, set.Observation) == projectionmeta.ObservationOlder {
		// The owner's stored observation is newer: this set is stale and
		// must neither retract, assert, nor create any endpoint. Rolling
		// back (deferred above) discards even the marker row's no-op
		// touch.
		return false, nil
	}

	if set.Incomplete {
		// An accepted incomplete observation advances the scope's
		// ordering guard but neither retracts/asserts any link nor
		// creates any endpoint (ValidateProjectedLinkSetEndpoints
		// already rejected an Incomplete set carrying Endpoints).
		if _, err := tx.ExecContext(ctx, `
UPDATE link_set_observations SET observation_json = $7::jsonb, updated_at = NOW()
WHERE owner_urn = $1 AND relation = $2 AND outgoing = $3 AND tenant_id = $4 AND source_id = $5 AND runtime_id = $6`,
			ownerURN, relation, set.Outgoing, tenantID, sourceID, runtimeID, observationJSON); err != nil {
			return false, fmt.Errorf("commit link set %q %q observation marker: %w", ownerURN, relation, err)
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit link set replacement %q %q: %w", ownerURN, relation, err)
		}
		return false, nil
	}

	desired := map[string]struct{}{}
	for _, link := range prepared {
		other := link.ToURN
		if !set.Outgoing {
			other = link.FromURN
		}
		desired[other] = struct{}{}
	}

	// R05/GraphReview issue 1: plan the full set of logical link keys
	// this call can affect, lock all of them in one deterministic global
	// order before any mutation, then verify the scope's current
	// assertions have not changed since planning. If they have, a
	// concurrent writer asserted or retracted a key we never locked;
	// replan from a fresh read instead of acquiring a late lock out of
	// order, and instead of retracting via a broad WHERE that could also
	// catch that unplanned key without ever reconciling it.
	currentScope, err := selectProjectedLinkSetScopeKeys(ctx, tx, ownerURN, relation, tenantID, sourceID, runtimeID, set.Outgoing)
	if err != nil {
		return false, fmt.Errorf("plan link set %q %q keys: %w", ownerURN, relation, err)
	}
	plannedKeys := make([]projectedLinkIdentity, 0, len(currentScope)+len(prepared))
	plannedKeys = append(plannedKeys, currentScope...)
	for _, link := range prepared {
		plannedKeys = append(plannedKeys, projectedLinkIdentity{fromURN: link.FromURN, relation: link.Relation, toURN: link.ToURN})
	}
	plannedKeys = dedupeProjectedLinkIdentities(plannedKeys)
	sortProjectedLinkIdentities(plannedKeys)
	for _, key := range plannedKeys {
		if err := lockProjectedLinkKey(ctx, tx, tenantID, key); err != nil {
			return false, fmt.Errorf("lock link set %q %q: %w", ownerURN, relation, err)
		}
	}
	verifiedScope, err := selectProjectedLinkSetScopeKeys(ctx, tx, ownerURN, relation, tenantID, sourceID, runtimeID, set.Outgoing)
	if err != nil {
		return false, fmt.Errorf("verify link set %q %q keys: %w", ownerURN, relation, err)
	}
	if !projectedLinkIdentitySetsEqual(currentScope, verifiedScope) {
		return true, nil
	}

	// RR04: order guarded-endpoint creation deterministically, matching
	// the logical-link lock order above. set.Endpoints is caller-provided
	// (and may be reused by the caller), so build a sorted, deduplicated
	// copy by URN rather than mutating it in place; two different finding
	// owners that share absent consumer endpoints but list them in
	// opposite caller order must insert them in the same relative order
	// to avoid a circular-wait deadlock between their transactions.
	for _, endpoint := range sortedDedupedProjectedLinkSetEndpoints(set.Endpoints) {
		if err := createProjectedLinkSetEndpoint(ctx, tx, endpoint); err != nil {
			return false, fmt.Errorf("create link set %q %q endpoint %q: %w", ownerURN, relation, endpoint.URN, err)
		}
	}

	// Retract exactly the planned-and-verified current-scope keys that
	// are not in the desired set (GraphReview issue 1): never a broad
	// WHERE that could also catch a key outside the locked/verified plan.
	toRetract := make([]projectedLinkIdentity, 0, len(currentScope))
	for _, key := range currentScope {
		other := key.toURN
		if !set.Outgoing {
			other = key.fromURN
		}
		if _, wanted := desired[other]; wanted {
			continue
		}
		toRetract = append(toRetract, key)
	}
	if len(toRetract) != 0 {
		if err := retractProjectedLinkSetAssertions(ctx, tx, toRetract, tenantID, sourceID, runtimeID); err != nil {
			return false, fmt.Errorf("retract link set %q %q assertions: %w", ownerURN, relation, err)
		}
	}

	sort.Slice(prepared, func(i, j int) bool {
		if prepared[i].FromURN != prepared[j].FromURN {
			return prepared[i].FromURN < prepared[j].FromURN
		}
		if prepared[i].Relation != prepared[j].Relation {
			return prepared[i].Relation < prepared[j].Relation
		}
		return prepared[i].ToURN < prepared[j].ToURN
	})
	for _, link := range prepared {
		attributesJSON, err := projectionAttributesJSON(link.Attributes)
		if err != nil {
			return false, fmt.Errorf("marshal link set %q %q link attributes: %w", ownerURN, relation, err)
		}
		workspaceID, err := ports.ValidateApplicationWorkspaceScope(link.TenantID, link.ApplicationWorkspaceID)
		if err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, projectedLinkAssertionUpsertSQL(), link.FromURN, link.Relation, link.ToURN, link.TenantID, workspaceID, link.SourceID, link.RuntimeID, attributesJSON); err != nil {
			return false, fmt.Errorf("assert link set %q %q link %q: %w", ownerURN, relation, link.ToURN, err)
		}
	}

	// Every key this call could touch (currentScope ∪ prepared) was
	// already locked above, in one global sorted order; reconciling in
	// that same order here only re-acquires already-held (reentrant)
	// locks.
	for _, key := range plannedKeys {
		if err := reconcileProjectedLink(ctx, tx, key.fromURN, key.relation, key.toURN, tenantID, ""); err != nil {
			return false, fmt.Errorf("reconcile link set %q %q link %q %q: %w", ownerURN, relation, key.fromURN, key.toURN, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE link_set_observations
SET observation_json = $7::jsonb, updated_at = NOW()
WHERE owner_urn = $1 AND relation = $2 AND outgoing = $3 AND tenant_id = $4 AND source_id = $5 AND runtime_id = $6`,
		ownerURN, relation, set.Outgoing, tenantID, sourceID, runtimeID, observationJSON); err != nil {
		return false, fmt.Errorf("commit link set %q %q observation marker: %w", ownerURN, relation, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit link set replacement %q %q: %w", ownerURN, relation, err)
	}
	return false, nil
}

// retractProjectedLinkSetAssertions retracts exactly the given already
// locked-and-verified keys' entity_link_assertions rows, scoped to this
// exact (tenant, source, runtime) writer (GraphReview issue 1): never a
// broad WHERE that could also catch a different, concurrently-asserted
// key that was never part of the plan.
func retractProjectedLinkSetAssertions(ctx context.Context, tx *sql.Tx, keys []projectedLinkIdentity, tenantID string, sourceID string, runtimeID string) error {
	fromURNs := make([]string, len(keys))
	relations := make([]string, len(keys))
	toURNs := make([]string, len(keys))
	for i, key := range keys {
		fromURNs[i] = key.fromURN
		relations[i] = key.relation
		toURNs[i] = key.toURN
	}
	_, err := tx.ExecContext(ctx, `
DELETE FROM entity_link_assertions a
USING unnest($1::text[], $2::text[], $3::text[]) AS p(from_urn, relation, to_urn)
WHERE a.from_urn = p.from_urn AND a.relation = p.relation AND a.to_urn = p.to_urn
  AND a.tenant_id = $4 AND a.source_id = $5 AND a.runtime_id = $6`,
		pgTextArray(fromURNs), pgTextArray(relations), pgTextArray(toURNs), tenantID, sourceID, runtimeID)
	return err
}

// projectedLinkIdentitySetsEqual reports whether a and b contain exactly
// the same logical link keys, order independent (GraphReview issue 1
// drift verification).
func projectedLinkIdentitySetsEqual(a []projectedLinkIdentity, b []projectedLinkIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[projectedLinkIdentity]struct{}, len(a))
	for _, key := range a {
		seen[key] = struct{}{}
	}
	for _, key := range b {
		if _, ok := seen[key]; !ok {
			return false
		}
	}
	return true
}

// selectProjectedLinkSetScopeKeys loads every logical link key currently
// asserted by this exact (owner, relation, direction, tenant, source,
// runtime) scope, before any retraction/assertion mutation (R05 planning).
func selectProjectedLinkSetScopeKeys(ctx context.Context, tx *sql.Tx, ownerURN string, relation string, tenantID string, sourceID string, runtimeID string, outgoing bool) ([]projectedLinkIdentity, error) {
	query := `SELECT from_urn, to_urn FROM entity_link_assertions WHERE to_urn = $1 AND relation = $2 AND tenant_id = $3 AND source_id = $4 AND runtime_id = $5`
	if outgoing {
		query = `SELECT from_urn, to_urn FROM entity_link_assertions WHERE from_urn = $1 AND relation = $2 AND tenant_id = $3 AND source_id = $4 AND runtime_id = $5`
	}
	return collectProjectionRows(ctx, tx, query, []any{ownerURN, relation, tenantID, sourceID, runtimeID}, func(rows *sql.Rows) (projectedLinkIdentity, error) {
		key := projectedLinkIdentity{relation: relation}
		err := rows.Scan(&key.fromURN, &key.toURN)
		return key, err
	})
}

// sortedDedupedProjectedLinkSetEndpoints returns a new slice containing
// set.Endpoints sorted by URN and deduplicated by URN, preserving
// attemptReplaceProjectedLinkSet's deterministic canonical endpoint
// insertion order (RR04). It never mutates the caller's slice: two
// different finding owners that both guard the same absent consumer
// endpoints, but list them in opposite caller order, must insert them in
// the same relative order so their transactions (already holding their
// planned logical-link locks in the same global sorted order) cannot
// circular-wait on each other's entities-table insert.
func sortedDedupedProjectedLinkSetEndpoints(endpoints []*ports.ProjectedEntity) []*ports.ProjectedEntity {
	sorted := make([]*ports.ProjectedEntity, len(endpoints))
	copy(sorted, endpoints)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].URN < sorted[j].URN
	})
	deduped := make([]*ports.ProjectedEntity, 0, len(sorted))
	var lastURN string
	for i, endpoint := range sorted {
		if i > 0 && endpoint.URN == lastURN {
			continue
		}
		lastURN = endpoint.URN
		deduped = append(deduped, endpoint)
	}
	return deduped
}

// createProjectedLinkSetEndpoint materializes one ProjectedLinkSet.Endpoints
// entry with exact CreateOnly semantics (Contract G1): the entity is
// created only when entirely absent, mirroring UpsertProjectedEntity's
// own CreateOnly insert, and an existing entity's ownership, label, and
// attributes stay exactly as its own owner already projected them.
func createProjectedLinkSetEndpoint(ctx context.Context, tx *sql.Tx, endpoint *ports.ProjectedEntity) error {
	if endpoint == nil {
		return errors.New("projected link set endpoint is required")
	}
	urn := strings.TrimSpace(endpoint.URN)
	if urn == "" {
		return errors.New("projected link set endpoint urn is required")
	}
	tenantID := strings.TrimSpace(endpoint.TenantID)
	if tenantID == "" {
		return fmt.Errorf("projected link set endpoint %q: tenant id is required", urn)
	}
	sourceID := strings.TrimSpace(endpoint.SourceID)
	if sourceID == "" {
		return fmt.Errorf("projected link set endpoint %q: source id is required", urn)
	}
	entityType := strings.TrimSpace(endpoint.EntityType)
	if entityType == "" {
		return fmt.Errorf("projected link set endpoint %q: entity type is required", urn)
	}
	runtimeID := strings.TrimSpace(endpoint.RuntimeID)
	label := strings.TrimSpace(endpoint.Label)
	if label == "" {
		label = urn
	}
	workspaceID, err := ports.ValidateApplicationWorkspaceScope(tenantID, endpoint.ApplicationWorkspaceID)
	if err != nil {
		return err
	}
	attributesJSON, err := projectionAttributesJSON(endpoint.Attributes)
	if err != nil {
		return fmt.Errorf("marshal link set endpoint %q attributes: %w", urn, err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO entities (urn, tenant_id, application_workspace_id, source_id, runtime_id, entity_type, label, attributes_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
ON CONFLICT (urn) DO NOTHING`, urn, tenantID, workspaceID, sourceID, runtimeID, entityType, label, attributesJSON); err != nil {
		return fmt.Errorf("create link set endpoint %q: %w", urn, err)
	}
	return nil
}

// validateProjectedLinkSetForPostgres validates one guarded link set and
// dedupes its links by other-endpoint URN, requiring every link to already
// match the set's own relation, tenant, source, runtime, and owner
// endpoint — the set's scope is the single source of truth for those
// fields, not any one link's copy of them. An Incomplete set (G1) must
// carry no links.
func validateProjectedLinkSetForPostgres(set *ports.ProjectedLinkSet) (ownerURN string, relation string, tenantID string, sourceID string, runtimeID string, prepared []*ports.ProjectedLink, err error) {
	if set == nil {
		return "", "", "", "", "", nil, errors.New("projected link set is required")
	}
	ownerURN = strings.TrimSpace(set.OwnerURN)
	if ownerURN == "" {
		return "", "", "", "", "", nil, errors.New("projected link set owner urn is required")
	}
	relation = strings.TrimSpace(set.Relation)
	if relation == "" {
		return "", "", "", "", "", nil, errors.New("projected link set relation is required")
	}
	tenantID = strings.TrimSpace(set.TenantID)
	if tenantID == "" {
		return "", "", "", "", "", nil, errors.New("projected link set tenant id is required")
	}
	sourceID = strings.TrimSpace(set.SourceID)
	if sourceID == "" {
		return "", "", "", "", "", nil, errors.New("projected link set source id is required")
	}
	runtimeID = strings.TrimSpace(set.RuntimeID)
	if err := ports.ValidateProjectedLinkSetTenantScope(set); err != nil {
		return "", "", "", "", "", nil, err
	}
	if err := ports.ValidateProjectedLinkSetIncomplete(set); err != nil {
		return "", "", "", "", "", nil, err
	}
	index := map[string]int{}
	for _, link := range set.Links {
		if link == nil {
			return "", "", "", "", "", nil, errors.New("projected link set link is required")
		}
		if strings.TrimSpace(link.Relation) != relation {
			return "", "", "", "", "", nil, fmt.Errorf("projected link set %q %q: link relation %q does not match the set", ownerURN, relation, link.Relation)
		}
		if strings.TrimSpace(link.TenantID) != tenantID || strings.TrimSpace(link.SourceID) != sourceID || strings.TrimSpace(link.RuntimeID) != runtimeID {
			return "", "", "", "", "", nil, fmt.Errorf("projected link set %q %q: link tenant/source/runtime does not match the set", ownerURN, relation)
		}
		owner := strings.TrimSpace(link.ToURN)
		if set.Outgoing {
			owner = strings.TrimSpace(link.FromURN)
		}
		if owner != ownerURN {
			return "", "", "", "", "", nil, fmt.Errorf("projected link set %q %q: link does not place the owner on the expected endpoint", ownerURN, relation)
		}
		other := strings.TrimSpace(link.ToURN)
		if !set.Outgoing {
			other = strings.TrimSpace(link.FromURN)
		}
		if existing, ok := index[other]; ok {
			prepared[existing].Attributes = mergeProjectionAttributes(prepared[existing].Attributes, link.Attributes)
			continue
		}
		clone := *link
		clone.FromURN = strings.TrimSpace(link.FromURN)
		clone.ToURN = strings.TrimSpace(link.ToURN)
		clone.Relation = relation
		clone.TenantID = tenantID
		clone.SourceID = sourceID
		clone.RuntimeID = runtimeID
		index[other] = len(prepared)
		prepared = append(prepared, &clone)
	}
	return ownerURN, relation, tenantID, sourceID, runtimeID, prepared, nil
}

func mergeProjectionAttributes(existing map[string]string, incoming map[string]string) map[string]string {
	if len(existing) == 0 && len(incoming) == 0 {
		return nil
	}
	merged := make(map[string]string, len(existing)+len(incoming))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range incoming {
		merged[key] = value
	}
	return merged
}

func projectionAttributesFromJSONRaw(raw []byte) (map[string]string, error) {
	attributes := map[string]string{}
	if len(raw) == 0 {
		return attributes, nil
	}
	if err := json.Unmarshal(raw, &attributes); err != nil {
		return nil, err
	}
	return attributes, nil
}
