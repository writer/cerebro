package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/snowflake"
)

const postgresFindingsTable = "cerebro_findings"

type PostgresStore struct {
	db               *sql.DB
	cache            map[string]*Finding
	semanticIndex    map[string]string
	dirty            map[string]bool
	attestor         FindingAttestor
	attestReobserved bool
	semanticDedup    bool
	rewriteSQL       func(string) string
	tableName        string
	mu               sync.RWMutex
	syncedAt         time.Time
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{
		db:            db,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
		tableName:     postgresFindingsTable,
	}
}

func NewPostgresStoreWithDB(db *sql.DB, schema string) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres findings store is not initialized")
	}
	store := NewPostgresStore(db)
	if strings.TrimSpace(schema) != "" {
		tableName, err := postgresFindingsQualifiedTable(schema)
		if err != nil {
			return nil, err
		}
		store.tableName = tableName
	}
	if err := store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return store, nil
}

func postgresFindingsQualifiedTable(schema string) (string, error) {
	schema = strings.TrimSpace(schema)
	if schema == "" {
		return postgresFindingsTable, nil
	}
	if !isSafePostgresIdentifier(schema) {
		return "", fmt.Errorf("invalid findings schema %q", schema)
	}
	return schema + ".findings", nil
}

func isSafePostgresIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func postgresFindingsIndexName(tableRef, suffix string) string {
	name := strings.NewReplacer(".", "_").Replace(strings.TrimSpace(tableRef))
	if name == "" {
		name = postgresFindingsTable
	}
	return "idx_" + name + "_" + suffix
}

func (s *PostgresStore) tableRef() string {
	if s != nil && strings.TrimSpace(s.tableName) != "" {
		return s.tableName
	}
	return postgresFindingsTable
}

func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres findings store is not initialized")
	}
	tableRef := s.tableRef()
	if schemaName, _, ok := strings.Cut(tableRef, "."); ok && strings.TrimSpace(schemaName) != "" {
		if _, err := s.db.ExecContext(ctx, s.q(`CREATE SCHEMA IF NOT EXISTS `+schemaName)); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, s.q(`
CREATE TABLE IF NOT EXISTS `+tableRef+` (
	id TEXT PRIMARY KEY,
	policy_id TEXT NOT NULL,
	policy_name TEXT NOT NULL,
	severity TEXT NOT NULL,
	status TEXT NOT NULL,
	resource_id TEXT,
	resource_type TEXT,
	resource_data TEXT,
	description TEXT,
	remediation TEXT,
	metadata TEXT NOT NULL DEFAULT '{}',
	first_seen TIMESTAMP NOT NULL,
	last_seen TIMESTAMP NOT NULL,
	resolved_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS `+postgresFindingsIndexName(tableRef, "status")+` ON `+tableRef+` (status);
CREATE INDEX IF NOT EXISTS `+postgresFindingsIndexName(tableRef, "severity")+` ON `+tableRef+` (severity);
CREATE INDEX IF NOT EXISTS `+postgresFindingsIndexName(tableRef, "policy_id")+` ON `+tableRef+` (policy_id);
`)); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, tableRef, "remediation", "TEXT"); err != nil {
		return err
	}
	return s.ensureColumn(ctx, tableRef, "metadata", "TEXT NOT NULL DEFAULT '{}'")
}

func (s *PostgresStore) ensureColumn(ctx context.Context, tableRef, columnName, columnDef string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres findings store is not initialized")
	}
	_, err := s.db.ExecContext(ctx, s.q(`ALTER TABLE `+tableRef+` ADD COLUMN `+columnName+` `+columnDef))
	if err == nil || isDuplicateColumnError(err) {
		return nil
	}
	return err
}

func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column name") ||
		(strings.Contains(msg, "column") && strings.Contains(msg, "already exists"))
}

func (s *PostgresStore) SetAttestor(attestor FindingAttestor, attestReobserved bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestor = attestor
	s.attestReobserved = attestReobserved
}

func (s *PostgresStore) SetSemanticDedup(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.semanticDedup = enabled
	s.rebuildSemanticIndexLocked()
}

func scanPostgresFinding(row interface {
	Scan(dest ...interface{}) error
}) (*Finding, error) {
	var finding Finding
	var resourceData sql.NullString
	var remediation sql.NullString
	var metadataData sql.NullString
	var resolvedAt sql.NullTime

	if err := row.Scan(
		&finding.ID,
		&finding.PolicyID,
		&finding.PolicyName,
		&finding.Severity,
		&finding.Status,
		&finding.ResourceID,
		&finding.ResourceType,
		&resourceData,
		&finding.Description,
		&remediation,
		&metadataData,
		&finding.FirstSeen,
		&finding.LastSeen,
		&resolvedAt,
	); err != nil {
		return nil, err
	}

	finding.FirstSeen = finding.FirstSeen.UTC()
	finding.LastSeen = finding.LastSeen.UTC()
	if resolvedAt.Valid {
		ts := resolvedAt.Time.UTC()
		finding.ResolvedAt = &ts
	}
	if resourceData.Valid && strings.TrimSpace(resourceData.String) != "" {
		if err := parseResourceData(&finding, []byte(resourceData.String)); err != nil {
			return nil, fmt.Errorf("parse resource data for finding %s: %w", finding.ID, err)
		}
	}
	if remediation.Valid {
		finding.Remediation = remediation.String
	}
	if metadataData.Valid {
		applyFindingMetadata(&finding, []byte(metadataData.String))
	}
	finding.Status = normalizeStatus(finding.Status)
	EnrichFinding(&finding)
	return &finding, nil
}

func (s *PostgresStore) loadPersistedFinding(ctx context.Context, id string) (*Finding, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("postgres findings store is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	row := s.db.QueryRowContext(ctx, s.q(`
SELECT id, policy_id, policy_name, severity, status,
	   resource_id, resource_type, resource_data, description,
	   remediation, metadata, first_seen, last_seen, resolved_at
FROM `+s.tableRef()+`
WHERE id = $1
`), id)
	finding, err := scanPostgresFinding(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("load finding %s: %w", id, err)
	}
	return finding, nil
}

func (s *PostgresStore) loadPersistedFindingTx(ctx context.Context, tx *sql.Tx, id string) (*Finding, error) {
	if tx == nil {
		return nil, fmt.Errorf("postgres findings transaction is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	row := tx.QueryRowContext(ctx, s.q(`
SELECT id, policy_id, policy_name, severity, status,
	   resource_id, resource_type, resource_data, description,
	   remediation, metadata, first_seen, last_seen, resolved_at
FROM `+s.tableRef()+`
WHERE id = $1
`), id)
	finding, err := scanPostgresFinding(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("load finding %s: %w", id, err)
	}
	return finding, nil
}

func (s *PostgresStore) findSemanticMatchTx(ctx context.Context, tx *sql.Tx, pf policy.Finding, semanticKey string) (*Finding, error) {
	if !findingNeedsSemanticMatch(s.semanticDedup, semanticKey) {
		return nil, nil
	}
	if tx == nil {
		return nil, fmt.Errorf("postgres findings transaction is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	resourceID := strings.TrimSpace(pf.ResourceID)
	if resourceID == "" {
		resourceID = extractResourceID(pf.Resource)
	}
	resourceType := strings.TrimSpace(pf.ResourceType)
	if resourceType == "" {
		resourceType = extractResourceType(pf.Resource)
	}

	query := `
SELECT id, policy_id, policy_name, severity, status,
	   resource_id, resource_type, resource_data, description,
	   remediation, metadata, first_seen, last_seen, resolved_at
FROM ` + s.tableRef() + `
WHERE LOWER(severity) = LOWER($1)
`
	args := []any{pf.Severity}
	switch {
	case resourceID != "":
		query += `
  AND COALESCE(resource_id, '') = $2
ORDER BY first_seen ASC, id ASC
`
		args = append(args, resourceID)
	case resourceType != "":
		query += `
  AND COALESCE(resource_type, '') = $2
ORDER BY first_seen ASC, id ASC
`
		args = append(args, resourceType)
	default:
		return nil, nil
	}

	rows, err := tx.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, fmt.Errorf("lookup semantic finding match: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		finding, scanErr := scanPostgresFinding(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		ensureFindingSemanticState(finding)
		if finding.SemanticKey == semanticKey {
			return finding, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *PostgresStore) persistFindingTx(ctx context.Context, tx *sql.Tx, finding *Finding, updateOnly bool) error {
	if tx == nil {
		return fmt.Errorf("postgres findings transaction is not initialized")
	}
	if finding == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	resourceJSON, err := resourceJSONForSync(finding)
	if err != nil {
		return fmt.Errorf("marshal resource data for finding %s: %w", finding.ID, err)
	}
	metadataJSON, err := buildFindingMetadata(finding)
	if err != nil {
		return err
	}
	if len(metadataJSON) == 0 {
		metadataJSON = []byte("{}")
	}

	var resolvedAt any
	if finding.ResolvedAt != nil {
		resolvedAt = finding.ResolvedAt.UTC()
	}

	query := `
INSERT INTO ` + s.tableRef() + ` (
	id, policy_id, policy_name, severity, status,
	resource_id, resource_type, resource_data, description,
	remediation, metadata, first_seen, last_seen, resolved_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (id) DO UPDATE SET
	policy_id = EXCLUDED.policy_id,
	policy_name = EXCLUDED.policy_name,
	severity = EXCLUDED.severity,
	status = EXCLUDED.status,
	resource_id = EXCLUDED.resource_id,
	resource_type = EXCLUDED.resource_type,
	resource_data = EXCLUDED.resource_data,
	description = EXCLUDED.description,
	remediation = EXCLUDED.remediation,
	metadata = EXCLUDED.metadata,
	first_seen = CASE
		WHEN first_seen <= EXCLUDED.first_seen THEN first_seen
		ELSE EXCLUDED.first_seen
	END,
	last_seen = CASE
		WHEN last_seen >= EXCLUDED.last_seen THEN last_seen
		ELSE EXCLUDED.last_seen
	END,
	resolved_at = EXCLUDED.resolved_at
`
	if updateOnly {
		query = `
UPDATE ` + s.tableRef() + `
SET policy_id = $2,
	policy_name = $3,
	severity = $4,
	status = $5,
	resource_id = $6,
	resource_type = $7,
	resource_data = $8,
	description = $9,
	remediation = $10,
	metadata = $11,
	first_seen = $12,
	last_seen = $13,
	resolved_at = $14
WHERE id = $1
`
	}

	result, err := tx.ExecContext(ctx, s.q(query),
		finding.ID,
		finding.PolicyID,
		finding.PolicyName,
		finding.Severity,
		normalizeStatus(finding.Status),
		finding.ResourceID,
		finding.ResourceType,
		string(resourceJSON),
		finding.Description,
		finding.Remediation,
		string(metadataJSON),
		finding.FirstSeen.UTC(),
		finding.LastSeen.UTC(),
		resolvedAt,
	)
	if err != nil {
		return fmt.Errorf("persist finding %s: %w", finding.ID, err)
	}
	if updateOnly {
		rowsAffected, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("read updated finding rows affected for %s: %w", finding.ID, rowsErr)
		}
		if rowsAffected == 0 {
			return ErrIssueNotFound
		}
	}
	return nil
}

func (s *PostgresStore) cacheFinding(finding *Finding, oldKey string) {
	if s == nil || finding == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheFindingLocked(finding, oldKey)
}

func (s *PostgresStore) cacheFindingLocked(finding *Finding, oldKey string) {
	if s == nil || finding == nil {
		return
	}
	s.ensureCacheStateLocked()
	s.cache[finding.ID] = finding
	s.syncSemanticIndexLocked(finding, oldKey)
	delete(s.dirty, finding.ID)
	s.syncedAt = time.Now().UTC()
}

func (s *PostgresStore) cacheFindingFromRead(finding *Finding) {
	if s == nil || finding == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureCacheStateLocked()
	oldKey := ""
	if existing, ok := s.cache[finding.ID]; ok && existing != nil {
		oldKey = existing.SemanticKey
	}
	s.cache[finding.ID] = finding
	s.syncSemanticIndexLocked(finding, oldKey)
}

func (s *PostgresStore) Load(ctx context.Context) error {
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}

	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	rows, err := s.db.QueryContext(ctx, s.q(`
SELECT id, policy_id, policy_name, severity, status,
	   resource_id, resource_type, resource_data, description,
	   remediation, metadata, first_seen, last_seen, resolved_at
FROM `+s.tableRef()+`
WHERE UPPER(status) != 'RESOLVED' OR resolved_at > $1
ORDER BY last_seen DESC
`), cutoff)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cache = make(map[string]*Finding)
	s.semanticIndex = make(map[string]string)
	s.dirty = make(map[string]bool)

	for rows.Next() {
		finding, scanErr := scanPostgresFinding(rows)
		if scanErr != nil {
			return scanErr
		}
		s.cache[finding.ID] = finding
		s.indexSemanticFindingLocked(finding)
	}

	s.syncedAt = time.Now().UTC()
	return rows.Err()
}

func (s *PostgresStore) ImportRecords(ctx context.Context, records []*snowflake.FindingRecord) error {
	if len(records) == 0 {
		return nil
	}
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}

	insertedAny := false
	for _, record := range records {
		finding := findingFromImportedRecord(record)
		if finding == nil {
			continue
		}
		inserted, err := s.insertImportedFinding(ctx, finding)
		if err != nil {
			return err
		}
		if !inserted {
			continue
		}
		insertedAny = true

		s.mu.Lock()
		s.ensureCacheStateLocked()
		s.cache[finding.ID] = finding
		s.syncSemanticIndexLocked(finding, "")
		s.mu.Unlock()
	}

	if insertedAny {
		s.mu.Lock()
		s.syncedAt = time.Now().UTC()
		s.mu.Unlock()
	}
	return nil
}

func (s *PostgresStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	if s == nil || s.db == nil {
		slog.Warn("findings: upsert failed", "finding_id", pf.ID, "error", "postgres findings store is not initialized")
		return nil
	}
	s.mu.Lock()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.EnsureSchema(ctx); err != nil {
		s.mu.Unlock()
		slog.Warn("findings: upsert failed", "finding_id", pf.ID, "error", err)
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.mu.Unlock()
		slog.Warn("findings: upsert failed", "finding_id", pf.ID, "error", err)
		return nil
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	semanticKey := semanticKeyForPolicyFinding(pf)
	existing, err := s.loadPersistedFindingTx(ctx, tx, pf.ID)
	if err != nil {
		s.mu.Unlock()
		slog.Warn("findings: upsert failed", "finding_id", pf.ID, "error", err)
		return nil
	}
	if existing == nil {
		if cached, ok := s.cache[pf.ID]; ok && cached != nil {
			existing = cloneFinding(cached)
		}
	}
	if existing == nil {
		existing, err = s.findSemanticMatchTx(ctx, tx, pf, semanticKey)
		if err != nil {
			s.mu.Unlock()
			slog.Warn("findings: upsert failed", "finding_id", pf.ID, "error", err)
			return nil
		}
	}
	if existing == nil {
		if match := s.findSemanticMatchLocked(semanticKey); match != nil {
			existing = cloneFinding(match)
		}
	}

	oldKey := ""
	finding := existing
	var eventType FindingAttestationEventType
	if finding == nil {
		finding = newFindingFromPolicyFinding(pf, now)
		applySemanticObservation(finding, pf, semanticKey)
		EnrichFinding(finding)
		if err := s.persistFindingTx(ctx, tx, finding, false); err != nil {
			s.mu.Unlock()
			slog.Warn("findings: upsert failed", "finding_id", finding.ID, "error", err)
			return nil
		}
		eventType = upsertAttestationEvent(false, "", s.attestReobserved)
	} else {
		oldKey = finding.SemanticKey
		previousStatus := applyPolicyFindingUpdate(finding, pf, now)
		applySemanticObservation(finding, pf, semanticKey)
		EnrichFinding(finding)
		if err := s.persistFindingTx(ctx, tx, finding, false); err != nil {
			s.mu.Unlock()
			slog.Warn("findings: upsert failed", "finding_id", finding.ID, "error", err)
			return nil
		}
		eventType = upsertAttestationEvent(true, previousStatus, s.attestReobserved)
	}

	if err := tx.Commit(); err != nil {
		s.mu.Unlock()
		slog.Warn("findings: upsert failed", "finding_id", finding.ID, "error", err)
		return nil
	}

	attestor := s.attestor
	s.cacheFindingLocked(finding, oldKey)
	s.mu.Unlock()
	if eventType != "" {
		_ = attestFindingEvent(ctx, attestor, finding, eventType, now)
	}
	return finding
}

func (s *PostgresStore) Get(id string) (*Finding, bool) {
	if s == nil {
		return nil, false
	}
	if s.db == nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		finding, ok := s.cache[id]
		return finding, ok
	}

	finding, err := s.loadPersistedFinding(context.Background(), id)
	if err != nil || finding == nil {
		if err != nil {
			slog.Warn("findings: get failed", "finding_id", id, "error", err)
		}
		s.mu.RLock()
		defer s.mu.RUnlock()
		cached, ok := s.cache[id]
		return cached, ok
	}
	s.cacheFindingFromRead(finding)
	return finding, true
}

func (s *PostgresStore) mutatePersistedFinding(ctx context.Context, id string, mutate func(*Finding) error) (*Finding, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("postgres findings store is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	current, ok := s.Get(id)
	if !ok || current == nil {
		return nil, ErrIssueNotFound
	}
	working := cloneFinding(current)
	if err := s.EnsureSchema(ctx); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	finding, err := s.loadPersistedFindingTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	if finding == nil {
		finding = working
	}
	oldKey := finding.SemanticKey
	if err := mutate(finding); err != nil {
		return nil, err
	}
	invalidateResourceJSONCache(finding)
	finding.Status = normalizeStatus(finding.Status)
	refreshFindingSemanticState(finding)
	EnrichFinding(finding)
	if err := s.persistFindingTx(ctx, tx, finding, false); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.cacheFinding(finding, oldKey)
	return finding, nil
}

func (s *PostgresStore) Update(id string, mutate func(*Finding) error) error {
	_, err := s.mutatePersistedFinding(context.Background(), id, mutate)
	return err
}

func (s *PostgresStore) List(filter FindingFilter) []*Finding {
	if s == nil {
		return nil
	}
	if s.db == nil {
		return s.listCached(filter)
	}
	if err := s.EnsureSchema(context.Background()); err != nil {
		slog.Warn("findings: list failed", "error", err)
		return s.listCached(filter)
	}

	query := `
SELECT id, policy_id, policy_name, severity, status,
	   resource_id, resource_type, resource_data, description,
	   remediation, metadata, first_seen, last_seen, resolved_at
FROM ` + s.tableRef() + `
WHERE 1=1
`
	args := make([]any, 0, 5)
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		query += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if status := normalizeStatus(filter.Status); status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND UPPER(status) = UPPER($%d)", len(args))
	}
	if filter.PolicyID != "" {
		args = append(args, filter.PolicyID)
		query += fmt.Sprintf(" AND policy_id = $%d", len(args))
	}
	query += " ORDER BY last_seen DESC, first_seen DESC, id ASC"
	if filter.TenantID == "" && filter.SignalType == "" && filter.Domain == "" {
		if filter.Limit > 0 {
			args = append(args, filter.Limit)
			query += fmt.Sprintf(" LIMIT $%d", len(args))
		}
		if filter.Offset > 0 {
			args = append(args, filter.Offset)
			query += fmt.Sprintf(" OFFSET $%d", len(args))
		}
	}

	rows, err := s.db.QueryContext(context.Background(), s.q(query), args...)
	if err != nil {
		slog.Warn("findings: list failed", "error", err)
		return s.listCached(filter)
	}
	defer func() { _ = rows.Close() }()

	result := make([]*Finding, 0)
	for rows.Next() {
		finding, scanErr := scanPostgresFinding(rows)
		if scanErr != nil {
			slog.Warn("findings: list failed", "error", scanErr)
			return s.listCached(filter)
		}
		if !matchesFindingFilter(finding, filter) {
			continue
		}
		result = append(result, finding)
		s.cacheFindingFromRead(finding)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("findings: list failed", "error", err)
		return s.listCached(filter)
	}

	if filter.TenantID != "" || filter.SignalType != "" || filter.Domain != "" {
		result = applyFindingPagination(result, filter)
	}
	return result
}

func (s *PostgresStore) Count(filter FindingFilter) int {
	unpaged := filter
	unpaged.Limit = 0
	unpaged.Offset = 0
	if s == nil {
		return 0
	}
	if s.db == nil {
		return len(s.listCached(unpaged))
	}
	if filter.TenantID != "" || filter.SignalType != "" || filter.Domain != "" {
		return len(s.List(unpaged))
	}
	if err := s.EnsureSchema(context.Background()); err != nil {
		slog.Warn("findings: count failed", "error", err)
		return len(s.listCached(unpaged))
	}

	query := `SELECT COUNT(*) FROM ` + s.tableRef() + ` WHERE 1=1`
	args := make([]any, 0, 3)
	if filter.Severity != "" {
		args = append(args, filter.Severity)
		query += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if status := normalizeStatus(filter.Status); status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND UPPER(status) = UPPER($%d)", len(args))
	}
	if filter.PolicyID != "" {
		args = append(args, filter.PolicyID)
		query += fmt.Sprintf(" AND policy_id = $%d", len(args))
	}

	var count int
	if err := s.db.QueryRowContext(context.Background(), s.q(query), args...).Scan(&count); err != nil {
		slog.Warn("findings: count failed", "error", err)
		return len(s.listCached(unpaged))
	}
	return count
}

func (s *PostgresStore) listCached(filter FindingFilter) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Finding, 0)
	for _, finding := range s.cache {
		if !matchesFindingFilter(finding, filter) {
			continue
		}
		result = append(result, finding)
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		if !result[i].FirstSeen.Equal(result[j].FirstSeen) {
			return result[i].FirstSeen.After(result[j].FirstSeen)
		}
		return result[i].ID < result[j].ID
	})
	return applyFindingPagination(result, filter)
}

func matchesFindingFilter(finding *Finding, filter FindingFilter) bool {
	if finding == nil {
		return false
	}
	if filter.Severity != "" && finding.Severity != filter.Severity {
		return false
	}
	if status := normalizeStatus(filter.Status); status != "" && normalizeStatus(finding.Status) != status {
		return false
	}
	if filter.PolicyID != "" && finding.PolicyID != filter.PolicyID {
		return false
	}
	if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(finding.TenantID), strings.TrimSpace(filter.TenantID)) {
		return false
	}
	if filter.SignalType != "" && !strings.EqualFold(strings.TrimSpace(finding.SignalType), strings.TrimSpace(filter.SignalType)) {
		return false
	}
	if filter.Domain != "" && !strings.EqualFold(strings.TrimSpace(finding.Domain), strings.TrimSpace(filter.Domain)) {
		return false
	}
	return true
}

func applyFindingPagination(findings []*Finding, filter FindingFilter) []*Finding {
	if filter.Offset <= 0 && filter.Limit <= 0 {
		return findings
	}
	if filter.Offset >= len(findings) {
		return []*Finding{}
	}
	start := filter.Offset
	if start < 0 {
		start = 0
	}
	end := len(findings)
	if filter.Limit > 0 && start+filter.Limit < end {
		end = start + filter.Limit
	}
	return findings[start:end]
}

func (s *PostgresStore) Resolve(id string) bool {
	if err := s.ResolveWithError(id); err != nil {
		if !errors.Is(err, ErrIssueNotFound) {
			slog.Warn("findings: resolve failed", "finding_id", id, "error", err)
		}
		return false
	}
	return true
}

func (s *PostgresStore) ResolveWithError(id string) error {
	_, err := s.mutatePersistedFinding(context.Background(), id, func(finding *Finding) error {
		now := time.Now()
		finding.Status = "RESOLVED"
		finding.ResolvedAt = &now
		finding.SnoozedUntil = nil
		finding.StatusChangedAt = &now
		finding.UpdatedAt = now
		return nil
	})
	return err
}

func (s *PostgresStore) Suppress(id string) bool {
	if err := s.SuppressWithError(id); err != nil {
		if !errors.Is(err, ErrIssueNotFound) {
			slog.Warn("findings: suppress failed", "finding_id", id, "error", err)
		}
		return false
	}
	return true
}

func (s *PostgresStore) SuppressWithError(id string) error {
	_, err := s.mutatePersistedFinding(context.Background(), id, func(finding *Finding) error {
		now := time.Now()
		finding.Status = "SUPPRESSED"
		finding.SnoozedUntil = nil
		finding.StatusChangedAt = &now
		finding.UpdatedAt = now
		return nil
	})
	return err
}

func (s *PostgresStore) Stats() Stats {
	stats := Stats{
		BySeverity:   make(map[string]int),
		ByStatus:     make(map[string]int),
		ByPolicy:     make(map[string]int),
		BySignalType: make(map[string]int),
		ByDomain:     make(map[string]int),
	}
	for _, finding := range s.List(FindingFilter{}) {
		stats.Total++
		stats.BySeverity[finding.Severity]++
		stats.ByStatus[normalizeStatus(finding.Status)]++
		stats.ByPolicy[finding.PolicyID]++
		signalType := strings.ToLower(strings.TrimSpace(finding.SignalType))
		if signalType == "" {
			signalType = SignalTypeSecurity
		}
		stats.BySignalType[signalType]++
		domain := strings.ToLower(strings.TrimSpace(finding.Domain))
		if domain == "" {
			domain = DomainInfra
		}
		stats.ByDomain[domain]++
	}
	return stats
}

func (s *PostgresStore) Sync(ctx context.Context) error {
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}

	s.mu.Lock()
	findings, err := snapshotDirtyFindings(s.cache, s.dirty)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("snapshot dirty findings: %w", err)
	}
	if len(findings) == 0 {
		return nil
	}

	const batchSize = 100
	for start := 0; start < len(findings); start += batchSize {
		end := start + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		batch := findings[start:end]
		if err := s.syncBatch(ctx, batch); err != nil {
			return err
		}

		s.mu.Lock()
		for _, finding := range batch {
			delete(s.dirty, finding.ID)
		}
		s.mu.Unlock()
	}

	s.syncedAt = time.Now().UTC()
	return nil
}

func (s *PostgresStore) syncBatch(ctx context.Context, batch []*Finding) error {
	tableRef := s.tableRef()
	args := make([]any, 0, len(batch)*14)
	values := make([]string, 0, len(batch))
	for _, finding := range batch {
		resourceJSON, err := resourceJSONForSync(finding)
		if err != nil {
			return fmt.Errorf("marshal resource data for finding %s: %w", finding.ID, err)
		}
		metadataJSON, err := buildFindingMetadata(finding)
		if err != nil {
			return err
		}
		if len(metadataJSON) == 0 {
			metadataJSON = []byte("{}")
		}

		var resolvedAt any
		if finding.ResolvedAt != nil {
			resolvedAt = finding.ResolvedAt.UTC()
		}

		values = append(values, placeholderTuple(len(args)+1, 14))
		args = append(args,
			finding.ID,
			finding.PolicyID,
			finding.PolicyName,
			finding.Severity,
			normalizeStatus(finding.Status),
			finding.ResourceID,
			finding.ResourceType,
			string(resourceJSON),
			finding.Description,
			finding.Remediation,
			string(metadataJSON),
			finding.FirstSeen.UTC(),
			finding.LastSeen.UTC(),
			resolvedAt,
		)
	}

	_, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO `+tableRef+` (
	id, policy_id, policy_name, severity, status,
	resource_id, resource_type, resource_data, description,
	remediation, metadata, first_seen, last_seen, resolved_at
) VALUES `+strings.Join(values, ",")+`
ON CONFLICT (id) DO UPDATE SET
	policy_id = EXCLUDED.policy_id,
	policy_name = EXCLUDED.policy_name,
	severity = EXCLUDED.severity,
	status = EXCLUDED.status,
	resource_id = EXCLUDED.resource_id,
	resource_type = EXCLUDED.resource_type,
	resource_data = EXCLUDED.resource_data,
	description = EXCLUDED.description,
	remediation = EXCLUDED.remediation,
	metadata = EXCLUDED.metadata,
	first_seen = CASE
		WHEN first_seen <= EXCLUDED.first_seen THEN first_seen
		ELSE EXCLUDED.first_seen
	END,
	last_seen = CASE
		WHEN last_seen >= EXCLUDED.last_seen THEN last_seen
		ELSE EXCLUDED.last_seen
	END,
	resolved_at = EXCLUDED.resolved_at
`), args...)
	if err != nil {
		return fmt.Errorf("sync findings batch: %w", err)
	}
	return nil
}

func (s *PostgresStore) SyncedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncedAt
}

func (s *PostgresStore) DirtyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.dirty)
}

func (s *PostgresStore) q(query string) string {
	if s != nil && s.rewriteSQL != nil {
		return s.rewriteSQL(query)
	}
	return query
}

func (s *PostgresStore) findSemanticMatchLocked(semanticKey string) *Finding {
	if !findingNeedsSemanticMatch(s.semanticDedup, semanticKey) {
		return nil
	}
	id, ok := s.semanticIndex[semanticKey]
	if !ok {
		return nil
	}
	return s.cache[id]
}

func (s *PostgresStore) syncSemanticIndexLocked(finding *Finding, oldKey string) {
	if !s.semanticDedup {
		return
	}
	ensureFindingSemanticState(finding)
	oldKey = strings.TrimSpace(oldKey)
	if oldKey != "" && oldKey != finding.SemanticKey && s.semanticIndex[oldKey] == finding.ID {
		delete(s.semanticIndex, oldKey)
	}
	if strings.TrimSpace(finding.SemanticKey) != "" {
		s.semanticIndex[finding.SemanticKey] = finding.ID
	}
}

func cloneFinding(src *Finding) *Finding {
	if src == nil {
		return nil
	}
	data, err := json.Marshal(src)
	if err != nil {
		clone := *src
		if src.resourceJSONRaw != nil {
			clone.resourceJSONRaw = append([]byte(nil), src.resourceJSONRaw...)
		}
		return &clone
	}
	var clone Finding
	if err := json.Unmarshal(data, &clone); err != nil {
		copy := *src
		if src.resourceJSONRaw != nil {
			copy.resourceJSONRaw = append([]byte(nil), src.resourceJSONRaw...)
		}
		return &copy
	}
	if src.resourceJSONRaw != nil {
		clone.resourceJSONRaw = append([]byte(nil), src.resourceJSONRaw...)
	}
	return &clone
}

func (s *PostgresStore) indexSemanticFindingLocked(finding *Finding) {
	if !s.semanticDedup {
		return
	}
	ensureFindingSemanticState(finding)
	if strings.TrimSpace(finding.SemanticKey) != "" {
		s.semanticIndex[finding.SemanticKey] = finding.ID
	}
}

func (s *PostgresStore) rebuildSemanticIndexLocked() {
	s.semanticIndex = make(map[string]string, len(s.cache))
	if !s.semanticDedup {
		return
	}
	for _, finding := range s.cache {
		s.indexSemanticFindingLocked(finding)
	}
}

func placeholderTuple(start, count int) string {
	parts := make([]string, count)
	for idx := 0; idx < count; idx++ {
		parts[idx] = fmt.Sprintf("$%d", start+idx)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func (s *PostgresStore) ensureCacheStateLocked() {
	if s.cache == nil {
		s.cache = make(map[string]*Finding)
	}
	if s.semanticIndex == nil {
		s.semanticIndex = make(map[string]string)
	}
	if s.dirty == nil {
		s.dirty = make(map[string]bool)
	}
}

func findingFromImportedRecord(record *snowflake.FindingRecord) *Finding {
	if record == nil || strings.TrimSpace(record.ID) == "" {
		return nil
	}
	finding := &Finding{
		ID:           record.ID,
		PolicyID:     record.PolicyID,
		PolicyName:   record.PolicyName,
		Severity:     record.Severity,
		Status:       normalizeStatus(record.Status),
		ResourceID:   record.ResourceID,
		ResourceType: record.ResourceType,
		Resource:     record.ResourceData,
		Description:  record.Description,
		Remediation:  record.Remediation,
		FirstSeen:    record.FirstSeen.UTC(),
		LastSeen:     record.LastSeen.UTC(),
	}
	if record.ResolvedAt != nil {
		ts := record.ResolvedAt.UTC()
		finding.ResolvedAt = &ts
	}
	if len(record.Metadata) > 0 {
		applyFindingMetadata(finding, record.Metadata)
	}
	if len(record.ResourceData) > 0 {
		resourceJSON, err := json.Marshal(record.ResourceData)
		if err == nil {
			finding.resourceJSONRaw = cloneBytes(resourceJSON)
		}
	}
	EnrichFinding(finding)
	return finding
}

func (s *PostgresStore) insertImportedFinding(ctx context.Context, finding *Finding) (bool, error) {
	resourceJSON, err := resourceJSONForSync(finding)
	if err != nil {
		return false, fmt.Errorf("marshal resource data for finding %s: %w", finding.ID, err)
	}
	metadataJSON, err := buildFindingMetadata(finding)
	if err != nil {
		return false, err
	}
	if len(metadataJSON) == 0 {
		metadataJSON = []byte("{}")
	}

	var resolvedAt any
	if finding.ResolvedAt != nil {
		resolvedAt = finding.ResolvedAt.UTC()
	}

	result, err := s.db.ExecContext(ctx, s.q(`
INSERT INTO `+s.tableRef()+` (
	id, policy_id, policy_name, severity, status,
	resource_id, resource_type, resource_data, description,
	remediation, metadata, first_seen, last_seen, resolved_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
ON CONFLICT (id) DO NOTHING
`),
		finding.ID,
		finding.PolicyID,
		finding.PolicyName,
		finding.Severity,
		normalizeStatus(finding.Status),
		finding.ResourceID,
		finding.ResourceType,
		string(resourceJSON),
		finding.Description,
		finding.Remediation,
		string(metadataJSON),
		finding.FirstSeen.UTC(),
		finding.LastSeen.UTC(),
		resolvedAt,
	)
	if err != nil {
		return false, fmt.Errorf("import finding %s: %w", finding.ID, err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read imported finding rows affected for %s: %w", finding.ID, err)
	}
	return rowsAffected > 0, nil
}

var _ FindingStore = (*PostgresStore)(nil)
