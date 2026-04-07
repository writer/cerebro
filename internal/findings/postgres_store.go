package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/warehouse"
)

type PostgresStore struct {
	db               *sql.DB
	mu               sync.RWMutex
	logger           *slog.Logger
	attestor         FindingAttestor
	attestReobserved bool
	semanticDedup    bool
	schema           string
	tableName        string
	ownsDB           bool
}

func NewPostgresStore(dsn, schema string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", strings.TrimSpace(dsn))
	if err != nil {
		return nil, fmt.Errorf("open postgres database: %w", err)
	}
	store, err := NewPostgresStoreWithDB(db, schema)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	store.ownsDB = true
	return store, nil
}

func NewPostgresStoreWithDB(db *sql.DB, schema string) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres database is nil")
	}
	schema = strings.TrimSpace(schema)
	if schema == "" {
		schema = "public"
	}

	store := &PostgresStore{
		db:            db,
		logger:        slog.Default(),
		semanticDedup: DefaultSemanticDedupEnabled,
		schema:        schema,
		tableName:     schema + ".findings",
	}
	if err := store.initSchema(); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return store, nil
}

func (s *PostgresStore) SetLogger(logger *slog.Logger) {
	s.logger = logger
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
}

func (s *PostgresStore) initSchema() error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres store is not initialized")
	}
	createSchema := fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, s.schema)
	if _, err := s.db.ExecContext(context.Background(), createSchema); err != nil {
		return err
	}
	schema := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL,
		policy_name TEXT NOT NULL,
		severity TEXT NOT NULL,
		status TEXT NOT NULL,
		resource_id TEXT,
		resource_type TEXT,
		resource_data JSONB,
		description TEXT,
		metadata JSONB,
		first_seen TIMESTAMPTZ NOT NULL,
		last_seen TIMESTAMPTZ NOT NULL,
		resolved_at TIMESTAMPTZ
	);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON %s (status);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON %s (severity);
	CREATE INDEX IF NOT EXISTS idx_findings_policy_id ON %s (policy_id);
	`, s.tableName, s.tableName, s.tableName, s.tableName)
	if _, err := s.db.ExecContext(context.Background(), schema); err != nil {
		return err
	}
	_, err := s.db.ExecContext(context.Background(), fmt.Sprintf(`ALTER TABLE %s ADD COLUMN IF NOT EXISTS metadata JSONB`, s.tableName))
	return err
}

func (s *PostgresStore) q(query string) string {
	return warehouse.RewriteQueryForDialect(query, warehouse.DialectPostgres)
}

func (s *PostgresStore) findSemanticMatchTx(ctx context.Context, tx *sql.Tx, pf policy.Finding, semanticKey string) (*Finding, error) {
	if !findingNeedsSemanticMatch(s.semanticDedup, semanticKey) {
		return nil, nil
	}

	resourceID := strings.TrimSpace(pf.ResourceID)
	if resourceID == "" {
		resourceID = extractResourceID(pf.Resource)
	}
	resourceType := strings.TrimSpace(pf.ResourceType)
	if resourceType == "" {
		resourceType = extractResourceType(pf.Resource)
	}

	query := fmt.Sprintf(`
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM %s
		WHERE LOWER(severity) = LOWER(?)
	`, s.tableName)
	args := []any{pf.Severity}
	switch {
	case resourceID != "":
		query += " AND resource_id = ?"
		args = append(args, resourceID)
	case resourceType != "":
		query += " AND resource_type = ?"
		args = append(args, resourceType)
	default:
		return nil, nil
	}
	query += " ORDER BY first_seen ASC, id ASC"

	rows, err := tx.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		f, err := scanSQLiteFinding(rows)
		if err != nil {
			return nil, err
		}
		if semanticKeyForFinding(f) == semanticKey {
			return f, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *PostgresStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	semanticKey := semanticKeyForPolicyFinding(pf)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Error("failed to begin transaction", "error", err)
		return nil
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := scanSQLiteFinding(tx.QueryRowContext(ctx, s.q(fmt.Sprintf(`
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM %s
		WHERE id = ?
	`, s.tableName)), pf.ID))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.logger.Error("failed to query finding", "error", err, "finding_id", pf.ID)
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		existing, err = s.findSemanticMatchTx(ctx, tx, pf, semanticKey)
		if err != nil {
			s.logger.Error("failed to query semantic finding match", "error", err, "finding_id", pf.ID)
			return nil
		}
	}

	if existing == nil {
		f := newFindingFromPolicyFinding(pf, now)
		applySemanticObservation(f, pf, semanticKey)
		EnrichFinding(f)
		if attestErr := attestFindingEvent(ctx, s.attestor, f, upsertAttestationEvent(false, "", s.attestReobserved), now); attestErr != nil {
			s.logger.Warn("finding attestation append failed", "error", attestErr, "finding_id", f.ID)
		}

		resourceData, _ := json.Marshal(f.Resource)
		metadataData, _ := buildFindingMetadata(f)

		_, err = tx.ExecContext(ctx, s.q(fmt.Sprintf(`
			INSERT INTO %s (id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, s.tableName)), f.ID, f.PolicyID, f.PolicyName, f.Severity, f.Status, f.ResourceID, f.ResourceType, resourceData, f.Description, metadataData, f.FirstSeen, f.LastSeen)
		if err != nil {
			s.logger.Error("failed to insert finding", "error", err, "finding_id", pf.ID)
			return nil
		}
		if commitErr := tx.Commit(); commitErr != nil {
			s.logger.Error("failed to commit insert", "error", commitErr, "finding_id", pf.ID)
			return nil
		}
		return f
	}

	previousStatus := applyPolicyFindingUpdate(existing, pf, now)
	applySemanticObservation(existing, pf, semanticKey)
	EnrichFinding(existing)
	eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
	if eventType != "" {
		if attestErr := attestFindingEvent(ctx, s.attestor, existing, eventType, now); attestErr != nil {
			s.logger.Warn("finding attestation append failed", "error", attestErr, "finding_id", existing.ID)
		}
	}

	resourceData, _ := json.Marshal(existing.Resource)
	metadataData, _ := buildFindingMetadata(existing)

	_, err = tx.ExecContext(ctx, s.q(fmt.Sprintf(`
		UPDATE %s
		SET policy_id = ?, policy_name = ?, severity = ?, status = ?, resource_id = ?, resource_type = ?, resource_data = ?, description = ?, metadata = ?, last_seen = ?, resolved_at = ?
		WHERE id = ?
	`, s.tableName)),
		existing.PolicyID,
		existing.PolicyName,
		existing.Severity,
		existing.Status,
		existing.ResourceID,
		existing.ResourceType,
		resourceData,
		existing.Description,
		metadataData,
		now,
		existing.ResolvedAt,
		existing.ID,
	)
	if err != nil {
		s.logger.Error("failed to update finding", "error", err, "finding_id", pf.ID)
		return nil
	}
	if err := tx.Commit(); err != nil {
		s.logger.Error("failed to commit update", "error", err, "finding_id", pf.ID)
		return nil
	}

	return existing
}

func (s *PostgresStore) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	f, err := scanSQLiteFinding(s.db.QueryRowContext(context.Background(), s.q(fmt.Sprintf(`
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM %s
		WHERE id = ?
	`, s.tableName)), id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		s.logger.Error("failed to get finding", "error", err, "finding_id", id)
		return nil, false
	}
	EnrichFinding(f)
	return f, true
}

func (s *PostgresStore) Update(id string, mutate func(*Finding) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	f, err := scanSQLiteFinding(tx.QueryRowContext(context.Background(), s.q(fmt.Sprintf(`
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM %s
		WHERE id = ?
	`, s.tableName)), id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIssueNotFound
	}
	if err != nil {
		return fmt.Errorf("query finding: %w", err)
	}

	if err := mutate(f); err != nil {
		return err
	}

	refreshFindingSemanticState(f)
	f.Status = normalizeStatus(f.Status)
	EnrichFinding(f)

	resourceData, _ := json.Marshal(f.Resource)
	metadataData, _ := buildFindingMetadata(f)

	_, err = tx.ExecContext(context.Background(), s.q(fmt.Sprintf(`
		UPDATE %s
		SET policy_id = ?, policy_name = ?, severity = ?, status = ?, resource_id = ?, resource_type = ?, resource_data = ?, description = ?, metadata = ?, last_seen = ?, resolved_at = ?
		WHERE id = ?
	`, s.tableName)),
		f.PolicyID,
		f.PolicyName,
		f.Severity,
		f.Status,
		f.ResourceID,
		f.ResourceType,
		resourceData,
		f.Description,
		metadataData,
		f.LastSeen,
		f.ResolvedAt,
		f.ID,
	)
	if err != nil {
		return fmt.Errorf("update finding: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit update: %w", err)
	}
	return nil
}

func (s *PostgresStore) List(filter FindingFilter) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := fmt.Sprintf("SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at FROM %s WHERE 1=1", s.tableName)
	var args []interface{}

	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		query += " AND UPPER(status) = ?"
		args = append(args, strings.ToUpper(filter.Status))
	}
	if filter.PolicyID != "" {
		query += " AND policy_id = ?"
		args = append(args, filter.PolicyID)
	}

	query += " ORDER BY first_seen DESC"
	applyDBPagination := strings.TrimSpace(filter.SignalType) == "" &&
		strings.TrimSpace(filter.Domain) == "" &&
		strings.TrimSpace(filter.TenantID) == ""
	if applyDBPagination {
		if filter.Limit > 0 {
			query += " LIMIT ?"
			args = append(args, filter.Limit)
		}
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(context.Background(), s.q(query), args...)
	if err != nil {
		s.logger.Error("failed to list findings", "error", err)
		return []*Finding{}
	}
	defer func() { _ = rows.Close() }()

	result := make([]*Finding, 0, 100)
	for rows.Next() {
		f, err := scanSQLiteFinding(rows)
		if err != nil {
			continue
		}
		EnrichFinding(f)
		if filter.SignalType != "" && !strings.EqualFold(f.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(f.Domain, filter.Domain) {
			continue
		}
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(f.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		result = append(result, f)
	}

	if !applyDBPagination && (filter.Offset > 0 || filter.Limit > 0) {
		if filter.Offset >= len(result) {
			return []*Finding{}
		}
		end := len(result)
		if filter.Limit > 0 && filter.Offset+filter.Limit < end {
			end = filter.Offset + filter.Limit
		}
		result = result[filter.Offset:end]
	}

	return result
}

func (s *PostgresStore) Count(filter FindingFilter) int {
	if strings.TrimSpace(filter.SignalType) != "" ||
		strings.TrimSpace(filter.Domain) != "" ||
		strings.TrimSpace(filter.TenantID) != "" {
		filter.Limit = 0
		filter.Offset = 0
		return len(s.List(filter))
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE 1=1", s.tableName)
	var args []interface{}

	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		query += " AND UPPER(status) = ?"
		args = append(args, strings.ToUpper(filter.Status))
	}
	if filter.PolicyID != "" {
		query += " AND policy_id = ?"
		args = append(args, filter.PolicyID)
	}

	var count int
	if err := s.db.QueryRowContext(context.Background(), s.q(query), args...).Scan(&count); err != nil {
		fmt.Fprintf(os.Stderr, "failed to count findings: %v\n", err)
		return 0
	}
	return count
}

func (s *PostgresStore) Resolve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	res, err := s.db.ExecContext(context.Background(), s.q(fmt.Sprintf("UPDATE %s SET status = 'RESOLVED', resolved_at = ? WHERE id = ?", s.tableName)), now, id)
	if err != nil {
		return false
	}
	rows, _ := res.RowsAffected()
	return rows > 0
}

func (s *PostgresStore) Suppress(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(context.Background(), s.q(fmt.Sprintf("UPDATE %s SET status = 'SUPPRESSED' WHERE id = ?", s.tableName)), id)
	if err != nil {
		return false
	}
	rows, _ := res.RowsAffected()
	return rows > 0
}

func (s *PostgresStore) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		BySeverity:   make(map[string]int),
		ByStatus:     make(map[string]int),
		ByPolicy:     make(map[string]int),
		BySignalType: make(map[string]int),
		ByDomain:     make(map[string]int),
	}

	rows, _ := s.db.QueryContext(context.Background(), fmt.Sprintf("SELECT severity, UPPER(status), policy_id, metadata FROM %s", s.tableName))
	if rows == nil {
		return stats
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var severity string
		var status string
		var policyID string
		var metadataData []byte
		if err := rows.Scan(&severity, &status, &policyID, &metadataData); err != nil {
			continue
		}

		stats.Total++
		stats.BySeverity[severity]++
		stats.ByStatus[status]++
		stats.ByPolicy[policyID]++

		var f Finding
		applyFindingMetadata(&f, metadataData)
		signalType := strings.ToLower(strings.TrimSpace(f.SignalType))
		if signalType == "" {
			signalType = SignalTypeSecurity
		}
		stats.BySignalType[signalType]++
		domain := strings.ToLower(strings.TrimSpace(f.Domain))
		if domain == "" {
			domain = DomainInfra
		}
		stats.ByDomain[domain]++
	}

	return stats
}

func (s *PostgresStore) Sync(context.Context) error {
	return nil
}

func (s *PostgresStore) Close() error {
	if s == nil || s.db == nil || !s.ownsDB {
		return nil
	}
	return s.db.Close()
}
