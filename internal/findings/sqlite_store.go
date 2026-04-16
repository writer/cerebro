package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writer/cerebro/internal/policy"
)

// SQLiteStore provides SQLite-based persistence for findings
type SQLiteStore struct {
	db               *sql.DB
	mu               sync.RWMutex
	dbPath           string
	logger           *slog.Logger
	attestor         FindingAttestor
	attestReobserved bool
	semanticDedup    bool
}

// NewSQLiteStore creates a SQLite-backed findings store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Initialize schema
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return &SQLiteStore{
		db:            db,
		dbPath:        dbPath,
		logger:        slog.Default(),
		semanticDedup: DefaultSemanticDedupEnabled,
	}, nil
}

// SetLogger sets a custom logger for the store
func (s *SQLiteStore) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

func (s *SQLiteStore) SetAttestor(attestor FindingAttestor, attestReobserved bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestor = attestor
	s.attestReobserved = attestReobserved
}

func (s *SQLiteStore) SetSemanticDedup(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.semanticDedup = enabled
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL,
		policy_name TEXT NOT NULL,
		severity TEXT NOT NULL,
		status TEXT NOT NULL,
		resource_id TEXT,
		resource_type TEXT,
		resource_data JSON,
		description TEXT,
		metadata JSON,
		first_seen TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL,
		resolved_at TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_findings_policy_id ON findings(policy_id);
	`
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		return err
	}

	_, err := db.ExecContext(context.Background(), "ALTER TABLE findings ADD COLUMN metadata JSON")
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
		return err
	}

	return nil
}

func scanSQLiteFinding(row interface {
	Scan(dest ...interface{}) error
}) (*Finding, error) {
	var f Finding
	var resourceData []byte
	var metadataData []byte
	var resolvedAt sql.NullTime

	if err := row.Scan(
		&f.ID,
		&f.PolicyID,
		&f.PolicyName,
		&f.Severity,
		&f.Status,
		&f.ResourceID,
		&f.ResourceType,
		&resourceData,
		&f.Description,
		&metadataData,
		&f.FirstSeen,
		&f.LastSeen,
		&resolvedAt,
	); err != nil {
		return nil, err
	}

	if len(resourceData) > 0 {
		_ = json.Unmarshal(resourceData, &f.Resource)
	}
	applyFindingMetadata(&f, metadataData)
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}
	f.Status = normalizeStatus(f.Status)
	return &f, nil
}

func (s *SQLiteStore) findSemanticMatchTx(ctx context.Context, tx *sql.Tx, pf policy.Finding, semanticKey string) (*Finding, error) {
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

	query := `
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM findings
		WHERE LOWER(severity) = LOWER(?)
	`
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

	rows, err := tx.QueryContext(ctx, query, args...)
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

func (s *SQLiteStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
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

	existing, err := scanSQLiteFinding(tx.QueryRowContext(ctx, `
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM findings
		WHERE id = ?
	`, pf.ID))

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

		_, err = tx.ExecContext(ctx, `
			INSERT INTO findings (id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, f.ID, f.PolicyID, f.PolicyName, f.Severity, f.Status, f.ResourceID, f.ResourceType, resourceData, f.Description, metadataData, f.FirstSeen, f.LastSeen)

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

	_, err = tx.ExecContext(ctx, `
		UPDATE findings
		SET policy_id = ?, policy_name = ?, severity = ?, status = ?, resource_id = ?, resource_type = ?, resource_data = ?, description = ?, metadata = ?, last_seen = ?, resolved_at = ?
		WHERE id = ?
	`,
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

func (s *SQLiteStore) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var f Finding
	var resourceData []byte
	var metadataData []byte
	var resolvedAt sql.NullTime

	err := s.db.QueryRowContext(context.Background(), "SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at FROM findings WHERE id = ?", id).
		Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status, &f.ResourceID, &f.ResourceType, &resourceData, &f.Description, &metadataData, &f.FirstSeen, &f.LastSeen, &resolvedAt)

	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		s.logger.Error("failed to get finding", "error", err, "finding_id", id)
		return nil, false
	}

	if len(resourceData) > 0 {
		_ = json.Unmarshal(resourceData, &f.Resource)
	}
	applyFindingMetadata(&f, metadataData)
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}
	f.Status = normalizeStatus(f.Status)
	EnrichFinding(&f)

	return &f, true
}

func (s *SQLiteStore) Update(id string, mutate func(*Finding) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var f Finding
	var resourceData []byte
	var metadataData []byte
	var resolvedAt sql.NullTime

	err = tx.QueryRowContext(context.Background(), `
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM findings
		WHERE id = ?
	`, id).Scan(
		&f.ID,
		&f.PolicyID,
		&f.PolicyName,
		&f.Severity,
		&f.Status,
		&f.ResourceID,
		&f.ResourceType,
		&resourceData,
		&f.Description,
		&metadataData,
		&f.FirstSeen,
		&f.LastSeen,
		&resolvedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIssueNotFound
	}
	if err != nil {
		return fmt.Errorf("query finding: %w", err)
	}

	if len(resourceData) > 0 {
		_ = json.Unmarshal(resourceData, &f.Resource)
	}
	applyFindingMetadata(&f, metadataData)
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}
	f.Status = normalizeStatus(f.Status)

	if err := mutate(&f); err != nil {
		return err
	}

	refreshFindingSemanticState(&f)
	f.Status = normalizeStatus(f.Status)
	EnrichFinding(&f)

	resourceData, _ = json.Marshal(f.Resource)
	metadataData, _ = buildFindingMetadata(&f)

	_, err = tx.ExecContext(context.Background(), `
		UPDATE findings
		SET policy_id = ?, policy_name = ?, severity = ?, status = ?, resource_id = ?, resource_type = ?, resource_data = ?, description = ?, metadata = ?, last_seen = ?, resolved_at = ?
		WHERE id = ?
	`,
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

func (s *SQLiteStore) List(filter FindingFilter) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at FROM findings WHERE 1=1"
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
			if filter.Limit <= 0 {
				query += " LIMIT -1"
			}
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		s.logger.Error("failed to list findings", "error", err)
		return []*Finding{}
	}
	defer func() { _ = rows.Close() }()

	result := make([]*Finding, 0, 100) // Pre-allocate for common case
	for rows.Next() {
		var f Finding
		var resourceData []byte
		var metadataData []byte
		var resolvedAt sql.NullTime

		if err := rows.Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status, &f.ResourceID, &f.ResourceType, &resourceData, &f.Description, &metadataData, &f.FirstSeen, &f.LastSeen, &resolvedAt); err != nil {
			continue
		}

		if len(resourceData) > 0 {
			_ = json.Unmarshal(resourceData, &f.Resource)
		}
		applyFindingMetadata(&f, metadataData)
		if resolvedAt.Valid {
			t := resolvedAt.Time
			f.ResolvedAt = &t
		}
		f.Status = normalizeStatus(f.Status)
		EnrichFinding(&f)
		if filter.SignalType != "" && !strings.EqualFold(f.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(f.Domain, filter.Domain) {
			continue
		}
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(f.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		result = append(result, &f)
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

func (s *SQLiteStore) Count(filter FindingFilter) int {
	if strings.TrimSpace(filter.SignalType) != "" ||
		strings.TrimSpace(filter.Domain) != "" ||
		strings.TrimSpace(filter.TenantID) != "" {
		filter.Limit = 0
		filter.Offset = 0
		return len(s.List(filter))
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT COUNT(*) FROM findings WHERE 1=1"
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
	if err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&count); err != nil {
		fmt.Fprintf(os.Stderr, "failed to count findings: %v\n", err)
		return 0
	}
	return count
}

func (s *SQLiteStore) Resolve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	res, err := s.db.ExecContext(context.Background(), "UPDATE findings SET status = 'RESOLVED', resolved_at = ? WHERE id = ?", now, id)
	if err != nil {
		return false
	}
	rows, _ := res.RowsAffected()
	return rows > 0
}

func (s *SQLiteStore) Suppress(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(context.Background(), "UPDATE findings SET status = 'SUPPRESSED' WHERE id = ?", id)
	if err != nil {
		return false
	}
	rows, _ := res.RowsAffected()
	return rows > 0
}

func (s *SQLiteStore) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		BySeverity:   make(map[string]int),
		ByStatus:     make(map[string]int),
		ByPolicy:     make(map[string]int),
		BySignalType: make(map[string]int),
		ByDomain:     make(map[string]int),
	}

	rows, _ := s.db.QueryContext(context.Background(), "SELECT severity, UPPER(status), policy_id, metadata FROM findings")
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

func (s *SQLiteStore) Sync(ctx context.Context) error {
	// SQLite is auto-commit or transaction based, no explicit sync needed usually
	// but we could use WAL checkpoint if needed
	return nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
