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
		db:     db,
		dbPath: dbPath,
		logger: slog.Default(),
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

func (s *SQLiteStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Error("failed to begin transaction", "error", err)
		return nil
	}
	defer func() { _ = tx.Rollback() }()

	var existing Finding
	var existingResourceData []byte
	var existingMetadataData []byte
	var resolvedAt sql.NullTime

	err = tx.QueryRowContext(ctx, `
		SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, metadata, first_seen, last_seen, resolved_at
		FROM findings
		WHERE id = ?
	`, pf.ID).Scan(
		&existing.ID,
		&existing.PolicyID,
		&existing.PolicyName,
		&existing.Severity,
		&existing.Status,
		&existing.ResourceID,
		&existing.ResourceType,
		&existingResourceData,
		&existing.Description,
		&existingMetadataData,
		&existing.FirstSeen,
		&existing.LastSeen,
		&resolvedAt,
	)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		s.logger.Error("failed to query finding", "error", err, "finding_id", pf.ID)
		return nil
	}

	if errors.Is(err, sql.ErrNoRows) {
		resourceID := pf.ResourceID
		if resourceID == "" {
			resourceID = extractResourceID(pf.Resource)
		}
		resourceType := pf.ResourceType
		if resourceType == "" {
			resourceType = extractResourceType(pf.Resource)
		}
		resourceName := pf.ResourceName
		if resourceName == "" {
			resourceName = extractResourceName(pf.Resource)
		}

		frameworks := make([]string, 0, len(pf.Frameworks))
		securityCategories := make([]string, 0)
		for _, fm := range pf.Frameworks {
			frameworks = append(frameworks, fm.Name)
			for _, control := range fm.Controls {
				securityCategories = append(securityCategories, fm.Name+":"+control)
			}
		}

		f := &Finding{
			ID:                 pf.ID,
			IssueID:            pf.ID,
			ControlID:          pf.ControlID,
			PolicyID:           pf.PolicyID,
			PolicyName:         pf.PolicyName,
			Title:              pf.Title,
			Severity:           pf.Severity,
			Status:             "OPEN",
			ResourceID:         resourceID,
			ResourceName:       resourceName,
			ResourceType:       resourceType,
			Resource:           pf.Resource,
			Description:        pf.Description,
			Remediation:        pf.Remediation,
			RiskCategories:     pf.RiskCategories,
			SecurityFrameworks: frameworks,
			SecurityCategories: securityCategories,
			ComplianceMappings: pf.Frameworks,
			MitreAttack:        pf.MitreAttack,
			CreatedAt:          now,
			UpdatedAt:          now,
			FirstSeen:          now,
			LastSeen:           now,
		}
		f.StatusChangedAt = &now
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

	if len(existingResourceData) > 0 {
		_ = json.Unmarshal(existingResourceData, &existing.Resource)
	}
	applyFindingMetadata(&existing, existingMetadataData)
	if resolvedAt.Valid {
		t := resolvedAt.Time
		existing.ResolvedAt = &t
	}

	previousStatus := normalizeStatus(existing.Status)
	existing.Status = previousStatus
	existing.LastSeen = now
	existing.UpdatedAt = now

	if pf.Description != "" {
		existing.Description = pf.Description
	}
	if pf.Severity != "" {
		existing.Severity = pf.Severity
	}
	if pf.ControlID != "" {
		existing.ControlID = pf.ControlID
	}
	if pf.Title != "" {
		existing.Title = pf.Title
	}
	if pf.Remediation != "" {
		existing.Remediation = pf.Remediation
	}
	if pf.PolicyID != "" {
		existing.PolicyID = pf.PolicyID
	}
	if pf.PolicyName != "" {
		existing.PolicyName = pf.PolicyName
	}
	if len(pf.Resource) > 0 {
		existing.Resource = pf.Resource
	}
	if pf.ResourceID != "" {
		existing.ResourceID = pf.ResourceID
	}
	if pf.ResourceType != "" {
		existing.ResourceType = pf.ResourceType
	}
	if pf.ResourceName != "" {
		existing.ResourceName = pf.ResourceName
	}
	if len(pf.RiskCategories) > 0 {
		existing.RiskCategories = pf.RiskCategories
	}
	if len(pf.Frameworks) > 0 {
		totalControls := 0
		for _, fm := range pf.Frameworks {
			totalControls += len(fm.Controls)
		}
		frameworks := make([]string, 0, len(pf.Frameworks))
		securityCategories := make([]string, 0, totalControls)
		for _, fm := range pf.Frameworks {
			frameworks = append(frameworks, fm.Name)
			for _, control := range fm.Controls {
				securityCategories = append(securityCategories, fm.Name+":"+control)
			}
		}
		existing.SecurityFrameworks = frameworks
		existing.SecurityCategories = securityCategories
		existing.ComplianceMappings = pf.Frameworks
	}
	if len(pf.MitreAttack) > 0 {
		existing.MitreAttack = pf.MitreAttack
	}

	if previousStatus == "RESOLVED" {
		existing.Status = "OPEN"
		existing.ResolvedAt = nil
		existing.StatusChangedAt = &now
	}

	EnrichFinding(&existing)
	eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
	if eventType != "" {
		if attestErr := attestFindingEvent(ctx, s.attestor, &existing, eventType, now); attestErr != nil {
			s.logger.Warn("finding attestation append failed", "error", attestErr, "finding_id", existing.ID)
		}
	}

	resourceData, _ := json.Marshal(existing.Resource)
	metadataData, _ := buildFindingMetadata(&existing)

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

	return &existing
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

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
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
		result = append(result, &f)
	}

	return result
}

func (s *SQLiteStore) Count(filter FindingFilter) int {
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
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
		ByPolicy:   make(map[string]int),
	}

	// Total
	_ = s.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM findings").Scan(&stats.Total)

	// By Severity
	rows, _ := s.db.QueryContext(context.Background(), "SELECT severity, COUNT(*) FROM findings GROUP BY severity")
	if rows != nil {
		for rows.Next() {
			var k string
			var v int
			_ = rows.Scan(&k, &v)
			stats.BySeverity[k] = v
		}
		_ = rows.Close()
	}

	// By Status
	rows, _ = s.db.QueryContext(context.Background(), "SELECT UPPER(status), COUNT(*) FROM findings GROUP BY UPPER(status)")
	if rows != nil {
		for rows.Next() {
			var k string
			var v int
			_ = rows.Scan(&k, &v)
			stats.ByStatus[k] = v
		}
		_ = rows.Close()
	}

	// By Policy
	rows, _ = s.db.QueryContext(context.Background(), "SELECT policy_id, COUNT(*) FROM findings GROUP BY policy_id")
	if rows != nil {
		for rows.Next() {
			var k string
			var v int
			_ = rows.Scan(&k, &v)
			stats.ByPolicy[k] = v
		}
		_ = rows.Close()
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
