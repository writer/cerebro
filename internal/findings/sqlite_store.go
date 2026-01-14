package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/writerinternal/cerebro/internal/policy"
)

// SQLiteStore provides SQLite-based persistence for findings
type SQLiteStore struct {
	db     *sql.DB
	mu     sync.RWMutex
	dbPath string
}

// NewSQLiteStore creates a SQLite-backed findings store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Initialize schema
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return &SQLiteStore{
		db:     db,
		dbPath: dbPath,
	}, nil
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
		first_seen TIMESTAMP NOT NULL,
		last_seen TIMESTAMP NOT NULL,
		resolved_at TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_findings_policy_id ON findings(policy_id);
	`
	_, err := db.Exec(schema)
	return err
}

func (s *SQLiteStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	resourceData, _ := json.Marshal(pf.Resource)
	resourceID := extractResourceID(pf.Resource)
	resourceType := extractResourceType(pf.Resource)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		// Fallback to in-memory behavior if DB fails? For now, log error and return
		fmt.Fprintf(os.Stderr, "failed to begin transaction: %v\n", err)
		return nil
	}
	defer tx.Rollback()

	// Check if exists
	var existing Finding
	var existingResourceData []byte
	var resolvedAt sql.NullTime

	err = tx.QueryRowContext(ctx, "SELECT id, first_seen, status, resource_data FROM findings WHERE id = ?", pf.ID).
		Scan(&existing.ID, &existing.FirstSeen, &existing.Status, &existingResourceData)

	if err == sql.ErrNoRows {
		// Insert new
		f := &Finding{
			ID:           pf.ID,
			PolicyID:     pf.PolicyID,
			PolicyName:   pf.PolicyName,
			Severity:     pf.Severity,
			Status:       "open",
			ResourceID:   resourceID,
			ResourceType: resourceType,
			Resource:     pf.Resource,
			Description:  pf.Description,
			FirstSeen:    now,
			LastSeen:     now,
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO findings (id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, f.ID, f.PolicyID, f.PolicyName, f.Severity, f.Status, f.ResourceID, f.ResourceType, resourceData, f.Description, f.FirstSeen, f.LastSeen)

		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to insert finding: %v\n", err)
			return nil
		}
		if err := tx.Commit(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to commit insert: %v\n", err)
			return nil
		}
		return f

	} else if err != nil {
		fmt.Fprintf(os.Stderr, "failed to query finding: %v\n", err)
		return nil
	}

	// Update existing
	status := existing.Status
	resolvedAtVal := resolvedAt
	if status == "resolved" {
		status = "open"
		resolvedAtVal = sql.NullTime{Valid: false}
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE findings 
		SET last_seen = ?, resource_data = ?, status = ?, resolved_at = ?
		WHERE id = ?
	`, now, resourceData, status, resolvedAtVal, pf.ID)

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to update finding: %v\n", err)
		return nil
	}
	if err := tx.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to commit update: %v\n", err)
		return nil
	}

	existing.LastSeen = now
	existing.Resource = pf.Resource
	existing.Status = status
	if resolvedAtVal.Valid {
		t := resolvedAtVal.Time
		existing.ResolvedAt = &t
	} else {
		existing.ResolvedAt = nil
	}
	existing.PolicyName = pf.PolicyName
	existing.Severity = pf.Severity
	existing.Description = pf.Description

	return &existing
}

func (s *SQLiteStore) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var f Finding
	var resourceData []byte
	var resolvedAt sql.NullTime

	err := s.db.QueryRow("SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, first_seen, last_seen, resolved_at FROM findings WHERE id = ?", id).
		Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status, &f.ResourceID, &f.ResourceType, &resourceData, &f.Description, &f.FirstSeen, &f.LastSeen, &resolvedAt)

	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get finding: %v\n", err)
		return nil, false
	}

	if len(resourceData) > 0 {
		_ = json.Unmarshal(resourceData, &f.Resource)
	}
	if resolvedAt.Valid {
		t := resolvedAt.Time
		f.ResolvedAt = &t
	}

	return &f, true
}

func (s *SQLiteStore) List(filter FindingFilter) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := "SELECT id, policy_id, policy_name, severity, status, resource_id, resource_type, resource_data, description, first_seen, last_seen, resolved_at FROM findings WHERE 1=1"
	var args []interface{}

	if filter.Severity != "" {
		query += " AND severity = ?"
		args = append(args, filter.Severity)
	}
	if filter.Status != "" {
		query += " AND status = ?"
		args = append(args, filter.Status)
	}
	if filter.PolicyID != "" {
		query += " AND policy_id = ?"
		args = append(args, filter.PolicyID)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to list findings: %v\n", err)
		return []*Finding{}
	}
	defer rows.Close()

	var result []*Finding
	for rows.Next() {
		var f Finding
		var resourceData []byte
		var resolvedAt sql.NullTime

		if err := rows.Scan(&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status, &f.ResourceID, &f.ResourceType, &resourceData, &f.Description, &f.FirstSeen, &f.LastSeen, &resolvedAt); err != nil {
			continue
		}

		if len(resourceData) > 0 {
			_ = json.Unmarshal(resourceData, &f.Resource)
		}
		if resolvedAt.Valid {
			t := resolvedAt.Time
			f.ResolvedAt = &t
		}
		result = append(result, &f)
	}

	return result
}

func (s *SQLiteStore) Resolve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	res, err := s.db.Exec("UPDATE findings SET status = 'resolved', resolved_at = ? WHERE id = ?", now, id)
	if err != nil {
		return false
	}
	rows, _ := res.RowsAffected()
	return rows > 0
}

func (s *SQLiteStore) Suppress(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec("UPDATE findings SET status = 'suppressed' WHERE id = ?", id)
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
	s.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&stats.Total)

	// By Severity
	rows, _ := s.db.Query("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
	if rows != nil {
		for rows.Next() {
			var k string
			var v int
			rows.Scan(&k, &v)
			stats.BySeverity[k] = v
		}
		rows.Close()
	}

	// By Status
	rows, _ = s.db.Query("SELECT status, COUNT(*) FROM findings GROUP BY status")
	if rows != nil {
		for rows.Next() {
			var k string
			var v int
			rows.Scan(&k, &v)
			stats.ByStatus[k] = v
		}
		rows.Close()
	}

	// By Policy
	rows, _ = s.db.Query("SELECT policy_id, COUNT(*) FROM findings GROUP BY policy_id")
	if rows != nil {
		for rows.Next() {
			var k string
			var v int
			rows.Scan(&k, &v)
			stats.ByPolicy[k] = v
		}
		rows.Close()
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
