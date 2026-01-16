package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/writerinternal/cerebro/internal/policy"
)

// SnowflakeStore persists findings to Snowflake with local cache
type SnowflakeStore struct {
	db       *sql.DB
	schema   string
	cache    map[string]*Finding
	dirty    map[string]bool // tracks which findings need sync
	mu       sync.RWMutex
	syncedAt time.Time
}

// NewSnowflakeStore creates a Snowflake-backed findings store
func NewSnowflakeStore(db *sql.DB, database, schema string) *SnowflakeStore {
	return &SnowflakeStore{
		db:     db,
		schema: fmt.Sprintf("%s.%s", database, schema),
		cache:  make(map[string]*Finding),
		dirty:  make(map[string]bool),
	}
}

// Load fetches all findings from Snowflake into cache
func (s *SnowflakeStore) Load(ctx context.Context) error {
	query := fmt.Sprintf(`
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, resource_data, description,
			   first_seen, last_seen, resolved_at, suppressed_at
		FROM %s.findings
		WHERE status != 'resolved' OR resolved_at > DATEADD(day, -30, CURRENT_TIMESTAMP())
		ORDER BY last_seen DESC
		LIMIT 10000
	`, s.schema)

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var f Finding
		var resourceData []byte
		var resolvedAt, suppressedAt sql.NullTime

		err := rows.Scan(
			&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status,
			&f.ResourceID, &f.ResourceType, &resourceData, &f.Description,
			&f.FirstSeen, &f.LastSeen, &resolvedAt, &suppressedAt,
		)
		if err != nil {
			continue
		}

		if resolvedAt.Valid {
			f.ResolvedAt = &resolvedAt.Time
		}
		if resourceData != nil {
			json.Unmarshal(resourceData, &f.Resource)
		}

		s.cache[f.ID] = &f
	}

	s.syncedAt = time.Now()
	return nil
}

func (s *SnowflakeStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if existing, ok := s.cache[pf.ID]; ok {
		existing.LastSeen = now
		existing.Resource = pf.Resource
		if existing.Status == "resolved" {
			existing.Status = "open"
			existing.ResolvedAt = nil
		}
		s.dirty[pf.ID] = true
		return existing
	}

	resourceID := ""
	if id, ok := pf.Resource["_cq_id"].(string); ok {
		resourceID = id
	}
	resourceType := ""
	if rt, ok := pf.Resource["_cq_table"].(string); ok {
		resourceType = rt
	}

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

	s.cache[pf.ID] = f
	s.dirty[pf.ID] = true
	return f
}

func (s *SnowflakeStore) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.cache[id]
	return f, ok
}

func (s *SnowflakeStore) List(filter FindingFilter) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Finding, 0)
	for _, f := range s.cache {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if filter.Status != "" && f.Status != filter.Status {
			continue
		}
		if filter.PolicyID != "" && f.PolicyID != filter.PolicyID {
			continue
		}
		result = append(result, f)
	}
	return result
}

func (s *SnowflakeStore) Resolve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.cache[id]
	if !ok {
		return false
	}
	now := time.Now()
	f.Status = "resolved"
	f.ResolvedAt = &now
	s.dirty[id] = true
	return true
}

func (s *SnowflakeStore) Suppress(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.cache[id]
	if !ok {
		return false
	}
	f.Status = "suppressed"
	s.dirty[id] = true
	return true
}

func (s *SnowflakeStore) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := Stats{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
		ByPolicy:   make(map[string]int),
	}

	for _, f := range s.cache {
		stats.Total++
		stats.BySeverity[f.Severity]++
		stats.ByStatus[f.Status]++
		stats.ByPolicy[f.PolicyID]++
	}

	return stats
}

// Sync persists dirty findings to Snowflake
func (s *SnowflakeStore) Sync(ctx context.Context) error {
	s.mu.Lock()
	dirtyIDs := make([]string, 0, len(s.dirty))
	for id := range s.dirty {
		dirtyIDs = append(dirtyIDs, id)
	}
	s.mu.Unlock()

	if len(dirtyIDs) == 0 {
		return nil
	}

	for _, id := range dirtyIDs {
		s.mu.RLock()
		f, ok := s.cache[id]
		s.mu.RUnlock()
		if !ok {
			continue
		}

		if err := s.upsertFinding(ctx, f); err != nil {
			return fmt.Errorf("sync finding %s: %w", id, err)
		}

		s.mu.Lock()
		delete(s.dirty, id)
		s.mu.Unlock()
	}

	s.syncedAt = time.Now()
	return nil
}

func (s *SnowflakeStore) upsertFinding(ctx context.Context, f *Finding) error {
	resourceJSON, _ := json.Marshal(f.Resource)

	query := fmt.Sprintf(`
		MERGE INTO %s.findings t
		USING (SELECT ? as id) s
		ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET
			last_seen = ?,
			status = ?,
			resource_data = PARSE_JSON(?),
			resolved_at = ?,
			_updated_at = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (
			id, policy_id, policy_name, severity, status,
			resource_id, resource_type, resource_data, description,
			first_seen, last_seen, resolved_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?), ?, ?, ?, ?)
	`, s.schema)

	var resolvedAt interface{}
	if f.ResolvedAt != nil {
		resolvedAt = *f.ResolvedAt
	}

	_, err := s.db.ExecContext(ctx, query,
		// USING
		f.ID,
		// WHEN MATCHED
		f.LastSeen, f.Status, string(resourceJSON), resolvedAt,
		// WHEN NOT MATCHED
		f.ID, f.PolicyID, f.PolicyName, f.Severity, f.Status,
		f.ResourceID, f.ResourceType, string(resourceJSON), f.Description,
		f.FirstSeen, f.LastSeen, resolvedAt,
	)
	return err
}

// SyncedAt returns when the store was last synced
func (s *SnowflakeStore) SyncedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncedAt
}

// DirtyCount returns number of unsaved findings
func (s *SnowflakeStore) DirtyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.dirty)
}

// Ensure SnowflakeStore implements FindingStore
var _ FindingStore = (*SnowflakeStore)(nil)
