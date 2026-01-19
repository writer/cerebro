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
			   remediation, metadata,
			   first_seen, last_seen, resolved_at, suppressed_at
		FROM %s.findings
		WHERE UPPER(status) != 'RESOLVED' OR resolved_at > DATEADD(day, -30, CURRENT_TIMESTAMP())
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
		var metadataData []byte
		var resolvedAt, suppressedAt sql.NullTime
		var remediation sql.NullString

		err := rows.Scan(
			&f.ID, &f.PolicyID, &f.PolicyName, &f.Severity, &f.Status,
			&f.ResourceID, &f.ResourceType, &resourceData, &f.Description,
			&remediation, &metadataData,
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
		if remediation.Valid {
			f.Remediation = remediation.String
		}
		applyFindingMetadata(&f, metadataData)
		f.Status = normalizeStatus(f.Status)
		EnrichFinding(&f)

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
		existing.Status = normalizeStatus(existing.Status)
		existing.LastSeen = now
		if len(pf.Resource) > 0 {
			existing.Resource = pf.Resource
		}
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
			frameworks := make([]string, 0, len(pf.Frameworks))
			securityCategories := make([]string, 0)
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
		if normalizeStatus(existing.Status) == "RESOLVED" {
			existing.Status = "OPEN"
			existing.ResolvedAt = nil
			existing.StatusChangedAt = &now
		}
		EnrichFinding(existing)
		s.dirty[pf.ID] = true
		return existing
	}

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

	statusFilter := normalizeStatus(filter.Status)

	result := make([]*Finding, 0)
	for _, f := range s.cache {
		if filter.Severity != "" && f.Severity != filter.Severity {
			continue
		}
		if statusFilter != "" && normalizeStatus(f.Status) != statusFilter {
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
	f.Status = "RESOLVED"
	f.ResolvedAt = &now
	f.StatusChangedAt = &now
	f.UpdatedAt = now
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
	now := time.Now()
	f.Status = "SUPPRESSED"
	f.StatusChangedAt = &now
	f.UpdatedAt = now
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
		stats.ByStatus[normalizeStatus(f.Status)]++
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
	metadataJSON, _ := buildFindingMetadata(f)
	if len(metadataJSON) == 0 {
		metadataJSON = []byte("{}")
	}

	query := fmt.Sprintf(`
		MERGE INTO %s.findings t
		USING (SELECT ? as id) s
		ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET
			last_seen = ?,
			status = ?,
			resource_data = PARSE_JSON(?),
			description = ?,
			remediation = ?,
			metadata = PARSE_JSON(?),
			resolved_at = ?,
			_updated_at = CURRENT_TIMESTAMP()
		WHEN NOT MATCHED THEN INSERT (
			id, policy_id, policy_name, severity, status,
			resource_id, resource_type, resource_data, description,
			remediation, metadata, first_seen, last_seen, resolved_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?), ?, ?, PARSE_JSON(?), ?, ?, ?)
	`, s.schema)

	var resolvedAt interface{}
	if f.ResolvedAt != nil {
		resolvedAt = *f.ResolvedAt
	}

	_, err := s.db.ExecContext(ctx, query,
		// USING
		f.ID,
		// WHEN MATCHED
		f.LastSeen, normalizeStatus(f.Status), string(resourceJSON), f.Description, f.Remediation, string(metadataJSON), resolvedAt,
		// WHEN NOT MATCHED
		f.ID, f.PolicyID, f.PolicyName, f.Severity, normalizeStatus(f.Status),
		f.ResourceID, f.ResourceType, string(resourceJSON), f.Description,
		f.Remediation, string(metadataJSON), f.FirstSeen, f.LastSeen, resolvedAt,
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
