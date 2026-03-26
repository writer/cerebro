package findings

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/writer/cerebro/internal/policy"
	"github.com/writer/cerebro/internal/postgres"
)

// PostgresStore persists findings to PostgreSQL with local cache
type PostgresStore struct {
	db               *sql.DB
	schema           string
	cache            map[string]*Finding
	semanticIndex    map[string]string
	dirty            map[string]bool // tracks which findings need sync
	attestor         FindingAttestor
	attestReobserved bool
	semanticDedup    bool
	mu               sync.RWMutex
	syncedAt         time.Time
}

// NewPostgresStore creates a Postgres-backed findings store
func NewPostgresStore(db *sql.DB, schema string) *PostgresStore {
	return &PostgresStore{
		db:            db,
		schema:        schema,
		cache:         make(map[string]*Finding),
		semanticIndex: make(map[string]string),
		dirty:         make(map[string]bool),
		semanticDedup: DefaultSemanticDedupEnabled,
	}
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

// SetConnection updates the Postgres database handle and schema used by the store.
func (s *PostgresStore) SetConnection(db *sql.DB, schema string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db
	if strings.TrimSpace(schema) != "" {
		s.schema = schema
	}
}

// qualifiedTable returns the schema-qualified table name for findings.
func (s *PostgresStore) qualifiedTable() string {
	if s.schema == "" {
		return "findings"
	}
	safeTableRef, err := postgres.SafeQualifiedTableRef(strings.TrimSpace(s.schema), "findings")
	if err != nil {
		return "findings"
	}
	return safeTableRef
}

// Load fetches all findings from Postgres into cache
func (s *PostgresStore) Load(ctx context.Context) error {
	table := s.qualifiedTable()

	// #nosec G202 -- table is built by qualifiedTable from validated identifiers only.
	query := `
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, resource_data, description,
			   remediation, metadata,
			   first_seen, last_seen, resolved_at, suppressed_at
		FROM ` + table + `
		WHERE UPPER(status) != 'RESOLVED' OR resolved_at > CURRENT_TIMESTAMP - INTERVAL '30 days'
		ORDER BY last_seen DESC
		LIMIT 10000
	`

	rows, err := s.db.QueryContext(ctx, query)
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
		if len(resourceData) > 0 {
			if err := parseResourceData(&f, resourceData); err != nil {
				return fmt.Errorf("parse resource data for finding %s: %w", f.ID, err)
			}
		}
		if remediation.Valid {
			f.Remediation = remediation.String
		}
		applyFindingMetadata(&f, metadataData)
		f.Status = normalizeStatus(f.Status)
		EnrichFinding(&f)

		s.cache[f.ID] = &f
		s.indexSemanticFindingLocked(&f)
	}

	s.syncedAt = time.Now()
	return nil
}

func (s *PostgresStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	semanticKey := semanticKeyForPolicyFinding(pf)

	if existing, ok := s.cache[pf.ID]; ok {
		oldKey := existing.SemanticKey
		previousStatus := applyPolicyFindingUpdate(existing, pf, now)
		applySemanticObservation(existing, pf, semanticKey)
		s.syncSemanticIndexLocked(existing, oldKey)
		EnrichFinding(existing)
		eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
		if eventType != "" {
			_ = attestFindingEvent(ctx, s.attestor, existing, eventType, now)
		}
		s.dirty[existing.ID] = true
		return existing
	}
	if match := s.findSemanticMatchLocked(semanticKey); match != nil {
		oldKey := match.SemanticKey
		previousStatus := applyPolicyFindingUpdate(match, pf, now)
		applySemanticObservation(match, pf, semanticKey)
		s.syncSemanticIndexLocked(match, oldKey)
		EnrichFinding(match)
		eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
		if eventType != "" {
			_ = attestFindingEvent(ctx, s.attestor, match, eventType, now)
		}
		s.dirty[match.ID] = true
		return match
	}

	f := newFindingFromPolicyFinding(pf, now)
	applySemanticObservation(f, pf, semanticKey)
	EnrichFinding(f)
	_ = attestFindingEvent(ctx, s.attestor, f, upsertAttestationEvent(false, "", s.attestReobserved), now)

	s.cache[pf.ID] = f
	s.indexSemanticFindingLocked(f)
	s.dirty[pf.ID] = true
	return f
}

func (s *PostgresStore) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.cache[id]
	return f, ok
}

func (s *PostgresStore) Update(id string, mutate func(*Finding) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.cache[id]
	if !ok {
		return ErrIssueNotFound
	}
	oldKey := f.SemanticKey
	if err := mutate(f); err != nil {
		return err
	}
	invalidateResourceJSONCache(f)
	f.Status = normalizeStatus(f.Status)
	refreshFindingSemanticState(f)
	s.syncSemanticIndexLocked(f, oldKey)
	EnrichFinding(f)
	s.dirty[id] = true
	return nil
}

func (s *PostgresStore) List(filter FindingFilter) []*Finding {
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
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(f.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		if filter.SignalType != "" && !strings.EqualFold(f.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(f.Domain, filter.Domain) {
			continue
		}
		result = append(result, f)
	}

	// Apply pagination if specified
	if filter.Offset > 0 || filter.Limit > 0 {
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
	s.mu.RLock()
	defer s.mu.RUnlock()

	statusFilter := normalizeStatus(filter.Status)

	count := 0
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
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(f.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		if filter.SignalType != "" && !strings.EqualFold(f.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(f.Domain, filter.Domain) {
			continue
		}
		count++
	}
	return count
}

func (s *PostgresStore) Resolve(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.cache[id]
	if !ok {
		return false
	}
	now := time.Now()
	f.Status = "RESOLVED"
	f.ResolvedAt = &now
	f.SnoozedUntil = nil
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	s.dirty[id] = true
	return true
}

func (s *PostgresStore) Suppress(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.cache[id]
	if !ok {
		return false
	}
	now := time.Now()
	f.Status = "SUPPRESSED"
	f.SnoozedUntil = nil
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	s.dirty[id] = true
	return true
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

	for _, f := range s.cache {
		stats.Total++
		stats.BySeverity[f.Severity]++
		stats.ByStatus[normalizeStatus(f.Status)]++
		stats.ByPolicy[f.PolicyID]++
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

// Sync persists dirty findings to Postgres
func (s *PostgresStore) Sync(ctx context.Context) error {
	s.mu.Lock()
	dirtyIDs := make([]string, 0, len(s.dirty))
	for id := range s.dirty {
		dirtyIDs = append(dirtyIDs, id)
	}
	s.mu.Unlock()

	if len(dirtyIDs) == 0 {
		return nil
	}

	findings := make([]*Finding, 0, len(dirtyIDs))
	for _, id := range dirtyIDs {
		s.mu.RLock()
		f, ok := s.cache[id]
		s.mu.RUnlock()
		if ok {
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 {
		return nil
	}

	table := s.qualifiedTable()

	const batchSize = 100
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		batch := findings[i:end]

		valuePlaceholders := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*14)
		paramIdx := 1
		for _, f := range batch {
			resourceJSON, err := resourceJSONForSync(f)
			if err != nil {
				return fmt.Errorf("marshal resource data for finding %s: %w", f.ID, err)
			}
			metadataJSON, _ := buildFindingMetadata(f)
			if len(metadataJSON) == 0 {
				metadataJSON = []byte("{}")
			}

			var resolvedAt interface{}
			if f.ResolvedAt != nil {
				resolvedAt = *f.ResolvedAt
			}

			valuePlaceholders = append(valuePlaceholders, fmt.Sprintf(
				"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d::jsonb, $%d, $%d, $%d::jsonb, $%d, $%d, $%d)",
				paramIdx, paramIdx+1, paramIdx+2, paramIdx+3, paramIdx+4,
				paramIdx+5, paramIdx+6, paramIdx+7, paramIdx+8, paramIdx+9,
				paramIdx+10, paramIdx+11, paramIdx+12, paramIdx+13,
			))
			paramIdx += 14

			args = append(args,
				f.ID,
				f.PolicyID,
				f.PolicyName,
				f.Severity,
				normalizeStatus(f.Status),
				f.ResourceID,
				f.ResourceType,
				string(resourceJSON),
				f.Description,
				f.Remediation,
				string(metadataJSON),
				f.FirstSeen,
				f.LastSeen,
				resolvedAt,
			)
		}

		// #nosec G202 -- table is validated by qualifiedTable and valuePlaceholders are generated positional parameters.
		upsert := `
			INSERT INTO ` + table + ` (
				id, policy_id, policy_name, severity, status,
				resource_id, resource_type, resource_data, description,
				remediation, metadata, first_seen, last_seen, resolved_at
			) VALUES ` + strings.Join(valuePlaceholders, ",") + `
			ON CONFLICT (id) DO UPDATE SET
				last_seen = EXCLUDED.last_seen,
				status = EXCLUDED.status,
				resource_data = EXCLUDED.resource_data,
				description = EXCLUDED.description,
				remediation = EXCLUDED.remediation,
				metadata = EXCLUDED.metadata,
				resolved_at = EXCLUDED.resolved_at,
				updated_at = CURRENT_TIMESTAMP
		`
		if _, err := s.db.ExecContext(ctx, upsert, args...); err != nil {
			return fmt.Errorf("sync findings batch: %w", err)
		}

		s.mu.Lock()
		for _, f := range batch {
			delete(s.dirty, f.ID)
		}
		s.mu.Unlock()
	}

	s.syncedAt = time.Now()
	return nil
}

// SyncedAt returns when the store was last synced
func (s *PostgresStore) SyncedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncedAt
}

// DirtyCount returns number of unsaved findings
func (s *PostgresStore) DirtyCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.dirty)
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

func (s *PostgresStore) syncSemanticIndexLocked(f *Finding, oldKey string) {
	if !s.semanticDedup {
		return
	}
	ensureFindingSemanticState(f)
	oldKey = strings.TrimSpace(oldKey)
	if oldKey != "" && oldKey != f.SemanticKey && s.semanticIndex[oldKey] == f.ID {
		delete(s.semanticIndex, oldKey)
	}
	if strings.TrimSpace(f.SemanticKey) != "" {
		s.semanticIndex[f.SemanticKey] = f.ID
	}
}

func (s *PostgresStore) indexSemanticFindingLocked(f *Finding) {
	if !s.semanticDedup {
		return
	}
	ensureFindingSemanticState(f)
	if strings.TrimSpace(f.SemanticKey) != "" {
		s.semanticIndex[f.SemanticKey] = f.ID
	}
}

func (s *PostgresStore) rebuildSemanticIndexLocked() {
	s.semanticIndex = make(map[string]string, len(s.cache))
	if !s.semanticDedup {
		return
	}
	for _, f := range s.cache {
		s.indexSemanticFindingLocked(f)
	}
}

// Ensure PostgresStore implements FindingStore
var _ FindingStore = (*PostgresStore)(nil)
