package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
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
	}
}

func NewPostgresStoreWithDB(db *sql.DB, _ string) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("postgres findings store is not initialized")
	}
	store := NewPostgresStore(db)
	if err := store.EnsureSchema(context.Background()); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("postgres findings store is not initialized")
	}
	_, err := s.db.ExecContext(ctx, s.q(`
CREATE TABLE IF NOT EXISTS `+postgresFindingsTable+` (
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
CREATE INDEX IF NOT EXISTS idx_`+postgresFindingsTable+`_status ON `+postgresFindingsTable+` (status);
CREATE INDEX IF NOT EXISTS idx_`+postgresFindingsTable+`_severity ON `+postgresFindingsTable+` (severity);
CREATE INDEX IF NOT EXISTS idx_`+postgresFindingsTable+`_policy_id ON `+postgresFindingsTable+` (policy_id);
`))
	return err
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

func (s *PostgresStore) Load(ctx context.Context) error {
	if err := s.EnsureSchema(ctx); err != nil {
		return err
	}

	cutoff := time.Now().UTC().Add(-30 * 24 * time.Hour)
	rows, err := s.db.QueryContext(ctx, s.q(`
SELECT id, policy_id, policy_name, severity, status,
	   resource_id, resource_type, resource_data, description,
	   remediation, metadata, first_seen, last_seen, resolved_at
FROM `+postgresFindingsTable+`
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
		var finding Finding
		var resourceData sql.NullString
		var remediation sql.NullString
		var metadataData string
		var resolvedAt sql.NullTime

		if err := rows.Scan(
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
			return err
		}

		if resolvedAt.Valid {
			ts := resolvedAt.Time.UTC()
			finding.ResolvedAt = &ts
		}
		if resourceData.Valid && strings.TrimSpace(resourceData.String) != "" {
			if err := parseResourceData(&finding, []byte(resourceData.String)); err != nil {
				return fmt.Errorf("parse resource data for finding %s: %w", finding.ID, err)
			}
		}
		if remediation.Valid {
			finding.Remediation = remediation.String
		}
		applyFindingMetadata(&finding, []byte(metadataData))
		finding.Status = normalizeStatus(finding.Status)
		EnrichFinding(&finding)

		s.cache[finding.ID] = &finding
		s.indexSemanticFindingLocked(&finding)
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

	finding := newFindingFromPolicyFinding(pf, now)
	applySemanticObservation(finding, pf, semanticKey)
	EnrichFinding(finding)
	_ = attestFindingEvent(ctx, s.attestor, finding, upsertAttestationEvent(false, "", s.attestReobserved), now)

	s.cache[pf.ID] = finding
	s.indexSemanticFindingLocked(finding)
	s.dirty[pf.ID] = true
	return finding
}

func (s *PostgresStore) Get(id string) (*Finding, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	finding, ok := s.cache[id]
	return finding, ok
}

func (s *PostgresStore) Update(id string, mutate func(*Finding) error) error {
	s.mu.Lock()
	finding, ok := s.cache[id]
	if !ok {
		s.mu.Unlock()
		return ErrIssueNotFound
	}
	oldKey := finding.SemanticKey
	if err := mutate(finding); err != nil {
		s.mu.Unlock()
		return err
	}
	invalidateResourceJSONCache(finding)
	finding.Status = normalizeStatus(finding.Status)
	refreshFindingSemanticState(finding)
	s.syncSemanticIndexLocked(finding, oldKey)
	EnrichFinding(finding)
	s.dirty[id] = true
	s.mu.Unlock()
	s.syncMutation(context.Background())
	return nil
}

func (s *PostgresStore) List(filter FindingFilter) []*Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()

	statusFilter := normalizeStatus(filter.Status)
	result := make([]*Finding, 0)
	for _, finding := range s.cache {
		if filter.Severity != "" && finding.Severity != filter.Severity {
			continue
		}
		if statusFilter != "" && normalizeStatus(finding.Status) != statusFilter {
			continue
		}
		if filter.PolicyID != "" && finding.PolicyID != filter.PolicyID {
			continue
		}
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(finding.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		if filter.SignalType != "" && !strings.EqualFold(finding.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(finding.Domain, filter.Domain) {
			continue
		}
		result = append(result, finding)
	}

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
	for _, finding := range s.cache {
		if filter.Severity != "" && finding.Severity != filter.Severity {
			continue
		}
		if statusFilter != "" && normalizeStatus(finding.Status) != statusFilter {
			continue
		}
		if filter.PolicyID != "" && finding.PolicyID != filter.PolicyID {
			continue
		}
		if filter.TenantID != "" && !strings.EqualFold(strings.TrimSpace(finding.TenantID), strings.TrimSpace(filter.TenantID)) {
			continue
		}
		if filter.SignalType != "" && !strings.EqualFold(finding.SignalType, filter.SignalType) {
			continue
		}
		if filter.Domain != "" && !strings.EqualFold(finding.Domain, filter.Domain) {
			continue
		}
		count++
	}
	return count
}

func (s *PostgresStore) Resolve(id string) bool {
	s.mu.Lock()
	finding, ok := s.cache[id]
	if !ok {
		s.mu.Unlock()
		return false
	}
	now := time.Now()
	finding.Status = "RESOLVED"
	finding.ResolvedAt = &now
	finding.SnoozedUntil = nil
	finding.StatusChangedAt = &now
	finding.UpdatedAt = now
	s.dirty[id] = true
	s.mu.Unlock()
	s.syncMutation(context.Background())
	return true
}

func (s *PostgresStore) Suppress(id string) bool {
	s.mu.Lock()
	finding, ok := s.cache[id]
	if !ok {
		s.mu.Unlock()
		return false
	}
	now := time.Now()
	finding.Status = "SUPPRESSED"
	finding.SnoozedUntil = nil
	finding.StatusChangedAt = &now
	finding.UpdatedAt = now
	s.dirty[id] = true
	s.mu.Unlock()
	s.syncMutation(context.Background())
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
	for _, finding := range s.cache {
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
		finding, ok := s.cache[id]
		s.mu.RUnlock()
		if ok {
			findings = append(findings, finding)
		}
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
INSERT INTO `+postgresFindingsTable+` (
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
	first_seen = EXCLUDED.first_seen,
	last_seen = EXCLUDED.last_seen,
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

func (s *PostgresStore) syncMutation(ctx context.Context) {
	if s == nil || s.db == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.Sync(ctx); err != nil {
		slog.Warn("findings: sync after mutation failed", "error", err)
	}
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
INSERT INTO `+postgresFindingsTable+` (
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
