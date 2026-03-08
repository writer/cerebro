package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/evalops/cerebro/internal/policy"
	"github.com/evalops/cerebro/internal/snowflake"
)

// SnowflakeStore persists findings to Snowflake with local cache
type SnowflakeStore struct {
	db               *sql.DB
	schema           string
	cache            map[string]*Finding
	dirty            map[string]bool // tracks which findings need sync
	attestor         FindingAttestor
	attestReobserved bool
	mu               sync.RWMutex
	syncedAt         time.Time
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

func (s *SnowflakeStore) SetAttestor(attestor FindingAttestor, attestReobserved bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestor = attestor
	s.attestReobserved = attestReobserved
}

// SetConnection updates the Snowflake database handle and schema used by the store.
func (s *SnowflakeStore) SetConnection(db *sql.DB, database, schema string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db = db
	if strings.TrimSpace(database) != "" && strings.TrimSpace(schema) != "" {
		s.schema = fmt.Sprintf("%s.%s", database, schema)
	}
}

// Load fetches all findings from Snowflake into cache
func (s *SnowflakeStore) Load(ctx context.Context) error {
	findingsTable, err := snowflake.SafeQualifiedTableRef(s.schema, "findings")
	if err != nil {
		return fmt.Errorf("invalid findings table reference: %w", err)
	}

	// #nosec G202 -- findingsTable is validated via SafeQualifiedTableRef.
	query := `
		SELECT id, policy_id, policy_name, severity, status,
			   resource_id, resource_type, resource_data, description,
			   remediation, metadata,
			   first_seen, last_seen, resolved_at, suppressed_at
		FROM ` + findingsTable + `
		WHERE UPPER(status) != 'RESOLVED' OR resolved_at > DATEADD(day, -30, CURRENT_TIMESTAMP())
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
	}

	s.syncedAt = time.Now()
	return nil
}

func (s *SnowflakeStore) Upsert(ctx context.Context, pf policy.Finding) *Finding {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if existing, ok := s.cache[pf.ID]; ok {
		previousStatus := normalizeStatus(existing.Status)
		existing.Status = normalizeStatus(existing.Status)
		existing.LastSeen = now
		if len(pf.Resource) > 0 {
			existing.Resource = pf.Resource
			invalidateResourceJSONCache(existing)
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
		if existing.SignalType == "" {
			existing.SignalType = SignalTypeSecurity
		}
		if existing.Domain == "" {
			existing.Domain = inferDomain(existing.PolicyID, existing.ResourceType)
		}
		if previousStatus == "RESOLVED" || previousStatus == "SNOOZED" {
			existing.Status = "OPEN"
			existing.ResolvedAt = nil
			existing.SnoozedUntil = nil
			existing.StatusChangedAt = &now
		}
		EnrichFinding(existing)
		eventType := upsertAttestationEvent(true, previousStatus, s.attestReobserved)
		if eventType != "" {
			_ = attestFindingEvent(ctx, s.attestor, existing, eventType, now)
		}
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
		SignalType:         SignalTypeSecurity,
		Domain:             inferDomain(pf.PolicyID, resourceType),
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
	_ = attestFindingEvent(ctx, s.attestor, f, upsertAttestationEvent(false, "", s.attestReobserved), now)

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

func (s *SnowflakeStore) Update(id string, mutate func(*Finding) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, ok := s.cache[id]
	if !ok {
		return ErrIssueNotFound
	}
	if err := mutate(f); err != nil {
		return err
	}
	invalidateResourceJSONCache(f)
	f.Status = normalizeStatus(f.Status)
	EnrichFinding(f)
	s.dirty[id] = true
	return nil
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

func (s *SnowflakeStore) Count(filter FindingFilter) int {
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
	f.SnoozedUntil = nil
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
	f.SnoozedUntil = nil
	f.StatusChangedAt = &now
	f.UpdatedAt = now
	s.dirty[id] = true
	return true
}

func (s *SnowflakeStore) Stats() Stats {
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

	findingsTable, err := snowflake.SafeQualifiedTableRef(s.schema, "findings")
	if err != nil {
		return fmt.Errorf("invalid findings table reference: %w", err)
	}

	const batchSize = 100
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		batch := findings[i:end]
		values := make([]string, 0, len(batch))
		args := make([]interface{}, 0, len(batch)*14)
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

			values = append(values, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
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

		// #nosec G202 -- findingsTable is validated and VALUES placeholders are generated internally.
		merge := `
			MERGE INTO ` + findingsTable + ` t
			USING (SELECT column1 AS id,
			              column2 AS policy_id,
			              column3 AS policy_name,
			              column4 AS severity,
			              column5 AS status,
			              column6 AS resource_id,
			              column7 AS resource_type,
			              column8 AS resource_data,
			              column9 AS description,
			              column10 AS remediation,
			              column11 AS metadata,
			              column12 AS first_seen,
			              column13 AS last_seen,
			              column14 AS resolved_at
			       FROM VALUES ` + strings.Join(values, ",") + `) s
			ON t.ID = s.id
			WHEN MATCHED THEN UPDATE SET
				LAST_SEEN = s.last_seen,
				STATUS = s.status,
				RESOURCE_DATA = PARSE_JSON(s.resource_data),
				DESCRIPTION = s.description,
				REMEDIATION = s.remediation,
				METADATA = PARSE_JSON(s.metadata),
				RESOLVED_AT = s.resolved_at,
				UPDATED_AT = CURRENT_TIMESTAMP()
			WHEN NOT MATCHED THEN INSERT (
				ID, POLICY_ID, POLICY_NAME, SEVERITY, STATUS,
				RESOURCE_ID, RESOURCE_TYPE, RESOURCE_DATA, DESCRIPTION,
				REMEDIATION, METADATA, FIRST_SEEN, LAST_SEEN, RESOLVED_AT
			) VALUES (
				s.id, s.policy_id, s.policy_name, s.severity, s.status,
				s.resource_id, s.resource_type, PARSE_JSON(s.resource_data), s.description,
				s.remediation, PARSE_JSON(s.metadata), s.first_seen, s.last_seen, s.resolved_at
			)
		`
		if _, err := s.db.ExecContext(ctx, merge, args...); err != nil {
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

func parseResourceData(f *Finding, raw []byte) error {
	if len(raw) == 0 {
		f.Resource = nil
		f.resourceJSONRaw = nil
		return nil
	}

	f.resourceJSONRaw = cloneBytes(raw)
	return json.Unmarshal(raw, &f.Resource)
}

func resourceJSONForSync(f *Finding) ([]byte, error) {
	if len(f.resourceJSONRaw) > 0 {
		return cloneBytes(f.resourceJSONRaw), nil
	}

	resourceJSON, err := json.Marshal(f.Resource)
	if err != nil {
		return nil, err
	}
	f.resourceJSONRaw = cloneBytes(resourceJSON)
	return resourceJSON, nil
}

func invalidateResourceJSONCache(f *Finding) {
	if f == nil {
		return
	}
	f.resourceJSONRaw = nil
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
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
