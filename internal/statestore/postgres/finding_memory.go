package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/findingmemory"
	"github.com/writer/cerebro/internal/ports"
)

var ensureFindingMemoryStatements = []string{
	`CREATE TABLE IF NOT EXISTS platform_finding_memory (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  type TEXT NOT NULL,
  source_urn TEXT NOT NULL DEFAULT '',
  finding_id TEXT NOT NULL DEFAULT '',
  rule_id TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT '',
  evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  subject_urns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  embedding_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS platform_finding_memory_tenant_type_idx ON platform_finding_memory (tenant_id, type, updated_at DESC)`,
	`CREATE INDEX IF NOT EXISTS platform_finding_memory_finding_idx ON platform_finding_memory (tenant_id, finding_id) WHERE finding_id <> ''`,
	`CREATE INDEX IF NOT EXISTS platform_finding_memory_rule_idx ON platform_finding_memory (tenant_id, rule_id) WHERE rule_id <> ''`,
	`CREATE INDEX IF NOT EXISTS platform_finding_memory_subjects_gin_idx ON platform_finding_memory USING GIN (subject_urns_json)`,
}

func (s *Store) UpsertFindingMemory(ctx context.Context, record *ports.FindingMemoryRecord) (*ports.FindingMemoryRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if record == nil {
		return nil, errors.New("finding memory record is required")
	}
	if err := s.ensureFindingMemoryTables(ctx); err != nil {
		return nil, err
	}
	normalized := normalizeFindingMemoryRecord(record)
	if normalized.ID == "" || normalized.TenantID == "" || normalized.Type == "" {
		return nil, errors.New("finding memory id, tenant_id, and type are required")
	}
	evidenceRefs, err := json.Marshal(normalized.EvidenceRefs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding memory evidence refs: %w", err)
	}
	subjectURNs, err := json.Marshal(normalized.SubjectURNs)
	if err != nil {
		return nil, fmt.Errorf("marshal finding memory subject urns: %w", err)
	}
	embedding, err := json.Marshal(normalized.Embedding)
	if err != nil {
		return nil, fmt.Errorf("marshal finding memory embedding: %w", err)
	}
	metadata, err := json.Marshal(normalized.Metadata)
	if err != nil {
		return nil, fmt.Errorf("marshal finding memory metadata: %w", err)
	}
	row := s.db.QueryRowContext(ctx, `
INSERT INTO platform_finding_memory (
  id, tenant_id, type, source_urn, finding_id, rule_id, fingerprint, summary,
  evidence_refs_json, subject_urns_json, embedding_json, confidence, observed_at,
  expires_at, metadata_json
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11::jsonb, $12, $13, $14, $15::jsonb)
ON CONFLICT (id) DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  type = EXCLUDED.type,
  source_urn = EXCLUDED.source_urn,
  finding_id = EXCLUDED.finding_id,
  rule_id = EXCLUDED.rule_id,
  fingerprint = EXCLUDED.fingerprint,
  summary = EXCLUDED.summary,
  evidence_refs_json = EXCLUDED.evidence_refs_json,
  subject_urns_json = EXCLUDED.subject_urns_json,
  embedding_json = EXCLUDED.embedding_json,
  confidence = EXCLUDED.confidence,
  observed_at = EXCLUDED.observed_at,
  expires_at = EXCLUDED.expires_at,
  metadata_json = EXCLUDED.metadata_json,
  updated_at = NOW()
RETURNING id, tenant_id, type, source_urn, finding_id, rule_id, fingerprint, summary,
  evidence_refs_json::text, subject_urns_json::text, embedding_json::text, confidence,
  observed_at, expires_at, metadata_json::text, created_at, updated_at`,
		normalized.ID,
		normalized.TenantID,
		normalized.Type,
		normalized.SourceURN,
		normalized.FindingID,
		normalized.RuleID,
		normalized.Fingerprint,
		normalized.Summary,
		string(evidenceRefs),
		string(subjectURNs),
		string(embedding),
		normalized.Confidence,
		normalized.ObservedAt,
		nullableTimeArg(normalized.ExpiresAt),
		string(metadata),
	)
	return scanFindingMemory(row)
}

func (s *Store) ListFindingMemory(ctx context.Context, request ports.ListFindingMemoryRequest) ([]*ports.FindingMemoryRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingMemoryTables(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"tenant_id = $1"}
	args := []any{strings.TrimSpace(request.TenantID)}
	if args[0] == "" {
		return nil, errors.New("tenant_id is required")
	}
	if value := strings.TrimSpace(request.Type); value != "" {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("type = $%d", len(args)))
	}
	if value := strings.TrimSpace(request.FindingID); value != "" {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("finding_id = $%d", len(args)))
	}
	if value := strings.TrimSpace(request.SubjectURN); value != "" {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf("subject_urns_json ? $%d", len(args)))
	}
	limit := request.Limit
	if limit == 0 || limit > 500 {
		limit = 50
	}
	args = append(args, limit)
	// #nosec G201 -- clauses are built only from fixed predicates above.
	query := fmt.Sprintf(`
SELECT id, tenant_id, type, source_urn, finding_id, rule_id, fingerprint, summary,
  evidence_refs_json::text, subject_urns_json::text, embedding_json::text, confidence,
  observed_at, expires_at, metadata_json::text, created_at, updated_at
FROM platform_finding_memory
WHERE %s
ORDER BY updated_at DESC, id ASC
LIMIT $%d`, strings.Join(clauses, " AND "), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list finding memory: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := []*ports.FindingMemoryRecord{}
	for rows.Next() {
		record, err := scanFindingMemory(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) SimilarFindingMemory(ctx context.Context, request ports.SimilarFindingMemoryRequest) ([]ports.ScoredFindingMemoryRecord, error) {
	records, err := s.ListFindingMemory(ctx, ports.ListFindingMemoryRequest{
		TenantID: request.TenantID,
		Type:     request.Type,
		Limit:    500,
	})
	if err != nil {
		return nil, err
	}
	scored := make([]ports.ScoredFindingMemoryRecord, 0, len(records))
	for _, record := range records {
		score := findingmemory.CosineSimilarity(request.Embedding, record.Embedding)
		if score <= 0 {
			continue
		}
		scored = append(scored, ports.ScoredFindingMemoryRecord{Record: record, Score: score})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		return scored[i].Record.ID < scored[j].Record.ID
	})
	limit := request.Limit
	if limit == 0 || limit > 50 {
		limit = 10
	}
	if len(scored) > int(limit) {
		scored = scored[:limit]
	}
	return scored, nil
}

func (s *Store) ensureFindingMemoryTables(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.findingIntel.memory, "finding_memory", ensureFindingMemoryStatements)
}

type findingMemoryScanner interface {
	Scan(dest ...any) error
}

func scanFindingMemory(scanner findingMemoryScanner) (*ports.FindingMemoryRecord, error) {
	var record ports.FindingMemoryRecord
	var evidenceRefsJSON, subjectURNsJSON, embeddingJSON, metadataJSON string
	var expiresAt sql.NullTime
	if err := scanner.Scan(
		&record.ID,
		&record.TenantID,
		&record.Type,
		&record.SourceURN,
		&record.FindingID,
		&record.RuleID,
		&record.Fingerprint,
		&record.Summary,
		&evidenceRefsJSON,
		&subjectURNsJSON,
		&embeddingJSON,
		&record.Confidence,
		&record.ObservedAt,
		&expiresAt,
		&metadataJSON,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(evidenceRefsJSON), &record.EvidenceRefs); err != nil {
		return nil, fmt.Errorf("decode finding memory evidence refs: %w", err)
	}
	if err := json.Unmarshal([]byte(subjectURNsJSON), &record.SubjectURNs); err != nil {
		return nil, fmt.Errorf("decode finding memory subject urns: %w", err)
	}
	if err := json.Unmarshal([]byte(embeddingJSON), &record.Embedding); err != nil {
		return nil, fmt.Errorf("decode finding memory embedding: %w", err)
	}
	if err := json.Unmarshal([]byte(metadataJSON), &record.Metadata); err != nil {
		return nil, fmt.Errorf("decode finding memory metadata: %w", err)
	}
	if expiresAt.Valid {
		record.ExpiresAt = expiresAt.Time
	}
	return &record, nil
}

func normalizeFindingMemoryRecord(record *ports.FindingMemoryRecord) ports.FindingMemoryRecord {
	normalized := *record
	normalized.ID = strings.TrimSpace(normalized.ID)
	normalized.TenantID = strings.TrimSpace(normalized.TenantID)
	normalized.Type = strings.TrimSpace(normalized.Type)
	normalized.SourceURN = strings.TrimSpace(normalized.SourceURN)
	normalized.FindingID = strings.TrimSpace(normalized.FindingID)
	normalized.RuleID = strings.TrimSpace(normalized.RuleID)
	normalized.Fingerprint = strings.TrimSpace(normalized.Fingerprint)
	normalized.Summary = strings.TrimSpace(normalized.Summary)
	normalized.EvidenceRefs = normalizedNonEmptyStrings(normalized.EvidenceRefs)
	normalized.SubjectURNs = normalizedNonEmptyStrings(normalized.SubjectURNs)
	normalized.Embedding = append([]float64(nil), normalized.Embedding...)
	if normalized.ObservedAt.IsZero() {
		normalized.ObservedAt = time.Now().UTC()
	} else {
		normalized.ObservedAt = normalized.ObservedAt.UTC()
	}
	if !normalized.ExpiresAt.IsZero() {
		normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	}
	if normalized.Metadata == nil {
		normalized.Metadata = map[string]string{}
	}
	return normalized
}

func nullableTimeArg(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
