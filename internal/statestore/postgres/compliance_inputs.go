package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultInputSnapshotPageSize = uint32(250)
	maxInputSnapshotPageSize     = uint32(500)
)

// ScanFindingSnapshot returns one cutoff-bounded finding page with a stable ID
// cursor and an invariant total for complete assessment collection.
func (s *Store) ScanFindingSnapshot(ctx context.Context, request ports.InputSnapshotRequest) (ports.InputSnapshotPage[*ports.FindingRecord], error) {
	normalized, err := normalizeInputSnapshotRequest(request)
	if err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, err
	}
	if s == nil || s.db == nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingTables(ctx); err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, fmt.Errorf("begin finding snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	scopeClauses, scopeArgs := inputSnapshotScopeClauses(normalized, "tenant_id", "runtime_id")
	total, watermark, err := measureInputSnapshot(ctx, tx, "findings", scopeClauses, scopeArgs)
	if err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, err
	}
	if err := verifyInputSnapshotInvariant(normalized, total, watermark); err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, err
	}
	clauses, args := addInputSnapshotCutoff(scopeClauses, scopeArgs, normalized.Cutoff)
	pageClauses, pageArgs := addInputSnapshotCursor(clauses, args, normalized.AfterID)
	pageArgs = append(pageArgs, int64(normalized.Limit+1))
	// #nosec G201 -- columns and predicates are fixed; all values are parameterized.
	query := fmt.Sprintf(`
SELECT %s
FROM findings
WHERE %s
ORDER BY id ASC
LIMIT $%d`, findingSelectColumns, strings.Join(pageClauses, " AND "), len(pageArgs))
	rows, err := tx.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, fmt.Errorf("query finding snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := make([]*ports.FindingRecord, 0, normalized.Limit+1)
	for rows.Next() {
		var row findingRow
		if err := scanFindingRow(rows, &row); err != nil {
			return ports.InputSnapshotPage[*ports.FindingRecord]{}, fmt.Errorf("scan finding snapshot: %w", err)
		}
		record, err := row.record()
		if err != nil {
			return ports.InputSnapshotPage[*ports.FindingRecord]{}, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, err
	}
	page := finishInputSnapshotPage(records, normalized, total, watermark, func(record *ports.FindingRecord) string { return record.ID })
	if err := tx.Commit(); err != nil {
		return ports.InputSnapshotPage[*ports.FindingRecord]{}, fmt.Errorf("commit finding snapshot: %w", err)
	}
	return page, nil
}

// ScanFindingEvidenceSnapshot returns one complete-collection evidence page.
func (s *Store) ScanFindingEvidenceSnapshot(ctx context.Context, request ports.InputSnapshotRequest) (ports.InputSnapshotPage[*cerebrov1.FindingEvidence], error) {
	normalized, err := normalizeInputSnapshotRequest(request)
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, err
	}
	if s == nil || s.db == nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, errors.New("postgres is not configured")
	}
	if err := s.ensureFindingEvidenceTables(ctx); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, err
	}
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, fmt.Errorf("begin finding evidence snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	scopeClauses, scopeArgs := findingEvidenceInputSnapshotScopeClauses(normalized)
	total, watermark, err := measureInputSnapshot(ctx, tx, "finding_evidence", scopeClauses, scopeArgs)
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, err
	}
	if err := verifyInputSnapshotInvariant(normalized, total, watermark); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, err
	}
	clauses, args := addInputSnapshotCutoff(scopeClauses, scopeArgs, normalized.Cutoff)
	pageClauses, pageArgs := addInputSnapshotCursor(clauses, args, normalized.AfterID)
	pageArgs = append(pageArgs, int64(normalized.Limit+1))
	// #nosec G201 -- predicates and ordering are fixed; all values are parameterized.
	query := fmt.Sprintf(`
SELECT id, finding_evidence_json::text
FROM finding_evidence
WHERE %s
ORDER BY id ASC
LIMIT $%d`, strings.Join(pageClauses, " AND "), len(pageArgs))
	rows, err := tx.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, fmt.Errorf("query finding evidence snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := make([]*cerebrov1.FindingEvidence, 0, normalized.Limit+1)
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, fmt.Errorf("scan finding evidence snapshot: %w", err)
		}
		record := &cerebrov1.FindingEvidence{}
		if err := protojson.Unmarshal([]byte(payload), record); err != nil {
			return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, fmt.Errorf("decode finding evidence %q: %w", id, err)
		}
		if strings.TrimSpace(record.GetId()) != id {
			return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, fmt.Errorf("finding evidence id mismatch: row %q payload %q", id, record.GetId())
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, err
	}
	page := finishInputSnapshotPage(records, normalized, total, watermark, func(record *cerebrov1.FindingEvidence) string { return record.GetId() })
	if err := tx.Commit(); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.FindingEvidence]{}, fmt.Errorf("commit finding evidence snapshot: %w", err)
	}
	return page, nil
}

// ScanSourceRuntimeSnapshot returns one complete-collection runtime page.
func (s *Store) ScanSourceRuntimeSnapshot(ctx context.Context, request ports.InputSnapshotRequest) (ports.InputSnapshotPage[*cerebrov1.SourceRuntime], error) {
	normalized, err := normalizeInputSnapshotRequest(request)
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, err
	}
	if s == nil || s.db == nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, fmt.Errorf("begin source runtime snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	scopeClauses, scopeArgs := inputSnapshotScopeClauses(normalized, "runtime_json->>'tenant_id'", "id")
	total, watermark, err := measureInputSnapshot(ctx, tx, "source_runtimes", scopeClauses, scopeArgs)
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, err
	}
	if err := verifyInputSnapshotInvariant(normalized, total, watermark); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, err
	}
	clauses, args := addInputSnapshotCutoff(scopeClauses, scopeArgs, normalized.Cutoff)
	pageClauses, pageArgs := addInputSnapshotCursor(clauses, args, normalized.AfterID)
	pageArgs = append(pageArgs, int64(normalized.Limit+1))
	// #nosec G201 -- predicates and ordering are fixed; all values are parameterized.
	query := fmt.Sprintf(`
SELECT id, runtime_json::text
FROM source_runtimes
WHERE %s
ORDER BY id ASC
LIMIT $%d`, strings.Join(pageClauses, " AND "), len(pageArgs))
	rows, err := tx.QueryContext(ctx, query, pageArgs...)
	if err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, fmt.Errorf("query source runtime snapshot: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := make([]*cerebrov1.SourceRuntime, 0, normalized.Limit+1)
	for rows.Next() {
		var id, payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, fmt.Errorf("scan source runtime snapshot: %w", err)
		}
		record := &cerebrov1.SourceRuntime{}
		if err := protojson.Unmarshal([]byte(payload), record); err != nil {
			return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, fmt.Errorf("decode source runtime %q: %w", id, err)
		}
		if strings.TrimSpace(record.GetId()) != id {
			return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, fmt.Errorf("source runtime id mismatch: row %q payload %q", id, record.GetId())
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, err
	}
	page := finishInputSnapshotPage(records, normalized, total, watermark, func(record *cerebrov1.SourceRuntime) string { return record.GetId() })
	if err := tx.Commit(); err != nil {
		return ports.InputSnapshotPage[*cerebrov1.SourceRuntime]{}, fmt.Errorf("commit source runtime snapshot: %w", err)
	}
	return page, nil
}

func normalizeInputSnapshotRequest(request ports.InputSnapshotRequest) (ports.InputSnapshotRequest, error) {
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.RuntimeIDs = normalizedNonEmptyStrings(request.RuntimeIDs)
	request.AfterID = strings.TrimSpace(request.AfterID)
	request.Cutoff = request.Cutoff.UTC()
	if request.TenantID == "" {
		return ports.InputSnapshotRequest{}, errors.New("input snapshot tenant id is required")
	}
	if len(request.RuntimeIDs) == 0 {
		return ports.InputSnapshotRequest{}, errors.New("input snapshot runtime ids are required")
	}
	if request.Cutoff.IsZero() {
		return ports.InputSnapshotRequest{}, errors.New("input snapshot cutoff is required")
	}
	if request.Limit == 0 {
		request.Limit = defaultInputSnapshotPageSize
	}
	if request.Limit > maxInputSnapshotPageSize {
		return ports.InputSnapshotRequest{}, fmt.Errorf("input snapshot limit must be <= %d", maxInputSnapshotPageSize)
	}
	return request, nil
}

func inputSnapshotScopeClauses(request ports.InputSnapshotRequest, tenantColumn string, runtimeColumn string) ([]string, []any) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, len(request.RuntimeIDs)+1)
	if tenantColumn != "" {
		args = append(args, request.TenantID)
		clauses = append(clauses, fmt.Sprintf("%s = $%d", tenantColumn, len(args)))
	}
	placeholders := make([]string, 0, len(request.RuntimeIDs))
	for _, runtimeID := range request.RuntimeIDs {
		args = append(args, runtimeID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	clauses = append(clauses, fmt.Sprintf("%s IN (%s)", runtimeColumn, strings.Join(placeholders, ", ")))
	return clauses, args
}

func findingEvidenceInputSnapshotScopeClauses(request ports.InputSnapshotRequest) ([]string, []any) {
	args := []any{request.TenantID}
	clauses := []string{"EXISTS (SELECT 1 FROM source_runtimes input_runtime WHERE input_runtime.id = finding_evidence.runtime_id AND input_runtime.runtime_json->>'tenant_id' = $1)"}
	placeholders := make([]string, 0, len(request.RuntimeIDs))
	for _, runtimeID := range request.RuntimeIDs {
		args = append(args, runtimeID)
		placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
	}
	clauses = append(clauses, fmt.Sprintf("runtime_id IN (%s)", strings.Join(placeholders, ", ")))
	return clauses, args
}

func addInputSnapshotCutoff(clauses []string, args []any, cutoff time.Time) ([]string, []any) {
	resultClauses := append([]string(nil), clauses...)
	resultArgs := append([]any(nil), args...)
	resultArgs = append(resultArgs, cutoff.UTC())
	resultClauses = append(resultClauses, fmt.Sprintf("updated_at <= $%d", len(resultArgs)))
	return resultClauses, resultArgs
}

func addInputSnapshotCursor(clauses []string, args []any, afterID string) ([]string, []any) {
	pageClauses := append([]string(nil), clauses...)
	pageArgs := append([]any(nil), args...)
	if afterID != "" {
		pageArgs = append(pageArgs, afterID)
		pageClauses = append(pageClauses, fmt.Sprintf("id > $%d", len(pageArgs)))
	}
	return pageClauses, pageArgs
}

func measureInputSnapshot(ctx context.Context, tx *sql.Tx, table string, clauses []string, args []any) (uint64, time.Time, error) {
	// #nosec G201 -- callers supply fixed internal table names and predicates.
	query := fmt.Sprintf("SELECT COUNT(*), MAX(updated_at) FROM %s WHERE %s", table, strings.Join(clauses, " AND "))
	var count int64
	var watermark sql.NullTime
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&count, &watermark); err != nil {
		return 0, time.Time{}, fmt.Errorf("measure %s input snapshot: %w", table, err)
	}
	if count < 0 {
		return 0, time.Time{}, fmt.Errorf("count %s input snapshot returned a negative value", table)
	}
	if !watermark.Valid {
		return uint64(count), time.Time{}, nil
	}
	return uint64(count), watermark.Time.UTC(), nil
}

func verifyInputSnapshotInvariant(request ports.InputSnapshotRequest, total uint64, watermark time.Time) error {
	if request.ExpectedTotal != nil && *request.ExpectedTotal != total {
		return fmt.Errorf("%w: expected %d records, found %d", ports.ErrInputSnapshotChanged, *request.ExpectedTotal, total)
	}
	if request.ExpectedWatermark != nil && !request.ExpectedWatermark.Equal(watermark) {
		return fmt.Errorf("%w: input watermark changed", ports.ErrInputSnapshotChanged)
	}
	if watermark.After(request.Cutoff) {
		return fmt.Errorf("%w: input changed after cutoff", ports.ErrInputSnapshotChanged)
	}
	return nil
}

func finishInputSnapshotPage[T any](records []T, request ports.InputSnapshotRequest, total uint64, watermark time.Time, id func(T) string) ports.InputSnapshotPage[T] {
	complete := len(records) <= int(request.Limit)
	if !complete {
		records = records[:request.Limit]
	}
	nextCursor := ""
	if !complete && len(records) > 0 {
		nextCursor = strings.TrimSpace(id(records[len(records)-1]))
	}
	return ports.InputSnapshotPage[T]{Records: records, Total: total, NextCursor: nextCursor, Complete: complete, Cutoff: request.Cutoff, Watermark: watermark}
}

var _ ports.ComplianceInputSnapshotStore = (*Store)(nil)
