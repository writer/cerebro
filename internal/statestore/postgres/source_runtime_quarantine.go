package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultSourceRuntimeQuarantineLimit = 50
	maxSourceRuntimeQuarantineLimit     = 500
)

func (s *Store) ListSourceRuntimeQuarantines(ctx context.Context, filter ports.SourceRuntimeQuarantineFilter) ([]ports.SourceRuntimeQuarantineRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	tenantID := strings.TrimSpace(filter.TenantID)
	runtimeID := strings.TrimSpace(filter.RuntimeID)
	state := strings.TrimSpace(filter.State)
	if tenantID == "" || runtimeID == "" {
		return nil, errors.New("source runtime quarantine tenant and runtime are required")
	}
	if !validSourceRuntimeQuarantineState(state) {
		return nil, fmt.Errorf("source runtime quarantine state %q is invalid", state)
	}
	limit := filter.Limit
	if limit == 0 {
		limit = defaultSourceRuntimeQuarantineLimit
	}
	if limit > maxSourceRuntimeQuarantineLimit {
		limit = maxSourceRuntimeQuarantineLimit
	}
	if err := s.ensureSourceRuntimePageLedgerTables(ctx); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT quarantine_id, runtime_id, source_id, tenant_id, event_id, event_kind,
       event_sha256, rejection_code, rejection_field, state, occurrence_count,
       first_observed_at, last_observed_at, occurred_at, admission_abi_version,
       admission_contracts_sha256, admission_result_sha256
FROM source_runtime_event_quarantine
WHERE tenant_id = $1
  AND runtime_id = $2
  AND state = $3
ORDER BY last_observed_at DESC, quarantine_id DESC
LIMIT $4`, tenantID, runtimeID, state, limit)
	if err != nil {
		return nil, fmt.Errorf("list source runtime quarantines: %w", err)
	}
	defer func() { _ = rows.Close() }()
	records := make([]ports.SourceRuntimeQuarantineRecord, 0)
	for rows.Next() {
		var record ports.SourceRuntimeQuarantineRecord
		var occurrenceCount int64
		var abiVersion int64
		var occurredAt sql.NullTime
		if err := rows.Scan(
			&record.ID,
			&record.RuntimeID,
			&record.SourceID,
			&record.TenantID,
			&record.EventID,
			&record.EventKind,
			&record.EventSHA256,
			&record.FailureCategory,
			&record.FailureField,
			&record.State,
			&occurrenceCount,
			&record.FirstObservedAt,
			&record.LastObservedAt,
			&occurredAt,
			&abiVersion,
			&record.AdmissionContractsSHA256,
			&record.AdmissionResultSHA256,
		); err != nil {
			return nil, fmt.Errorf("scan source runtime quarantine: %w", err)
		}
		if occurrenceCount < 0 || abiVersion < 0 || abiVersion > math.MaxUint32 {
			return nil, errors.New("source runtime quarantine counters are invalid")
		}
		record.OccurrenceCount = uint64(occurrenceCount)
		record.AdmissionABIVersion = uint32(abiVersion)
		if occurredAt.Valid {
			record.OccurredAt = occurredAt.Time.UTC()
		}
		record.FirstObservedAt = record.FirstObservedAt.UTC()
		record.LastObservedAt = record.LastObservedAt.UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list source runtime quarantines rows: %w", err)
	}
	return records, nil
}

func validSourceRuntimeQuarantineState(state string) bool {
	switch state {
	case ports.SourceRuntimeQuarantineStateCaptured,
		ports.SourceRuntimeQuarantineStatePending,
		ports.SourceRuntimeQuarantineStateResolved,
		ports.SourceRuntimeQuarantineStateDiscarded:
		return true
	default:
		return false
	}
}

var _ ports.SourceRuntimeQuarantineStore = (*Store)(nil)
