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

var ensureSourceRuntimeStatements = []string{`CREATE TABLE IF NOT EXISTS source_runtimes (
  id TEXT PRIMARY KEY,
  runtime_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`, `ALTER TABLE source_runtimes ADD COLUMN IF NOT EXISTS lease_owner TEXT`, `ALTER TABLE source_runtimes ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ`}

// PutSourceRuntime upserts one source runtime definition.
func (s *Store) PutSourceRuntime(ctx context.Context, runtime *cerebrov1.SourceRuntime) error {
	if runtime == nil {
		return errors.New("source runtime is required")
	}
	id := strings.TrimSpace(runtime.GetId())
	if id == "" {
		return errors.New("source runtime id is required")
	}
	if strings.TrimSpace(runtime.GetSourceId()) == "" {
		return errors.New("source id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return err
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(runtime)
	if err != nil {
		return fmt.Errorf("marshal source runtime: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO source_runtimes (id, runtime_json)
VALUES ($1, $2::jsonb)
ON CONFLICT (id)
DO UPDATE SET runtime_json = EXCLUDED.runtime_json, updated_at = NOW()`, id, string(payload)); err != nil {
		return fmt.Errorf("upsert source runtime %q: %w", id, err)
	}
	return nil
}

// GetSourceRuntime loads one persisted source runtime definition.
func (s *Store) GetSourceRuntime(ctx context.Context, runtimeID string) (*cerebrov1.SourceRuntime, error) {
	id := strings.TrimSpace(runtimeID)
	if id == "" {
		return nil, errors.New("source runtime id is required")
	}
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return nil, err
	}
	var payload string
	if err := s.db.QueryRowContext(ctx, `SELECT runtime_json::text FROM source_runtimes WHERE id = $1`, id).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrSourceRuntimeNotFound, id)
		}
		return nil, fmt.Errorf("query source runtime %q: %w", id, err)
	}
	runtime := &cerebrov1.SourceRuntime{}
	if err := protojson.Unmarshal([]byte(payload), runtime); err != nil {
		return nil, fmt.Errorf("decode source runtime %q: %w", id, err)
	}
	return runtime, nil
}

// ListSourceRuntimes loads persisted source runtime definitions.
func (s *Store) ListSourceRuntimes(ctx context.Context, filter ports.SourceRuntimeFilter) ([]*cerebrov1.SourceRuntime, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return nil, err
	}
	clauses := []string{"1=1"}
	args := []any{}
	if tenantID := strings.TrimSpace(filter.TenantID); tenantID != "" {
		args = append(args, tenantID)
		clauses = append(clauses, fmt.Sprintf("runtime_json->>'tenant_id' = $%d", len(args)))
	}
	if sourceID := strings.TrimSpace(filter.SourceID); sourceID != "" {
		args = append(args, sourceID)
		clauses = append(clauses, fmt.Sprintf("runtime_json->>'source_id' = $%d", len(args)))
	}
	limit := filter.Limit
	if limit == 0 {
		limit = 100
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT runtime_json::text
FROM source_runtimes
WHERE %s
ORDER BY %s
LIMIT $%d`, strings.Join(clauses, " AND "), sourceRuntimeListOrderClause(), len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list source runtimes: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	var runtimes []*cerebrov1.SourceRuntime
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan source runtime: %w", err)
		}
		runtime := &cerebrov1.SourceRuntime{}
		if err := protojson.Unmarshal([]byte(payload), runtime); err != nil {
			return nil, fmt.Errorf("decode source runtime: %w", err)
		}
		runtimes = append(runtimes, runtime)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate source runtimes: %w", err)
	}
	return runtimes, nil
}

// AcquireSourceRuntimeLease leases one source runtime without replacing runtime JSON.
func (s *Store) AcquireSourceRuntimeLease(ctx context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	id := strings.TrimSpace(runtimeID)
	leaseOwner, err := validateSourceRuntimeLeaseRequest(owner, ttl)
	if err != nil {
		return false, err
	}
	if err := s.prepareSourceRuntimeLease(ctx, id); err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE source_runtimes
SET lease_owner = $2,
    lease_expires_at = NOW() + $3::interval,
    updated_at = NOW()
WHERE id = $1
  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW() OR lease_owner = $2)`, id, leaseOwner, sourceRuntimeLeaseInterval(ttl))
	if err != nil {
		return false, fmt.Errorf("acquire source runtime lease %q: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("acquire source runtime lease %q rows affected: %w", id, err)
	}
	return rows > 0, nil
}

// RenewSourceRuntimeLease extends a source runtime lease held by owner.
func (s *Store) RenewSourceRuntimeLease(ctx context.Context, runtimeID string, owner string, ttl time.Duration) (bool, error) {
	id := strings.TrimSpace(runtimeID)
	leaseOwner, err := validateSourceRuntimeLeaseRequest(owner, ttl)
	if err != nil {
		return false, err
	}
	if err := s.prepareSourceRuntimeLease(ctx, id); err != nil {
		return false, err
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE source_runtimes
SET lease_expires_at = NOW() + $3::interval
WHERE id = $1
  AND lease_owner = $2
  AND lease_expires_at > NOW()`, id, leaseOwner, sourceRuntimeLeaseInterval(ttl))
	if err != nil {
		return false, fmt.Errorf("renew source runtime lease %q: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("renew source runtime lease %q rows affected: %w", id, err)
	}
	return rows > 0, nil
}

// ReleaseSourceRuntimeLease releases a source runtime lease held by owner.
func (s *Store) ReleaseSourceRuntimeLease(ctx context.Context, runtimeID string, owner string) error {
	id := strings.TrimSpace(runtimeID)
	if id == "" {
		return errors.New("source runtime id is required")
	}
	leaseOwner := strings.TrimSpace(owner)
	if leaseOwner == "" {
		return errors.New("source runtime lease owner is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.ensureSourceRuntimeTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
UPDATE source_runtimes
SET lease_owner = NULL,
    lease_expires_at = NULL
WHERE id = $1 AND lease_owner = $2`, id, leaseOwner); err != nil {
		return fmt.Errorf("release source runtime lease %q: %w", id, err)
	}
	return nil
}

func validateSourceRuntimeLeaseRequest(owner string, ttl time.Duration) (string, error) {
	leaseOwner := strings.TrimSpace(owner)
	if leaseOwner == "" {
		return "", errors.New("source runtime lease owner is required")
	}
	if ttl <= 0 {
		return "", errors.New("source runtime lease ttl must be positive")
	}
	return leaseOwner, nil
}

func (s *Store) prepareSourceRuntimeLease(ctx context.Context, id string) error {
	if id == "" {
		return errors.New("source runtime id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	return s.ensureSourceRuntimeTable(ctx)
}

func sourceRuntimeLeaseInterval(ttl time.Duration) string {
	milliseconds := ttl.Milliseconds()
	if milliseconds < 1 {
		milliseconds = 1
	}
	return fmt.Sprintf("%d milliseconds", milliseconds)
}

func sourceRuntimeListOrderClause() string {
	return "updated_at ASC, id ASC"
}

func (s *Store) ensureSourceRuntimeTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.sourceRuntimeTableReady, "source runtime", ensureSourceRuntimeStatements)
}
