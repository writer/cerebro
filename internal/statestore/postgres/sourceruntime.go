package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

const ensureSourceRuntimeTableSQL = `
CREATE TABLE IF NOT EXISTS source_runtimes (
  id TEXT PRIMARY KEY,
  runtime_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

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

func (s *Store) ensureSourceRuntimeTable(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, ensureSourceRuntimeTableSQL); err != nil {
		return fmt.Errorf("ensure source runtime table: %w", err)
	}
	return nil
}
