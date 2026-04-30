//go:build cgo

package kuzu

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// GetIngestCheckpoint returns one persisted graph ingest checkpoint.
func (s *Store) GetIngestCheckpoint(ctx context.Context, id string) (IngestCheckpoint, bool, error) {
	normalizedID := strings.TrimSpace(id)
	if normalizedID == "" {
		return IngestCheckpoint{}, false, errors.New("ingest checkpoint id is required")
	}
	if s == nil || s.db == nil {
		return IngestCheckpoint{}, false, errors.New("kuzu is not configured")
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return IngestCheckpoint{}, false, err
	}
	if !tables["ingest_checkpoint"] {
		return IngestCheckpoint{}, false, nil
	}
	var checkpoint IngestCheckpoint
	var completed string
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		"MATCH (c:ingest_checkpoint {id: %s}) RETURN c.id, c.source_id, c.tenant_id, c.config_hash, c.cursor_opaque, c.checkpoint_opaque, c.completed, c.pages_read, c.events_read, c.updated_at",
		cypherString(normalizedID),
	)).Scan(
		&checkpoint.ID,
		&checkpoint.SourceID,
		&checkpoint.TenantID,
		&checkpoint.ConfigHash,
		&checkpoint.CursorOpaque,
		&checkpoint.CheckpointOpaque,
		&completed,
		&checkpoint.PagesRead,
		&checkpoint.EventsRead,
		&checkpoint.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IngestCheckpoint{}, false, nil
		}
		return IngestCheckpoint{}, false, fmt.Errorf("query ingest checkpoint %q: %w", normalizedID, err)
	}
	checkpoint.Completed, err = strconv.ParseBool(completed)
	if err != nil {
		return IngestCheckpoint{}, false, fmt.Errorf("parse ingest checkpoint completion %q: %w", normalizedID, err)
	}
	return checkpoint, true, nil
}

// PutIngestCheckpoint upserts one durable graph ingest checkpoint.
func (s *Store) PutIngestCheckpoint(ctx context.Context, checkpoint IngestCheckpoint) error {
	checkpoint.ID = strings.TrimSpace(checkpoint.ID)
	if checkpoint.ID == "" {
		return errors.New("ingest checkpoint id is required")
	}
	checkpoint.SourceID = strings.TrimSpace(checkpoint.SourceID)
	if checkpoint.SourceID == "" {
		return errors.New("ingest checkpoint source id is required")
	}
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	if err := s.ensureIngestCheckpointSchema(ctx); err != nil {
		return err
	}
	statement := fmt.Sprintf(
		"MERGE (c:ingest_checkpoint {id: %s}) SET c.source_id = %s, c.tenant_id = %s, c.config_hash = %s, c.cursor_opaque = %s, c.checkpoint_opaque = %s, c.completed = %s, c.pages_read = %d, c.events_read = %d, c.updated_at = %s",
		cypherString(checkpoint.ID),
		cypherString(checkpoint.SourceID),
		cypherString(strings.TrimSpace(checkpoint.TenantID)),
		cypherString(strings.TrimSpace(checkpoint.ConfigHash)),
		cypherString(strings.TrimSpace(checkpoint.CursorOpaque)),
		cypherString(strings.TrimSpace(checkpoint.CheckpointOpaque)),
		cypherString(strconv.FormatBool(checkpoint.Completed)),
		checkpoint.PagesRead,
		checkpoint.EventsRead,
		cypherString(strings.TrimSpace(checkpoint.UpdatedAt)),
	)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("upsert ingest checkpoint %q: %w", checkpoint.ID, err)
	}
	return nil
}

func (s *Store) ensureIngestCheckpointSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.checkpointSchemaReady {
		return nil
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return err
	}
	if !tables["ingest_checkpoint"] {
		if _, err := s.db.ExecContext(ctx, "CREATE NODE TABLE ingest_checkpoint(id STRING, source_id STRING, tenant_id STRING, config_hash STRING, cursor_opaque STRING, checkpoint_opaque STRING, completed STRING, pages_read INT64, events_read INT64, updated_at STRING, PRIMARY KEY (id))"); err != nil {
			return fmt.Errorf("create ingest checkpoint table: %w", err)
		}
	}
	s.checkpointSchemaReady = true
	return nil
}
