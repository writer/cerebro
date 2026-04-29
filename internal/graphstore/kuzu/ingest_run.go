package kuzu

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/graphstore"
)

const defaultIngestRunListLimit = 25

// PutIngestRun upserts one operational graph ingest run.
func (s *Store) PutIngestRun(ctx context.Context, run IngestRun) error {
	run.ID = strings.TrimSpace(run.ID)
	if run.ID == "" {
		return errors.New("ingest run id is required")
	}
	run.Status = strings.TrimSpace(run.Status)
	if run.Status == "" {
		return errors.New("ingest run status is required")
	}
	if !validIngestRunStatus(run.Status) {
		return fmt.Errorf("unsupported ingest run status %q", run.Status)
	}
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	if err := s.ensureIngestRunSchema(ctx); err != nil {
		return err
	}
	statement := fmt.Sprintf(
		"MERGE (r:ingest_run {id: %s}) SET r.runtime_id = %s, r.source_id = %s, r.tenant_id = %s, r.checkpoint_id = %s, r.status = %s, r.trigger = %s, r.pages_read = %d, r.events_read = %d, r.entities_projected = %d, r.links_projected = %d, r.graph_nodes_before = %d, r.graph_links_before = %d, r.graph_nodes_after = %d, r.graph_links_after = %d, r.started_at = %s, r.finished_at = %s, r.error_message = %s",
		cypherString(run.ID),
		cypherString(strings.TrimSpace(run.RuntimeID)),
		cypherString(strings.TrimSpace(run.SourceID)),
		cypherString(strings.TrimSpace(run.TenantID)),
		cypherString(strings.TrimSpace(run.CheckpointID)),
		cypherString(run.Status),
		cypherString(strings.TrimSpace(run.Trigger)),
		run.PagesRead,
		run.EventsRead,
		run.EntitiesProjected,
		run.LinksProjected,
		run.GraphNodesBefore,
		run.GraphLinksBefore,
		run.GraphNodesAfter,
		run.GraphLinksAfter,
		cypherString(strings.TrimSpace(run.StartedAt)),
		cypherString(strings.TrimSpace(run.FinishedAt)),
		cypherString(strings.TrimSpace(run.Error)),
	)
	if _, err := s.db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("upsert ingest run %q: %w", run.ID, err)
	}
	return nil
}

// GetIngestRun returns one operational graph ingest run.
func (s *Store) GetIngestRun(ctx context.Context, id string) (IngestRun, bool, error) {
	normalizedID := strings.TrimSpace(id)
	if normalizedID == "" {
		return IngestRun{}, false, errors.New("ingest run id is required")
	}
	if s == nil || s.db == nil {
		return IngestRun{}, false, errors.New("kuzu is not configured")
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return IngestRun{}, false, err
	}
	if !tables["ingest_run"] {
		return IngestRun{}, false, nil
	}
	var run IngestRun
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		"MATCH (r:ingest_run {id: %s}) RETURN r.id, r.runtime_id, r.source_id, r.tenant_id, r.checkpoint_id, r.status, r.trigger, r.pages_read, r.events_read, r.entities_projected, r.links_projected, r.graph_nodes_before, r.graph_links_before, r.graph_nodes_after, r.graph_links_after, r.started_at, r.finished_at, r.error_message",
		cypherString(normalizedID),
	)).Scan(
		&run.ID,
		&run.RuntimeID,
		&run.SourceID,
		&run.TenantID,
		&run.CheckpointID,
		&run.Status,
		&run.Trigger,
		&run.PagesRead,
		&run.EventsRead,
		&run.EntitiesProjected,
		&run.LinksProjected,
		&run.GraphNodesBefore,
		&run.GraphLinksBefore,
		&run.GraphNodesAfter,
		&run.GraphLinksAfter,
		&run.StartedAt,
		&run.FinishedAt,
		&run.Error,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return IngestRun{}, false, nil
		}
		return IngestRun{}, false, fmt.Errorf("query ingest run %q: %w", normalizedID, err)
	}
	return run, true, nil
}

// ListIngestRuns returns recent operational graph ingest runs.
func (s *Store) ListIngestRuns(ctx context.Context, filter IngestRunFilter) (_ []IngestRun, err error) {
	if s == nil || s.db == nil {
		return nil, errors.New("kuzu is not configured")
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return nil, err
	}
	if !tables["ingest_run"] {
		return nil, nil
	}
	limit := filter.Limit
	if limit == 0 {
		limit = defaultIngestRunListLimit
	}
	if limit < 0 || limit > 500 {
		return nil, fmt.Errorf("ingest run limit must be between 1 and 500")
	}
	where := make([]string, 0, 2)
	if runtimeID := strings.TrimSpace(filter.RuntimeID); runtimeID != "" {
		where = append(where, "r.runtime_id = "+cypherString(runtimeID))
	}
	if status := strings.TrimSpace(filter.Status); status != "" {
		if !validIngestRunStatus(status) {
			return nil, fmt.Errorf("unsupported ingest run status %q", status)
		}
		where = append(where, "r.status = "+cypherString(status))
	}
	query := "MATCH (r:ingest_run)"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += fmt.Sprintf(" RETURN r.id, r.runtime_id, r.source_id, r.tenant_id, r.checkpoint_id, r.status, r.trigger, r.pages_read, r.events_read, r.entities_projected, r.links_projected, r.graph_nodes_before, r.graph_links_before, r.graph_nodes_after, r.graph_links_after, r.started_at, r.finished_at, r.error_message ORDER BY r.started_at DESC, r.id DESC LIMIT %d", limit)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list ingest runs: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close ingest runs: %w", closeErr)
		}
	}()
	runs := make([]IngestRun, 0, limit)
	for rows.Next() {
		run, err := scanIngestRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ingest runs: %w", err)
	}
	return runs, nil
}

func (s *Store) ensureIngestRunSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if s.ingestRunSchemaReady {
		return nil
	}
	tables, err := s.graphTables(ctx)
	if err != nil {
		return err
	}
	if !tables["ingest_run"] {
		if _, err := s.db.ExecContext(ctx, "CREATE NODE TABLE ingest_run(id STRING, runtime_id STRING, source_id STRING, tenant_id STRING, checkpoint_id STRING, status STRING, trigger STRING, pages_read INT64, events_read INT64, entities_projected INT64, links_projected INT64, graph_nodes_before INT64, graph_links_before INT64, graph_nodes_after INT64, graph_links_after INT64, started_at STRING, finished_at STRING, error_message STRING, PRIMARY KEY (id))"); err != nil {
			return fmt.Errorf("create ingest run table: %w", err)
		}
	}
	s.ingestRunSchemaReady = true
	return nil
}

func scanIngestRun(scanner interface {
	Scan(dest ...any) error
}) (IngestRun, error) {
	var run IngestRun
	if err := scanner.Scan(
		&run.ID,
		&run.RuntimeID,
		&run.SourceID,
		&run.TenantID,
		&run.CheckpointID,
		&run.Status,
		&run.Trigger,
		&run.PagesRead,
		&run.EventsRead,
		&run.EntitiesProjected,
		&run.LinksProjected,
		&run.GraphNodesBefore,
		&run.GraphLinksBefore,
		&run.GraphNodesAfter,
		&run.GraphLinksAfter,
		&run.StartedAt,
		&run.FinishedAt,
		&run.Error,
	); err != nil {
		return IngestRun{}, fmt.Errorf("scan ingest run: %w", err)
	}
	return run, nil
}

func validIngestRunStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case graphstore.IngestRunStatusRunning, graphstore.IngestRunStatusCompleted, graphstore.IngestRunStatusFailed:
		return true
	default:
		return false
	}
}
