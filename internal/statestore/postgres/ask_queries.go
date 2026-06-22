package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

var _ ports.AskQueryStore = (*Store)(nil)

var ensureAskQueryStatements = []string{
	`CREATE TABLE IF NOT EXISTS ask_queries (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  question TEXT NOT NULL,
  scope_urn TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  pinned BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`,
	`CREATE INDEX IF NOT EXISTS ask_queries_tenant_idx ON ask_queries (tenant_id, pinned DESC, created_at DESC)`,
}

const askQueryColumns = `id, tenant_id, name, question, scope_urn, model, pinned, created_at, updated_at`

func (s *Store) ensureAskQueryTable(ctx context.Context) error {
	return s.ensureStatements(ctx, &s.ask.savedQuery, "ask query", ensureAskQueryStatements)
}

// PutAskQuery upserts one saved ask query.
func (s *Store) PutAskQuery(ctx context.Context, query *ports.AskQuery) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if query == nil {
		return errors.New("ask query is required")
	}
	id := strings.TrimSpace(query.ID)
	tenantID := strings.TrimSpace(query.TenantID)
	name := strings.TrimSpace(query.Name)
	question := strings.TrimSpace(query.Question)
	if id == "" || tenantID == "" || name == "" || question == "" {
		return errors.New("ask query id, tenant_id, name, and question are required")
	}
	if err := s.ensureAskQueryTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO ask_queries (id, tenant_id, name, question, scope_urn, model, pinned)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
  tenant_id = EXCLUDED.tenant_id,
  name = EXCLUDED.name,
  question = EXCLUDED.question,
  scope_urn = EXCLUDED.scope_urn,
  model = EXCLUDED.model,
  pinned = EXCLUDED.pinned,
  updated_at = NOW()`,
		id, tenantID, name, question, strings.TrimSpace(query.ScopeURN), strings.TrimSpace(query.Model), query.Pinned); err != nil {
		return fmt.Errorf("upsert ask query %q: %w", id, err)
	}
	return nil
}

// GetAskQuery loads one saved ask query.
func (s *Store) GetAskQuery(ctx context.Context, queryID string) (*ports.AskQuery, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	id := strings.TrimSpace(queryID)
	if id == "" {
		return nil, errors.New("ask query id is required")
	}
	if err := s.ensureAskQueryTable(ctx); err != nil {
		return nil, err
	}
	// #nosec G201 -- column list is a fixed constant and the id remains parameterized.
	row := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT %s FROM ask_queries WHERE id = $1", askQueryColumns), id)
	query, err := scanAskQuery(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ports.ErrAskQueryNotFound, id)
		}
		return nil, fmt.Errorf("query ask query %q: %w", id, err)
	}
	return query, nil
}

// ListAskQueries returns saved ask queries for one tenant, pinned first then
// newest-first.
func (s *Store) ListAskQueries(ctx context.Context, filter ports.AskQueryFilter) ([]*ports.AskQuery, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres is not configured")
	}
	if err := s.ensureAskQueryTable(ctx); err != nil {
		return nil, err
	}
	clauses := []string{}
	args := []any{}
	if tenantID := strings.TrimSpace(filter.TenantID); tenantID != "" {
		args = append(args, tenantID)
		clauses = append(clauses, fmt.Sprintf("tenant_id = $%d", len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}
	args = append(args, askQueryListLimit(filter.Limit))
	// #nosec G201 -- column list and clauses are fixed predicates; all values remain parameterized.
	query := fmt.Sprintf("SELECT %s FROM ask_queries %s ORDER BY pinned DESC, created_at DESC LIMIT $%d", askQueryColumns, where, len(args))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list ask queries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	queries := []*ports.AskQuery{}
	for rows.Next() {
		item, err := scanAskQuery(rows)
		if err != nil {
			return nil, err
		}
		queries = append(queries, item)
	}
	return queries, rows.Err()
}

// DeleteAskQuery removes one saved ask query.
func (s *Store) DeleteAskQuery(ctx context.Context, queryID string) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	id := strings.TrimSpace(queryID)
	if id == "" {
		return errors.New("ask query id is required")
	}
	if err := s.ensureAskQueryTable(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM ask_queries WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete ask query %q: %w", id, err)
	}
	return nil
}

func askQueryListLimit(limit uint32) uint32 {
	const (
		defaultLimit uint32 = 100
		maxLimit     uint32 = 500
	)
	switch {
	case limit == 0:
		return defaultLimit
	case limit > maxLimit:
		return maxLimit
	default:
		return limit
	}
}

func scanAskQuery(row scanner) (*ports.AskQuery, error) {
	var query ports.AskQuery
	if err := row.Scan(
		&query.ID,
		&query.TenantID,
		&query.Name,
		&query.Question,
		&query.ScopeURN,
		&query.Model,
		&query.Pinned,
		&query.CreatedAt,
		&query.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &query, nil
}
