package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/writer/cerebro/internal/config"
)

// Store is the Postgres-backed current-state store implementation.
type Store struct {
	db                        *sql.DB
	schemaMu                  sync.Mutex
	claimTablesReady          bool
	projectionTablesReady     bool
	sourceRuntimeTableReady   bool
	findingEvidenceReady      bool
	findingEvaluationRunReady bool
}

// Open opens a Postgres-backed current-state store.
func Open(cfg config.StateStoreConfig) (*Store, error) {
	dsn := strings.TrimSpace(cfg.PostgresDSN)
	if dsn == "" {
		return nil, errors.New("postgres dsn is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database handle.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Ping verifies that Postgres is reachable.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres is not configured")
	}
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	return nil
}

func (s *Store) ensureStatements(ctx context.Context, ready *bool, label string, statements []string) error {
	s.schemaMu.Lock()
	defer s.schemaMu.Unlock()
	if *ready {
		return nil
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("ensure %s tables: %w", label, err)
		}
	}
	*ready = true
	return nil
}
