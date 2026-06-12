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
	db                           *sql.DB
	schemaMu                     sync.Mutex
	claimTablesReady             bool
	projectionTablesReady        bool
	findingTablesReady           bool
	reportRunTableReady          bool
	sourceRuntimeTableReady      bool
	findingEvidenceReady         bool
	findingEvaluationRunReady    bool
	findingCandidateReady        bool
	vulnDBTablesReady            bool
	deviceAuthTablesReady        bool
	mcpOAuthTablesReady          bool
	startupLeaseTableReady       bool
	askTrajectoryReady           bool
	jobTablesReady               bool
	runtimeBlocklistReady        bool
	grcInventoryScopeReady       bool
	grcInventoryAssetReportReady bool
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
	if cfg.PostgresMaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.PostgresMaxOpenConns)
	}
	if cfg.PostgresMaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.PostgresMaxIdleConns)
	}
	if cfg.PostgresConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.PostgresConnMaxLifetime)
	}
	if cfg.PostgresConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.PostgresConnMaxIdleTime)
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

func normalizedNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func addStringInFilter(clauses *[]string, args *[]any, column string, values []string) {
	normalized := normalizedNonEmptyStrings(values)
	switch len(normalized) {
	case 0:
		return
	case 1:
		*args = append(*args, normalized[0])
		*clauses = append(*clauses, fmt.Sprintf("%s = $%d", column, len(*args)))
	default:
		placeholders := make([]string, 0, len(normalized))
		for _, value := range normalized {
			*args = append(*args, value)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(*args)))
		}
		*clauses = append(*clauses, fmt.Sprintf("%s IN (%s)", column, strings.Join(placeholders, ", ")))
	}
}
