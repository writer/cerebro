//go:build cgo

package kuzu

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	kuzudb "github.com/kuzudb/go-kuzu"

	"github.com/writer/cerebro/internal/config"
)

// Store is the Kuzu-backed graph projection store implementation.
type Store struct {
	db *sql.DB
}

// Open opens a Kuzu-backed graph projection store.
func Open(cfg config.GraphStoreConfig) (*Store, error) {
	rawPath := strings.TrimSpace(cfg.KuzuPath)
	if rawPath == "" {
		return nil, errors.New("kuzu path is required")
	}
	absPath, err := filepath.Abs(rawPath)
	if err != nil {
		return nil, fmt.Errorf("resolve kuzu path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, fmt.Errorf("create kuzu parent directory: %w", err)
	}
	dsn := kuzuDSN(absPath)
	db, err := sql.Open(kuzudb.Name, dsn)
	if err != nil {
		return nil, fmt.Errorf("open kuzu: %w", err)
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

// Ping verifies that Kuzu can answer a trivial query.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("kuzu is not configured")
	}
	var result int64
	if err := s.db.QueryRowContext(ctx, "RETURN 1 AS ok").Scan(&result); err != nil {
		return fmt.Errorf("query kuzu: %w", err)
	}
	if result != 1 {
		return fmt.Errorf("unexpected kuzu ping result %d", result)
	}
	return nil
}

func kuzuDSN(absPath string) string {
	return (&url.URL{
		Scheme: "kuzu",
		Path:   filepath.ToSlash(absPath),
	}).String()
}
