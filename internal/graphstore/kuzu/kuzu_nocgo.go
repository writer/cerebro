//go:build !cgo

package kuzu

import (
	"context"
	"errors"
	"strings"

	"github.com/writer/cerebro/internal/config"
)

var errCGORequired = errors.New("kuzu graph store requires CGO; rebuild with CGO_ENABLED=1")

// Store is a non-CGO placeholder for the Kuzu-backed graph store.
type Store struct{}

// Open returns a clear error in non-CGO builds because go-kuzu requires CGO.
func Open(cfg config.GraphStoreConfig) (*Store, error) {
	if strings.TrimSpace(cfg.KuzuPath) == "" {
		return nil, errors.New("kuzu path is required")
	}
	return nil, errCGORequired
}

// Close is a no-op for the non-CGO placeholder.
func (s *Store) Close() error {
	return nil
}

// Ping returns a clear error in non-CGO builds because go-kuzu requires CGO.
func (s *Store) Ping(context.Context) error {
	return errCGORequired
}
