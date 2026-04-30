//go:build !cgo

package kuzu

import (
	"context"
	"errors"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphstore"
	"github.com/writer/cerebro/internal/ports"
)

var errCGORequired = errors.New("kuzu graph store requires CGO; rebuild with CGO_ENABLED=1")

// Store is a non-CGO placeholder for the Kuzu-backed graph store.
type Store struct{}

type Counts = graphstore.Counts
type Traversal = graphstore.Traversal
type IntegrityCheck = graphstore.IntegrityCheck
type PathPattern = graphstore.PathPattern
type Topology = graphstore.Topology
type IngestCheckpoint = graphstore.IngestCheckpoint
type IngestRun = graphstore.IngestRun
type IngestRunFilter = graphstore.IngestRunFilter

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

func (s *Store) Project(context.Context, *cerebrov1.EventEnvelope) (ports.ProjectionResult, error) {
	return ports.ProjectionResult{}, errCGORequired
}

func (s *Store) UpsertProjectedEntity(context.Context, *ports.ProjectedEntity) error {
	return errCGORequired
}

func (s *Store) UpsertProjectedLink(context.Context, *ports.ProjectedLink) error {
	return errCGORequired
}

func (s *Store) DeleteProjectedLink(context.Context, *ports.ProjectedLink) error {
	return errCGORequired
}

func (s *Store) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, errCGORequired
}

func (s *Store) Counts(context.Context) (Counts, error) {
	return Counts{}, errCGORequired
}

func (s *Store) IntegrityChecks(context.Context) ([]IntegrityCheck, error) {
	return nil, errCGORequired
}

func (s *Store) PathPatterns(context.Context, int) ([]PathPattern, error) {
	return nil, errCGORequired
}

func (s *Store) Topology(context.Context) (Topology, error) {
	return Topology{}, errCGORequired
}

func (s *Store) SampleTraversals(context.Context, int) ([]Traversal, error) {
	return nil, errCGORequired
}

func (s *Store) GetIngestCheckpoint(context.Context, string) (IngestCheckpoint, bool, error) {
	return IngestCheckpoint{}, false, errCGORequired
}

func (s *Store) PutIngestCheckpoint(context.Context, IngestCheckpoint) error {
	return errCGORequired
}

func (s *Store) PutIngestRun(context.Context, IngestRun) error {
	return errCGORequired
}

func (s *Store) GetIngestRun(context.Context, string) (IngestRun, bool, error) {
	return IngestRun{}, false, errCGORequired
}

func (s *Store) ListIngestRuns(context.Context, IngestRunFilter) ([]IngestRun, error) {
	return nil, errCGORequired
}
