package workflowprojection

import (
	"context"

	"github.com/writer/cerebro/internal/ports"
)

// projectionWriteBuffer collects the entity and link upserts for one finding
// projection so a batch-capable graph store writes them in a few UNWIND
// transactions instead of one round trip per record. Entities flush before
// links because the store only materializes a link when both endpoints exist.
type projectionWriteBuffer struct {
	store    ports.ProjectionGraphBatchStore
	entities []*ports.ProjectedEntity
	links    []*ports.ProjectedLink
}

// withBufferedWrites returns a copy of the service that buffers upserts when
// the graph store supports batches. The copy keeps the shared Service free of
// per-call state.
func (s *Service) withBufferedWrites() *Service {
	if s == nil || s.pending != nil {
		return s
	}
	store, ok := s.graph.(ports.ProjectionGraphBatchStore)
	if !ok {
		return s
	}
	scoped := *s
	scoped.pending = &projectionWriteBuffer{store: store}
	return &scoped
}

func (s *Service) flushPendingWrites(ctx context.Context) error {
	if s == nil || s.pending == nil {
		return nil
	}
	pending := s.pending
	if len(pending.entities) > 0 {
		entities := pending.entities
		pending.entities = nil
		if err := pending.store.UpsertProjectedEntities(ctx, entities); err != nil {
			return err
		}
	}
	if len(pending.links) > 0 {
		links := pending.links
		pending.links = nil
		if err := pending.store.UpsertProjectedLinks(ctx, links); err != nil {
			return err
		}
	}
	return nil
}
