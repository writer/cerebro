package graph

import (
	"context"
	"time"
)

// GraphMetadataStore exposes graph metadata/status reads without forcing a
// full snapshot restore.
type GraphMetadataStore interface {
	GraphMetadata(ctx context.Context) (Metadata, error)
}

func AsGraphMetadataStore(store GraphStore) (GraphMetadataStore, bool) {
	if store == nil {
		return nil, false
	}
	metadataStore, ok := store.(GraphMetadataStore)
	return metadataStore, ok
}

// GraphMetadataFromStore resolves metadata from the store-native metadata
// surface when available and otherwise falls back to lightweight count queries.
func GraphMetadataFromStore(ctx context.Context, store GraphStore) (Metadata, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return Metadata{}, err
	}
	if store == nil {
		return Metadata{}, ErrStoreUnavailable
	}
	if metadataStore, ok := AsGraphMetadataStore(store); ok {
		return metadataStore.GraphMetadata(ctx)
	}
	return graphMetadataFromCounts(ctx, store)
}

var _ GraphMetadataStore = (*Graph)(nil)
var _ GraphMetadataStore = (*SnapshotGraphStore)(nil)
var _ GraphMetadataStore = (*TenantScopedReadOnlyGraphStore)(nil)
var _ GraphMetadataStore = (*DualWriteGraphStore)(nil)
var _ GraphMetadataStore = (*NeptuneGraphStore)(nil)
var _ GraphMetadataStore = (*SpannerGraphStore)(nil)

func (g *Graph) GraphMetadata(ctx context.Context) (Metadata, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return Metadata{}, err
	}
	if g == nil {
		return Metadata{}, ErrStoreUnavailable
	}
	meta := g.Metadata()
	if meta.NodeCount == 0 {
		meta.NodeCount = g.NodeCount()
	}
	if meta.EdgeCount == 0 {
		meta.EdgeCount = g.EdgeCount()
	}
	return meta, nil
}

func (s *SnapshotGraphStore) GraphMetadata(ctx context.Context) (Metadata, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return Metadata{}, err
	}
	if s == nil || s.snapshot == nil {
		return Metadata{}, ErrStoreUnavailable
	}
	meta := s.snapshot.Metadata
	if meta.BuiltAt.IsZero() {
		meta.BuiltAt = s.snapshot.CreatedAt.UTC()
	}
	if meta.NodeCount == 0 || meta.EdgeCount == 0 {
		s.ensureIndexes()
		if meta.NodeCount == 0 {
			meta.NodeCount = s.nodeCount
		}
		if meta.EdgeCount == 0 {
			meta.EdgeCount = s.edgeCount
		}
	}
	return meta, nil
}

func (s *TenantScopedReadOnlyGraphStore) GraphMetadata(ctx context.Context) (Metadata, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return Metadata{}, err
	}
	if s == nil || s.store == nil {
		return Metadata{}, ErrStoreUnavailable
	}
	scopedCtx := s.scopeContext(ctx)
	if metadataStore, ok := AsGraphMetadataStore(s.store); ok {
		return metadataStore.GraphMetadata(scopedCtx)
	}
	return graphMetadataFromCounts(scopedCtx, s.store)
}

func (s *DualWriteGraphStore) GraphMetadata(ctx context.Context) (Metadata, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return Metadata{}, err
	}
	if s == nil || s.GraphStore == nil {
		return Metadata{}, ErrStoreUnavailable
	}
	if metadataStore, ok := AsGraphMetadataStore(s.GraphStore); ok {
		return metadataStore.GraphMetadata(ctx)
	}
	return graphMetadataFromCounts(ctx, s.GraphStore)
}

func (s *NeptuneGraphStore) GraphMetadata(ctx context.Context) (Metadata, error) {
	return graphMetadataFromCounts(ctx, s)
}

func (s *SpannerGraphStore) GraphMetadata(ctx context.Context) (Metadata, error) {
	return graphMetadataFromCounts(ctx, s)
}

func graphMetadataFromCounts(ctx context.Context, store GraphStore) (Metadata, error) {
	if err := graphStoreContextErr(ctx); err != nil {
		return Metadata{}, err
	}
	if store == nil {
		return Metadata{}, ErrStoreUnavailable
	}
	nodeCount, err := store.CountNodes(ctx)
	if err != nil {
		return Metadata{}, err
	}
	edgeCount, err := store.CountEdges(ctx)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{
		BuiltAt:   time.Now().UTC(),
		NodeCount: nodeCount,
		EdgeCount: edgeCount,
	}, nil
}
