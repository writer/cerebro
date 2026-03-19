package graph

import (
	"sync"
	"sync/atomic"
	"time"
)

type GraphChangeType string

const (
	GraphChangeNodeUpserted        GraphChangeType = "node_upserted"
	GraphChangeNodeRemoved         GraphChangeType = "node_removed"
	GraphChangeNodePropertyChanged GraphChangeType = "node_property_changed"
	GraphChangeEdgeUpserted        GraphChangeType = "edge_upserted"
	GraphChangeEdgeRemoved         GraphChangeType = "edge_removed"
	GraphChangeGraphCleared        GraphChangeType = "graph_cleared"
	GraphChangeEdgesCleared        GraphChangeType = "edges_cleared"
)

type GraphChange struct {
	Type        GraphChangeType `json:"type"`
	Timestamp   time.Time       `json:"timestamp"`
	NodeID      string          `json:"node_id,omitempty"`
	NodeKind    NodeKind        `json:"node_kind,omitempty"`
	PropertyKey string          `json:"property_key,omitempty"`
	EdgeID      string          `json:"edge_id,omitempty"`
	SourceID    string          `json:"source_id,omitempty"`
	TargetID    string          `json:"target_id,omitempty"`
	EdgeKind    EdgeKind        `json:"edge_kind,omitempty"`
}

type GraphChangeFilter struct {
	NodeKinds []NodeKind
	EdgeKinds []EdgeKind
}

type GraphChangeSubscription struct {
	ch        chan GraphChange
	feed      *graphChangeFeed
	id        uint64
	closeOnce sync.Once
	doneCh    chan struct{}
	wakeCh    chan struct{}

	mu        sync.Mutex
	closed    bool
	pending   *GraphChange
	nodeKinds map[NodeKind]struct{}
	edgeKinds map[EdgeKind]struct{}
	matchAll  bool
}

func (s *GraphChangeSubscription) Changes() <-chan GraphChange {
	return s.ch
}

func (s *GraphChangeSubscription) Close() {
	s.closeOnce.Do(func() {
		if s.feed != nil {
			s.feed.unsubscribe(s.id)
		}
		s.mu.Lock()
		s.closed = true
		s.pending = nil
		s.mu.Unlock()
		close(s.doneCh)
	})
}

func (s *GraphChangeSubscription) matches(change GraphChange) bool {
	if s.matchAll {
		return true
	}

	switch change.Type {
	case GraphChangeNodeUpserted, GraphChangeNodeRemoved, GraphChangeNodePropertyChanged:
		_, ok := s.nodeKinds[change.NodeKind]
		return ok
	case GraphChangeEdgeUpserted, GraphChangeEdgeRemoved:
		_, ok := s.edgeKinds[change.EdgeKind]
		return ok
	case GraphChangeGraphCleared, GraphChangeEdgesCleared:
		return true
	default:
		return false
	}
}

func (s *GraphChangeSubscription) enqueue(change GraphChange) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	next := change
	s.pending = &next
	s.mu.Unlock()

	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
}

func (s *GraphChangeSubscription) run() {
	defer close(s.ch)

	for {
		select {
		case <-s.doneCh:
			return
		case <-s.wakeCh:
			for {
				s.mu.Lock()
				if s.closed || s.pending == nil {
					s.mu.Unlock()
					break
				}
				change := *s.pending
				s.pending = nil
				s.mu.Unlock()

				select {
				case <-s.doneCh:
					return
				case s.ch <- change:
				}
			}
		}
	}
}

type graphChangeFeed struct {
	mu          sync.RWMutex
	nextID      atomic.Uint64
	subscribers map[uint64]*GraphChangeSubscription
}

func newGraphChangeFeed() graphChangeFeed {
	return graphChangeFeed{
		subscribers: make(map[uint64]*GraphChangeSubscription),
	}
}

func (f *graphChangeFeed) subscribe(filter GraphChangeFilter, buffer int) *GraphChangeSubscription {
	if buffer <= 0 {
		buffer = 1
	}

	sub := &GraphChangeSubscription{
		ch:        make(chan GraphChange, buffer),
		feed:      f,
		id:        f.nextID.Add(1),
		doneCh:    make(chan struct{}),
		wakeCh:    make(chan struct{}, 1),
		nodeKinds: make(map[NodeKind]struct{}, len(filter.NodeKinds)),
		edgeKinds: make(map[EdgeKind]struct{}, len(filter.EdgeKinds)),
		matchAll:  len(filter.NodeKinds) == 0 && len(filter.EdgeKinds) == 0,
	}
	for _, kind := range filter.NodeKinds {
		sub.nodeKinds[kind] = struct{}{}
	}
	for _, kind := range filter.EdgeKinds {
		sub.edgeKinds[kind] = struct{}{}
	}

	f.mu.Lock()
	f.subscribers[sub.id] = sub
	f.mu.Unlock()

	go sub.run()

	return sub
}

func (f *graphChangeFeed) unsubscribe(id uint64) {
	f.mu.Lock()
	delete(f.subscribers, id)
	f.mu.Unlock()
}

func (f *graphChangeFeed) emit(change GraphChange) {
	f.mu.RLock()
	subscribers := make([]*GraphChangeSubscription, 0, len(f.subscribers))
	for _, sub := range f.subscribers {
		subscribers = append(subscribers, sub)
	}
	f.mu.RUnlock()

	for _, sub := range subscribers {
		if sub.matches(change) {
			sub.enqueue(change)
		}
	}
}

func (g *Graph) SubscribeChanges(filter GraphChangeFilter, buffer int) *GraphChangeSubscription {
	return g.changeFeed.subscribe(filter, buffer)
}

func (g *Graph) emitGraphChanges(changes ...GraphChange) {
	for _, change := range changes {
		if change.Timestamp.IsZero() {
			change.Timestamp = temporalNowUTC()
		}
		g.changeFeed.emit(change)
	}
}
