package risk

import (
	"context"
	"net"
	"sync"
)

// GeoLookup resolves an IP to a (country, ASN, lat, lon) fact.
type GeoLookup interface {
	Lookup(ctx context.Context, ip net.IP) (GeoFact, bool)
}

// NoOpLookup returns no facts. Useful for tests where geo is irrelevant.
type NoOpLookup struct{}

// Lookup implements [GeoLookup].
func (NoOpLookup) Lookup(_ context.Context, _ net.IP) (GeoFact, bool) { return GeoFact{}, false }

// InMemoryLookup is a thread-safe IP -> GeoFact map. Production should use
// a MaxMind reader or a managed lookup; the in-memory backing exists to
// keep the package free of mandatory third-party deps and to make tests
// trivial.
type InMemoryLookup struct {
	mu    sync.RWMutex
	facts map[string]GeoFact
}

// NewInMemoryLookup returns an empty lookup.
func NewInMemoryLookup() *InMemoryLookup {
	return &InMemoryLookup{facts: make(map[string]GeoFact)}
}

// Set associates an IP (string form, identical to [net.IP.String]) with a
// fact. The trie-style CIDR matching of MaxMind isn't reproduced here; we
// match exact addresses only.
func (l *InMemoryLookup) Set(ip string, fact GeoFact) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.facts[ip] = fact
}

// Lookup implements [GeoLookup].
func (l *InMemoryLookup) Lookup(_ context.Context, ip net.IP) (GeoFact, bool) {
	if ip == nil {
		return GeoFact{}, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	fact, ok := l.facts[ip.String()]
	return fact, ok
}

// ObservationStore tracks the most recent successful observation per
// device.
type ObservationStore interface {
	Get(ctx context.Context, deviceID string) (*Observation, bool)
	Put(ctx context.Context, deviceID string, obs Observation) error
}

// InMemoryObservationStore is a thread-safe ObservationStore. Production
// should use a Postgres-backed store keyed on (device_id) so observations
// survive replica restarts.
type InMemoryObservationStore struct {
	mu       sync.RWMutex
	current  map[string]Observation
}

// NewInMemoryObservationStore returns an empty store.
func NewInMemoryObservationStore() *InMemoryObservationStore {
	return &InMemoryObservationStore{current: make(map[string]Observation)}
}

// Get implements [ObservationStore].
func (s *InMemoryObservationStore) Get(_ context.Context, deviceID string) (*Observation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	obs, ok := s.current[deviceID]
	if !ok {
		return nil, false
	}
	cp := obs
	return &cp, true
}

// Put implements [ObservationStore].
func (s *InMemoryObservationStore) Put(_ context.Context, deviceID string, obs Observation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current[deviceID] = obs
	return nil
}
