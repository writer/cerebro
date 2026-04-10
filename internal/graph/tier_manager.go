package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultTierManagerHotRetention      = time.Hour
	defaultTierManagerWarmRetention     = 24 * time.Hour
	defaultTierManagerWarmMaxSnapshots  = 1
	defaultTierManagerWarmCleanupPeriod = 15 * time.Minute
)

type TierManagerOptions struct {
	HotRetention     time.Duration
	WarmRetention    time.Duration
	HotMaxEntries    int
	WarmBasePath     string
	WarmMaxSnapshots int
	Now              func() time.Time
	Pin              func(key string) bool
}

type tierManagerHotEntry struct {
	generation string
	graph      *Graph
	lastAccess time.Time
}

type tierManagerWarmDemotion struct {
	store      *SnapshotStore
	graph      *Graph
	accessedAt time.Time
}

type tierManagerWarmCleanup struct {
	basePath string
	cutoff   time.Time
}

type tierManagerEvictionWork struct {
	demotions []tierManagerWarmDemotion
	cleanup   *tierManagerWarmCleanup
}

// TierManager keeps a bounded in-memory hot tier backed by warm on-disk
// snapshots. Cold-tier loading is intentionally delegated to callers so the app
// layer can decide how to hydrate historical snapshots.
type TierManager struct {
	mu sync.Mutex

	hotRetention     time.Duration
	warmRetention    time.Duration
	hotMaxEntries    int
	warmBasePath     string
	warmMaxSnapshots int
	now              func() time.Time
	pin              func(key string) bool

	lastWarmCleanup time.Time
	hot             map[string]tierManagerHotEntry
}

func NewTierManager(opts TierManagerOptions) *TierManager {
	manager := &TierManager{}
	manager.Configure(opts)
	return manager
}

func (m *TierManager) Configure(opts TierManagerOptions) {
	if m == nil {
		return
	}
	hotRetention := opts.HotRetention
	if hotRetention <= 0 {
		hotRetention = defaultTierManagerHotRetention
	}
	warmRetention := opts.WarmRetention
	if warmRetention <= 0 {
		warmRetention = defaultTierManagerWarmRetention
	}
	warmMaxSnapshots := opts.WarmMaxSnapshots
	if warmMaxSnapshots <= 0 {
		warmMaxSnapshots = defaultTierManagerWarmMaxSnapshots
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time {
			return time.Now().UTC()
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.hotRetention = hotRetention
	m.warmRetention = warmRetention
	m.hotMaxEntries = opts.HotMaxEntries
	m.warmBasePath = strings.TrimSpace(opts.WarmBasePath)
	m.warmMaxSnapshots = warmMaxSnapshots
	m.now = now
	m.pin = opts.Pin
	if m.hot == nil {
		m.hot = make(map[string]tierManagerHotEntry)
	}
}

func (m *TierManager) ResetHot() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.hot)
}

func (m *TierManager) HotGraph(generation, key string) *Graph {
	key = strings.TrimSpace(key)
	if m == nil || key == "" {
		return nil
	}
	now := m.currentTime()
	m.mu.Lock()
	_, work := m.evictLocked(now)
	entry, ok := m.hot[key]
	if !ok || entry.graph == nil || !tierManagerGenerationMatches(entry.generation, generation) {
		m.mu.Unlock()
		work.run()
		return nil
	}
	entry.lastAccess = now
	m.hot[key] = entry
	m.mu.Unlock()
	work.run()
	return entry.graph
}

func (m *TierManager) PromoteHot(generation, key string, g *Graph, accessedAt time.Time) *Graph {
	g, finalize := m.PromoteHotDeferred(generation, key, g, accessedAt)
	finalize()
	return g
}

func (m *TierManager) PromoteHotDeferred(generation, key string, g *Graph, accessedAt time.Time) (*Graph, func()) {
	key = strings.TrimSpace(key)
	if m == nil || key == "" || g == nil {
		return g, func() {}
	}
	if accessedAt.IsZero() {
		accessedAt = m.currentTime()
	}
	m.mu.Lock()
	if m.hot == nil {
		m.hot = make(map[string]tierManagerHotEntry)
	}
	m.hot[key] = tierManagerHotEntry{
		generation: strings.TrimSpace(generation),
		graph:      g,
		lastAccess: accessedAt.UTC(),
	}
	_, work := m.evictLocked(accessedAt.UTC())
	m.mu.Unlock()
	return g, work.run
}

func (m *TierManager) SaveWarm(generation, key string, g *Graph, accessedAt time.Time) {
	key = strings.TrimSpace(key)
	generation = strings.TrimSpace(generation)
	if m == nil || key == "" || generation == "" || g == nil {
		return
	}
	needsAccessedAt := accessedAt.IsZero()
	var now func() time.Time
	m.mu.Lock()
	if needsAccessedAt {
		now = m.now
	}
	store := m.warmStore(generation, key)
	m.mu.Unlock()
	if needsAccessedAt {
		if now == nil {
			accessedAt = time.Now().UTC()
		} else {
			accessedAt = now().UTC()
		}
	}
	if store == nil {
		return
	}
	if _, _, err := store.SaveGraph(g); err != nil {
		return
	}
	m.touchWarmStore(store, accessedAt)
}

func (m *TierManager) WarmGraph(generation, key string) *Graph {
	snapshot := m.loadWarmSnapshot(strings.TrimSpace(generation), strings.TrimSpace(key))
	if snapshot == nil {
		return nil
	}
	return GraphViewFromSnapshot(snapshot)
}

func (m *TierManager) WarmStore(generation, key string) GraphStore {
	snapshot := m.loadWarmSnapshot(strings.TrimSpace(generation), strings.TrimSpace(key))
	if snapshot == nil {
		return nil
	}
	return NewSnapshotGraphStore(snapshot)
}

func (m *TierManager) Evict(now time.Time) int {
	if m == nil {
		return 0
	}
	if now.IsZero() {
		now = m.currentTime()
	}
	m.mu.Lock()
	evicted, work := m.evictLocked(now.UTC())
	m.mu.Unlock()
	work.run()
	return evicted
}

func (m *TierManager) HotCount() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, entry := range m.hot {
		if entry.graph != nil {
			count++
		}
	}
	return count
}

func (m *TierManager) WarmBasePath() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.TrimSpace(m.warmBasePath)
}

func (m *TierManager) currentTime() time.Time {
	if m == nil || m.now == nil {
		return time.Now().UTC()
	}
	return m.now().UTC()
}

func (m *TierManager) evictLocked(now time.Time) (int, tierManagerEvictionWork) {
	work := tierManagerEvictionWork{}
	if len(m.hot) == 0 {
		work.cleanup = m.maybeCleanupWarmTierLocked(now)
		return 0, work
	}

	evicted := 0
	if m.hotRetention > 0 {
		cutoff := now.Add(-m.hotRetention)
		for key, entry := range m.hot {
			if entry.lastAccess.After(cutoff) || m.pinned(key) {
				continue
			}
			work.addDemotion(m.demoteToWarmLocked(key, entry, now))
			evicted++
		}
	}

	if m.hotMaxEntries > 0 && len(m.hot) > m.hotMaxEntries {
		candidates := make([]struct {
			key   string
			entry tierManagerHotEntry
		}, 0, len(m.hot))
		for key, entry := range m.hot {
			if m.pinned(key) {
				continue
			}
			candidates = append(candidates, struct {
				key   string
				entry tierManagerHotEntry
			}{key: key, entry: entry})
		}
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].entry.lastAccess.Before(candidates[j].entry.lastAccess)
		})
		for _, candidate := range candidates {
			if len(m.hot) <= m.hotMaxEntries {
				break
			}
			if _, ok := m.hot[candidate.key]; !ok {
				continue
			}
			work.addDemotion(m.demoteToWarmLocked(candidate.key, candidate.entry, now))
			evicted++
		}
	}

	work.cleanup = m.maybeCleanupWarmTierLocked(now)
	return evicted, work
}

func (m *TierManager) demoteToWarmLocked(key string, entry tierManagerHotEntry, now time.Time) *tierManagerWarmDemotion {
	delete(m.hot, key)
	if entry.graph == nil {
		return nil
	}
	store := m.warmStore(entry.generation, key)
	if store == nil {
		return nil
	}
	return &tierManagerWarmDemotion{
		store:      store,
		graph:      entry.graph,
		accessedAt: now,
	}
}

func (m *TierManager) loadWarmSnapshot(generation, key string) *Snapshot {
	if m == nil || generation == "" || key == "" {
		return nil
	}
	now := m.currentTime()
	m.mu.Lock()
	cleanup := m.maybeCleanupWarmTierLocked(now)
	store := m.warmStore(generation, key)
	m.mu.Unlock()
	cleanup.run()
	if store == nil {
		return nil
	}
	snapshot, _, err := store.LoadLatestSnapshot()
	if err != nil || snapshot == nil {
		return nil
	}
	m.touchWarmStore(store, now)
	return snapshot
}

func (m *TierManager) maybeCleanupWarmTierLocked(now time.Time) *tierManagerWarmCleanup {
	basePath := strings.TrimSpace(m.warmBasePath)
	if basePath == "" || m.warmRetention <= 0 {
		return nil
	}
	interval := defaultTierManagerWarmCleanupPeriod
	if m.warmRetention < interval {
		interval = m.warmRetention
	}
	if !m.lastWarmCleanup.IsZero() && now.Sub(m.lastWarmCleanup) < interval {
		return nil
	}
	m.lastWarmCleanup = now
	return &tierManagerWarmCleanup{
		basePath: basePath,
		cutoff:   now.Add(-m.warmRetention),
	}
}

func (m *TierManager) touchWarmStore(store *SnapshotStore, accessedAt time.Time) {
	if store == nil {
		return
	}
	tierManagerTouchPath(store.BasePath(), accessedAt)
	tierManagerTouchPath(filepath.Dir(store.BasePath()), accessedAt)
}

func (m *TierManager) warmStore(generation, key string) *SnapshotStore {
	if m == nil {
		return nil
	}
	basePath := strings.TrimSpace(m.warmBasePath)
	generation = strings.TrimSpace(generation)
	key = strings.TrimSpace(key)
	if basePath == "" || generation == "" || key == "" {
		return nil
	}
	return NewSnapshotStore(
		filepath.Join(
			basePath,
			tierManagerCacheDirName("generation", generation),
			tierManagerCacheDirName("key", key),
		),
		m.warmMaxSnapshots,
	)
}

func (m *TierManager) pinned(key string) bool {
	if m == nil || m.pin == nil {
		return false
	}
	return m.pin(strings.TrimSpace(key))
}

func tierManagerGenerationMatches(current, want string) bool {
	return strings.TrimSpace(current) == strings.TrimSpace(want)
}

func tierManagerCacheDirName(prefix, value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

func tierManagerTouchPath(path string, now time.Time) {
	if strings.TrimSpace(path) == "" || now.IsZero() {
		return
	}
	_ = os.Chtimes(path, now, now)
}

func (w *tierManagerEvictionWork) addDemotion(demotion *tierManagerWarmDemotion) {
	if demotion == nil {
		return
	}
	w.demotions = append(w.demotions, *demotion)
}

func (w tierManagerEvictionWork) run() {
	for _, demotion := range w.demotions {
		if demotion.store == nil || demotion.graph == nil {
			continue
		}
		if _, _, err := demotion.store.SaveGraph(demotion.graph); err != nil {
			continue
		}
		tierManagerTouchPath(demotion.store.BasePath(), demotion.accessedAt)
		tierManagerTouchPath(filepath.Dir(demotion.store.BasePath()), demotion.accessedAt)
	}
	w.cleanup.run()
}

func (c *tierManagerWarmCleanup) run() {
	if c == nil || strings.TrimSpace(c.basePath) == "" || c.cutoff.IsZero() {
		return
	}
	entries, err := os.ReadDir(c.basePath)
	if err != nil {
		return
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.ModTime().After(c.cutoff) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(c.basePath, entry.Name()))
	}
}
