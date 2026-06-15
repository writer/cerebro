package querycache

import (
	"context"
	"strconv"
	"sync"
	"time"
)

type MemoryCache struct {
	mu       sync.Mutex
	options  Options
	entries  map[string]Entry
	versions map[string]uint64
}

func NewMemory(options Options) *MemoryCache {
	options = normalizeOptions(options)
	return &MemoryCache{
		options:  options,
		entries:  map[string]Entry{},
		versions: map[string]uint64{},
	}
}

func (c *MemoryCache) Get(_ context.Context, key string) (Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fullKey := cacheKey(c.options.Namespace, key)
	entry, ok := c.entries[fullKey]
	if !ok || entry.State(time.Now().UTC()) == StateMiss {
		delete(c.entries, fullKey)
		return Entry{}, ErrMiss
	}
	entry.Payload = append([]byte(nil), entry.Payload...)
	return entry, nil
}

func (c *MemoryCache) Set(_ context.Context, key string, payload []byte, ttl time.Duration, staleTTL time.Duration) error {
	if len(payload) == 0 || len(payload) > c.options.MaxPayloadBytes {
		return nil
	}
	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = time.Second
	}
	if staleTTL < 0 {
		staleTTL = 0
	}
	entry := Entry{
		Payload:    append([]byte(nil), payload...),
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		StaleUntil: now.Add(ttl + staleTTL),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cacheKey(c.options.Namespace, key)] = entry
	return nil
}

func (c *MemoryCache) Version(_ context.Context, scope string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strconv.FormatUint(c.versions[versionKey(c.options.Namespace, scope)], 10), nil
}

func (c *MemoryCache) BumpVersion(_ context.Context, scope string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := versionKey(c.options.Namespace, scope)
	c.versions[key]++
	return strconv.FormatUint(c.versions[key], 10), nil
}

func (c *MemoryCache) Ping(context.Context) error {
	return nil
}

func (c *MemoryCache) Close(context.Context) error {
	return nil
}
