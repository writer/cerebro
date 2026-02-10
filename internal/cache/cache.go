package cache

import (
	"container/list"
	"sync"
	"time"
)

// LRU is a thread-safe LRU cache with TTL support
type LRU struct {
	capacity int
	ttl      time.Duration
	items    map[string]*list.Element
	order    *list.List
	mu       sync.RWMutex
}

type entry struct {
	key       string
	value     interface{}
	expiresAt time.Time
}

func NewLRU(capacity int, ttl time.Duration) *LRU {
	return &LRU{
		capacity: capacity,
		ttl:      ttl,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

func (c *LRU) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	elem, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	e := elem.Value.(*entry)
	if time.Now().After(e.expiresAt) {
		c.Delete(key)
		return nil, false
	}

	c.mu.Lock()
	c.order.MoveToFront(elem)
	c.mu.Unlock()

	return e.value, true
}

func (c *LRU) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		e := elem.Value.(*entry)
		e.value = value
		e.expiresAt = time.Now().Add(c.ttl)
		return
	}

	if c.order.Len() >= c.capacity {
		c.evictOldest()
	}

	e := &entry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	elem := c.order.PushFront(e)
	c.items[key] = elem
}

func (c *LRU) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.Remove(elem)
		delete(c.items, key)
	}
}

func (c *LRU) evictOldest() {
	elem := c.order.Back()
	if elem != nil {
		c.order.Remove(elem)
		e := elem.Value.(*entry)
		delete(c.items, e.key)
	}
}

func (c *LRU) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

func (c *LRU) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.order.Init()
}

// Stats returns cache statistics
func (c *LRU) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return CacheStats{
		Size:     len(c.items),
		Capacity: c.capacity,
	}
}

type CacheStats struct {
	Size     int `json:"size"`
	Capacity int `json:"capacity"`
}

// PolicyCache is a specialized cache for policy evaluation results
type PolicyCache struct {
	cache *LRU
}

func NewPolicyCache(capacity int, ttl time.Duration) *PolicyCache {
	return &PolicyCache{
		cache: NewLRU(capacity, ttl),
	}
}

func (pc *PolicyCache) GetEvaluation(policyID, assetID string) (interface{}, bool) {
	key := policyID + ":" + assetID
	return pc.cache.Get(key)
}

func (pc *PolicyCache) SetEvaluation(policyID, assetID string, result interface{}) {
	key := policyID + ":" + assetID
	pc.cache.Set(key, result)
}

func (pc *PolicyCache) Stats() CacheStats {
	return pc.cache.Stats()
}
