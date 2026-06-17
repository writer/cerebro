package querycache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryCacheSweepsExpiredEntriesOnSet(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test", MaxEntries: 10})
	cache.entries[cacheKey("test", "expired")] = Entry{
		Payload:    []byte("old"),
		CreatedAt:  time.Now().Add(-2 * time.Second),
		ExpiresAt:  time.Now().Add(-2 * time.Second),
		StaleUntil: time.Now().Add(-time.Second),
	}

	if err := cache.Set(context.Background(), "fresh", []byte("new"), time.Minute, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	if _, ok := cache.entries[cacheKey("test", "expired")]; ok {
		t.Fatal("expired entry was not swept")
	}
	if _, ok := cache.entries[cacheKey("test", "fresh")]; !ok {
		t.Fatal("fresh entry missing after Set")
	}
}

func TestMemoryCacheEvictsOldestEntryWhenCapped(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test", MaxEntries: 2})

	if err := cache.Set(context.Background(), "oldest", []byte("a"), time.Minute, time.Minute); err != nil {
		t.Fatalf("Set(oldest) error = %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := cache.Set(context.Background(), "middle", []byte("b"), time.Minute, time.Minute); err != nil {
		t.Fatalf("Set(middle) error = %v", err)
	}
	time.Sleep(time.Millisecond)
	if err := cache.Set(context.Background(), "newest", []byte("c"), time.Minute, time.Minute); err != nil {
		t.Fatalf("Set(newest) error = %v", err)
	}

	if len(cache.entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(cache.entries))
	}
	if _, ok := cache.entries[cacheKey("test", "oldest")]; ok {
		t.Fatal("oldest entry was not evicted")
	}
	for _, key := range []string{"middle", "newest"} {
		if _, ok := cache.entries[cacheKey("test", key)]; !ok {
			t.Fatalf("entry %q missing after eviction", key)
		}
	}
}
