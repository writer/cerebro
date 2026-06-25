package querycache

import (
	"context"
	"strconv"
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

func TestMemoryCacheGetRemovesRequestedExpiredEntryBetweenSweeps(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test", MaxEntries: 10})
	now := time.Now()
	cache.nextSweepAt = now.Add(time.Hour)
	cache.entries[cacheKey("test", "expired")] = Entry{
		Payload:    []byte("old"),
		CreatedAt:  now.Add(-2 * time.Second),
		ExpiresAt:  now.Add(-2 * time.Second),
		StaleUntil: now.Add(-time.Second),
	}

	_, err := cache.Get(context.Background(), "expired")
	if err == nil {
		t.Fatal("Get(expired) error = nil, want miss")
	}
	if _, ok := cache.entries[cacheKey("test", "expired")]; ok {
		t.Fatal("expired requested entry was not removed")
	}
}

func TestMemoryCacheVersionsReturnsBatchWithMissingScopes(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	if _, err := cache.BumpVersion(context.Background(), "findings"); err != nil {
		t.Fatalf("BumpVersion() error = %v", err)
	}

	versions, err := cache.Versions(context.Background(), []string{"findings", "evidence"})
	if err != nil {
		t.Fatalf("Versions() error = %v", err)
	}
	if versions["findings"] != "1" {
		t.Fatalf("Versions(findings) = %q, want 1", versions["findings"])
	}
	if versions["evidence"] != "0" {
		t.Fatalf("Versions(evidence) = %q, want 0", versions["evidence"])
	}
}

func BenchmarkMemoryCacheGetFreshManyEntries(b *testing.B) {
	cache := NewMemory(Options{Namespace: "bench", MaxEntries: 8192})
	ctx := context.Background()
	for i := 0; i < 4096; i++ {
		if err := cache.Set(ctx, strconv.Itoa(i), []byte("payload"), time.Hour, time.Hour); err != nil {
			b.Fatalf("Set() error = %v", err)
		}
	}
	cache.nextSweepAt = time.Now().Add(time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cache.Get(ctx, "2048"); err != nil {
			b.Fatalf("Get() error = %v", err)
		}
	}
}
