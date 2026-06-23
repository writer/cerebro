package querycache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEntryStateReturnsStateMissForEmptyPayload(t *testing.T) {
	entry := Entry{StaleUntil: time.Now().Add(time.Hour)}
	if got := entry.State(time.Now()); got != StateMiss {
		t.Fatalf("State() = %q, want %q", got, StateMiss)
	}
}

func TestEntryStateReturnsStateMissForZeroStaleUntil(t *testing.T) {
	entry := Entry{Payload: []byte("data")}
	if got := entry.State(time.Now()); got != StateMiss {
		t.Fatalf("State() = %q, want %q", got, StateMiss)
	}
}

func TestEntryStateReturnsStateMissWhenPastStaleUntil(t *testing.T) {
	entry := Entry{
		Payload:    []byte("data"),
		StaleUntil: time.Now().Add(-time.Second),
	}
	if got := entry.State(time.Now()); got != StateMiss {
		t.Fatalf("State() = %q, want %q", got, StateMiss)
	}
}

func TestEntryStateReturnsStateFreshBeforeExpiresAt(t *testing.T) {
	now := time.Now()
	entry := Entry{
		Payload:    []byte("data"),
		ExpiresAt:  now.Add(time.Hour),
		StaleUntil: now.Add(2 * time.Hour),
	}
	if got := entry.State(now); got != StateFresh {
		t.Fatalf("State() = %q, want %q", got, StateFresh)
	}
}

func TestEntryStateReturnsStateStaleAfterExpiry(t *testing.T) {
	now := time.Now()
	entry := Entry{
		Payload:    []byte("data"),
		ExpiresAt:  now.Add(-time.Second),
		StaleUntil: now.Add(time.Hour),
	}
	if got := entry.State(now); got != StateStale {
		t.Fatalf("State() = %q, want %q", got, StateStale)
	}
}

func TestEntryStateReturnsStateStaleWhenExpiresAtZero(t *testing.T) {
	now := time.Now()
	entry := Entry{
		Payload:    []byte("data"),
		StaleUntil: now.Add(time.Hour),
	}
	if got := entry.State(now); got != StateStale {
		t.Fatalf("State() = %q, want %q (ExpiresAt zero)", got, StateStale)
	}
}

func TestNormalizeOptionsDefaults(t *testing.T) {
	opts := normalizeOptions(Options{})
	if opts.Namespace != "cerebro" {
		t.Fatalf("Namespace = %q, want cerebro", opts.Namespace)
	}
	if opts.MaxPayloadBytes != 1<<20 {
		t.Fatalf("MaxPayloadBytes = %d, want %d", opts.MaxPayloadBytes, 1<<20)
	}
	if opts.MaxEntries != 4096 {
		t.Fatalf("MaxEntries = %d, want 4096", opts.MaxEntries)
	}
}

func TestNormalizeOptionsTrimsNamespace(t *testing.T) {
	opts := normalizeOptions(Options{Namespace: " :my_cache: "})
	if opts.Namespace != "my_cache" {
		t.Fatalf("Namespace = %q, want my_cache", opts.Namespace)
	}
}

func TestNormalizeOptionsPreservesPositiveValues(t *testing.T) {
	opts := normalizeOptions(Options{
		Namespace:       "test",
		MaxPayloadBytes: 512,
		MaxEntries:      10,
	})
	if opts.MaxPayloadBytes != 512 {
		t.Fatalf("MaxPayloadBytes = %d, want 512", opts.MaxPayloadBytes)
	}
	if opts.MaxEntries != 10 {
		t.Fatalf("MaxEntries = %d, want 10", opts.MaxEntries)
	}
}

func TestCacheKeyFormatsCorrectly(t *testing.T) {
	if got := cacheKey("ns", "key"); got != "ns:key" {
		t.Fatalf("cacheKey = %q, want ns:key", got)
	}
}

func TestCacheKeyTrimsAndHandlesEmpty(t *testing.T) {
	if got := cacheKey("ns", "  "); got != "ns:empty" {
		t.Fatalf("cacheKey(empty) = %q, want ns:empty", got)
	}
	if got := cacheKey("ns", " :val: "); got != "ns:val" {
		t.Fatalf("cacheKey(colons) = %q, want ns:val", got)
	}
}

func TestVersionKeyFormatsCorrectly(t *testing.T) {
	if got := versionKey("ns", "scope"); got != "ns:version:scope" {
		t.Fatalf("versionKey = %q, want ns:version:scope", got)
	}
}

func TestVersionKeyDefaultsToGlobal(t *testing.T) {
	if got := versionKey("ns", ""); got != "ns:version:global" {
		t.Fatalf("versionKey(empty) = %q, want ns:version:global", got)
	}
}

func TestMemoryCacheGetMissReturnsError(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	_, err := cache.Get(context.Background(), "nonexistent")
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("Get(nonexistent) error = %v, want ErrMiss", err)
	}
}

func TestMemoryCacheSetAndGetRoundTrip(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	payload := []byte("hello")
	if err := cache.Set(context.Background(), "key1", payload, time.Minute, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	entry, err := cache.Get(context.Background(), "key1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(entry.Payload) != "hello" {
		t.Fatalf("payload = %q, want hello", entry.Payload)
	}
}

func TestMemoryCacheSetSkipsEmptyPayload(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	if err := cache.Set(context.Background(), "key1", nil, time.Minute, time.Minute); err != nil {
		t.Fatalf("Set(nil) error = %v", err)
	}
	if err := cache.Set(context.Background(), "key1", []byte{}, time.Minute, time.Minute); err != nil {
		t.Fatalf("Set(empty) error = %v", err)
	}
	_, err := cache.Get(context.Background(), "key1")
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("Get after empty set error = %v, want ErrMiss", err)
	}
}

func TestMemoryCacheSetSkipsOversizedPayload(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test", MaxPayloadBytes: 10})
	big := make([]byte, 11)
	if err := cache.Set(context.Background(), "key1", big, time.Minute, time.Minute); err != nil {
		t.Fatalf("Set(oversized) error = %v", err)
	}
	_, err := cache.Get(context.Background(), "key1")
	if !errors.Is(err, ErrMiss) {
		t.Fatalf("Get after oversized set error = %v, want ErrMiss", err)
	}
}

func TestMemoryCacheVersionStartsAtZero(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	v, err := cache.Version(context.Background(), "scope")
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if v != "0" {
		t.Fatalf("Version() = %q, want 0", v)
	}
}

func TestMemoryCacheBumpVersionIncrements(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	v1, err := cache.BumpVersion(context.Background(), "scope")
	if err != nil {
		t.Fatalf("BumpVersion() error = %v", err)
	}
	if v1 != "1" {
		t.Fatalf("BumpVersion() = %q, want 1", v1)
	}
	v2, err := cache.BumpVersion(context.Background(), "scope")
	if err != nil {
		t.Fatalf("BumpVersion(2) error = %v", err)
	}
	if v2 != "2" {
		t.Fatalf("BumpVersion(2) = %q, want 2", v2)
	}
}

func TestMemoryCachePingReturnsNil(t *testing.T) {
	cache := NewMemory(Options{})
	if err := cache.Ping(context.Background()); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
}

func TestMemoryCacheCloseReturnsNil(t *testing.T) {
	cache := NewMemory(Options{})
	if err := cache.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestMemoryCacheGetCopiesPayload(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	original := []byte("data")
	if err := cache.Set(context.Background(), "key", original, time.Minute, time.Minute); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	entry, err := cache.Get(context.Background(), "key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	entry.Payload[0] = 'X'
	entry2, err := cache.Get(context.Background(), "key")
	if err != nil {
		t.Fatalf("Get(2) error = %v", err)
	}
	if string(entry2.Payload) != "data" {
		t.Fatalf("payload mutated through returned entry: %q", entry2.Payload)
	}
}

func TestMemoryCacheSetMinTTL(t *testing.T) {
	cache := NewMemory(Options{Namespace: "test"})
	if err := cache.Set(context.Background(), "key", []byte("x"), 0, 0); err != nil {
		t.Fatalf("Set(zero TTL) error = %v", err)
	}
	entry, err := cache.Get(context.Background(), "key")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if entry.ExpiresAt.Before(entry.CreatedAt) {
		t.Fatal("ExpiresAt should not be before CreatedAt with zero TTL")
	}
}
