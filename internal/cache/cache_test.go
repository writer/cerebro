package cache

import (
	"testing"
	"time"
)

func TestLRUBasic(t *testing.T) {
	c := NewLRU(3, time.Hour)

	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	if v, ok := c.Get("a"); !ok || v.(int) != 1 {
		t.Errorf("expected 1, got %v", v)
	}
	if v, ok := c.Get("b"); !ok || v.(int) != 2 {
		t.Errorf("expected 2, got %v", v)
	}
}

func TestLRUEviction(t *testing.T) {
	c := NewLRU(2, time.Hour)

	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3) // should evict "a"

	if _, ok := c.Get("a"); ok {
		t.Error("expected 'a' to be evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Error("expected 'b' to exist")
	}
	if _, ok := c.Get("c"); !ok {
		t.Error("expected 'c' to exist")
	}
}

func TestLRUExpiration(t *testing.T) {
	c := NewLRU(10, 50*time.Millisecond)

	c.Set("a", 1)

	if _, ok := c.Get("a"); !ok {
		t.Error("expected 'a' to exist before expiration")
	}

	c.mu.Lock()
	elem, ok := c.items["a"]
	if !ok {
		c.mu.Unlock()
		t.Fatal("expected cache entry to exist before forcing expiration")
	}
	e := elem.Value.(*entry)
	e.expiresAt = time.Now().Add(-time.Millisecond)
	c.mu.Unlock()

	if _, ok := c.Get("a"); ok {
		t.Error("expected 'a' to be expired")
	}
}

func TestLRUUpdate(t *testing.T) {
	c := NewLRU(10, time.Hour)

	c.Set("a", 1)
	c.Set("a", 2)

	if v, ok := c.Get("a"); !ok || v.(int) != 2 {
		t.Errorf("expected updated value 2, got %v", v)
	}

	if c.Len() != 1 {
		t.Errorf("expected length 1, got %d", c.Len())
	}
}

func TestPolicyCache(t *testing.T) {
	pc := NewPolicyCache(100, time.Hour)

	pc.SetEvaluation("policy-1", "asset-a", []string{"finding-1"})
	pc.SetEvaluation("policy-1", "asset-b", []string{})

	if val, ok := pc.GetEvaluation("policy-1", "asset-a"); !ok {
		t.Error("expected hit for asset-a")
	} else if findings, ok := val.([]string); !ok || len(findings) != 1 {
		t.Errorf("expected 1 finding for asset-a, got %v", val)
	}

	if val, ok := pc.GetEvaluation("policy-1", "asset-b"); !ok {
		t.Error("expected hit for asset-b")
	} else if findings, ok := val.([]string); !ok || len(findings) != 0 {
		t.Errorf("expected 0 findings for asset-b, got %v", val)
	}

	if _, ok := pc.GetEvaluation("policy-1", "asset-c"); ok {
		t.Error("expected miss for asset-c")
	}
}

func BenchmarkLRUSet(b *testing.B) {
	c := NewLRU(1000, time.Hour)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Set("key", i)
	}
}

func BenchmarkLRUGet(b *testing.B) {
	c := NewLRU(1000, time.Hour)
	c.Set("key", "value")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Get("key")
	}
}
