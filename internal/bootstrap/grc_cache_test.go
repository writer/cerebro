package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/querycache"
)

func TestGRCQueryCacheServesFreshHit(t *testing.T) {
	app := &App{
		cfg: config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{
			Namespace: "test",
		})},
	}
	calls := 0
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeJSON(w, http.StatusOK, map[string]any{"calls": calls})
	})

	first := httptest.NewRecorder()
	handler(first, httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil))
	if first.Header().Get("X-Cerebro-Cache") != "miss" {
		t.Fatalf("first X-Cerebro-Cache = %q, want miss", first.Header().Get("X-Cerebro-Cache"))
	}

	second := httptest.NewRecorder()
	handler(second, httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil))
	if second.Header().Get("X-Cerebro-Cache") != "hit" {
		t.Fatalf("second X-Cerebro-Cache = %q, want hit", second.Header().Get("X-Cerebro-Cache"))
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("cached body = %q, want %q", second.Body.String(), first.Body.String())
	}
}

func TestGRCQueryCacheBypassesNoCacheRequest(t *testing.T) {
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test"})},
	}
	calls := 0
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeJSON(w, http.StatusOK, map[string]any{"calls": calls})
	})

	req := httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil)
	req.Header.Set("Cache-Control", "no-cache")
	resp := httptest.NewRecorder()
	handler(resp, req)

	if resp.Header().Get("X-Cerebro-Cache") != "bypass" {
		t.Fatalf("X-Cerebro-Cache = %q, want bypass", resp.Header().Get("X-Cerebro-Cache"))
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
}

func TestGRCQueryCacheServesStaleOnRefreshError(t *testing.T) {
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Millisecond, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test"})},
	}
	calls := 0
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Millisecond), func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls > 1 {
			http.Error(w, "backend failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"calls": calls})
	})

	first := httptest.NewRecorder()
	handler(first, httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil))
	time.Sleep(5 * time.Millisecond)

	second := httptest.NewRecorder()
	handler(second, httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil))
	if second.Header().Get("X-Cerebro-Cache") != "stale" {
		t.Fatalf("second X-Cerebro-Cache = %q, want stale", second.Header().Get("X-Cerebro-Cache"))
	}
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200", second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("stale body = %q, want %q", second.Body.String(), first.Body.String())
	}
}
