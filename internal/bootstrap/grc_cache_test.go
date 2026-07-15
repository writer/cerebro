package bootstrap

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestGRCQueryCacheStoresCompressedRepresentation(t *testing.T) {
	const maxPayloadBytes = 256
	payload := `{"items":["` + strings.Repeat("compressible-content-", 512) + `"]}`
	app := &App{
		cfg: config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{
			Namespace:       "test",
			MaxPayloadBytes: maxPayloadBytes,
		})},
	}
	calls := 0
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	})
	request := func(acceptEncoding string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/grc/dashboard", nil)
		req.Header.Set("Accept-Encoding", acceptEncoding)
		return req
	}

	first := httptest.NewRecorder()
	handler(first, request("gzip"))
	second := httptest.NewRecorder()
	handler(second, request("gzip"))

	if got := first.Header().Get("X-Cerebro-Cache"); got != "miss" {
		t.Fatalf("first X-Cerebro-Cache = %q, want miss", got)
	}
	if got := second.Header().Get("X-Cerebro-Cache"); got != "hit" {
		t.Fatalf("second X-Cerebro-Cache = %q, want hit", got)
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
	if got := second.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("second Content-Encoding = %q, want gzip", got)
	}
	if second.Body.Len() >= maxPayloadBytes {
		t.Fatalf("compressed body = %d bytes, want below cache limit %d", second.Body.Len(), maxPayloadBytes)
	}
	reader, err := gzip.NewReader(second.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read compressed response: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close gzip reader: %v", err)
	}
	if got := string(decompressed); got != payload {
		t.Fatalf("decompressed body mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	identity := httptest.NewRecorder()
	handler(identity, request("gzip;q=0"))
	if got := identity.Header().Get("X-Cerebro-Cache"); got != "skip" {
		t.Fatalf("identity X-Cerebro-Cache = %q, want skip for oversized identity payload", got)
	}
	if got := identity.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("identity Content-Encoding = %q, want empty", got)
	}
	if calls != 2 {
		t.Fatalf("handler calls after identity variant = %d, want 2", calls)
	}
}

func TestGRCQueryCacheKeepsSmallGzipRequestIdentityEncoded(t *testing.T) {
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test"})},
	}
	calls := 0
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	for index := 0; index < 2; index++ {
		req := httptest.NewRequest(http.MethodGet, "/grc/dashboard", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp := httptest.NewRecorder()
		handler(resp, req)
		if got := resp.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("response %d Content-Encoding = %q, want empty", index, got)
		}
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
}

func BenchmarkGRCQueryCacheCompressedHit(b *testing.B) {
	payload := []byte(`{"items":["` + strings.Repeat("compressible-content-", 50000) + `"]}`)
	app := &App{
		cfg: config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{
			Namespace:       "benchmark",
			MaxPayloadBytes: 1 << 20,
			MaxEntries:      256,
		})},
	}
	handler := app.cacheGRCJSON(app.grcCachePolicy("runtime.health", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	})
	request := httptest.NewRequest(http.MethodGet, "/source-runtimes/health?view=full", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	warm := httptest.NewRecorder()
	handler(warm, request)
	if got := warm.Header().Get("X-Cerebro-Cache"); got != "miss" {
		b.Fatalf("warm X-Cerebro-Cache = %q, want miss", got)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	b.ReportMetric(float64(warm.Body.Len()), "wire-bytes")
	for range b.N {
		response := httptest.NewRecorder()
		handler(response, request)
	}
}

func TestGRCQueryCacheKeysByQuery(t *testing.T) {
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test"})},
	}
	calls := 0
	handler := app.cacheGRCJSON(app.grcCachePolicy("policy.lifecycle", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		calls++
		writeJSON(w, http.StatusOK, map[string]any{"calls": calls})
	})

	baseline := httptest.NewRecorder()
	handler(baseline, httptest.NewRequest(http.MethodGet, "/grc/policy-lifecycle?tenant_id=writer&rule_profile=baseline", nil))
	strict := httptest.NewRecorder()
	handler(strict, httptest.NewRequest(http.MethodGet, "/grc/policy-lifecycle?tenant_id=writer&rule_profile=strict", nil))
	baselineAgain := httptest.NewRecorder()
	handler(baselineAgain, httptest.NewRequest(http.MethodGet, "/grc/policy-lifecycle?rule_profile=baseline&tenant_id=writer", nil))

	if baseline.Header().Get("X-Cerebro-Cache") != "miss" || strict.Header().Get("X-Cerebro-Cache") != "miss" {
		t.Fatalf("profile cache headers = %q/%q, want separate misses", baseline.Header().Get("X-Cerebro-Cache"), strict.Header().Get("X-Cerebro-Cache"))
	}
	if baselineAgain.Header().Get("X-Cerebro-Cache") != "hit" {
		t.Fatalf("baseline repeat X-Cerebro-Cache = %q, want hit", baselineAgain.Header().Get("X-Cerebro-Cache"))
	}
	if calls != 2 {
		t.Fatalf("handler calls = %d, want 2", calls)
	}
	if baseline.Body.String() == strict.Body.String() {
		t.Fatalf("profile responses shared a cache entry: %s", baseline.Body.String())
	}
	if baselineAgain.Body.String() != baseline.Body.String() {
		t.Fatalf("baseline repeat body = %q, want cached %q", baselineAgain.Body.String(), baseline.Body.String())
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
	if got := resp.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("Cache-Control = %q, want empty on bypass", got)
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
}

func TestGRCQueryCacheDoesNotEmitCacheControlForErrorResponse(t *testing.T) {
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test"})},
	}
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "backend failed", http.StatusInternalServerError)
	})

	resp := httptest.NewRecorder()
	handler(resp, httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil))

	if resp.Header().Get("X-Cerebro-Cache") != "bypass" {
		t.Fatalf("X-Cerebro-Cache = %q, want bypass", resp.Header().Get("X-Cerebro-Cache"))
	}
	if got := resp.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("Cache-Control = %q, want empty for uncached error response", got)
	}
}

func TestGRCQueryCacheReportsOversizedResponseWithoutClientCacheHeaders(t *testing.T) {
	app := &App{
		cfg: config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{
			Namespace:       "test",
			MaxPayloadBytes: 10,
		})},
	}
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Minute), func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"payload": "larger than ten bytes"})
	})

	first := httptest.NewRecorder()
	handler(first, httptest.NewRequest(http.MethodGet, "/grc/dashboard", nil))
	second := httptest.NewRecorder()
	handler(second, httptest.NewRequest(http.MethodGet, "/grc/dashboard", nil))

	if got := first.Header().Get("X-Cerebro-Cache"); got != "skip" {
		t.Fatalf("first X-Cerebro-Cache = %q, want skip", got)
	}
	if got := first.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("first Cache-Control = %q, want empty", got)
	}
	if got := second.Header().Get("X-Cerebro-Cache"); got != "skip" {
		t.Fatalf("second X-Cerebro-Cache = %q, want skip", got)
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
