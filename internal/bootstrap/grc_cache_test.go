package bootstrap

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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
	if got := second.Header().Get("Cache-Control"); !strings.Contains(got, "stale-while-revalidate=60") {
		t.Fatalf("Cache-Control = %q, want stale-while-revalidate=60", got)
	}
}

func TestGRCQueryCacheIsolatesApplicationWorkspaceHeader(t *testing.T) {
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test"})},
	}
	calls := map[string]int{}
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Minute), func(w http.ResponseWriter, r *http.Request) {
		workspaceID, err := requestApplicationWorkspaceSelector(r)
		if err != nil {
			t.Fatalf("requestApplicationWorkspaceSelector() error = %v", err)
		}
		calls[workspaceID]++
		writeJSON(w, http.StatusOK, map[string]any{"workspace_id": workspaceID})
	})

	request := func(workspaceID string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/grc/vendors?tenant_id=writer", nil)
		r.Header.Set(applicationWorkspaceHeader, workspaceID)
		return r
	}
	serve := func(workspaceID string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler(response, request(workspaceID))
		return response
	}

	firstA, secondA := serve("workspace-a"), serve("workspace-a")
	firstB, secondB := serve("workspace-b"), serve("workspace-b")
	if firstA.Header().Get("X-Cerebro-Cache") != "miss" || secondA.Header().Get("X-Cerebro-Cache") != "hit" || firstB.Header().Get("X-Cerebro-Cache") != "miss" || secondB.Header().Get("X-Cerebro-Cache") != "hit" {
		t.Fatalf("workspace cache states = A:%q/%q B:%q/%q", firstA.Header().Get("X-Cerebro-Cache"), secondA.Header().Get("X-Cerebro-Cache"), firstB.Header().Get("X-Cerebro-Cache"), secondB.Header().Get("X-Cerebro-Cache"))
	}
	if calls["workspace-a"] != 1 || calls["workspace-b"] != 1 || firstA.Body.String() == firstB.Body.String() {
		t.Fatalf("workspace cache isolation = calls:%#v A:%q B:%q", calls, firstA.Body.String(), firstB.Body.String())
	}
	for _, response := range []*httptest.ResponseRecorder{firstA, secondA, firstB, secondB} {
		if !strings.Contains(response.Header().Get("Vary"), applicationWorkspaceHeader) {
			t.Fatalf("Vary = %q, want %q", response.Header().Get("Vary"), applicationWorkspaceHeader)
		}
	}
}

func TestGRCCacheKeyNormalizesWorkspaceSelectorAndBindsGrants(t *testing.T) {
	app := &App{}
	policy := app.grcCachePolicy("test", time.Minute)
	headerRequest := httptest.NewRequest(http.MethodGet, "/grc/vendors?tenant_id=writer", nil)
	headerRequest.Header.Set(applicationWorkspaceHeader, "workspace-a")
	queryRequest := httptest.NewRequest(http.MethodGet, "/grc/vendors?tenant_id=writer&workspace_id=workspace-a", nil)
	if headerKey, queryKey := app.grcCacheKey(headerRequest, policy), app.grcCacheKey(queryRequest, policy); headerKey == "" || headerKey != queryKey {
		t.Fatalf("equivalent workspace selector cache keys = header:%q query:%q", headerKey, queryKey)
	}

	withGrant := func(workspaceID string) *http.Request {
		request := headerRequest.Clone(context.WithValue(headerRequest.Context(), authContextKey{}, authContext{principal: authPrincipal{
			TenantID: "writer",
			ApplicationWorkspaceGrants: []config.ApplicationWorkspaceGrant{{
				TenantID: "writer", ApplicationWorkspaceIDs: []string{workspaceID},
			}},
		}}))
		return request
	}
	if keyA, keyB := app.grcCacheKey(withGrant("workspace-a"), policy), app.grcCacheKey(withGrant("workspace-b"), policy); keyA == keyB {
		t.Fatalf("workspace grant cache keys collide: %q", keyA)
	}

	conflict := queryRequest.Clone(queryRequest.Context())
	conflict.Header.Set(applicationWorkspaceHeader, "workspace-b")
	if key, validKey := app.grcCacheKey(conflict, policy), app.grcCacheKey(headerRequest, policy); key == validKey {
		t.Fatalf("conflicting workspace selector cache key = %q, collides with valid selector", key)
	}

	cacheApp := &App{cfg: config.Config{Cache: config.CacheConfig{DefaultTTL: time.Minute, StaleTTL: time.Minute}}, deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test-invalid"})}}
	calls := 0
	handler := cacheApp.cacheGRCJSON(policy, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if _, err := requestApplicationWorkspaceSelector(r); err != nil {
			http.Error(w, "invalid workspace selector", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	for range 2 {
		response := httptest.NewRecorder()
		handler(response, conflict.Clone(conflict.Context()))
		if response.Code != http.StatusBadRequest || response.Header().Get("X-Cerebro-Cache") != "bypass" {
			t.Fatalf("invalid selector response = status:%d cache:%q", response.Code, response.Header().Get("X-Cerebro-Cache"))
		}
	}
	if calls != 2 {
		t.Fatalf("invalid selector handler calls = %d, want uncached calls", calls)
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

func TestGRCQueryCacheServesStaleWithoutWaitingForRefresh(t *testing.T) {
	cache := querycache.NewMemory(querycache.Options{Namespace: "test"})
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Millisecond, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: cache},
	}
	var calls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Millisecond), func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		if call > 1 {
			close(refreshStarted)
			<-releaseRefresh
		}
		writeJSON(w, http.StatusOK, map[string]any{"calls": call})
	})

	request := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil)
	}
	first := httptest.NewRecorder()
	handler(first, request())
	time.Sleep(5 * time.Millisecond)

	served := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		second := httptest.NewRecorder()
		handler(second, request())
		served <- second
	}()
	var second *httptest.ResponseRecorder
	select {
	case second = <-served:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("stale response waited for backend refresh")
	}
	if second.Header().Get("X-Cerebro-Cache") != "stale" {
		t.Fatalf("second X-Cerebro-Cache = %q, want stale", second.Header().Get("X-Cerebro-Cache"))
	}
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, want 200", second.Code)
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("stale body = %q, want %q", second.Body.String(), first.Body.String())
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not start")
	}
	close(releaseRefresh)

	key := app.grcCacheKey(request(), app.grcCachePolicy("test", time.Millisecond))
	deadline := time.Now().Add(time.Second)
	for {
		entry, err := cache.Get(t.Context(), key)
		if err == nil && strings.Contains(string(entry.Payload), `"calls":2`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background refresh did not replace cached payload: calls=%d err=%v", calls.Load(), err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGRCQueryCacheCoalescesBackgroundRefreshes(t *testing.T) {
	app := &App{
		cfg:  config.Config{Cache: config.CacheConfig{DefaultTTL: time.Millisecond, StaleTTL: time.Minute}},
		deps: Dependencies{QueryCache: querycache.NewMemory(querycache.Options{Namespace: "test"})},
	}
	var calls atomic.Int32
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	handler := app.cacheGRCJSON(app.grcCachePolicy("test", time.Millisecond), func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		if call > 1 {
			close(refreshStarted)
			<-releaseRefresh
		}
		writeJSON(w, http.StatusOK, map[string]any{"calls": call})
	})

	request := func() *http.Request {
		return httptest.NewRequest(http.MethodGet, "/grc/dashboard?tenant_id=writer", nil)
	}
	handler(httptest.NewRecorder(), request())
	time.Sleep(5 * time.Millisecond)

	for range 20 {
		response := httptest.NewRecorder()
		handler(response, request())
		if got := response.Header().Get("X-Cerebro-Cache"); got != "stale" {
			t.Fatalf("X-Cerebro-Cache = %q, want stale", got)
		}
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("background refresh did not start")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("handler calls = %d, want one initial load and one coalesced refresh", got)
	}
	close(releaseRefresh)
}
