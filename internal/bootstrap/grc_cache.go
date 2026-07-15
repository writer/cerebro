package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/querycache"
	httpcompression "github.com/writer/cerebro/internal/sourcehttp/compression"
	"github.com/writer/cerebro/internal/telemetry"
)

const (
	grcCacheScopeFindings  = "findings"
	grcCacheScopeEvidence  = "evidence"
	grcCacheScopeRuntime   = "runtime"
	grcCacheScopeGraph     = "graph"
	grcCacheScopeInventory = "inventory"
)

type queryCacheRefreshGroup struct {
	group singleflight.Group
}

type queryCacheVersionBatcher interface {
	Versions(context.Context, []string) (map[string]string, error)
}

func (g *queryCacheRefreshGroup) Do(key string, fn func() (*capturedHTTPResponse, error)) (*capturedHTTPResponse, error) {
	value, err, _ := g.group.Do(key, func() (any, error) {
		return fn()
	})
	if err != nil {
		return nil, err
	}
	response, _ := value.(*capturedHTTPResponse)
	return response, nil
}

type grcCachePolicy struct {
	Family        string
	TTL           time.Duration
	StaleTTL      time.Duration
	VersionScopes []string
}

func (a *App) cacheGRCJSON(policy grcCachePolicy, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cache := a.deps.QueryCache
		if cache == nil || r.Method != http.MethodGet || requestBypassesQueryCache(r) {
			w.Header().Set("X-Cerebro-Cache", "bypass")
			next(w, r)
			return
		}
		key := a.grcCacheKey(r, policy)
		entry, err := cache.Get(r.Context(), key)
		now := time.Now().UTC()
		if err == nil {
			switch entry.State(now) {
			case querycache.StateFresh:
				writeCachedJSON(w, http.StatusOK, entry.Payload, "hit", policy)
				return
			case querycache.StateStale:
				response, refreshErr := a.queryCacheGroup.Do(key, func() (*capturedHTTPResponse, error) {
					return captureCacheResponse(next, r), nil
				})
				if refreshErr == nil && response.cacheableJSON() {
					setErr := cache.Set(r.Context(), key, response.body.Bytes(), policy.TTL, policy.StaleTTL)
					response.writeTo(w, queryCacheWriteState(r.Context(), setErr), policy)
					return
				}
				if refreshErr != nil || response == nil || response.statusCode >= http.StatusInternalServerError {
					writeCachedJSON(w, http.StatusOK, entry.Payload, "stale", policy)
					return
				}
				response.writeTo(w, "bypass", policy)
				return
			}
		} else if !errors.Is(err, querycache.ErrMiss) {
			w.Header().Set("X-Cerebro-Cache", "bypass")
			next(w, r)
			return
		}

		response, err := a.queryCacheGroup.Do(key, func() (*capturedHTTPResponse, error) {
			return captureCacheResponse(next, r), nil
		})
		if err != nil || response == nil {
			w.Header().Set("X-Cerebro-Cache", "bypass")
			next(w, r)
			return
		}
		if response.cacheableJSON() {
			setErr := cache.Set(r.Context(), key, response.body.Bytes(), policy.TTL, policy.StaleTTL)
			response.writeTo(w, queryCacheWriteState(r.Context(), setErr), policy)
			return
		}
		response.writeTo(w, "bypass", policy)
	}
}

func queryCacheWriteState(ctx context.Context, err error) string {
	if err == nil {
		return "miss"
	}
	if errors.Is(err, querycache.ErrPayloadTooLarge) {
		telemetry.IncrementMain(ctx, "query_cache.payload_too_large.count", 1)
		return "skip"
	}
	telemetry.IncrementMain(ctx, "query_cache.write_error.count", 1)
	return "bypass"
}

func (a *App) grcCachePolicy(family string, ttl time.Duration, scopes ...string) grcCachePolicy {
	if ttl <= 0 {
		ttl = a.cfg.Cache.DefaultTTL
	}
	staleTTL := a.cfg.Cache.StaleTTL
	if staleTTL <= 0 {
		staleTTL = 5 * time.Minute
	}
	return grcCachePolicy{
		Family:        family,
		TTL:           ttl,
		StaleTTL:      staleTTL,
		VersionScopes: append([]string(nil), scopes...),
	}
}

func requestBypassesQueryCache(r *http.Request) bool {
	cacheControl := strings.ToLower(r.Header.Get("Cache-Control"))
	return strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "no-store")
}

func (a *App) grcCacheKey(r *http.Request, policy grcCachePolicy) string {
	tenantID := grcCacheTenantID(r)
	versions := a.grcCacheVersions(r, tenantID, policy.VersionScopes)
	material := map[string]any{
		"family":            policy.Family,
		"method":            r.Method,
		"path":              r.URL.EscapedPath(),
		"query":             canonicalRawQuery(r),
		"auth":              grcCacheAuthMaterial(r),
		"tenant":            tenantID,
		"versions":          versions,
		"response_encoding": grcCacheResponseEncoding(r),
	}
	raw, err := json.Marshal(material)
	if err != nil {
		log.Printf("grc: cache key marshal failed: %v", err)
		return ""
	}
	digest := sha256.Sum256(raw)
	return "http:grc:" + strings.TrimSpace(policy.Family) + ":" + hex.EncodeToString(digest[:])
}

func (a *App) grcCacheVersions(r *http.Request, tenantID string, scopes []string) map[string]string {
	cache := a.deps.QueryCache
	if cache == nil {
		return nil
	}
	versionScopes := []string{grcGlobalCacheVersionScope()}
	tenantID = strings.TrimSpace(tenantID)
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if tenantID != "" && scope != "" {
			versionScopes = append(versionScopes, grcTenantCacheVersionScope(tenantID, scope))
		}
	}
	sort.Strings(versionScopes)
	versions := map[string]string{}
	if batcher, ok := cache.(queryCacheVersionBatcher); ok {
		batched, err := batcher.Versions(r.Context(), versionScopes)
		if err == nil {
			for _, scope := range versionScopes {
				version := strings.TrimSpace(batched[scope])
				if version == "" {
					version = "0"
				}
				versions[scope] = version
			}
			return versions
		}
		log.Printf("grc: cache version batch failed: %v", err)
	}
	for _, scope := range versionScopes {
		version, err := cache.Version(r.Context(), scope)
		if err != nil || strings.TrimSpace(version) == "" {
			version = "0"
		}
		versions[scope] = version
	}
	return versions
}

func grcCacheTenantID(r *http.Request) string {
	if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok {
		if tenantID := strings.TrimSpace(auth.principal.TenantID); tenantID != "" {
			return tenantID
		}
	}
	if tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id")); tenantID != "" {
		return tenantID
	}
	if tenantID := strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant")); tenantID != "" {
		return tenantID
	}
	for _, key := range []string{"root_urn", "urn"} {
		if tenantID := tenantIDFromCerebroURN(r.URL.Query().Get(key)); tenantID != "" {
			return tenantID
		}
	}
	if tenantID := tenantIDFromCerebroURN(r.PathValue("entityID")); tenantID != "" {
		return tenantID
	}
	return ""
}

func canonicalRawQuery(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Query().Encode()
}

func grcCacheAuthMaterial(r *http.Request) string {
	auth, _ := r.Context().Value(authContextKey{}).(authContext)
	material := map[string]any{
		"mode":            auth.principal.AuthMode,
		"name":            auth.principal.Name,
		"tenant_id":       auth.principal.TenantID,
		"credential_id":   auth.principal.CredentialID,
		"client_id":       auth.principal.ClientID,
		"token_resource":  auth.principal.TokenResource,
		"allowed_tenants": normalizedStringSlice(auth.principal.AllowedTenants),
		"scopes":          normalizedStringSlice(expandedPrincipalScopes(auth.principal)),
		"roles":           normalizedStringSlice(auth.principal.Roles),
		"groups":          normalizedStringSlice(auth.principal.Groups),
		"capability":      auth.principal.Capability,
		"device_id":       auth.principal.DeviceID,
		"assurance":       auth.principal.AssuranceLevel,
	}
	raw, err := json.Marshal(material)
	if err != nil {
		log.Printf("grc: auth material marshal failed: %v", err)
		return ""
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func normalizedStringSlice(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

type capturedHTTPResponse struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func captureHTTPResponse(handler http.HandlerFunc, r *http.Request) *capturedHTTPResponse {
	response := &capturedHTTPResponse{header: http.Header{}}
	handler(response, r)
	if response.statusCode == 0 {
		response.statusCode = http.StatusOK
	}
	return response
}

func captureCacheResponse(handler http.HandlerFunc, r *http.Request) *capturedHTTPResponse {
	return captureHTTPResponse(httpcompression.Middleware(handler).ServeHTTP, r)
}

func (w *capturedHTTPResponse) Header() http.Header {
	return w.header
}

func (w *capturedHTTPResponse) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
}

func (w *capturedHTTPResponse) Write(payload []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.body.Write(payload)
}

func (w *capturedHTTPResponse) cacheableJSON() bool {
	if w == nil || w.statusCode != http.StatusOK || w.body.Len() == 0 {
		return false
	}
	contentType := strings.ToLower(w.header.Get("Content-Type"))
	return contentType == "" || strings.Contains(contentType, "application/json")
}

func (w *capturedHTTPResponse) writeTo(dst http.ResponseWriter, cacheState string, policy grcCachePolicy) {
	copyHeaders(dst.Header(), w.header)
	setGRCQueryCacheHeaders(dst.Header(), cacheState, policy)
	dst.WriteHeader(w.statusCode)
	_, _ = dst.Write(w.body.Bytes())
}

func writeCachedJSON(w http.ResponseWriter, statusCode int, payload []byte, cacheState string, policy grcCachePolicy) {
	w.Header().Set("Content-Type", "application/json")
	if cachedPayloadIsGzip(payload) {
		w.Header().Set("Content-Encoding", "gzip")
	} else {
		w.Header().Del("Content-Encoding")
	}
	setGRCQueryCacheHeaders(w.Header(), cacheState, policy)
	w.WriteHeader(statusCode)
	_, _ = w.Write(payload)
}

func copyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func setGRCQueryCacheHeaders(header http.Header, cacheState string, policy grcCachePolicy) {
	header.Set("X-Cerebro-Cache", cacheState)
	header.Set("Vary", appendVary(header.Get("Vary"), "Accept-Encoding", "Authorization", "X-Cerebro-API-Key", "X-Cerebro-Tenant"))
	if (cacheState == "hit" || cacheState == "miss" || cacheState == "stale") && policy.TTL > 0 {
		maxAge := int(policy.TTL / time.Second)
		if maxAge < 1 {
			maxAge = 1
		}
		value := "private, max-age=" + strconv.Itoa(maxAge)
		if policy.StaleTTL > 0 {
			stale := int(policy.StaleTTL / time.Second)
			if stale < 1 {
				stale = 1
			}
			value += ", stale-if-error=" + strconv.Itoa(stale)
		}
		header.Set("Cache-Control", value)
	}
}

func grcCacheResponseEncoding(r *http.Request) string {
	if r != nil && httpcompression.AcceptsGzip(r.Header.Get("Accept-Encoding")) {
		return "gzip"
	}
	return "identity"
}

func cachedPayloadIsGzip(payload []byte) bool {
	return len(payload) >= 2 && payload[0] == 0x1f && payload[1] == 0x8b
}

func appendVary(existing string, values ...string) string {
	seen := map[string]string{}
	for _, value := range strings.Split(existing, ",") {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			seen[strings.ToLower(trimmed)] = trimmed
		}
	}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			seen[strings.ToLower(trimmed)] = trimmed
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return strings.Join(out, ", ")
}

func grcGlobalCacheVersionScope() string {
	return "grc:global"
}

func grcTenantCacheVersionScope(tenantID string, scope string) string {
	return "grc:tenant:" + strings.TrimSpace(tenantID) + ":" + strings.TrimSpace(scope)
}

func bumpGRCCacheVersions(ctx context.Context, cache querycache.Cache, tenantID string, scopes ...string) {
	if cache == nil {
		return
	}
	if _, err := cache.BumpVersion(ctx, grcGlobalCacheVersionScope()); err != nil {
		log.Printf("grc: bump global cache version failed: %v", err)
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return
	}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, err := cache.BumpVersion(ctx, grcTenantCacheVersionScope(tenantID, scope)); err != nil {
			log.Printf("grc: bump tenant cache version failed: %v", err)
		}
	}
}

func (a *App) bumpGRCCacheVersions(ctx context.Context, tenantID string, scopes ...string) {
	bumpGRCCacheVersions(ctx, a.deps.QueryCache, tenantID, scopes...)
}

func bumpGRCCacheForFinding(ctx context.Context, cache querycache.Cache, finding *ports.FindingRecord) {
	if finding == nil {
		bumpGRCCacheVersions(ctx, cache, "", grcCacheScopeFindings, grcCacheScopeEvidence)
		return
	}
	bumpGRCCacheVersions(ctx, cache, finding.TenantID, grcCacheScopeFindings, grcCacheScopeEvidence, grcCacheScopeInventory)
}

func (a *App) bumpGRCCacheForFinding(ctx context.Context, finding *ports.FindingRecord) {
	bumpGRCCacheForFinding(ctx, a.deps.QueryCache, finding)
}

func bumpGRCCacheForRuntime(ctx context.Context, deps Dependencies, runtimeID string, scopes ...string) {
	tenantID := ""
	if store := sourceRuntimeStore(deps.StateStore); store != nil {
		if runtime, err := store.GetSourceRuntime(ctx, runtimeID); err == nil && runtime != nil {
			tenantID = runtime.GetTenantId()
		}
	}
	bumpGRCCacheVersions(ctx, deps.QueryCache, tenantID, scopes...)
}
