package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGraphCrossTenantPatternEndpoints(t *testing.T) {
	s := newTestServer(t)
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	for i := 0; i < 5; i++ {
		w := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected risk report 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcome record 200, got %d: %s", record.Code, record.Body.String())
	}

	buildA := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-alpha",
		"window_days": 365,
	})
	if buildA.Code != http.StatusOK {
		t.Fatalf("expected build samples 200, got %d: %s", buildA.Code, buildA.Body.String())
	}
	buildABody := decodeJSON(t, buildA)
	samplesA, ok := buildABody["samples"].([]any)
	if !ok || len(samplesA) == 0 {
		t.Fatalf("expected samples in build response, got %+v", buildABody["samples"])
	}

	buildB := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-beta",
		"window_days": 365,
	})
	if buildB.Code != http.StatusOK {
		t.Fatalf("expected build samples 200, got %d: %s", buildB.Code, buildB.Body.String())
	}
	buildBBody := decodeJSON(t, buildB)
	samplesB, ok := buildBBody["samples"].([]any)
	if !ok || len(samplesB) == 0 {
		t.Fatalf("expected samples in second build response, got %+v", buildBBody["samples"])
	}

	combinedSamples := append([]any{}, samplesA...)
	combinedSamples = append(combinedSamples, samplesB...)
	ingest := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/ingest", map[string]any{
		"samples": combinedSamples,
	})
	if ingest.Code != http.StatusOK {
		t.Fatalf("expected ingest 200, got %d: %s", ingest.Code, ingest.Body.String())
	}
	ingestBody := decodeJSON(t, ingest)
	if received, ok := ingestBody["received"].(float64); !ok || received < float64(len(combinedSamples)) {
		t.Fatalf("expected ingest received count, got %+v", ingestBody)
	}

	list := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/patterns?min_tenants=2", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("expected list patterns 200, got %d: %s", list.Code, list.Body.String())
	}
	listBody := decodeJSON(t, list)
	if count, ok := listBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one pattern, got %+v", listBody)
	}

	matches := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/matches?min_probability=0.5&limit=5", nil)
	if matches.Code != http.StatusOK {
		t.Fatalf("expected matches 200, got %d: %s", matches.Code, matches.Body.String())
	}
	matchesBody := decodeJSON(t, matches)
	if count, ok := matchesBody["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected at least one match, got %+v", matchesBody)
	}
}

func TestGraphCrossTenantPatternEndpoints_InvalidQueries(t *testing.T) {
	s := newTestServer(t)
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	w := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/matches?min_probability=2.0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid min_probability, got %d: %s", w.Code, w.Body.String())
	}

	w = do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/patterns?min_tenants=0", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid min_tenants, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGraphCrossTenantPatternIngest_RequiresSignedPayloadWhenConfigured(t *testing.T) {
	s := newTestServer(t)
	s.app.Config.GraphCrossTenantRequireSignedIngest = true
	s.app.Config.GraphCrossTenantSigningKey = "cross-tenant-test-key"
	s.app.Config.GraphCrossTenantSignatureSkew = 5 * time.Minute
	s.app.Config.GraphCrossTenantReplayTTL = time.Hour
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	for i := 0; i < 3; i++ {
		w := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected risk report 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(3 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcome record 200, got %d: %s", record.Code, record.Body.String())
	}
	build := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{
		"tenant_id":   "tenant-alpha",
		"window_days": 365,
	})
	if build.Code != http.StatusOK {
		t.Fatalf("expected build response 200, got %d: %s", build.Code, build.Body.String())
	}
	buildBody := decodeJSON(t, build)
	samples, ok := buildBody["samples"].([]any)
	if !ok || len(samples) == 0 {
		t.Fatalf("expected samples in build response, got %+v", buildBody["samples"])
	}

	unsigned := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/ingest", map[string]any{
		"samples": samples,
	})
	if unsigned.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned ingest to be rejected with 401, got %d: %s", unsigned.Code, unsigned.Body.String())
	}

	body := map[string]any{"samples": samples}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := "nonce-1"
	signed := doWithHeaders(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/ingest", body, map[string]string{
		"X-Cerebro-Timestamp": timestamp,
		"X-Cerebro-Nonce":     nonce,
		"X-Cerebro-Signature": "sha256=" + signCrossTenantIngestPayload(s.app.Config.GraphCrossTenantSigningKey, timestamp, nonce, mustJSON(t, body)),
	})
	if signed.Code != http.StatusOK {
		t.Fatalf("expected signed ingest 200, got %d: %s", signed.Code, signed.Body.String())
	}

	replay := doWithHeaders(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/ingest", body, map[string]string{
		"X-Cerebro-Timestamp": timestamp,
		"X-Cerebro-Nonce":     nonce,
		"X-Cerebro-Signature": "sha256=" + signCrossTenantIngestPayload(s.app.Config.GraphCrossTenantSigningKey, timestamp, nonce, mustJSON(t, body)),
	})
	if replay.Code != http.StatusConflict {
		t.Fatalf("expected replay nonce to be rejected with 409, got %d: %s", replay.Code, replay.Body.String())
	}
}

func TestGraphCrossTenantPatterns_PrivacyThresholds(t *testing.T) {
	s := newTestServer(t)
	s.app.Config.GraphCrossTenantMinTenants = 2
	s.app.Config.GraphCrossTenantMinSupport = 3
	seedGraphRiskFeedbackGraph(s.app.SecurityGraph)

	for i := 0; i < 5; i++ {
		w := do(t, s, http.MethodGet, "/api/v1/graph/risk-report", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("expected risk report 200, got %d: %s", w.Code, w.Body.String())
		}
	}
	record := do(t, s, http.MethodPost, "/api/v1/graph/outcomes", map[string]any{
		"entity_id":   "customer:acme",
		"outcome":     "churn",
		"occurred_at": time.Now().UTC().Add(4 * time.Hour),
	})
	if record.Code != http.StatusOK {
		t.Fatalf("expected outcome record 200, got %d: %s", record.Code, record.Body.String())
	}

	buildA := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{"tenant_id": "tenant-alpha", "window_days": 365})
	buildB := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/build", map[string]any{"tenant_id": "tenant-beta", "window_days": 365})
	if buildA.Code != http.StatusOK || buildB.Code != http.StatusOK {
		t.Fatalf("expected build responses 200, got A=%d B=%d", buildA.Code, buildB.Code)
	}
	samplesA, okA := decodeJSON(t, buildA)["samples"].([]any)
	samplesB, okB := decodeJSON(t, buildB)["samples"].([]any)
	if !okA || !okB || len(samplesA) == 0 || len(samplesB) == 0 {
		t.Fatalf("expected samples for two tenants")
	}

	ingest := do(t, s, http.MethodPost, "/api/v1/graph/cross-tenant/patterns/ingest", map[string]any{
		"samples": append(append([]any{}, samplesA...), samplesB...),
	})
	if ingest.Code != http.StatusOK {
		t.Fatalf("expected ingest 200, got %d: %s", ingest.Code, ingest.Body.String())
	}

	patterns := do(t, s, http.MethodGet, "/api/v1/graph/cross-tenant/patterns?min_tenants=1", nil)
	if patterns.Code != http.StatusOK {
		t.Fatalf("expected list patterns 200, got %d: %s", patterns.Code, patterns.Body.String())
	}
	if count, ok := decodeJSON(t, patterns)["count"].(float64); !ok || count != 0 {
		t.Fatalf("expected privacy threshold to suppress low-support patterns, got %+v", decodeJSON(t, patterns))
	}
}

func doWithHeaders(t *testing.T, s *Server, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	payload := mustJSON(t, body)
	reader = bytes.NewReader(payload)

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return payload
}
