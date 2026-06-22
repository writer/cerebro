package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
)

type stubRiskScoringConfigStore struct {
	configs map[string]*ports.RiskScoringConfig
}

func newStubRiskScoringConfigStore() *stubRiskScoringConfigStore {
	return &stubRiskScoringConfigStore{configs: map[string]*ports.RiskScoringConfig{}}
}

func (s *stubRiskScoringConfigStore) Ping(context.Context) error { return nil }

func (s *stubRiskScoringConfigStore) PutRiskScoringConfig(_ context.Context, config *ports.RiskScoringConfig) error {
	copied := *config
	copied.RelationWeights = cloneIntMap(config.RelationWeights)
	copied.FactorWeights = cloneFactorWeightMap(config.FactorWeights)
	if copied.CreatedAt.IsZero() {
		copied.CreatedAt = time.Now().UTC()
	}
	copied.UpdatedAt = time.Now().UTC()
	s.configs[strings.TrimSpace(config.TenantID)] = &copied
	return nil
}

func (s *stubRiskScoringConfigStore) GetRiskScoringConfig(_ context.Context, tenantID string) (*ports.RiskScoringConfig, error) {
	config, ok := s.configs[strings.TrimSpace(tenantID)]
	if !ok {
		return nil, ports.ErrRiskScoringConfigNotFound
	}
	copied := *config
	copied.RelationWeights = cloneIntMap(config.RelationWeights)
	copied.FactorWeights = cloneFactorWeightMap(config.FactorWeights)
	return &copied, nil
}

func (s *stubRiskScoringConfigStore) DeleteRiskScoringConfig(_ context.Context, tenantID string) error {
	delete(s.configs, strings.TrimSpace(tenantID))
	return nil
}

func TestHandleGetRiskScoringConfigReturnsDefault(t *testing.T) {
	app := askQueryTestApp(newStubRiskScoringConfigStore())
	recorder := httptest.NewRecorder()
	app.handleGetRiskScoringConfig(recorder, askQueryTestRequest(http.MethodGet, "/grc/risk-scoring-config", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response riskScoringConfigResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Persisted {
		t.Fatal("Persisted = true, want default config")
	}
	if response.Config.Thresholds.Critical != 85 || response.Config.ModelVersion == "" {
		t.Fatalf("config = %#v, want default thresholds and model version", response.Config)
	}
}

func TestHandlePutRiskScoringConfigPersistsOverride(t *testing.T) {
	store := newStubRiskScoringConfigStore()
	app := askQueryTestApp(store)
	body := `{"thresholds":{"critical":90,"high":75,"medium":45},"signals":{"epss_high":0.75},"relation_weights":{"can_admin":12},"factor_weights":{"external_exposure":{"likelihood":20}}}`
	recorder := httptest.NewRecorder()
	app.handlePutRiskScoringConfig(recorder, askQueryTestRequest(http.MethodPut, "/grc/risk-scoring-config", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	stored := store.configs["local"]
	if stored == nil {
		t.Fatal("config was not persisted")
	}
	if stored.Thresholds.Critical != 90 || stored.Signals.EPSSHigh != 0.75 || stored.RelationWeights["can_admin"] != 12 {
		t.Fatalf("stored config = %#v", stored)
	}
	var response riskScoringConfigResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Persisted || response.Config.ModelVersion == "" {
		t.Fatalf("response = %#v, want persisted config with model version", response)
	}
}

func TestHandlePutRiskScoringConfigRejectsInvalidThresholds(t *testing.T) {
	app := askQueryTestApp(newStubRiskScoringConfigStore())
	recorder := httptest.NewRecorder()
	app.handlePutRiskScoringConfig(recorder, askQueryTestRequest(http.MethodPut, "/grc/risk-scoring-config", `{"thresholds":{"critical":60,"high":70,"medium":40}}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestHandleDeleteRiskScoringConfigResetsOverride(t *testing.T) {
	store := newStubRiskScoringConfigStore()
	_ = store.PutRiskScoringConfig(context.Background(), &ports.RiskScoringConfig{TenantID: "local"})
	app := askQueryTestApp(store)
	recorder := httptest.NewRecorder()
	app.handleDeleteRiskScoringConfig(recorder, askQueryTestRequest(http.MethodDelete, "/grc/risk-scoring-config", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if _, ok := store.configs["local"]; ok {
		t.Fatal("config still persisted after delete")
	}
	var response riskScoringConfigResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Persisted {
		t.Fatalf("response persisted = true after delete: %#v", response)
	}
}

func cloneIntMap(input map[string]int) map[string]int {
	if input == nil {
		return nil
	}
	out := make(map[string]int, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func cloneFactorWeightMap(input map[string]ports.RiskScoringFactorWeight) map[string]ports.RiskScoringFactorWeight {
	if input == nil {
		return nil
	}
	out := make(map[string]ports.RiskScoringFactorWeight, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
