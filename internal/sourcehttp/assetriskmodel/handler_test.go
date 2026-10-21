package assetriskmodel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/assetrisk"
	"github.com/writer/cerebro/internal/ports"
)

type stubModelStore struct {
	models map[string]ports.AssetRiskModel
}

func newStubModelStore() *stubModelStore {
	return &stubModelStore{models: map[string]ports.AssetRiskModel{}}
}

func (s *stubModelStore) Ping(context.Context) error { return nil }

func (s *stubModelStore) PutAssetRiskModel(_ context.Context, model *ports.AssetRiskModel) error {
	payload, _ := json.Marshal(model)
	var copied ports.AssetRiskModel
	_ = json.Unmarshal(payload, &copied)
	copied.UpdatedAt = time.Date(2026, 6, 22, 9, 0, 0, 0, time.UTC)
	s.models[model.TenantID] = copied
	return nil
}

func (s *stubModelStore) GetAssetRiskModel(_ context.Context, tenantID string) (*ports.AssetRiskModel, error) {
	model, ok := s.models[tenantID]
	if !ok {
		return nil, ports.ErrAssetRiskModelNotFound
	}
	return &model, nil
}

func (s *stubModelStore) DeleteAssetRiskModel(_ context.Context, tenantID string) error {
	delete(s.models, tenantID)
	return nil
}

type stubGraph struct {
	entities  map[string]ports.CatalogEntity
	relations map[string][]ports.EntityCatalogRelation
}

func (g *stubGraph) ListEntities(_ context.Context, request ports.EntityCatalogPageRequest) (*ports.EntityCatalogPage, error) {
	page := &ports.EntityCatalogPage{TenantID: request.Filter.TenantID}
	if entity, ok := g.entities[request.Filter.ExactAgentKey]; ok {
		page.Entities = []ports.CatalogEntity{entity}
	}
	return page, nil
}

func (g *stubGraph) CountEntityKinds(context.Context, ports.EntityKindCountRequest) (*ports.EntityKindCountPage, error) {
	return &ports.EntityKindCountPage{}, nil
}

func (g *stubGraph) ListEntityRelations(_ context.Context, request ports.EntityRelationPageRequest) (*ports.EntityRelationPage, error) {
	return &ports.EntityRelationPage{TenantID: request.TenantID, Relations: g.relations[request.AgentKey]}, nil
}

func testGraph() *stubGraph {
	user := ports.CatalogEntity{URN: "urn:user", TenantID: "local", EntityType: "okta.user"}
	app := ports.CatalogEntity{URN: "urn:app", TenantID: "local", EntityType: "okta.application", Attributes: map[string]string{"crown_jewel": "true"}}
	return &stubGraph{
		entities: map[string]ports.CatalogEntity{user.URN: user, app.URN: app},
		relations: map[string][]ports.EntityCatalogRelation{
			user.URN: {{Direction: ports.EntityRelationOutgoing, Relation: "can_admin", Entity: app}},
		},
	}
}

func testHandler(store ports.StateStore, graph ports.EntityCatalogStore) Handler {
	return NewHandler(store, graph, func(_ context.Context, requested string) (string, error) {
		if requested != "" && requested != "local" {
			return "", errors.New("tenant forbidden")
		}
		return "local", nil
	})
}

func serve(handler http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(method, target, strings.NewReader(body)))
	return recorder
}

func decode[T any](t *testing.T, recorder *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, recorder.Body.String())
	}
	return value
}

func TestGetModelReturnsDefaults(t *testing.T) {
	handler := testHandler(newStubModelStore(), nil)
	recorder := serve(handler.GetModel, http.MethodGet, "/grc/asset-risk-model", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	response := decode[ModelResponse](t, recorder)
	if response.Persisted || response.Model.ModelVersion != assetrisk.ModelVersion || response.Model.TenantID != "local" {
		t.Fatalf("response = %#v", response)
	}
	if len(response.Model.Countermeasures) == 0 || len(response.Model.Relations) == 0 {
		t.Fatal("defaults should include countermeasures and relations")
	}
}

func TestPutModelSavesAndDeleteResets(t *testing.T) {
	store := newStubModelStore()
	handler := testHandler(store, nil)
	recorder := serve(handler.PutModel, http.MethodPut, "/grc/asset-risk-model", `{"tenant_id":"local","countermeasures":[],"exposure":{"entry_probability":0.5,"internet":1,"internal":0.3,"internet_attributes":["public"]}}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	response := decode[ModelResponse](t, recorder)
	if !response.Persisted || len(response.Model.Countermeasures) != 0 || response.Model.Exposure.EntryProbability != 0.5 || response.Model.UpdatedAt == "" {
		t.Fatalf("response = %#v", response)
	}
	if !strings.HasPrefix(response.Model.ModelVersion, assetrisk.ModelVersion+"+config:") {
		t.Fatalf("model version = %q", response.Model.ModelVersion)
	}
	recorder = serve(handler.DeleteModel, http.MethodDelete, "/grc/asset-risk-model?tenant_id=local", "")
	if recorder.Code != http.StatusOK || decode[ModelResponse](t, recorder).Persisted || len(store.models) != 0 {
		t.Fatalf("delete status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestPutModelRejectsInvalidModelAndForeignTenant(t *testing.T) {
	handler := testHandler(newStubModelStore(), nil)
	if recorder := serve(handler.PutModel, http.MethodPut, "/grc/asset-risk-model", `{"exposure":{"entry_probability":2}}`); recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid model status = %d", recorder.Code)
	}
	if recorder := serve(handler.PutModel, http.MethodPut, "/grc/asset-risk-model", `{"tenant_id":"other"}`); recorder.Code != http.StatusForbidden {
		t.Fatalf("foreign tenant status = %d", recorder.Code)
	}
	if recorder := serve(testHandler(nil, nil).PutModel, http.MethodPut, "/grc/asset-risk-model", `{}`); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing store status = %d", recorder.Code)
	}
}

func TestGetPathsScoresFromRoot(t *testing.T) {
	handler := testHandler(newStubModelStore(), testGraph())
	recorder := serve(handler.GetPaths, http.MethodGet, "/platform/graph/risk-paths?root_urn=urn:user&assume_compromised=true", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	response := decode[PathsResponse](t, recorder)
	if response.ModelVersion != assetrisk.ModelVersion || response.PathResult == nil || len(response.Paths) != 1 {
		t.Fatalf("response = %s", recorder.Body.String())
	}
	path := response.Paths[0]
	if path.TargetURN != "urn:app" || path.Probability != 0.9 || path.Score != 90 || path.Level != "critical" {
		t.Fatalf("path = %#v", path)
	}
}

func TestGetPathsErrors(t *testing.T) {
	handler := testHandler(newStubModelStore(), testGraph())
	cases := map[string]int{
		"/platform/graph/risk-paths":                                            http.StatusBadRequest,
		"/platform/graph/risk-paths?root_urn=urn:user&max_depth=0":              http.StatusBadRequest,
		"/platform/graph/risk-paths?root_urn=urn:user&assume_compromised=maybe": http.StatusBadRequest,
		"/platform/graph/risk-paths?root_urn=urn:missing":                       http.StatusNotFound,
		"/platform/graph/risk-paths?root_urn=urn:user&tenant_id=other":          http.StatusForbidden,
	}
	for target, want := range cases {
		if recorder := serve(handler.GetPaths, http.MethodGet, target, ""); recorder.Code != want {
			t.Fatalf("%s status = %d, want %d (body %s)", target, recorder.Code, want, recorder.Body.String())
		}
	}
	if recorder := serve(testHandler(newStubModelStore(), nil).GetPaths, http.MethodGet, "/platform/graph/risk-paths?root_urn=urn:user", ""); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing graph status = %d", recorder.Code)
	}
}
