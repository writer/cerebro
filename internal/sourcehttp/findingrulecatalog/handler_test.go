package findingrulecatalog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/rulecatalog"
)

type stubCustomFindingRuleStore struct {
	rules map[string]ports.CustomFindingRule
}

func newStubCustomFindingRuleStore() *stubCustomFindingRuleStore {
	return &stubCustomFindingRuleStore{rules: map[string]ports.CustomFindingRule{}}
}

func (s *stubCustomFindingRuleStore) Ping(context.Context) error { return nil }

func (s *stubCustomFindingRuleStore) ListCustomFindingRules(_ context.Context, tenantID string) ([]ports.CustomFindingRule, error) {
	out := []ports.CustomFindingRule{}
	for _, rule := range s.rules {
		if rule.TenantID == tenantID {
			out = append(out, rule)
		}
	}
	return out, nil
}

func (s *stubCustomFindingRuleStore) GetCustomFindingRule(_ context.Context, tenantID string, ruleID string) (*ports.CustomFindingRule, error) {
	rule, ok := s.rules[tenantID+"/"+ruleID]
	if !ok {
		return nil, ports.ErrCustomFindingRuleNotFound
	}
	return &rule, nil
}

func (s *stubCustomFindingRuleStore) PutCustomFindingRule(_ context.Context, rule *ports.CustomFindingRule) error {
	key := rule.TenantID + "/" + rule.ID
	copied := *rule
	now := time.Now().UTC()
	if existing, ok := s.rules[key]; ok {
		copied.CreatedBy = existing.CreatedBy
		copied.CreatedAt = existing.CreatedAt
	} else {
		copied.CreatedAt = now
	}
	copied.UpdatedAt = now
	s.rules[key] = copied
	return nil
}

func (s *stubCustomFindingRuleStore) DeleteCustomFindingRule(_ context.Context, tenantID string, ruleID string) error {
	key := tenantID + "/" + ruleID
	if _, ok := s.rules[key]; !ok {
		return ports.ErrCustomFindingRuleNotFound
	}
	delete(s.rules, key)
	return nil
}

const customRuleTestYAML = `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: custom-github-repo-public-no-branch-protection
  name: Public GitHub repository without branch protection
  description: A public repository allows direct pushes to the default branch.
spec:
  severity: high
  effect: forbid
  resource: github.code.repository
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "visibility"), "public")
      - cmp_eq(path(resource, "default_branch_protected"), false)
  remediation:
    summary: Enable branch protection with required reviews on the default branch.
  frameworks:
    - name: SOC 2
      controls: [CC8.1]
`

func testHandler(store ports.StateStore) Handler {
	return NewHandler(store, func(_ context.Context, requested string) (string, error) {
		if requested != "" && requested != "local" {
			return "", errors.New("tenant forbidden")
		}
		return "local", nil
	}, func(context.Context) string { return "analyst@example.com" })
}

func testRequest(method, target, body string) *http.Request {
	return httptest.NewRequest(method, target, strings.NewReader(body))
}

func ruleDocumentBody(t *testing.T, format string, content string, resource map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(DocumentRequest{Format: format, Content: content, Resource: resource})
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}

func TestHandleListRuleCatalogIncludesBuiltinAndCustomRules(t *testing.T) {
	store := newStubCustomFindingRuleStore()
	store.rules["local/custom-github-repo-public-no-branch-protection"] = ports.CustomFindingRule{TenantID: "local", ID: "custom-github-repo-public-no-branch-protection", Document: customRuleTestYAML}
	handler := testHandler(store)
	recorder := httptest.NewRecorder()
	handler.List(recorder, testRequest(http.MethodGet, "/finding-rules/catalog", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var response CatalogResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.CustomRulesReady || response.Total != len(response.Rules) || response.Total <= len(rulecatalog.Builtin()) {
		t.Fatalf("unexpected catalog summary: ready=%v total=%d", response.CustomRulesReady, response.Total)
	}
	last := response.Rules[len(response.Rules)-1]
	if last.Origin != rulecatalog.OriginCustom || last.Domain != rulecatalog.DomainSaaS || last.Provider != "github" {
		t.Fatalf("custom entry = %+v", last)
	}
}

func TestHandleGetRuleCatalogEntryReturnsBuiltinDetail(t *testing.T) {
	handler := testHandler(newStubCustomFindingRuleStore())
	request := testRequest(http.MethodGet, "/finding-rules/catalog/aws-user-inactive-admin-no-mfa", "")
	request.SetPathValue("ruleID", "aws-user-inactive-admin-no-mfa")
	recorder := httptest.NewRecorder()
	handler.Get(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var detail rulecatalog.Detail
	if err := json.Unmarshal(recorder.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Document == "" || detail.Remediation == "" || strings.Contains(recorder.Body.String(), "wiz") {
		t.Fatalf("unexpected detail: %+v", detail.Entry)
	}

	missing := testRequest(http.MethodGet, "/finding-rules/catalog/nope", "")
	missing.SetPathValue("ruleID", "nope")
	recorder = httptest.NewRecorder()
	handler.Get(recorder, missing)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d, want 404", recorder.Code)
	}
}

func TestHandleValidateAndTestCustomRule(t *testing.T) {
	handler := testHandler(newStubCustomFindingRuleStore())
	recorder := httptest.NewRecorder()
	handler.Validate(recorder, testRequest(http.MethodPost, "/finding-rules/validate", ruleDocumentBody(t, "yaml", customRuleTestYAML, nil)))
	var validation rulecatalog.ValidationResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &validation); err != nil || recorder.Code != http.StatusOK || !validation.Valid || validation.JSON == "" {
		t.Fatalf("validate status=%d err=%v body=%s", recorder.Code, err, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	body := ruleDocumentBody(t, "json", validation.JSON, map[string]any{"visibility": "public", "default_branch_protected": false})
	handler.Test(recorder, testRequest(http.MethodPost, "/finding-rules/test", body))
	var result rulecatalog.TestResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil || !result.Evaluated || !result.Matched {
		t.Fatalf("test status=%d err=%v body=%s", recorder.Code, err, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	handler.Validate(recorder, testRequest(http.MethodPost, "/finding-rules/validate", `{"format":"yaml","content":"x","unexpected":1}`))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown request field status = %d, want 400", recorder.Code)
	}
}

func TestHandlePutAndDeleteCustomRule(t *testing.T) {
	store := newStubCustomFindingRuleStore()
	handler := testHandler(store)
	ruleID := "custom-github-repo-public-no-branch-protection"
	put := func(pathID string, content string) *httptest.ResponseRecorder {
		request := testRequest(http.MethodPut, "/finding-rules/custom/"+pathID, ruleDocumentBody(t, "yaml", content, nil))
		request.SetPathValue("ruleID", pathID)
		recorder := httptest.NewRecorder()
		handler.Put(recorder, request)
		return recorder
	}

	recorder := put(ruleID, customRuleTestYAML)
	if recorder.Code != http.StatusOK {
		t.Fatalf("put status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var detail rulecatalog.Detail
	if err := json.Unmarshal(recorder.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail.ID != ruleID || !detail.Editable || detail.CreatedAt == "" {
		t.Fatalf("saved detail = %+v", detail)
	}
	stored := store.rules["local/"+ruleID]
	if !strings.Contains(stored.Document, "apiVersion: cerebro.writer.com/v1alpha1") || stored.CreatedBy == "" {
		t.Fatalf("stored rule = %+v", stored)
	}

	if recorder := put("custom-other-id", customRuleTestYAML); recorder.Code != http.StatusBadRequest {
		t.Fatalf("mismatched id status = %d, want 400", recorder.Code)
	}
	if recorder := put(ruleID, strings.Replace(customRuleTestYAML, "severity: high", "severity: urgent", 1)); recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid document status = %d, want 422", recorder.Code)
	}
	builtinDoc := strings.Replace(customRuleTestYAML, ruleID, "aws-user-inactive-admin-no-mfa", 1)
	if recorder := put("aws-user-inactive-admin-no-mfa", builtinDoc); recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("builtin id status = %d, want 422", recorder.Code)
	}

	deleteRequest := testRequest(http.MethodDelete, "/finding-rules/custom/"+ruleID, "")
	deleteRequest.SetPathValue("ruleID", ruleID)
	recorder = httptest.NewRecorder()
	handler.Delete(recorder, deleteRequest)
	if recorder.Code != http.StatusOK || len(store.rules) != 0 {
		t.Fatalf("delete status = %d, remaining = %d", recorder.Code, len(store.rules))
	}
	recorder = httptest.NewRecorder()
	handler.Delete(recorder, deleteRequest)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", recorder.Code)
	}
}

func TestHandleRejectsOtherTenant(t *testing.T) {
	store := newStubCustomFindingRuleStore()
	handler := testHandler(store)
	payload, err := json.Marshal(DocumentRequest{TenantID: "other", Format: "yaml", Content: customRuleTestYAML})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest(http.MethodPut, "/finding-rules/custom/custom-github-repo-public-no-branch-protection", string(payload))
	request.SetPathValue("ruleID", "custom-github-repo-public-no-branch-protection")
	recorder := httptest.NewRecorder()
	handler.Put(recorder, request)
	if recorder.Code != http.StatusForbidden || len(store.rules) != 0 {
		t.Fatalf("status = %d, stored = %d, want 403 and nothing stored", recorder.Code, len(store.rules))
	}
}

func TestHandlePutCustomRuleRequiresStore(t *testing.T) {
	handler := testHandler(nil)
	request := testRequest(http.MethodPut, "/finding-rules/custom/x", ruleDocumentBody(t, "yaml", customRuleTestYAML, nil))
	request.SetPathValue("ruleID", "x")
	recorder := httptest.NewRecorder()
	handler.Put(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
}
