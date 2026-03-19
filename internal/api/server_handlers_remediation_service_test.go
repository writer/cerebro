package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/remediation"
)

type stubRemediationOperationsService struct {
	listRulesFunc      func() ([]remediation.Rule, error)
	createRuleFunc     func(context.Context, remediation.Rule, string) (remediation.Rule, error)
	updateRuleFunc     func(string, remediation.Rule) (*remediation.Rule, error)
	deleteRuleFunc     func(string) error
	getRuleFunc        func(string) (*remediation.Rule, bool, error)
	enableRuleFunc     func(string) error
	disableRuleFunc    func(string) error
	listExecutionsFunc func(int) ([]*remediation.Execution, error)
	getExecutionFunc   func(string) (*remediation.Execution, bool, error)
	approveExecFunc    func(context.Context, string, string) error
	rejectExecFunc     func(context.Context, string, string, string) error
}

func (s stubRemediationOperationsService) ListRules() ([]remediation.Rule, error) {
	if s.listRulesFunc != nil {
		return s.listRulesFunc()
	}
	return nil, nil
}

func (s stubRemediationOperationsService) CreateRule(ctx context.Context, rule remediation.Rule, createdBy string) (remediation.Rule, error) {
	if s.createRuleFunc != nil {
		return s.createRuleFunc(ctx, rule, createdBy)
	}
	return remediation.Rule{}, nil
}

func (s stubRemediationOperationsService) UpdateRule(id string, rule remediation.Rule) (*remediation.Rule, error) {
	if s.updateRuleFunc != nil {
		return s.updateRuleFunc(id, rule)
	}
	return nil, nil
}

func (s stubRemediationOperationsService) DeleteRule(id string) error {
	if s.deleteRuleFunc != nil {
		return s.deleteRuleFunc(id)
	}
	return nil
}

func (s stubRemediationOperationsService) GetRule(id string) (*remediation.Rule, bool, error) {
	if s.getRuleFunc != nil {
		return s.getRuleFunc(id)
	}
	return nil, false, nil
}

func (s stubRemediationOperationsService) EnableRule(id string) error {
	if s.enableRuleFunc != nil {
		return s.enableRuleFunc(id)
	}
	return nil
}

func (s stubRemediationOperationsService) DisableRule(id string) error {
	if s.disableRuleFunc != nil {
		return s.disableRuleFunc(id)
	}
	return nil
}

func (s stubRemediationOperationsService) ListExecutions(limit int) ([]*remediation.Execution, error) {
	if s.listExecutionsFunc != nil {
		return s.listExecutionsFunc(limit)
	}
	return nil, nil
}

func (s stubRemediationOperationsService) GetExecution(id string) (*remediation.Execution, bool, error) {
	if s.getExecutionFunc != nil {
		return s.getExecutionFunc(id)
	}
	return nil, false, nil
}

func (s stubRemediationOperationsService) ApproveExecution(ctx context.Context, id, approverID string) error {
	if s.approveExecFunc != nil {
		return s.approveExecFunc(ctx, id, approverID)
	}
	return nil
}

func (s stubRemediationOperationsService) RejectExecution(ctx context.Context, id, rejecterID, reason string) error {
	if s.rejectExecFunc != nil {
		return s.rejectExecFunc(ctx, id, rejecterID, reason)
	}
	return nil
}

func TestRemediationRuleHandlersUseServiceInterface(t *testing.T) {
	var (
		listCalled    bool
		createCalled  bool
		updateCalled  bool
		deleteCalled  bool
		getCalled     bool
		enableCalled  bool
		disableCalled bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		remediationOperations: stubRemediationOperationsService{
			listRulesFunc: func() ([]remediation.Rule, error) {
				listCalled = true
				return []remediation.Rule{{ID: "rule-1", Name: "Notify owner"}}, nil
			},
			createRuleFunc: func(_ context.Context, rule remediation.Rule, createdBy string) (remediation.Rule, error) {
				createCalled = true
				if createdBy != "" {
					t.Fatalf("expected empty test user id, got %q", createdBy)
				}
				if rule.ID != "rule-1" || rule.Name != "Notify owner" {
					t.Fatalf("unexpected created rule: %#v", rule)
				}
				return rule, nil
			},
			updateRuleFunc: func(id string, rule remediation.Rule) (*remediation.Rule, error) {
				updateCalled = true
				if id != "rule-1" || rule.ID != "rule-1" || rule.Name != "Updated rule" {
					t.Fatalf("unexpected update payload: id=%q rule=%#v", id, rule)
				}
				return &rule, nil
			},
			deleteRuleFunc: func(id string) error {
				deleteCalled = true
				if id != "rule-1" {
					t.Fatalf("expected delete rule-1, got %q", id)
				}
				return nil
			},
			getRuleFunc: func(id string) (*remediation.Rule, bool, error) {
				getCalled = true
				if id != "rule-1" {
					t.Fatalf("expected get rule-1, got %q", id)
				}
				return &remediation.Rule{ID: id, Name: "Notify owner"}, true, nil
			},
			enableRuleFunc: func(id string) error {
				enableCalled = true
				if id != "rule-1" {
					t.Fatalf("expected enable rule-1, got %q", id)
				}
				return nil
			},
			disableRuleFunc: func(id string) error {
				disableCalled = true
				if id != "rule-1" {
					t.Fatalf("expected disable rule-1, got %q", id)
				}
				return nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/remediation/rules", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed rule list, got %d: %s", w.Code, w.Body.String())
	}
	if !listCalled {
		t.Fatal("expected remediation rule list handler to use service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/remediation/rules", map[string]any{"id": "rule-1", "name": "Notify owner"}); w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for service-backed create rule, got %d: %s", w.Code, w.Body.String())
	}
	if !createCalled {
		t.Fatal("expected remediation rule create handler to use service")
	}

	if w := do(t, s, http.MethodPut, "/api/v1/remediation/rules/rule-1", map[string]any{"name": "Updated rule"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed update rule, got %d: %s", w.Code, w.Body.String())
	}
	if !updateCalled {
		t.Fatal("expected remediation rule update handler to use service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/remediation/rules/rule-1", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed get rule, got %d: %s", w.Code, w.Body.String())
	}
	if !getCalled {
		t.Fatal("expected remediation rule get handler to use service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/remediation/rules/rule-1/enable", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed enable rule, got %d: %s", w.Code, w.Body.String())
	}
	if !enableCalled {
		t.Fatal("expected remediation rule enable handler to use service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/remediation/rules/rule-1/disable", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed disable rule, got %d: %s", w.Code, w.Body.String())
	}
	if !disableCalled {
		t.Fatal("expected remediation rule disable handler to use service")
	}

	if w := do(t, s, http.MethodDelete, "/api/v1/remediation/rules/rule-1", nil); w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for service-backed delete rule, got %d: %s", w.Code, w.Body.String())
	}
	if !deleteCalled {
		t.Fatal("expected remediation rule delete handler to use service")
	}
}

func TestRemediationExecutionHandlersUseServiceInterface(t *testing.T) {
	var (
		listCalled    bool
		getCalled     bool
		approveCalled bool
		rejectCalled  bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		remediationOperations: stubRemediationOperationsService{
			listExecutionsFunc: func(limit int) ([]*remediation.Execution, error) {
				listCalled = true
				if limit != 7 {
					t.Fatalf("expected limit 7, got %d", limit)
				}
				return []*remediation.Execution{{ID: "exec-1", RuleID: "rule-1"}}, nil
			},
			getExecutionFunc: func(id string) (*remediation.Execution, bool, error) {
				getCalled = true
				if id != "exec-1" {
					t.Fatalf("expected get exec-1, got %q", id)
				}
				return &remediation.Execution{ID: id, RuleID: "rule-1"}, true, nil
			},
			approveExecFunc: func(_ context.Context, id, approverID string) error {
				approveCalled = true
				if id != "exec-1" || approverID != "approver-1" {
					t.Fatalf("unexpected approve payload: id=%q approver=%q", id, approverID)
				}
				return nil
			},
			rejectExecFunc: func(_ context.Context, id, rejecterID, reason string) error {
				rejectCalled = true
				if id != "exec-1" || rejecterID != "reviewer-1" || reason != "not safe" {
					t.Fatalf("unexpected reject payload: id=%q rejecter=%q reason=%q", id, rejecterID, reason)
				}
				return nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/remediation/executions?limit=7", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed execution list, got %d: %s", w.Code, w.Body.String())
	}
	if !listCalled {
		t.Fatal("expected remediation execution list handler to use service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/remediation/executions/exec-1", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed execution get, got %d: %s", w.Code, w.Body.String())
	}
	if !getCalled {
		t.Fatal("expected remediation execution get handler to use service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/remediation/executions/exec-1/approve", map[string]any{"approver_id": "approver-1"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed approve execution, got %d: %s", w.Code, w.Body.String())
	}
	if !approveCalled {
		t.Fatal("expected remediation execution approve handler to use service")
	}

	if w := do(t, s, http.MethodPost, "/api/v1/remediation/executions/exec-1/reject", map[string]any{"rejecter_id": "reviewer-1", "reason": "not safe"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed reject execution, got %d: %s", w.Code, w.Body.String())
	}
	if !rejectCalled {
		t.Fatal("expected remediation execution reject handler to use service")
	}
}
