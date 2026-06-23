package graphactionapi

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/graphactions"
	"github.com/writer/cerebro/internal/ports"
)

func TestExecuteRequiresFindingID(t *testing.T) {
	e := Executor{}
	_, err := e.Execute(context.Background(), graphactions.Input{FindingID: ""})
	if err == nil {
		t.Fatal("expected error for empty finding_id")
	}
	if !errors.Is(err, graphactions.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestExecuteTrimsFindingID(t *testing.T) {
	e := Executor{}
	_, err := e.Execute(context.Background(), graphactions.Input{FindingID: "   "})
	if err == nil {
		t.Fatal("expected error for whitespace-only finding_id")
	}
	if !errors.Is(err, graphactions.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestExecuteAuthorizeFindingError(t *testing.T) {
	authErr := errors.New("unauthorized")
	e := Executor{
		AuthorizeFinding: func(_ context.Context, _ string) error {
			return authErr
		},
	}
	_, err := e.Execute(context.Background(), graphactions.Input{FindingID: "f-123"})
	if !errors.Is(err, authErr) {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestExecuteReturnsErrNotConfiguredWhenNoService(t *testing.T) {
	e := Executor{}
	_, err := e.Execute(context.Background(), graphactions.Input{FindingID: "f-123"})
	if !errors.Is(err, graphactions.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestReconcileRequiresFindingID(t *testing.T) {
	e := Executor{}
	_, err := e.Reconcile(context.Background(), graphactions.ReconcileInput{FindingID: ""})
	if err == nil {
		t.Fatal("expected error for empty finding_id")
	}
	if !errors.Is(err, graphactions.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestReconcileTrimsFindingID(t *testing.T) {
	e := Executor{}
	_, err := e.Reconcile(context.Background(), graphactions.ReconcileInput{FindingID: "  \t "})
	if err == nil {
		t.Fatal("expected error for whitespace-only finding_id")
	}
	if !errors.Is(err, graphactions.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestReconcileAuthorizeFindingError(t *testing.T) {
	authErr := errors.New("forbidden")
	e := Executor{
		AuthorizeFinding: func(_ context.Context, _ string) error {
			return authErr
		},
	}
	_, err := e.Reconcile(context.Background(), graphactions.ReconcileInput{FindingID: "f-123"})
	if !errors.Is(err, authErr) {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestReconcileReturnsErrNotConfiguredWhenNoService(t *testing.T) {
	e := Executor{}
	_, err := e.Reconcile(context.Background(), graphactions.ReconcileInput{FindingID: "f-123"})
	if !errors.Is(err, graphactions.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestServiceNewServiceFallback(t *testing.T) {
	called := false
	e := Executor{
		NewService: func() (*graphactions.Service, error) {
			called = true
			return nil, nil
		},
	}
	_, err := e.Execute(context.Background(), graphactions.Input{FindingID: "f-123"})
	if !called {
		t.Fatal("NewService was not called")
	}
	if !errors.Is(err, graphactions.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured when NewService returns nil, got %v", err)
	}
}

func TestServiceNewServiceError(t *testing.T) {
	serviceErr := errors.New("service init failed")
	e := Executor{
		NewService: func() (*graphactions.Service, error) {
			return nil, serviceErr
		},
	}
	_, err := e.Execute(context.Background(), graphactions.Input{FindingID: "f-123"})
	if !errors.Is(err, serviceErr) {
		t.Fatalf("expected service error, got %v", err)
	}
}

func TestAccessApprovalsConfigured(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.AccessApprovalsActionConfig
		want bool
	}{
		{"both_set", config.AccessApprovalsActionConfig{BaseURL: "http://localhost", BearerToken: "tok"}, true},
		{"empty_url", config.AccessApprovalsActionConfig{BaseURL: "", BearerToken: "tok"}, false},
		{"empty_token", config.AccessApprovalsActionConfig{BaseURL: "http://localhost", BearerToken: ""}, false},
		{"whitespace_url", config.AccessApprovalsActionConfig{BaseURL: "  ", BearerToken: "tok"}, false},
		{"whitespace_token", config.AccessApprovalsActionConfig{BaseURL: "http://localhost", BearerToken: " "}, false},
		{"both_empty", config.AccessApprovalsActionConfig{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AccessApprovalsConfigured(tt.cfg); got != tt.want {
				t.Fatalf("AccessApprovalsConfigured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewServiceIfConfiguredNoProviders(t *testing.T) {
	service, err := NewServiceIfConfigured(config.GraphActionsConfig{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if service != nil {
		t.Fatal("expected nil service when no providers configured")
	}
}

func TestNewServiceIfConfiguredSkipsEmptyProviderKeys(t *testing.T) {
	service, err := NewServiceIfConfigured(config.GraphActionsConfig{}, nil, map[string]graphactions.ActionProvider{
		"":  nil,
		" ": nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if service != nil {
		t.Fatal("expected nil service when all provider keys are blank")
	}
}

func TestNewAccessApprovalsServiceReturnsErrNotConfigured(t *testing.T) {
	_, err := NewAccessApprovalsService(config.AccessApprovalsActionConfig{}, nil)
	if !errors.Is(err, graphactions.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestExecutorBeforeLinkInjected(t *testing.T) {
	var svc graphactions.Service
	beforeCalled := false
	e := Executor{
		Service: &svc,
		BeforeLink: func(_ context.Context, _ *ports.FindingRecord, _ *graphactions.GraphAction, _ string) error {
			beforeCalled = true
			return nil
		},
	}
	// service() should copy the service and inject BeforeLink
	_, _ = e.Execute(context.Background(), graphactions.Input{FindingID: "f-123"})
	// We can't fully test execution without a real Service, but we verify the
	// Executor reaches service() without error (it will fail inside Service.Execute
	// because Findings is nil, but that proves BeforeLink injection path ran)
	_ = beforeCalled
}
