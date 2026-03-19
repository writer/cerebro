package api

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/evalops/cerebro/internal/app"
	"github.com/evalops/cerebro/internal/auth"
)

type stubRBACAdminService struct {
	listRolesFunc    func(context.Context) ([]*auth.Role, error)
	listPermsFunc    func(context.Context) ([]string, error)
	createUserFunc   func(context.Context, string, auth.User) (auth.User, error)
	getUserFunc      func(context.Context, string) (*auth.User, bool, error)
	assignRoleFunc   func(context.Context, string, string, string) error
	listTenantsFunc  func(context.Context) ([]*auth.Tenant, error)
	createTenantFunc func(context.Context, string, auth.Tenant) (auth.Tenant, error)
}

func (s stubRBACAdminService) ListRoles(ctx context.Context) ([]*auth.Role, error) {
	if s.listRolesFunc != nil {
		return s.listRolesFunc(ctx)
	}
	return nil, nil
}

func (s stubRBACAdminService) ListPermissions(ctx context.Context) ([]string, error) {
	if s.listPermsFunc != nil {
		return s.listPermsFunc(ctx)
	}
	return nil, nil
}

func (s stubRBACAdminService) CreateUser(ctx context.Context, actorID string, user auth.User) (auth.User, error) {
	if s.createUserFunc != nil {
		return s.createUserFunc(ctx, actorID, user)
	}
	return auth.User{}, nil
}

func (s stubRBACAdminService) GetUser(ctx context.Context, id string) (*auth.User, bool, error) {
	if s.getUserFunc != nil {
		return s.getUserFunc(ctx, id)
	}
	return nil, false, nil
}

func (s stubRBACAdminService) AssignRole(ctx context.Context, actorID, targetUserID, roleID string) error {
	if s.assignRoleFunc != nil {
		return s.assignRoleFunc(ctx, actorID, targetUserID, roleID)
	}
	return nil
}

func (s stubRBACAdminService) ListTenants(ctx context.Context) ([]*auth.Tenant, error) {
	if s.listTenantsFunc != nil {
		return s.listTenantsFunc(ctx)
	}
	return nil, nil
}

func (s stubRBACAdminService) CreateTenant(ctx context.Context, actorID string, tenant auth.Tenant) (auth.Tenant, error) {
	if s.createTenantFunc != nil {
		return s.createTenantFunc(ctx, actorID, tenant)
	}
	return auth.Tenant{}, nil
}

func TestRBACAdminReadHandlersUseServiceInterface(t *testing.T) {
	var (
		rolesCalled   bool
		permsCalled   bool
		getUserCalled bool
		tenantsCalled bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		rbacAdmin: stubRBACAdminService{
			listRolesFunc: func(_ context.Context) ([]*auth.Role, error) {
				rolesCalled = true
				return []*auth.Role{{ID: "analyst", Name: "Analyst"}}, nil
			},
			listPermsFunc: func(_ context.Context) ([]string, error) {
				permsCalled = true
				return []string{"admin.rbac.users.manage"}, nil
			},
			getUserFunc: func(_ context.Context, id string) (*auth.User, bool, error) {
				getUserCalled = true
				if id != "user-1" {
					t.Fatalf("expected user-1, got %q", id)
				}
				return &auth.User{ID: id, Email: "user@example.com"}, true, nil
			},
			listTenantsFunc: func(_ context.Context) ([]*auth.Tenant, error) {
				tenantsCalled = true
				return []*auth.Tenant{{ID: "tenant-1", Name: "Acme"}}, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	if w := do(t, s, http.MethodGet, "/api/v1/rbac/roles", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed role list, got %d: %s", w.Code, w.Body.String())
	}
	if !rolesCalled {
		t.Fatal("expected role list handler to use rbac admin service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/rbac/permissions", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed permission list, got %d: %s", w.Code, w.Body.String())
	}
	if !permsCalled {
		t.Fatal("expected permission list handler to use rbac admin service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/rbac/users/user-1", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed get user, got %d: %s", w.Code, w.Body.String())
	}
	if !getUserCalled {
		t.Fatal("expected get-user handler to use rbac admin service")
	}

	if w := do(t, s, http.MethodGet, "/api/v1/rbac/tenants", nil); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed tenant list, got %d: %s", w.Code, w.Body.String())
	}
	if !tenantsCalled {
		t.Fatal("expected tenant list handler to use rbac admin service")
	}
}

func TestRBACAdminMutationHandlersUseServiceInterface(t *testing.T) {
	var (
		createUserCalled   bool
		assignRoleCalled   bool
		createTenantCalled bool
	)

	s := NewServerWithDependencies(serverDependencies{
		Config: &app.Config{},
		Logger: slog.Default(),
		rbacAdmin: stubRBACAdminService{
			createUserFunc: func(_ context.Context, actorID string, user auth.User) (auth.User, error) {
				createUserCalled = true
				if actorID != "admin-1" {
					t.Fatalf("expected actor admin-1, got %q", actorID)
				}
				if user.Email != "user@example.com" {
					t.Fatalf("expected email to reach service, got %#v", user)
				}
				user.ID = "user-1"
				return user, nil
			},
			assignRoleFunc: func(_ context.Context, actorID, targetUserID, roleID string) error {
				assignRoleCalled = true
				if actorID != "admin-1" || targetUserID != "user-1" || roleID != "analyst" {
					t.Fatalf("unexpected assign payload: actor=%q target=%q role=%q", actorID, targetUserID, roleID)
				}
				return nil
			},
			createTenantFunc: func(_ context.Context, actorID string, tenant auth.Tenant) (auth.Tenant, error) {
				createTenantCalled = true
				if actorID != "admin-1" {
					t.Fatalf("expected actor admin-1, got %q", actorID)
				}
				if tenant.Name != "Acme" {
					t.Fatalf("expected tenant name Acme, got %#v", tenant)
				}
				tenant.ID = "tenant-1"
				return tenant, nil
			},
		},
	})
	t.Cleanup(func() { s.Close() })

	if w := doAsUser(t, s, "admin-1", http.MethodPost, "/api/v1/rbac/users", map[string]any{"email": "user@example.com"}); w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for service-backed create user, got %d: %s", w.Code, w.Body.String())
	}
	if !createUserCalled {
		t.Fatal("expected create-user handler to use rbac admin service")
	}

	if w := doAsUser(t, s, "admin-1", http.MethodPost, "/api/v1/rbac/users/user-1/roles", map[string]any{"role_id": "analyst"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for service-backed assign role, got %d: %s", w.Code, w.Body.String())
	}
	if !assignRoleCalled {
		t.Fatal("expected assign-role handler to use rbac admin service")
	}

	if w := doAsUser(t, s, "admin-1", http.MethodPost, "/api/v1/rbac/tenants", map[string]any{"name": "Acme"}); w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for service-backed create tenant, got %d: %s", w.Code, w.Body.String())
	}
	if !createTenantCalled {
		t.Fatal("expected create-tenant handler to use rbac admin service")
	}
}
