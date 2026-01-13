package auth

import (
	"context"
	"testing"
)

func TestRBAC_DefaultRoles(t *testing.T) {
	rbac := NewRBAC()
	roles := rbac.ListRoles()

	if len(roles) == 0 {
		t.Error("expected default roles to be loaded")
	}

	// Check for expected roles
	roleIDs := make(map[string]bool)
	for _, r := range roles {
		roleIDs[r.ID] = true
	}

	expectedRoles := []string{"admin", "analyst", "viewer"}
	for _, id := range expectedRoles {
		if !roleIDs[id] {
			t.Errorf("expected role %s to be loaded", id)
		}
	}
}

func TestRBAC_CreateUser(t *testing.T) {
	rbac := NewRBAC()

	user := &User{
		Email:    "test@example.com",
		Name:     "Test User",
		TenantID: "tenant-1",
	}

	err := rbac.CreateUser(user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if user.ID == "" {
		t.Error("expected user ID to be generated")
	}

	// Retrieve user
	found, ok := rbac.GetUser(user.ID)
	if !ok {
		t.Error("expected to find created user")
	}

	if found.Email != user.Email {
		t.Errorf("got email %s, want %s", found.Email, user.Email)
	}
}

func TestRBAC_AssignRole(t *testing.T) {
	rbac := NewRBAC()

	// Create user
	user := &User{
		Email: "test@example.com",
		Name:  "Test User",
	}
	rbac.CreateUser(user)

	// Assign role
	err := rbac.AssignRole(user.ID, "analyst")
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// Verify role assigned
	found, _ := rbac.GetUser(user.ID)
	if len(found.RoleIDs) != 1 || found.RoleIDs[0] != "analyst" {
		t.Error("expected analyst role to be assigned")
	}
}

func TestRBAC_AssignRole_InvalidUser(t *testing.T) {
	rbac := NewRBAC()

	err := rbac.AssignRole("non-existent", "analyst")
	if err == nil {
		t.Error("expected error for non-existent user")
	}
}

func TestRBAC_HasPermission(t *testing.T) {
	rbac := NewRBAC()

	// Create user with analyst role
	user := &User{
		Email:   "test@example.com",
		Name:    "Test User",
		RoleIDs: []string{"analyst"},
	}
	rbac.CreateUser(user)

	tests := []struct {
		permission string
		want       bool
	}{
		{"findings:read", true},
		{"findings:write", true},
		{"policies:read", true},
		{"admin:users", false},    // analyst doesn't have admin permissions
		{"admin:roles", false},
	}

	for _, tt := range tests {
		t.Run(tt.permission, func(t *testing.T) {
			got := rbac.HasPermission(context.Background(), user.ID, tt.permission)
			if got != tt.want {
				t.Errorf("HasPermission(%s) = %v, want %v", tt.permission, got, tt.want)
			}
		})
	}
}

func TestRBAC_CreateTenant(t *testing.T) {
	rbac := NewRBAC()

	tenant := &Tenant{
		Name:        "Test Organization",
		Domain:      "test.example.com",
		MFARequired: true,
	}

	err := rbac.CreateTenant(tenant)
	if err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	if tenant.ID == "" {
		t.Error("expected tenant ID to be generated")
	}

	// Retrieve tenant
	found, ok := rbac.GetTenant(tenant.ID)
	if !ok {
		t.Error("expected to find created tenant")
	}

	if found.Name != tenant.Name {
		t.Errorf("got name %s, want %s", found.Name, tenant.Name)
	}

	if !found.MFARequired {
		t.Error("expected MFARequired to be true")
	}
}

func TestRBAC_ListTenants(t *testing.T) {
	rbac := NewRBAC()

	// Create tenants
	rbac.CreateTenant(&Tenant{Name: "Org 1"})
	rbac.CreateTenant(&Tenant{Name: "Org 2"})

	tenants := rbac.ListTenants()
	if len(tenants) != 2 {
		t.Errorf("expected 2 tenants, got %d", len(tenants))
	}
}
