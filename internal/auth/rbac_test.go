package auth

import (
	"context"
	"os"
	"path/filepath"
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
	if err := rbac.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

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
	if err := rbac.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	tests := []struct {
		permission string
		want       bool
	}{
		{"findings:read", true},
		{"findings:write", true},
		{"policies:read", true},
		{"agents:read", true},
		{"agents:write", true},
		{"tickets:read", true},
		{"tickets:write", true},
		{"runtime:read", true},
		{"runtime:write", true},
		{"graph:read", true},
		{"graph:write", true},
		{"admin:users", false}, // analyst doesn't have admin permissions
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

func TestRBAC_HasPermission_ScopedNamespaces(t *testing.T) {
	rbac := NewRBAC()

	user := &User{
		Email:   "platform@example.com",
		Name:    "Platform Analyst",
		RoleIDs: []string{"analyst"},
	}
	if err := rbac.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	tests := []struct {
		permission string
		want       bool
	}{
		{"platform.graph.read", true},
		{"platform.intelligence.read", true},
		{"platform.intelligence.run", true},
		{"platform.knowledge.read", true},
		{"platform.knowledge.write", true},
		{"security.findings.manage", true},
		{"security.analyses.run", true},
		{"org.expertise.read", true},
		{"org.reorg.simulate", true},
		{"admin.operations.manage", false},
		{"admin.rbac.roles.manage", false},
	}

	for _, tt := range tests {
		t.Run(tt.permission, func(t *testing.T) {
			if got := rbac.HasPermission(context.Background(), user.ID, tt.permission); got != tt.want {
				t.Fatalf("HasPermission(%s) = %v, want %v", tt.permission, got, tt.want)
			}
		})
	}
}

func TestRBAC_ListPermissionIDsIncludesScopedNamespaces(t *testing.T) {
	rbac := NewRBAC()
	ids := rbac.ListPermissionIDs()
	expected := []string{
		"platform.graph.read",
		"platform.intelligence.read",
		"platform.intelligence.run",
		"platform.knowledge.read",
		"security.findings.read",
		"org.intelligence.read",
		"admin.providers.manage",
	}
	for _, want := range expected {
		found := false
		for _, id := range ids {
			if id == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected permission id %q in list", want)
		}
	}
}

func TestRBAC_HasPermission_EmptyUserIDDenied(t *testing.T) {
	rbac := NewRBAC()
	if got := rbac.HasPermission(context.Background(), "", "findings:read"); got {
		t.Fatal("expected empty user ID to be denied")
	}
}

func TestRBAC_HasPermission_DeniesCrossTenantRole(t *testing.T) {
	rbac := NewRBAC()
	rbac.roles["tenant-a-role"] = &Role{
		ID:          "tenant-a-role",
		Name:        "Tenant A Analyst",
		Permissions: []string{"findings:read"},
		TenantID:    "tenant-a",
	}

	user := &User{
		Email:    "tenant-b@example.com",
		Name:     "Tenant B User",
		TenantID: "tenant-b",
		RoleIDs:  []string{"tenant-a-role"},
	}
	if err := rbac.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if got := rbac.HasPermission(context.Background(), user.ID, "findings:read"); got {
		t.Fatal("expected permission denial for cross-tenant role")
	}
}

func TestRBAC_AssignRole_DeniesCrossTenantRole(t *testing.T) {
	rbac := NewRBAC()
	rbac.roles["tenant-a-role"] = &Role{
		ID:          "tenant-a-role",
		Name:        "Tenant A Analyst",
		Permissions: []string{"findings:read"},
		TenantID:    "tenant-a",
	}

	user := &User{
		Email:    "tenant-b@example.com",
		Name:     "Tenant B User",
		TenantID: "tenant-b",
	}
	if err := rbac.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if err := rbac.AssignRole(user.ID, "tenant-a-role"); err == nil {
		t.Fatal("expected role tenant mismatch error")
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
	if err := rbac.CreateTenant(&Tenant{Name: "Org 1"}); err != nil {
		t.Fatalf("CreateTenant Org 1 failed: %v", err)
	}
	if err := rbac.CreateTenant(&Tenant{Name: "Org 2"}); err != nil {
		t.Fatalf("CreateTenant Org 2 failed: %v", err)
	}

	tenants := rbac.ListTenants()
	if len(tenants) != 2 {
		t.Errorf("expected 2 tenants, got %d", len(tenants))
	}
}

func TestRBAC_PersistenceRoundTrip(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "rbac-state.json")

	rbac, err := NewRBACWithStateFile(stateFile)
	if err != nil {
		t.Fatalf("NewRBACWithStateFile failed: %v", err)
	}

	user := &User{Email: "persist@example.com", Name: "Persist User"}
	if err := rbac.CreateUser(user); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if err := rbac.AssignRole(user.ID, "analyst"); err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}
	if err := rbac.CreateTenant(&Tenant{Name: "Persist Tenant"}); err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	reloaded, err := NewRBACWithStateFile(stateFile)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	loadedUser, ok := reloaded.GetUser(user.ID)
	if !ok {
		t.Fatal("expected persisted user to be loaded")
	}
	if len(loadedUser.RoleIDs) != 1 || loadedUser.RoleIDs[0] != "analyst" {
		t.Fatalf("expected persisted role assignment, got %+v", loadedUser.RoleIDs)
	}
	if len(reloaded.ListTenants()) != 1 {
		t.Fatalf("expected 1 tenant after reload, got %d", len(reloaded.ListTenants()))
	}
}

func TestRBAC_NewWithStateFileInvalidJSON(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "rbac-state.json")
	if err := os.WriteFile(stateFile, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write invalid state file: %v", err)
	}

	if _, err := NewRBACWithStateFile(stateFile); err == nil {
		t.Fatal("expected error for invalid persisted RBAC state")
	}
}
