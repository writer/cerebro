// Package auth provides role-based access control (RBAC) and multi-tenant
// authentication capabilities for the Cerebro platform.
//
// The package implements:
//   - Role-based access control with fine-grained permissions
//   - Multi-tenant isolation for enterprise deployments
//   - SAML SSO integration for identity providers
//   - MFA enforcement policies per tenant
//
// Default roles include:
//   - admin: Full system access including user/role management
//   - analyst: Read/write findings and policies, read assets
//   - viewer: Read-only access to all security data
//
// Permissions follow a resource:action format (e.g., "findings:read",
// "policies:write", "admin:users") and can be combined into custom roles.
//
// Example usage:
//
//	rbac := auth.NewRBAC()
//	rbac.CreateUser(&User{Email: "analyst@company.com", RoleIDs: []string{"analyst"}})
//	if rbac.HasPermission(ctx, userID, "findings:write") {
//	    // User can modify findings
//	}
package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// RBAC is the role-based access control service. It manages users, roles,
// permissions, and tenants for multi-tenant enterprise deployments.
//
// The service is thread-safe and supports concurrent access checks.
type RBAC struct {
	roles       map[string]*Role       // Roles indexed by ID
	permissions map[string]*Permission // Permissions indexed by ID
	users       map[string]*User       // Users indexed by ID
	tenants     map[string]*Tenant     // Tenants indexed by ID
	stateFile   string                 // Optional persisted state file
	mu          sync.RWMutex           // Protects all maps
}

type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	TenantID    string    `json:"tenant_id,omitempty"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

type Permission struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

type User struct {
	ID         string     `json:"id"`
	Email      string     `json:"email"`
	Name       string     `json:"name"`
	TenantID   string     `json:"tenant_id"`
	RoleIDs    []string   `json:"role_ids"`
	MFAEnabled bool       `json:"mfa_enabled"`
	LastLogin  *time.Time `json:"last_login,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type Tenant struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Domain      string            `json:"domain,omitempty"`
	SAMLConfig  *SAMLConfig       `json:"saml_config,omitempty"`
	MFARequired bool              `json:"mfa_required"`
	Settings    map[string]string `json:"settings,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
}

type SAMLConfig struct {
	Enabled     bool              `json:"enabled"`
	EntityID    string            `json:"entity_id"`
	SSOURL      string            `json:"sso_url"`
	Certificate string            `json:"certificate"`
	AttrMapping map[string]string `json:"attribute_mapping"`
}

func NewRBAC() *RBAC {
	rbac := &RBAC{
		roles:       make(map[string]*Role),
		permissions: make(map[string]*Permission),
		users:       make(map[string]*User),
		tenants:     make(map[string]*Tenant),
	}
	rbac.loadDefaults()
	return rbac
}

func (r *RBAC) loadDefaults() {
	perms := []Permission{
		{ID: "findings:read", Resource: "findings", Action: "read"},
		{ID: "findings:write", Resource: "findings", Action: "write"},
		{ID: "policies:read", Resource: "policies", Action: "read"},
		{ID: "policies:write", Resource: "policies", Action: "write"},
		{ID: "agents:read", Resource: "agents", Action: "read"},
		{ID: "agents:write", Resource: "agents", Action: "write"},
		{ID: "tickets:read", Resource: "tickets", Action: "read"},
		{ID: "tickets:write", Resource: "tickets", Action: "write"},
		{ID: "runtime:read", Resource: "runtime", Action: "read"},
		{ID: "runtime:write", Resource: "runtime", Action: "write"},
		{ID: "graph:read", Resource: "graph", Action: "read"},
		{ID: "graph:write", Resource: "graph", Action: "write"},
		{ID: "assets:read", Resource: "assets", Action: "read"},
		{ID: "compliance:read", Resource: "compliance", Action: "read"},
		{ID: "compliance:export", Resource: "compliance", Action: "export"},
		{ID: "admin:users", Resource: "admin", Action: "users"},
		{ID: "admin:roles", Resource: "admin", Action: "roles"},
	}
	for i := range perms {
		r.permissions[perms[i].ID] = &perms[i]
	}

	r.roles["admin"] = &Role{ID: "admin", Name: "Administrator", Permissions: []string{"findings:read", "findings:write", "policies:read", "policies:write", "agents:read", "agents:write", "tickets:read", "tickets:write", "runtime:read", "runtime:write", "graph:read", "graph:write", "assets:read", "compliance:read", "compliance:export", "admin:users", "admin:roles"}, IsSystem: true}
	r.roles["analyst"] = &Role{ID: "analyst", Name: "Security Analyst", Permissions: []string{"findings:read", "findings:write", "policies:read", "agents:read", "agents:write", "tickets:read", "tickets:write", "runtime:read", "runtime:write", "graph:read", "graph:write", "assets:read", "compliance:read"}, IsSystem: true}
	r.roles["viewer"] = &Role{ID: "viewer", Name: "Viewer", Permissions: []string{"findings:read", "policies:read", "agents:read", "tickets:read", "runtime:read", "graph:read", "assets:read", "compliance:read"}, IsSystem: true}
}

func (r *RBAC) HasPermission(ctx context.Context, userID, permID string) bool {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(permID) == "" {
		return false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.users[userID]
	if !ok {
		return false
	}

	for _, roleID := range user.RoleIDs {
		role, ok := r.roles[roleID]
		if !ok {
			continue
		}
		if role.TenantID != "" && role.TenantID != user.TenantID {
			continue
		}
		for _, p := range role.Permissions {
			if p == permID {
				return true
			}
		}
	}
	return false
}

func (r *RBAC) CreateUser(user *User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	user.CreatedAt = time.Now().UTC()
	r.users[user.ID] = user
	return r.persistLocked()
}

func (r *RBAC) GetUser(id string) (*User, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	return u, ok
}

func (r *RBAC) AssignRole(userID, roleID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user, ok := r.users[userID]
	if !ok {
		return fmt.Errorf("user not found")
	}
	role, ok := r.roles[roleID]
	if !ok {
		return fmt.Errorf("role not found")
	}
	if role.TenantID != "" && role.TenantID != user.TenantID {
		return fmt.Errorf("role tenant mismatch")
	}
	user.RoleIDs = append(user.RoleIDs, roleID)
	return r.persistLocked()
}

func (r *RBAC) ListRoles() []*Role {
	r.mu.RLock()
	defer r.mu.RUnlock()
	roles := make([]*Role, 0, len(r.roles))
	for _, role := range r.roles {
		roles = append(roles, role)
	}
	return roles
}

func (r *RBAC) CreateTenant(t *Tenant) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	t.CreatedAt = time.Now().UTC()
	r.tenants[t.ID] = t
	return r.persistLocked()
}

func (r *RBAC) GetTenant(id string) (*Tenant, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tenants[id]
	return t, ok
}

func (r *RBAC) ListTenants() []*Tenant {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenants := make([]*Tenant, 0, len(r.tenants))
	for _, t := range r.tenants {
		tenants = append(tenants, t)
	}
	return tenants
}
