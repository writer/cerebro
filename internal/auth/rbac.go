package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

type RBAC struct {
	roles       map[string]*Role
	permissions map[string]*Permission
	users       map[string]*User
	tenants     map[string]*Tenant
	mu          sync.RWMutex
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
		{ID: "assets:read", Resource: "assets", Action: "read"},
		{ID: "compliance:read", Resource: "compliance", Action: "read"},
		{ID: "compliance:export", Resource: "compliance", Action: "export"},
		{ID: "admin:users", Resource: "admin", Action: "users"},
		{ID: "admin:roles", Resource: "admin", Action: "roles"},
	}
	for i := range perms {
		r.permissions[perms[i].ID] = &perms[i]
	}

	r.roles["admin"] = &Role{ID: "admin", Name: "Administrator", Permissions: []string{"findings:read", "findings:write", "policies:read", "policies:write", "assets:read", "compliance:read", "compliance:export", "admin:users", "admin:roles"}, IsSystem: true}
	r.roles["analyst"] = &Role{ID: "analyst", Name: "Security Analyst", Permissions: []string{"findings:read", "findings:write", "policies:read", "assets:read", "compliance:read"}, IsSystem: true}
	r.roles["viewer"] = &Role{ID: "viewer", Name: "Viewer", Permissions: []string{"findings:read", "policies:read", "assets:read", "compliance:read"}, IsSystem: true}
}

func (r *RBAC) HasPermission(ctx context.Context, userID, permID string) bool {
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
	return nil
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
	user.RoleIDs = append(user.RoleIDs, roleID)
	return nil
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
	return nil
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
