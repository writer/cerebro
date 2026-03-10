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
	"sort"
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
	perms := defaultPermissions()
	for i := range perms {
		r.permissions[perms[i].ID] = &perms[i]
	}

	r.roles["admin"] = &Role{
		ID:          "admin",
		Name:        "Administrator",
		Permissions: defaultAdminRolePermissions(),
		IsSystem:    true,
	}
	r.roles["analyst"] = &Role{
		ID:          "analyst",
		Name:        "Security Analyst",
		Permissions: defaultAnalystRolePermissions(),
		IsSystem:    true,
	}
	r.roles["viewer"] = &Role{
		ID:          "viewer",
		Name:        "Viewer",
		Permissions: defaultViewerRolePermissions(),
		IsSystem:    true,
	}
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
			if permissionImplies(p, permID) {
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

func (r *RBAC) ListPermissionIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.permissions))
	for id := range r.permissions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func defaultPermissions() []Permission {
	return []Permission{
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

		{ID: "platform.graph.read", Resource: "platform.graph", Action: "read"},
		{ID: "platform.graph.write", Resource: "platform.graph", Action: "write"},
		{ID: "platform.intelligence.read", Resource: "platform.intelligence", Action: "read"},
		{ID: "platform.intelligence.run", Resource: "platform.intelligence", Action: "run"},
		{ID: "platform.jobs.read", Resource: "platform.jobs", Action: "read"},
		{ID: "platform.knowledge.write", Resource: "platform.knowledge", Action: "write"},
		{ID: "platform.workflow.write", Resource: "platform.workflow", Action: "write"},
		{ID: "platform.schema.read", Resource: "platform.schema", Action: "read"},
		{ID: "platform.schema.manage", Resource: "platform.schema", Action: "manage"},
		{ID: "platform.identity.review", Resource: "platform.identity", Action: "review"},
		{ID: "platform.simulation.run", Resource: "platform.simulation", Action: "run"},

		{ID: "security.assets.read", Resource: "security.assets", Action: "read"},
		{ID: "security.findings.read", Resource: "security.findings", Action: "read"},
		{ID: "security.findings.manage", Resource: "security.findings", Action: "manage"},
		{ID: "security.policies.read", Resource: "security.policies", Action: "read"},
		{ID: "security.policies.manage", Resource: "security.policies", Action: "manage"},
		{ID: "security.compliance.read", Resource: "security.compliance", Action: "read"},
		{ID: "security.compliance.export", Resource: "security.compliance", Action: "export"},
		{ID: "security.runtime.read", Resource: "security.runtime", Action: "read"},
		{ID: "security.runtime.write", Resource: "security.runtime", Action: "write"},
		{ID: "security.tickets.read", Resource: "security.tickets", Action: "read"},
		{ID: "security.tickets.manage", Resource: "security.tickets", Action: "manage"},
		{ID: "security.analyses.read", Resource: "security.analyses", Action: "read"},
		{ID: "security.analyses.run", Resource: "security.analyses", Action: "run"},
		{ID: "security.incidents.read", Resource: "security.incidents", Action: "read"},
		{ID: "security.incidents.manage", Resource: "security.incidents", Action: "manage"},
		{ID: "security.identity.read", Resource: "security.identity", Action: "read"},
		{ID: "security.identity.manage", Resource: "security.identity", Action: "manage"},
		{ID: "security.threat.read", Resource: "security.threat", Action: "read"},
		{ID: "security.threat.manage", Resource: "security.threat", Action: "manage"},

		{ID: "org.expertise.read", Resource: "org.expertise", Action: "read"},
		{ID: "org.intelligence.read", Resource: "org.intelligence", Action: "read"},
		{ID: "org.team.recommend", Resource: "org.team", Action: "recommend"},
		{ID: "org.reorg.simulate", Resource: "org.reorg", Action: "simulate"},

		{ID: "admin.audit.read", Resource: "admin.audit", Action: "read"},
		{ID: "admin.operations.read", Resource: "admin.operations", Action: "read"},
		{ID: "admin.operations.manage", Resource: "admin.operations", Action: "manage"},
		{ID: "admin.providers.manage", Resource: "admin.providers", Action: "manage"},
		{ID: "admin.webhooks.manage", Resource: "admin.webhooks", Action: "manage"},
		{ID: "admin.scheduler.manage", Resource: "admin.scheduler", Action: "manage"},
		{ID: "admin.notifications.manage", Resource: "admin.notifications", Action: "manage"},
		{ID: "admin.rbac.users.manage", Resource: "admin.rbac.users", Action: "manage"},
		{ID: "admin.rbac.roles.manage", Resource: "admin.rbac.roles", Action: "manage"},
	}
}

func defaultAdminRolePermissions() []string {
	return []string{
		"findings:read", "findings:write",
		"policies:read", "policies:write",
		"agents:read", "agents:write",
		"tickets:read", "tickets:write",
		"runtime:read", "runtime:write",
		"graph:read", "graph:write",
		"assets:read", "compliance:read", "compliance:export",
		"admin:users", "admin:roles",

		"platform.graph.read", "platform.graph.write", "platform.intelligence.read",
		"platform.intelligence.run",
		"platform.jobs.read", "platform.knowledge.write", "platform.workflow.write",
		"platform.schema.read", "platform.schema.manage", "platform.identity.review",
		"platform.simulation.run",

		"security.assets.read", "security.findings.read", "security.findings.manage",
		"security.policies.read", "security.policies.manage",
		"security.compliance.read", "security.compliance.export",
		"security.runtime.read", "security.runtime.write",
		"security.tickets.read", "security.tickets.manage",
		"security.analyses.read", "security.analyses.run",
		"security.incidents.read", "security.incidents.manage",
		"security.identity.read", "security.identity.manage",
		"security.threat.read", "security.threat.manage",

		"org.expertise.read", "org.intelligence.read", "org.team.recommend", "org.reorg.simulate",

		"admin.audit.read", "admin.operations.read", "admin.operations.manage",
		"admin.providers.manage", "admin.webhooks.manage",
		"admin.scheduler.manage", "admin.notifications.manage",
		"admin.rbac.users.manage", "admin.rbac.roles.manage",
	}
}

func defaultAnalystRolePermissions() []string {
	return []string{
		"findings:read", "findings:write",
		"policies:read",
		"agents:read", "agents:write",
		"tickets:read", "tickets:write",
		"runtime:read", "runtime:write",
		"graph:read", "graph:write",
		"assets:read", "compliance:read",

		"platform.graph.read", "platform.graph.write", "platform.intelligence.read",
		"platform.intelligence.run",
		"platform.jobs.read", "platform.knowledge.write", "platform.workflow.write",
		"platform.schema.read", "platform.identity.review", "platform.simulation.run",

		"security.assets.read", "security.findings.read", "security.findings.manage",
		"security.policies.read", "security.compliance.read",
		"security.runtime.read", "security.runtime.write",
		"security.tickets.read", "security.tickets.manage",
		"security.analyses.read", "security.analyses.run",
		"security.incidents.read", "security.incidents.manage",
		"security.identity.read", "security.identity.manage",
		"security.threat.read", "security.threat.manage",

		"org.expertise.read", "org.intelligence.read", "org.team.recommend", "org.reorg.simulate",
	}
}

func defaultViewerRolePermissions() []string {
	return []string{
		"findings:read", "policies:read", "agents:read", "tickets:read",
		"runtime:read", "graph:read", "assets:read", "compliance:read",

		"platform.graph.read", "platform.intelligence.read", "platform.jobs.read", "platform.schema.read",

		"security.assets.read", "security.findings.read", "security.policies.read",
		"security.compliance.read", "security.runtime.read", "security.tickets.read",
		"security.analyses.read", "security.incidents.read", "security.identity.read", "security.threat.read",

		"org.expertise.read", "org.intelligence.read",
	}
}

func permissionImplies(granted, requested string) bool {
	granted = strings.TrimSpace(granted)
	requested = strings.TrimSpace(requested)
	if granted == "" || requested == "" {
		return false
	}
	if granted == requested {
		return true
	}

	implied := permissionImplications()[granted]
	for _, candidate := range implied {
		if candidate == requested {
			return true
		}
	}
	return false
}

func permissionImplications() map[string][]string {
	return map[string][]string{
		"findings:read":             {"security.findings.read", "security.incidents.read", "security.identity.read", "security.threat.read"},
		"findings:write":            {"security.findings.manage", "security.incidents.manage", "security.identity.manage", "security.threat.manage"},
		"policies:read":             {"security.policies.read"},
		"policies:write":            {"security.policies.manage"},
		"tickets:read":              {"security.tickets.read"},
		"tickets:write":             {"security.tickets.manage"},
		"runtime:read":              {"security.runtime.read"},
		"runtime:write":             {"security.runtime.write"},
		"graph:read":                {"platform.graph.read", "platform.intelligence.read", "platform.jobs.read", "platform.schema.read", "security.analyses.read", "org.expertise.read", "org.intelligence.read"},
		"graph:write":               {"platform.graph.write", "platform.intelligence.run", "platform.knowledge.write", "platform.workflow.write", "platform.schema.manage", "platform.identity.review", "platform.simulation.run", "security.analyses.run", "org.team.recommend", "org.reorg.simulate"},
		"assets:read":               {"security.assets.read"},
		"compliance:read":           {"security.compliance.read"},
		"compliance:export":         {"security.compliance.export"},
		"admin:users":               {"admin.audit.read", "admin.operations.read", "admin.operations.manage", "admin.providers.manage", "admin.webhooks.manage", "admin.scheduler.manage", "admin.notifications.manage", "admin.rbac.users.manage"},
		"admin:roles":               {"admin.rbac.roles.manage"},
		"platform.graph.write":      {"platform.intelligence.run", "platform.simulation.run"},
		"platform.intelligence.run": {"platform.jobs.read"},
	}
}
