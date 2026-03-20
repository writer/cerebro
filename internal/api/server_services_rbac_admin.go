package api

import (
	"context"
	"errors"

	"github.com/writer/cerebro/internal/auth"
	"github.com/writer/cerebro/internal/webhooks"
)

var (
	errRBACUnavailable         = errors.New("rbac not initialized")
	errRBACUsersManageRequired = errors.New("permission denied: admin.rbac.users.manage required")
	errRBACRolesManageRequired = errors.New("permission denied: admin.rbac.roles.manage required")
)

type rbacAdminService interface {
	ListRoles(context.Context) ([]*auth.Role, error)
	ListPermissions(context.Context) ([]string, error)
	CreateUser(context.Context, string, auth.User) (auth.User, error)
	GetUser(context.Context, string) (*auth.User, bool, error)
	AssignRole(context.Context, string, string, string) error
	ListTenants(context.Context) ([]*auth.Tenant, error)
	CreateTenant(context.Context, string, auth.Tenant) (auth.Tenant, error)
}

type serverRBACAdminService struct {
	deps *serverDependencies
}

func newRBACAdminService(deps *serverDependencies) rbacAdminService {
	return serverRBACAdminService{deps: deps}
}

func (s serverRBACAdminService) ListRoles(_ context.Context) ([]*auth.Role, error) {
	if s.deps == nil || s.deps.RBAC == nil {
		return nil, errRBACUnavailable
	}
	return s.deps.RBAC.ListRoles(), nil
}

func (s serverRBACAdminService) ListPermissions(_ context.Context) ([]string, error) {
	if s.deps == nil || s.deps.RBAC == nil {
		return nil, errRBACUnavailable
	}
	return s.deps.RBAC.ListPermissionIDs(), nil
}

func (s serverRBACAdminService) CreateUser(ctx context.Context, createdBy string, user auth.User) (auth.User, error) {
	if s.deps == nil || s.deps.RBAC == nil {
		return auth.User{}, errRBACUnavailable
	}
	if !s.deps.RBAC.HasPermission(ctx, createdBy, "admin.rbac.users.manage") {
		return auth.User{}, errRBACUsersManageRequired
	}
	if err := s.deps.RBAC.CreateUser(&user); err != nil {
		return auth.User{}, err
	}
	if s.deps.Webhooks != nil {
		if err := s.deps.Webhooks.EmitWithErrors(ctx, webhooks.EventRbacUserCreated, map[string]interface{}{
			"user_id":    user.ID,
			"tenant_id":  user.TenantID,
			"created_by": createdBy,
		}); err != nil && s.deps.Logger != nil {
			s.deps.Logger.Warn("failed to emit RBAC user event", "user_id", user.ID, "error", err)
		}
	}
	return user, nil
}

func (s serverRBACAdminService) GetUser(_ context.Context, id string) (*auth.User, bool, error) {
	if s.deps == nil || s.deps.RBAC == nil {
		return nil, false, errRBACUnavailable
	}
	user, found := s.deps.RBAC.GetUser(id)
	return user, found, nil
}

func (s serverRBACAdminService) AssignRole(ctx context.Context, assignedBy, targetUserID, roleID string) error {
	if s.deps == nil || s.deps.RBAC == nil {
		return errRBACUnavailable
	}
	if !s.deps.RBAC.HasPermission(ctx, assignedBy, "admin.rbac.roles.manage") {
		return errRBACRolesManageRequired
	}
	if err := s.deps.RBAC.AssignRole(targetUserID, roleID); err != nil {
		return err
	}
	if s.deps.Webhooks != nil {
		if err := s.deps.Webhooks.EmitWithErrors(ctx, webhooks.EventRbacRoleAssigned, map[string]interface{}{
			"target_user_id": targetUserID,
			"role_id":        roleID,
			"assigned_by":    assignedBy,
		}); err != nil && s.deps.Logger != nil {
			s.deps.Logger.Warn("failed to emit RBAC role assignment event", "target_user_id", targetUserID, "role_id", roleID, "error", err)
		}
	}
	return nil
}

func (s serverRBACAdminService) ListTenants(_ context.Context) ([]*auth.Tenant, error) {
	if s.deps == nil || s.deps.RBAC == nil {
		return nil, errRBACUnavailable
	}
	return s.deps.RBAC.ListTenants(), nil
}

func (s serverRBACAdminService) CreateTenant(ctx context.Context, createdBy string, tenant auth.Tenant) (auth.Tenant, error) {
	if s.deps == nil || s.deps.RBAC == nil {
		return auth.Tenant{}, errRBACUnavailable
	}
	if !s.deps.RBAC.HasPermission(ctx, createdBy, "admin.rbac.users.manage") {
		return auth.Tenant{}, errRBACUsersManageRequired
	}
	if err := s.deps.RBAC.CreateTenant(&tenant); err != nil {
		return auth.Tenant{}, err
	}
	if s.deps.Webhooks != nil {
		if err := s.deps.Webhooks.EmitWithErrors(ctx, webhooks.EventRbacTenantCreated, map[string]interface{}{
			"tenant_id":  tenant.ID,
			"created_by": createdBy,
		}); err != nil && s.deps.Logger != nil {
			s.deps.Logger.Warn("failed to emit RBAC tenant event", "tenant_id", tenant.ID, "error", err)
		}
	}
	return tenant, nil
}

var _ rbacAdminService = serverRBACAdminService{}
