package sourceprojection

import (
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func oneloginUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityUserProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginGroupsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginAppsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityApplicationProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginAuditEventsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAuditProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginPrivilegesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginMappingsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityPolicyRuleProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginUserAppsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAppAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginUserPrivilegesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginDelegatedPrivilegesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginMFADevicesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityCredentialProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginRoleUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityGroupMembershipProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginRoleAdminsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginRoleAppsProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAppAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginAppUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityAppAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginAppRulesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityPolicyRuleProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginPrivilegeUsersProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}

func oneloginPrivilegeRolesProjections(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return identityRoleAssignmentProjections(event, identityProjectionProfile{Provider: "onelogin"})
}
