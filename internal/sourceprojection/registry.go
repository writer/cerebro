package sourceprojection

import (
	"fmt"
	"sort"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

// ProjectFunc converts one source event into graph projection records.
type ProjectFunc func(*cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error)

// EventProjector binds one event kind to one projector.
type EventProjector struct {
	Kind    string
	Project ProjectFunc
}

// Registry indexes projectors by event kind.
type Registry struct {
	projectors map[string]ProjectFunc
}

// NewRegistry constructs an event projection registry.
func NewRegistry(projectors ...EventProjector) (*Registry, error) {
	registry := &Registry{projectors: make(map[string]ProjectFunc, len(projectors))}
	for _, projector := range projectors {
		kind := strings.TrimSpace(projector.Kind)
		if kind == "" {
			return nil, fmt.Errorf("projector kind is required")
		}
		if projector.Project == nil {
			return nil, fmt.Errorf("projector %q function is required", kind)
		}
		if _, ok := registry.projectors[kind]; ok {
			return nil, fmt.Errorf("duplicate projector kind %q", kind)
		}
		registry.projectors[kind] = projector.Project
	}
	return registry, nil
}

var builtinRegistry = &Registry{projectors: map[string]ProjectFunc{
	"github.pull_request":              githubPullRequestProjections,
	"github.audit":                     githubAuditProjections,
	"github.dependabot_alert":          githubDependabotAlertProjections,
	"aws.access_key":                   awsAccessKeyProjections,
	"aws.cloudtrail":                   awsCloudTrailProjections,
	"aws.iam_group":                    awsIAMGroupProjections,
	"aws.iam_group_membership":         awsIAMGroupMembershipProjections,
	"aws.iam_role":                     awsIAMRoleProjections,
	"aws.iam_role_assignment":          awsIAMRoleAssignmentProjections,
	"aws.iam_user":                     awsIAMUserProjections,
	"gcp.audit":                        gcpAuditProjections,
	"gcp.group":                        gcpGroupProjections,
	"gcp.group_membership":             gcpGroupMembershipProjections,
	"gcp.iam_role_assignment":          gcpIAMRoleAssignmentProjections,
	"gcp.service_account":              gcpServiceAccountProjections,
	"gcp.service_account_key":          gcpServiceAccountKeyProjections,
	"okta.user":                        oktaUserProjections,
	"okta.group":                       oktaGroupProjections,
	"okta.group_membership":            oktaGroupMembershipProjections,
	"okta.application":                 oktaApplicationProjections,
	"okta.app_assignment":              oktaAppAssignmentProjections,
	"okta.admin_role":                  oktaAdminRoleProjections,
	"okta.audit":                       oktaAuditProjections,
	"google_workspace.user":            googleWorkspaceUserProjections,
	"google_workspace.group":           googleWorkspaceGroupProjections,
	"google_workspace.group_member":    googleWorkspaceGroupMemberProjections,
	"google_workspace.role_assignment": googleWorkspaceRoleAssignmentProjections,
	"google_workspace.audit":           googleWorkspaceAuditProjections,
}}

// BuiltinRegistry returns the default source event projector registry.
func BuiltinRegistry() *Registry {
	return builtinRegistry
}

// Kinds returns sorted registered event kinds.
func (r *Registry) Kinds() []string {
	if r == nil {
		return nil
	}
	kinds := make([]string, 0, len(r.projectors))
	for kind := range r.projectors {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// Project applies the registered projector for an event.
func (r *Registry) Project(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	if event == nil {
		return nil, nil, fmt.Errorf("event is required")
	}
	if r == nil {
		return nil, nil, nil
	}
	project, ok := r.projectors[strings.TrimSpace(event.GetKind())]
	if !ok {
		return nil, nil, nil
	}
	return project(event)
}

// ProjectEvent projects one event through the built-in registry without stores.
func ProjectEvent(event *cerebrov1.EventEnvelope) ([]*ports.ProjectedEntity, []*ports.ProjectedLink, error) {
	return BuiltinRegistry().Project(event)
}
