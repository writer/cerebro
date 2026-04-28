package findings

import (
	"sort"
	"strings"
)

type identityCapability string

const (
	identityCapabilityAdminRole       identityCapability = "admin_role"
	identityCapabilityAppAssignment   identityCapability = "app_assignment"
	identityCapabilityAudit           identityCapability = "audit"
	identityCapabilityCredential      identityCapability = "credential"
	identityCapabilityGroupMembership identityCapability = "group_membership"
	identityCapabilityRoleAssignment  identityCapability = "role_assignment"
	identityCapabilityUser            identityCapability = "user"
)

type identityEventCapability struct {
	SourceID   string
	Kind       string
	Capability identityCapability
}

type identityCapabilityRegistry struct {
	events []identityEventCapability
}

var builtinIdentityCapabilities = newIdentityCapabilityRegistry()

func newIdentityCapabilityRegistry() identityCapabilityRegistry {
	return identityCapabilityRegistry{events: []identityEventCapability{
		{SourceID: "aws", Kind: "aws.cloudtrail", Capability: identityCapabilityAudit},
		{SourceID: "aws", Kind: "aws.access_key", Capability: identityCapabilityCredential},
		{SourceID: "aws", Kind: "aws.iam_group_membership", Capability: identityCapabilityGroupMembership},
		{SourceID: "aws", Kind: "aws.iam_role", Capability: identityCapabilityUser},
		{SourceID: "aws", Kind: "aws.iam_role_assignment", Capability: identityCapabilityRoleAssignment},
		{SourceID: "aws", Kind: "aws.iam_user", Capability: identityCapabilityUser},
		{SourceID: "azure", Kind: "azure.activity_log", Capability: identityCapabilityAudit},
		{SourceID: "azure", Kind: "azure.app_role_assignment", Capability: identityCapabilityAppAssignment},
		{SourceID: "azure", Kind: "azure.credential", Capability: identityCapabilityCredential},
		{SourceID: "azure", Kind: "azure.directory_audit", Capability: identityCapabilityAudit},
		{SourceID: "azure", Kind: "azure.directory_role_assignment", Capability: identityCapabilityRoleAssignment},
		{SourceID: "azure", Kind: "azure.group_membership", Capability: identityCapabilityGroupMembership},
		{SourceID: "azure", Kind: "azure.iam_role_assignment", Capability: identityCapabilityRoleAssignment},
		{SourceID: "azure", Kind: "azure.service_principal", Capability: identityCapabilityUser},
		{SourceID: "azure", Kind: "azure.user", Capability: identityCapabilityUser},
		{SourceID: "gcp", Kind: "gcp.audit", Capability: identityCapabilityAudit},
		{SourceID: "gcp", Kind: "gcp.group_membership", Capability: identityCapabilityGroupMembership},
		{SourceID: "gcp", Kind: "gcp.iam_role_assignment", Capability: identityCapabilityRoleAssignment},
		{SourceID: "gcp", Kind: "gcp.service_account", Capability: identityCapabilityUser},
		{SourceID: "gcp", Kind: "gcp.service_account_key", Capability: identityCapabilityCredential},
		{SourceID: "okta", Kind: "okta.admin_role", Capability: identityCapabilityAdminRole},
		{SourceID: "okta", Kind: "okta.app_assignment", Capability: identityCapabilityAppAssignment},
		{SourceID: "okta", Kind: "okta.audit", Capability: identityCapabilityAudit},
		{SourceID: "okta", Kind: "okta.group_membership", Capability: identityCapabilityGroupMembership},
		{SourceID: "okta", Kind: "okta.user", Capability: identityCapabilityUser},
		{SourceID: "google_workspace", Kind: "google_workspace.audit", Capability: identityCapabilityAudit},
		{SourceID: "google_workspace", Kind: "google_workspace.group_member", Capability: identityCapabilityGroupMembership},
		{SourceID: "google_workspace", Kind: "google_workspace.role_assignment", Capability: identityCapabilityRoleAssignment},
		{SourceID: "google_workspace", Kind: "google_workspace.user", Capability: identityCapabilityUser},
	}}
}

func (r identityCapabilityRegistry) SourceIDs() []string {
	values := map[string]struct{}{}
	for _, event := range r.events {
		if sourceID := strings.TrimSpace(event.SourceID); sourceID != "" {
			values[sourceID] = struct{}{}
		}
	}
	return sortedKeys(values)
}

func (r identityCapabilityRegistry) EventKinds(capabilities ...identityCapability) []string {
	allowed := map[identityCapability]struct{}{}
	for _, capability := range capabilities {
		allowed[capability] = struct{}{}
	}
	values := map[string]struct{}{}
	for _, event := range r.events {
		if _, ok := allowed[event.Capability]; !ok {
			continue
		}
		if kind := strings.TrimSpace(event.Kind); kind != "" {
			values[kind] = struct{}{}
		}
	}
	return sortedKeys(values)
}

func (r identityCapabilityRegistry) KindHasCapability(kind string, capabilities ...identityCapability) bool {
	trimmed := strings.TrimSpace(kind)
	for _, event := range r.events {
		if !strings.EqualFold(trimmed, event.Kind) {
			continue
		}
		for _, capability := range capabilities {
			if event.Capability == capability {
				return true
			}
		}
	}
	return false
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
