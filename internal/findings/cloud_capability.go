package findings

import (
	"sort"
	"strings"
)

type cloudCapability string

const (
	cloudCapabilityEffectivePermission cloudCapability = "effective_permission"
	cloudCapabilityPrivilegePath       cloudCapability = "privilege_path"
	cloudCapabilityResourceExposure    cloudCapability = "resource_exposure"
)

type cloudEventCapability struct {
	SourceID   string
	Kind       string
	Capability cloudCapability
}

type cloudCapabilityRegistry struct {
	events []cloudEventCapability
}

var builtinCloudCapabilities = newCloudCapabilityRegistry()

func newCloudCapabilityRegistry() cloudCapabilityRegistry {
	return cloudCapabilityRegistry{events: []cloudEventCapability{
		{SourceID: "aws", Kind: "aws.effective_permission", Capability: cloudCapabilityEffectivePermission},
		{SourceID: "aws", Kind: "aws.iam_role_trust", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "aws", Kind: "aws.resource_exposure", Capability: cloudCapabilityResourceExposure},
		{SourceID: "azure", Kind: "azure.app_role_assignment", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "azure", Kind: "azure.effective_permission", Capability: cloudCapabilityEffectivePermission},
		{SourceID: "azure", Kind: "azure.resource_exposure", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.effective_permission", Capability: cloudCapabilityEffectivePermission},
		{SourceID: "gcp", Kind: "gcp.resource_exposure", Capability: cloudCapabilityResourceExposure},
		{SourceID: "gcp", Kind: "gcp.service_account_impersonation", Capability: cloudCapabilityPrivilegePath},
		{SourceID: "kubernetes", Kind: "kubernetes.workload_identity_binding", Capability: cloudCapabilityPrivilegePath},
	}}
}

func (r cloudCapabilityRegistry) SourceIDs() []string {
	values := map[string]struct{}{}
	for _, event := range r.events {
		if sourceID := strings.TrimSpace(event.SourceID); sourceID != "" {
			values[sourceID] = struct{}{}
		}
	}
	return sortedCloudKeys(values)
}

func (r cloudCapabilityRegistry) EventKinds(capabilities ...cloudCapability) []string {
	allowed := map[cloudCapability]struct{}{}
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
	return sortedCloudKeys(values)
}

func sortedCloudKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}
