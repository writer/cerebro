package graphquery

import "strings"

const (
	InventoryGroupSecrets    = "secrets"
	InventoryGroupDevices    = "devices"
	InventoryGroupIdentities = "identities"
	InventoryGroupCode       = "code"
	InventoryGroupCloud      = "cloud"
	InventoryGroupSaaS       = "saas"
)

type inventoryGroupRule struct {
	id       string
	label    string
	exact    []string
	prefixes []string
	suffixes []string
}

// Most entity types are assembled at projection time from a provider and a
// resource type rather than written as literals, so groups are matched by rule
// instead of enumerated. Grouping never hides a record: every asset is still
// reachable from the ungrouped inventory search.
//
// Order is load-bearing. The first rule that matches wins, so narrow rules are
// declared before the provider-prefix rules that would otherwise absorb them.
func inventoryGroupRules() []inventoryGroupRule {
	return []inventoryGroupRule{
		{
			id:       InventoryGroupSecrets,
			label:    "Secrets",
			exact:    []string{"secret", "certificate"},
			suffixes: []string{".secret", ".credential", ".certificate"},
		},
		{
			id:       InventoryGroupDevices,
			label:    "Devices",
			exact:    []string{"device"},
			prefixes: []string{"trusted_endpoint.", "kandji.", "kolide.", "jamf.", "intune.", "sentinelone."},
			suffixes: []string{".device", ".endpoint"},
		},
		{
			id:       InventoryGroupIdentities,
			label:    "Identities",
			exact:    []string{"user", "person", "group", "identity_application", "cerebro.principal", "privileged.capability"},
			prefixes: []string{"aws.sso.", "kubernetes.rbac_"},
			suffixes: []string{".user", ".person", ".group", ".role", ".service_account", ".service_principal", ".principal"},
		},
		{
			id:       InventoryGroupCode,
			label:    "Code",
			exact:    []string{"repository", "deployment"},
			prefixes: []string{"github.", "gitlab.", "bitbucket.", "container.", "aws.ecr."},
			suffixes: []string{".repository", ".runner", ".pipeline", ".workflow"},
		},
		{
			id:       InventoryGroupCloud,
			label:    "Cloud",
			prefixes: []string{"aws.", "gcp.", "azure.", "kubernetes.", "linode.", "oci.", "cloud."},
			suffixes: []string{".cluster", ".instance", ".bucket", ".volume"},
		},
		{
			id:       InventoryGroupSaaS,
			label:    "SaaS",
			exact:    []string{"vendor", "saas.application", "sdk.integration", "grc.integration"},
			prefixes: []string{"okta.", "google_workspace.", "auth0."},
			suffixes: []string{".application", ".integration", ".tenant", ".workspace"},
		},
	}
}

// Projectors join the parts of an entity type with either a dot or an
// underscore for the same concept, so both sides are compared in one form.
func normalizeInventoryEntityType(entityType string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(entityType)), "_", ".")
}

func (rule inventoryGroupRule) matches(entityType string) bool {
	for _, candidate := range rule.exact {
		if entityType == normalizeInventoryEntityType(candidate) {
			return true
		}
	}
	for _, prefix := range rule.prefixes {
		if strings.HasPrefix(entityType, normalizeInventoryEntityType(prefix)) {
			return true
		}
	}
	for _, suffix := range rule.suffixes {
		if strings.HasSuffix(entityType, normalizeInventoryEntityType(suffix)) {
			return true
		}
	}
	return false
}

// InventoryGroupForEntityType reports the inventory group an entity type belongs
// to. Unmatched types report false and keep their per-class category.
func InventoryGroupForEntityType(entityType string) (string, string, bool) {
	entityType = normalizeInventoryEntityType(entityType)
	if entityType == "" {
		return "", "", false
	}
	for _, rule := range inventoryGroupRules() {
		if rule.matches(entityType) {
			return rule.id, rule.label, true
		}
	}
	return "", "", false
}

// InventoryGroupLabel returns the display label for a group id.
func InventoryGroupLabel(groupID string) (string, bool) {
	groupID = strings.ToLower(strings.TrimSpace(groupID))
	for _, rule := range inventoryGroupRules() {
		if rule.id == groupID {
			return rule.label, true
		}
	}
	return "", false
}

// IsInventoryGroupID reports whether a category id names an inventory group
// rather than a per-class category.
func IsInventoryGroupID(categoryID string) bool {
	_, ok := InventoryGroupLabel(categoryID)
	return ok
}
