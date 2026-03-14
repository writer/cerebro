package remediation

import "strings"

type BlastRadiusClass string

const (
	BlastRadiusLow    BlastRadiusClass = "low"
	BlastRadiusMedium BlastRadiusClass = "medium"
	BlastRadiusHigh   BlastRadiusClass = "high"
)

type CatalogEntry struct {
	ID                     string            `json:"id"`
	ActionType             ActionType        `json:"action_type"`
	Name                   string            `json:"name"`
	Description            string            `json:"description"`
	Providers              []string          `json:"providers,omitempty"`
	ResourceTypes          []string          `json:"resource_types,omitempty"`
	SafeByDefault          bool              `json:"safe_by_default"`
	SupportsDryRun         bool              `json:"supports_dry_run"`
	SupportsRollback       bool              `json:"supports_rollback"`
	RequiresApproval       bool              `json:"requires_approval"`
	BlastRadius            BlastRadiusClass  `json:"blast_radius"`
	Preconditions          []string          `json:"preconditions,omitempty"`
	RollbackSteps          []string          `json:"rollback_steps,omitempty"`
	EvidenceFields         []string          `json:"evidence_fields,omitempty"`
	DefaultRemoteTools     map[string]string `json:"default_remote_tools,omitempty"`
	SupportedDeliveryModes []DeliveryMode    `json:"supported_delivery_modes,omitempty"`
	DefaultDeliveryMode    DeliveryMode      `json:"default_delivery_mode,omitempty"`
	BlastRadiusRationale   string            `json:"blast_radius_rationale,omitempty"`
}

var remediationCatalog = []CatalogEntry{
	{
		ID:               "restrict_public_storage_access",
		ActionType:       ActionRestrictPublicStorageAccess,
		Name:             "Restrict public storage access",
		Description:      "Remove or block anonymous/public access from cloud object storage resources.",
		Providers:        []string{"aws", "gcp", "azure"},
		ResourceTypes:    []string{"bucket", "storage/bucket", "storage_bucket", "blob_container", "storage/container"},
		SafeByDefault:    true,
		SupportsDryRun:   true,
		SupportsRollback: true,
		RequiresApproval: true,
		BlastRadius:      BlastRadiusLow,
		Preconditions: []string{
			"The resource still appears to allow public access.",
			"The resource identifier and provider are known.",
		},
		RollbackSteps: []string{
			"Restore the prior bucket or container access policy from the captured evidence snapshot.",
			"Re-apply the prior ACL or public-access settings if the change was rolled back intentionally.",
		},
		EvidenceFields: []string{
			"policy_id",
			"resource_id",
			"resource_name",
			"resource_type",
			"provider",
			"public_access",
			"before",
			"after",
		},
		SupportedDeliveryModes: []DeliveryMode{
			DeliveryModeRemoteApply,
			DeliveryModeTerraform,
		},
		DefaultDeliveryMode: DeliveryModeRemoteApply,
		DefaultRemoteTools: map[string]string{
			"aws":   "aws.s3.block_public_access",
			"gcp":   "gcp.storage.remove_public_access",
			"azure": "azure.storage.disable_container_public_access",
		},
		BlastRadiusRationale: "Restricts exposure on a single storage resource without deleting data.",
	},
	{
		ID:               "disable_stale_access_key",
		ActionType:       ActionDisableStaleAccessKey,
		Name:             "Disable stale access key",
		Description:      "Disable a long-lived access key that has been inactive beyond a configured threshold.",
		Providers:        []string{"aws", "gcp"},
		ResourceTypes:    []string{"iam_user", "identity/user", "service_account", "identity/service_account"},
		SafeByDefault:    true,
		SupportsDryRun:   true,
		SupportsRollback: true,
		RequiresApproval: true,
		BlastRadius:      BlastRadiusLow,
		Preconditions: []string{
			"A concrete access key identifier is present.",
			"The key has been inactive at or beyond the configured threshold.",
		},
		RollbackSteps: []string{
			"Re-enable the access key if disablement was incorrect.",
			"Rotate and distribute replacement credentials before re-enabling if the credential may be compromised.",
		},
		EvidenceFields: []string{
			"policy_id",
			"resource_id",
			"resource_name",
			"provider",
			"access_key_id",
			"inactive_days",
			"threshold_days",
			"before",
			"after",
		},
		SupportedDeliveryModes: []DeliveryMode{
			DeliveryModeRemoteApply,
		},
		DefaultDeliveryMode: DeliveryModeRemoteApply,
		DefaultRemoteTools: map[string]string{
			"aws": "aws.iam.disable_access_key",
			"gcp": "gcp.iam.disable_service_account_key",
		},
		BlastRadiusRationale: "Disables one stale credential instead of deleting an identity or broadening access.",
	},
	{
		ID:               "enable_bucket_default_encryption",
		ActionType:       ActionEnableBucketDefaultEncryption,
		Name:             "Enable bucket default encryption",
		Description:      "Configure default server-side encryption on a cloud bucket so new objects are encrypted at rest.",
		Providers:        []string{"aws"},
		ResourceTypes:    []string{"bucket", "storage/bucket", "storage_bucket", "aws:s3:bucket"},
		SafeByDefault:    true,
		SupportsDryRun:   true,
		SupportsRollback: true,
		RequiresApproval: true,
		BlastRadius:      BlastRadiusLow,
		Preconditions: []string{
			"The bucket still does not have default encryption configured.",
			"The bucket identifier and provider are known.",
		},
		RollbackSteps: []string{
			"Restore the previous bucket encryption configuration from the captured evidence snapshot.",
			"Remove the newly applied default encryption configuration only if the change was intentional and validated.",
		},
		EvidenceFields: []string{
			"policy_id",
			"resource_id",
			"resource_name",
			"provider",
			"sse_algorithm",
			"kms_master_key_id",
			"bucket_key_enabled",
			"artifact",
			"before",
			"after",
		},
		SupportedDeliveryModes: []DeliveryMode{
			DeliveryModeTerraform,
			DeliveryModeRemoteApply,
		},
		DefaultDeliveryMode: DeliveryModeTerraform,
		DefaultRemoteTools: map[string]string{
			"aws": "aws.s3.put_bucket_encryption",
		},
		BlastRadiusRationale: "Applies default encryption to one bucket for future writes without deleting data or changing access.",
	},
	{
		ID:               "restrict_public_security_group_ingress",
		ActionType:       ActionRestrictPublicSecurityGroupIngress,
		Name:             "Restrict public security group ingress",
		Description:      "Revoke public AWS security group ingress rules for SSH, RDP, or all-traffic exposures.",
		Providers:        []string{"aws"},
		ResourceTypes:    []string{"security_group", "security_group_rule", "aws:ec2:security_group"},
		SafeByDefault:    true,
		SupportsDryRun:   true,
		SupportsRollback: true,
		RequiresApproval: true,
		BlastRadius:      BlastRadiusLow,
		Preconditions: []string{
			"A matching public ingress rule is still present on the security group.",
			"The security group identifier and provider are known.",
		},
		RollbackSteps: []string{
			"Re-authorize the captured ingress rule if access was intentionally public.",
			"Restore the previous CIDR, protocol, and port range from the captured evidence snapshot.",
		},
		EvidenceFields: []string{
			"policy_id",
			"resource_id",
			"resource_name",
			"provider",
			"matched_rule_count",
			"matched_ports",
			"matched_cidrs",
			"before",
			"after",
		},
		SupportedDeliveryModes: []DeliveryMode{
			DeliveryModeRemoteApply,
		},
		DefaultDeliveryMode: DeliveryModeRemoteApply,
		DefaultRemoteTools: map[string]string{
			"aws": "aws.ec2.revoke_security_group_ingress",
		},
		BlastRadiusRationale: "Revokes targeted public ingress rules on one security group without deleting the resource.",
	},
}

func Catalog() []CatalogEntry {
	entries := make([]CatalogEntry, 0, len(remediationCatalog))
	for _, entry := range remediationCatalog {
		entries = append(entries, cloneCatalogEntry(entry))
	}
	return entries
}

func CatalogEntryByAction(actionType ActionType) (CatalogEntry, bool) {
	for _, entry := range remediationCatalog {
		if entry.ActionType == actionType {
			return cloneCatalogEntry(entry), true
		}
	}
	return CatalogEntry{}, false
}

func catalogToolForProvider(entry CatalogEntry, provider string) string {
	if len(entry.DefaultRemoteTools) == 0 {
		return ""
	}
	return strings.TrimSpace(entry.DefaultRemoteTools[strings.ToLower(strings.TrimSpace(provider))])
}

func cloneCatalogEntry(entry CatalogEntry) CatalogEntry {
	entry.Providers = append([]string(nil), entry.Providers...)
	entry.ResourceTypes = append([]string(nil), entry.ResourceTypes...)
	entry.Preconditions = append([]string(nil), entry.Preconditions...)
	entry.RollbackSteps = append([]string(nil), entry.RollbackSteps...)
	entry.EvidenceFields = append([]string(nil), entry.EvidenceFields...)
	entry.SupportedDeliveryModes = append([]DeliveryMode(nil), entry.SupportedDeliveryModes...)
	if len(entry.DefaultRemoteTools) > 0 {
		clonedTools := make(map[string]string, len(entry.DefaultRemoteTools))
		for key, value := range entry.DefaultRemoteTools {
			clonedTools[key] = value
		}
		entry.DefaultRemoteTools = clonedTools
	}
	return entry
}
