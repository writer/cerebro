package connectors

import (
	"sort"
	"strings"
)

type ProviderID string

type ArtifactKind string

type PermissionScope string

type ValidationMode string

const (
	ProviderAWS   ProviderID = "aws"
	ProviderGCP   ProviderID = "gcp"
	ProviderAzure ProviderID = "azure"
)

const (
	ArtifactCloudFormationStackSet ArtifactKind = "cloudformation_stackset"
	ArtifactTerraformModule        ArtifactKind = "terraform_module"
	ArtifactARMTemplate            ArtifactKind = "arm_template"
)

const (
	PermissionScopeAccount      PermissionScope = "account"
	PermissionScopeProject      PermissionScope = "project"
	PermissionScopeSubscription PermissionScope = "subscription"
)

const (
	ValidationAuthOnly ValidationMode = "auth_only"
	ValidationLiveRead ValidationMode = "live_read"
	ValidationDryRun   ValidationMode = "dry_run"
)

type ArtifactSpec struct {
	Kind    ArtifactKind `json:"kind"`
	Summary string       `json:"summary"`
	Files   []string     `json:"files"`
}

type RequiredPermission struct {
	Name        string          `json:"name"`
	Scope       PermissionScope `json:"scope"`
	Summary     string          `json:"summary"`
	Conditions  []string        `json:"conditions,omitempty"`
	ProviderRef string          `json:"provider_ref,omitempty"`
}

type ValidationCheckSpec struct {
	ID             string         `json:"id"`
	Mode           ValidationMode `json:"mode"`
	Summary        string         `json:"summary"`
	RequiredInputs []string       `json:"required_inputs,omitempty"`
}

type ProviderCatalog struct {
	ID                  ProviderID            `json:"id"`
	Title               string                `json:"title"`
	Summary             string                `json:"summary"`
	Artifacts           []ArtifactSpec        `json:"artifacts"`
	RequiredPermissions []RequiredPermission  `json:"required_permissions"`
	ValidationChecks    []ValidationCheckSpec `json:"validation_checks"`
}

type Catalog struct {
	APIVersion string            `json:"api_version"`
	Kind       string            `json:"kind"`
	Providers  []ProviderCatalog `json:"providers"`
}

func BuiltInCatalog() Catalog {
	providers := []ProviderCatalog{
		{
			ID:      ProviderAWS,
			Title:   "AWS Cross-Account Snapshot Connector",
			Summary: "CloudFormation StackSet contract for a read-only plus snapshot-limited IAM role that Cerebro can assume into workload accounts.",
			Artifacts: []ArtifactSpec{
				{
					Kind:    ArtifactCloudFormationStackSet,
					Summary: "StackSet-ready template, example parameters, and rollout notes for the CerebroScanRole deployment.",
					Files:   []string{"aws/stackset.yaml", "aws/parameters.example.json", "aws/README.md"},
				},
			},
			RequiredPermissions: []RequiredPermission{
				{Name: "ec2:DescribeInstances", Scope: PermissionScopeAccount, Summary: "Read instance attachment context before staging snapshot-backed inspection.", ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html"},
				{Name: "ec2:DescribeVolumes", Scope: PermissionScopeAccount, Summary: "Read source EBS volumes for snapshot eligibility and attachment mapping.", ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html"},
				{Name: "ec2:DescribeSnapshots", Scope: PermissionScopeAccount, Summary: "Read Cerebro-managed snapshots during validation and cleanup.", ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html"},
				{Name: "ec2:CreateSnapshot", Scope: PermissionScopeAccount, Summary: "Create inspection snapshots from source volumes.", Conditions: []string{"Require request tag marking Cerebro-managed snapshot operations."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshot.html"},
				{Name: "ec2:CopySnapshot", Scope: PermissionScopeAccount, Summary: "Copy snapshots into inspection or regional isolation flows.", Conditions: []string{"Restrict copy operations to tagged Cerebro-managed snapshots."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CopySnapshot.html"},
				{Name: "ec2:ModifySnapshotAttribute", Scope: PermissionScopeAccount, Summary: "Share Cerebro-managed snapshots with the inspection account when required.", Conditions: []string{"Restrict mutable operations to tagged Cerebro-managed snapshots."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html"},
				{Name: "ec2:DeleteSnapshot", Scope: PermissionScopeAccount, Summary: "Clean up Cerebro-managed snapshots after inspection.", Conditions: []string{"Restrict deletion to tagged Cerebro-managed snapshots."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteSnapshot.html"},
				{Name: "ec2:CreateVolume", Scope: PermissionScopeAccount, Summary: "Materialize temporary inspection volumes from snapshots.", Conditions: []string{"Require request tag marking Cerebro-managed temporary volumes."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html"},
				{Name: "ec2:AttachVolume", Scope: PermissionScopeAccount, Summary: "Attach temporary inspection volumes when a scanner runtime is introduced.", Conditions: []string{"Restrict attachments to tagged Cerebro-managed volumes."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AttachVolume.html"},
				{Name: "ec2:DetachVolume", Scope: PermissionScopeAccount, Summary: "Detach temporary inspection volumes during teardown.", Conditions: []string{"Restrict detaches to tagged Cerebro-managed volumes."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DetachVolume.html"},
				{Name: "ec2:DeleteVolume", Scope: PermissionScopeAccount, Summary: "Delete temporary inspection volumes after use.", Conditions: []string{"Restrict deletion to tagged Cerebro-managed volumes."}, ProviderRef: "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteVolume.html"},
				{Name: "kms:DescribeKey", Scope: PermissionScopeAccount, Summary: "Inspect EBS snapshot key manager metadata before cross-account encrypted scans.", ProviderRef: "https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html"},
				{Name: "kms:Decrypt", Scope: PermissionScopeAccount, Summary: "Use customer-managed keys when encrypted EBS volumes are snapshotted.", Conditions: []string{"Limit use to EC2 via-service requests and AWS-resource grants."}, ProviderRef: "https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html"},
				{Name: "kms:CreateGrant", Scope: PermissionScopeAccount, Summary: "Delegate one-time EC2 snapshot access for encrypted volumes.", Conditions: []string{"Require kms:GrantIsForAWSResource=true and EC2 via-service usage."}, ProviderRef: "https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html"},
				{Name: "kms:ReEncryptFrom", Scope: PermissionScopeAccount, Summary: "Support encrypted snapshot copy workflows.", Conditions: []string{"Limit use to EC2 snapshot copy flows."}, ProviderRef: "https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html"},
				{Name: "kms:ReEncryptTo", Scope: PermissionScopeAccount, Summary: "Support encrypted snapshot copy workflows.", Conditions: []string{"Limit use to EC2 snapshot copy flows."}, ProviderRef: "https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html"},
			},
			ValidationChecks: []ValidationCheckSpec{
				{ID: "auth", Mode: ValidationAuthOnly, Summary: "Resolve and prove the current AWS auth chain via STS caller identity."},
				{ID: "describe", Mode: ValidationLiveRead, Summary: "Confirm read-only EC2 describe permissions required for workload targeting."},
				{ID: "snapshot_dry_run", Mode: ValidationDryRun, Summary: "Optionally dry-run snapshot and volume mutation permissions with caller-supplied sample resources.", RequiredInputs: []string{"aws-region", "aws-volume-id or aws-snapshot-id"}},
			},
		},
		{
			ID:      ProviderGCP,
			Title:   "GCP Snapshot Connector",
			Summary: "Terraform module that provisions a custom role, service account, and optional Workload Identity Federation path for agentless workload snapshot access.",
			Artifacts: []ArtifactSpec{
				{
					Kind:    ArtifactTerraformModule,
					Summary: "Terraform module for service-account provisioning plus optional Workload Identity Federation trust.",
					Files:   []string{"gcp/main.tf", "gcp/variables.tf", "gcp/outputs.tf", "gcp/README.md"},
				},
			},
			RequiredPermissions: []RequiredPermission{
				{Name: "compute.disks.createSnapshot", Scope: PermissionScopeProject, Summary: "Create snapshots from source persistent disks.", ProviderRef: "https://cloud.google.com/compute/docs/access/iam"},
				{Name: "compute.snapshots.get", Scope: PermissionScopeProject, Summary: "Read created snapshots for downstream inspection and cleanup.", ProviderRef: "https://cloud.google.com/compute/docs/access/iam"},
				{Name: "compute.snapshots.delete", Scope: PermissionScopeProject, Summary: "Delete temporary inspection snapshots after use.", ProviderRef: "https://cloud.google.com/compute/docs/access/iam"},
				{Name: "compute.snapshots.setIamPolicy", Scope: PermissionScopeProject, Summary: "Share snapshot access when an external inspection project is used.", ProviderRef: "https://cloud.google.com/compute/docs/access/iam"},
				{Name: "compute.instances.get", Scope: PermissionScopeProject, Summary: "Read workload instance metadata for snapshot targeting.", ProviderRef: "https://cloud.google.com/compute/docs/access/iam"},
			},
			ValidationChecks: []ValidationCheckSpec{
				{ID: "auth", Mode: ValidationAuthOnly, Summary: "Resolve ADC, credentials-file, impersonation, or WIF auth and retrieve an access token."},
				{ID: "project_read", Mode: ValidationLiveRead, Summary: "Confirm project-scope control-plane access for the target connector project.", RequiredInputs: []string{"gcp-project"}},
				{ID: "iam_permissions", Mode: ValidationDryRun, Summary: "Use Cloud Resource Manager testIamPermissions to verify the snapshot permission set without creating resources.", RequiredInputs: []string{"gcp-project"}},
			},
		},
		{
			ID:      ProviderAzure,
			Title:   "Azure Snapshot Connector",
			Summary: "Azure ARM and Terraform contracts for assigning Reader plus snapshot mutation rights to a Cerebro service principal or existing principal.",
			Artifacts: []ArtifactSpec{
				{
					Kind:    ArtifactARMTemplate,
					Summary: "ARM template for assigning Reader and a snapshot-writer custom role to an existing principal.",
					Files:   []string{"azure/arm-template.json", "azure/parameters.example.json", "azure/README.md"},
				},
				{
					Kind:    ArtifactTerraformModule,
					Summary: "Terraform module for creating a service principal and assigning Reader plus snapshot permissions.",
					Files:   []string{"azure/main.tf", "azure/variables.tf", "azure/outputs.tf"},
				},
			},
			RequiredPermissions: []RequiredPermission{
				{Name: "Microsoft.Resources/subscriptions/resourceGroups/read", Scope: PermissionScopeSubscription, Summary: "Reader baseline for discovering workload resource groups and compute assets.", ProviderRef: "https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations"},
				{Name: "Microsoft.Compute/virtualMachines/read", Scope: PermissionScopeSubscription, Summary: "Read VM metadata before snapshot staging.", ProviderRef: "https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations"},
				{Name: "Microsoft.Compute/disks/read", Scope: PermissionScopeSubscription, Summary: "Read managed disk metadata for snapshot targeting.", ProviderRef: "https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations"},
				{Name: "Microsoft.Compute/snapshots/write", Scope: PermissionScopeSubscription, Summary: "Create temporary snapshots for inspection.", ProviderRef: "https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations"},
				{Name: "Microsoft.Compute/snapshots/delete", Scope: PermissionScopeSubscription, Summary: "Delete temporary snapshots after inspection.", ProviderRef: "https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations"},
			},
			ValidationChecks: []ValidationCheckSpec{
				{ID: "auth", Mode: ValidationAuthOnly, Summary: "Resolve Azure credential chain and acquire a management-plane token."},
				{ID: "subscription_read", Mode: ValidationLiveRead, Summary: "Confirm the target subscription is readable with the current principal.", RequiredInputs: []string{"azure-subscription"}},
				{ID: "permissions", Mode: ValidationDryRun, Summary: "Inspect effective subscription-scope permission actions and verify Reader plus snapshot writes/deletes are present.", RequiredInputs: []string{"azure-subscription"}},
			},
		},
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].ID < providers[j].ID })
	return Catalog{
		APIVersion: "connectors.cerebro/v1alpha1",
		Kind:       "ConnectorProvisioningCatalog",
		Providers:  providers,
	}
}

func RegisteredProviders() []ProviderCatalog {
	catalog := BuiltInCatalog()
	providers := make([]ProviderCatalog, len(catalog.Providers))
	copy(providers, catalog.Providers)
	return providers
}

func ProviderByID(id string) (ProviderCatalog, bool) {
	needle := NormalizeProviderID(id)
	for _, provider := range RegisteredProviders() {
		if string(provider.ID) == needle {
			return provider, true
		}
	}
	return ProviderCatalog{}, false
}

func NormalizeProviderID(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}
