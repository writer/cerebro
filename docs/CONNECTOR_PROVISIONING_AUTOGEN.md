# Connector Provisioning Auto-Generated Catalog

Generated from `internal/connectors` via `go run ./scripts/generate_connector_docs/main.go`.

This catalog keeps provider-specific provisioning artifacts, required permissions, and validation expectations in one machine-readable surface.

## AWS Cross-Account Snapshot Connector

CloudFormation StackSet contract for a read-only plus snapshot-limited IAM role that Cerebro can assume into workload accounts.

### Artifacts

- `cloudformation_stackset`: StackSet-ready template, example parameters, and rollout notes for the CerebroScanRole deployment.
  - `aws/stackset.yaml`
  - `aws/parameters.example.json`
  - `aws/README.md`

### Required Permissions

- `ec2:DescribeInstances` (`account`): Read instance attachment context before staging snapshot-backed inspection.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
- `ec2:DescribeVolumes` (`account`): Read source EBS volumes for snapshot eligibility and attachment mapping.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html
- `ec2:DescribeSnapshots` (`account`): Read Cerebro-managed snapshots during validation and cleanup.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html
- `ec2:CreateSnapshot` (`account`): Create inspection snapshots from source volumes.
  - Condition: Require request tag marking Cerebro-managed snapshot operations.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshot.html
- `ec2:CopySnapshot` (`account`): Copy snapshots into inspection or regional isolation flows.
  - Condition: Restrict copy operations to tagged Cerebro-managed snapshots.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CopySnapshot.html
- `ec2:ModifySnapshotAttribute` (`account`): Share Cerebro-managed snapshots with the inspection account when required.
  - Condition: Restrict mutable operations to tagged Cerebro-managed snapshots.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html
- `ec2:DeleteSnapshot` (`account`): Clean up Cerebro-managed snapshots after inspection.
  - Condition: Restrict deletion to tagged Cerebro-managed snapshots.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteSnapshot.html
- `ec2:CreateVolume` (`account`): Materialize temporary inspection volumes from snapshots.
  - Condition: Require request tag marking Cerebro-managed temporary volumes.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html
- `ec2:AttachVolume` (`account`): Attach temporary inspection volumes when a scanner runtime is introduced.
  - Condition: Restrict attachments to tagged Cerebro-managed volumes.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AttachVolume.html
- `ec2:DetachVolume` (`account`): Detach temporary inspection volumes during teardown.
  - Condition: Restrict detaches to tagged Cerebro-managed volumes.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DetachVolume.html
- `ec2:DeleteVolume` (`account`): Delete temporary inspection volumes after use.
  - Condition: Restrict deletion to tagged Cerebro-managed volumes.
  - Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteVolume.html
- `kms:DescribeKey` (`account`): Inspect EBS snapshot key manager metadata before cross-account encrypted scans.
  - Reference: https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html
- `kms:Decrypt` (`account`): Use customer-managed keys when encrypted EBS volumes are snapshotted.
  - Condition: Limit use to EC2 via-service requests and AWS-resource grants.
  - Reference: https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html
- `kms:CreateGrant` (`account`): Delegate one-time EC2 snapshot access for encrypted volumes.
  - Condition: Require kms:GrantIsForAWSResource=true and EC2 via-service usage.
  - Reference: https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html
- `kms:ReEncryptFrom` (`account`): Support encrypted snapshot copy workflows.
  - Condition: Limit use to EC2 snapshot copy flows.
  - Reference: https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html
- `kms:ReEncryptTo` (`account`): Support encrypted snapshot copy workflows.
  - Condition: Limit use to EC2 snapshot copy flows.
  - Reference: https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html

### Validation Checks

- `auth` (`auth_only`): Resolve and prove the current AWS auth chain via STS caller identity.
- `describe` (`live_read`): Confirm read-only EC2 describe permissions required for workload targeting.
- `snapshot_dry_run` (`dry_run`): Optionally dry-run snapshot and volume mutation permissions with caller-supplied sample resources.
  - Inputs: `aws-region`, `aws-volume-id or aws-snapshot-id`

### CLI

- Scaffold: `cerebro connector scaffold aws --output-dir ./.cerebro/connectors/aws`
- Validate: `cerebro connector validate aws --dry-run`

## Azure Snapshot Connector

Azure ARM and Terraform contracts for assigning Reader plus snapshot mutation rights to a Cerebro service principal or existing principal.

### Artifacts

- `arm_template`: ARM template for assigning Reader and a snapshot-writer custom role to an existing principal.
  - `azure/arm-template.json`
  - `azure/parameters.example.json`
  - `azure/README.md`
- `terraform_module`: Terraform module for creating a service principal and assigning Reader plus snapshot permissions.
  - `azure/main.tf`
  - `azure/variables.tf`
  - `azure/outputs.tf`

### Required Permissions

- `Microsoft.Resources/subscriptions/resourceGroups/read` (`subscription`): Reader baseline for discovering workload resource groups and compute assets.
  - Reference: https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations
- `Microsoft.Compute/virtualMachines/read` (`subscription`): Read VM metadata before snapshot staging.
  - Reference: https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations
- `Microsoft.Compute/disks/read` (`subscription`): Read managed disk metadata for snapshot targeting.
  - Reference: https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations
- `Microsoft.Compute/snapshots/write` (`subscription`): Create temporary snapshots for inspection.
  - Reference: https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations
- `Microsoft.Compute/snapshots/delete` (`subscription`): Delete temporary snapshots after inspection.
  - Reference: https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations

### Validation Checks

- `auth` (`auth_only`): Resolve Azure credential chain and acquire a management-plane token.
- `subscription_read` (`live_read`): Confirm the target subscription is readable with the current principal.
  - Inputs: `azure-subscription`
- `permissions` (`dry_run`): Inspect effective subscription-scope permission actions and verify Reader plus snapshot writes/deletes are present.
  - Inputs: `azure-subscription`

### CLI

- Scaffold: `cerebro connector scaffold azure --output-dir ./.cerebro/connectors/azure`
- Validate: `cerebro connector validate azure --dry-run`

## GCP Snapshot Connector

Terraform module that provisions a custom role, service account, and optional Workload Identity Federation path for agentless workload snapshot access.

### Artifacts

- `terraform_module`: Terraform module for service-account provisioning plus optional Workload Identity Federation trust.
  - `gcp/main.tf`
  - `gcp/variables.tf`
  - `gcp/outputs.tf`
  - `gcp/README.md`

### Required Permissions

- `compute.disks.createSnapshot` (`project`): Create snapshots from source persistent disks.
  - Reference: https://cloud.google.com/compute/docs/access/iam
- `compute.snapshots.get` (`project`): Read created snapshots for downstream inspection and cleanup.
  - Reference: https://cloud.google.com/compute/docs/access/iam
- `compute.snapshots.delete` (`project`): Delete temporary inspection snapshots after use.
  - Reference: https://cloud.google.com/compute/docs/access/iam
- `compute.snapshots.setIamPolicy` (`project`): Share snapshot access when an external inspection project is used.
  - Reference: https://cloud.google.com/compute/docs/access/iam
- `compute.instances.get` (`project`): Read workload instance metadata for snapshot targeting.
  - Reference: https://cloud.google.com/compute/docs/access/iam

### Validation Checks

- `auth` (`auth_only`): Resolve ADC, credentials-file, impersonation, or WIF auth and retrieve an access token.
- `project_read` (`live_read`): Confirm project-scope control-plane access for the target connector project.
  - Inputs: `gcp-project`
- `iam_permissions` (`dry_run`): Use Cloud Resource Manager testIamPermissions to verify the snapshot permission set without creating resources.
  - Inputs: `gcp-project`

### CLI

- Scaffold: `cerebro connector scaffold gcp --output-dir ./.cerebro/connectors/gcp`
- Validate: `cerebro connector validate gcp --dry-run`

## Machine-Readable Catalog

- `docs/CONNECTOR_PROVISIONING_CATALOG.json` is the machine-readable catalog for code generation and extension tooling.
