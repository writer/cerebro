# Connector Provisioning Architecture

Cerebro's workload-scanning stack should not assume one-off credentials hand-entered in product settings. The connector provisioning layer defines the install-time contract for granting narrowly-scoped, revocable cloud access that later workload scanners can consume.

## Goals

- Keep cloud access generation typed and provider-specific instead of scattering IAM snippets across issues and docs.
- Make validation non-destructive by default.
- Reuse the existing auth-chain logic already present in the CLI for AWS, GCP, and Azure.
- Separate provisioning from scanning: this layer grants and verifies access, but does not perform snapshot inspection itself.

## Current Surface

CLI commands:

- `cerebro connector catalog`
- `cerebro connector scaffold aws|gcp|azure`
- `cerebro connector validate aws|gcp|azure`

Generated contract artifacts:

- `docs/CONNECTOR_PROVISIONING_AUTOGEN.md`
- `docs/CONNECTOR_PROVISIONING_CATALOG.json`

## Provider Strategy

### AWS

Provisioning is emitted as a StackSet-safe CloudFormation template for `CerebroScanRole`.

Validation semantics:

- always prove STS caller identity
- always prove `DescribeInstances`, `DescribeVolumes`, and `DescribeSnapshots`
- optionally probe mutation permissions with `DryRun=true` when sample volume/snapshot IDs are supplied

Why the optional sample-resource requirement exists:

- AWS does not provide a universally available, non-privileged equivalent to GCP `testIamPermissions`
- `iam:SimulatePrincipalPolicy` is not a safe assumption for the target scan role
- explicit dry-run probes with sample resources are the most honest low-risk path

### GCP

Provisioning is emitted as a Terraform module with a custom role, service account, and optional Workload Identity Federation trust.

Validation semantics:

- resolve ADC / credentials-file / impersonation / WIF
- prove project-scope read access
- call `projects.testIamPermissions` to verify the snapshot permission set without creating compute resources

### Azure

Provisioning is emitted as:

- an ARM template for assigning Reader + snapshot rights to an existing principal
- a Terraform module for creating a dedicated service principal and assigning the same permissions

Validation semantics:

- acquire a management-plane token
- prove subscription read access
- inspect effective subscription-scope permissions from the ARM permissions API

## Extensibility Rules

When adding a new connector provider:

1. Add a built-in catalog entry in `internal/connectors`.
2. Add a renderer for provider artifacts.
3. Add a live validator that clearly distinguishes `passed`, `failed`, and `skipped/inconclusive` checks.
4. Regenerate the connector docs catalog.
5. Update this document and the execution backlog.

## Known Gaps

- AWS dry-run mutation validation still depends on caller-supplied sample resources.
- No HTTP API or platform resource exists yet for connector bundles; the current surface is CLI-first.
- Bundle compatibility checks are not yet enforced against a historical baseline.
- Actual scanner execution and snapshot lifecycle orchestration remain separate issues in the workload-scan stack.
