"""
GCP infrastructure for Cerebro Security Platform.

Deploys:
- Workload Identity Federation (WIF) pool + AWS provider
- Scanner service account with WIF impersonation binding
- Project IAM roles for scanner SA

Security model:
  AWS ECS task role -> WIF (attribute-conditioned) -> GCP SA
  No service account keys; short-lived credentials only.
"""

import re

import pulumi
import pulumi_gcp as gcp

config = pulumi.Config("cerebro")
gcp_project = pulumi.Config("gcp").require("project")

# ---------------------------------------------------------------------------
# Required config
# ---------------------------------------------------------------------------
trusted_aws_account_id = config.require("trustedAwsAccountId")
trusted_aws_role_arns: list[str] = config.require_object("trustedAwsRoleArns")
scanner_role_projects: list[str] = config.require_object("scannerRoleProjects")
scanner_roles: list[str] = config.require_object("scannerRoles")

# ---------------------------------------------------------------------------
# Optional config with defaults
# ---------------------------------------------------------------------------
pool_id = config.get("wifPoolId") or "cerebro-aws-pool"
provider_id = config.get("wifProviderId") or "cerebro-aws-provider"
scanner_sa_id = config.get("scannerServiceAccountId") or "cerebro-scanner"

_role_arn_pattern = re.compile(r"^arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]+)$")
_allowed_scanner_roles = {"roles/viewer", "roles/logging.privateLogViewer"}


def _validate_config() -> None:
    if not re.fullmatch(r"[0-9]{12}", trusted_aws_account_id):
        raise ValueError("cerebro:trustedAwsAccountId must be a 12 digit AWS account ID")
    if not trusted_aws_role_arns:
        raise ValueError("cerebro:trustedAwsRoleArns must not be empty")
    for arn in trusted_aws_role_arns:
        match = _role_arn_pattern.fullmatch(str(arn).strip())
        if not match:
            raise ValueError(f"trusted AWS role ARN is invalid: {arn}")
        if match.group(1) != trusted_aws_account_id:
            raise ValueError(f"trusted AWS role ARN account {match.group(1)} must match {trusted_aws_account_id}")
    if not scanner_role_projects:
        raise ValueError("cerebro:scannerRoleProjects must not be empty")
    if not scanner_roles:
        raise ValueError("cerebro:scannerRoles must not be empty")
    disallowed = sorted(set(scanner_roles) - _allowed_scanner_roles)
    if disallowed:
        raise ValueError(f"scanner roles are not allowed: {', '.join(disallowed)}")


_validate_config()

# Extract role names from ARNs for attribute conditions and principal bindings.
# arn:aws:iam::<account>:role/<name> -> <name>
role_names = [arn.rsplit("/", 1)[-1] for arn in trusted_aws_role_arns]

# =============================================================================
# WORKLOAD IDENTITY FEDERATION
# =============================================================================

wif_pool = gcp.iam.WorkloadIdentityPool(
    "cerebro-wif-pool",
    workload_identity_pool_id=pool_id,
    display_name="Cerebro AWS Pool",
    description="WIF pool for Cerebro AWS-to-GCP cross-cloud access",
    project=gcp_project,
)

# Build attribute condition that allows each trusted role.
# STS assumed-role ARNs: arn:aws:sts::<account>:assumed-role/<role-name>/<session>
_role_conditions = [
    f"assertion.arn.startsWith('arn:aws:sts::{trusted_aws_account_id}:assumed-role/{name}/')"
    for name in role_names
]
attribute_condition = " || ".join(_role_conditions)

wif_provider = gcp.iam.WorkloadIdentityPoolProvider(
    "cerebro-wif-aws-provider",
    workload_identity_pool_id=wif_pool.workload_identity_pool_id,
    workload_identity_pool_provider_id=provider_id,
    display_name="Cerebro AWS Provider",
    description="AWS provider restricted to Cerebro ECS task roles",
    aws=gcp.iam.WorkloadIdentityPoolProviderAwsArgs(
        account_id=trusted_aws_account_id,
    ),
    attribute_mapping={
        "google.subject": "assertion.arn",
        "attribute.aws_role": "assertion.arn.extract('assumed-role/{role}/')",
    },
    attribute_condition=attribute_condition,
    project=gcp_project,
)

# =============================================================================
# SCANNER SERVICE ACCOUNT
# =============================================================================

scanner_sa = gcp.serviceaccount.Account(
    "cerebro-scanner-sa",
    account_id=scanner_sa_id,
    display_name="Cerebro Scanner",
    description="Service account for Cerebro cloud scanner (AWS WIF)",
    project=gcp_project,
)

# IAM binding per trusted role: allow each AWS role to impersonate this SA.
for name in role_names:
    principal = pulumi.Output.format(
        "principalSet://iam.googleapis.com/{0}/attribute.aws_role/{1}",
        wif_pool.name,
        name,
    )
    gcp.serviceaccount.IAMMember(
        f"cerebro-scanner-wif-{name}",
        service_account_id=scanner_sa.name,
        role="roles/iam.workloadIdentityUser",
        member=principal,
    )

def _sanitize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9-]", "-", name)

for target_project in scanner_role_projects:
    for role in scanner_roles:
        resource_name = f"cerebro-scanner-{_sanitize(target_project)}-{_sanitize(role)}"
        gcp.projects.IAMMember(
            resource_name,
            project=target_project,
            role=role,
            member=scanner_sa.email.apply(lambda e: f"serviceAccount:{e}"),
        )

# =============================================================================
# OUTPUTS
# =============================================================================

pulumi.export("scanner_service_account_email", scanner_sa.email)
pulumi.export("wif_pool_name", wif_pool.name)
pulumi.export("wif_provider_name", wif_provider.name)

# Export the principal for each trusted role
for name in role_names:
    pulumi.export(
        f"wif_principal_{name}",
        pulumi.Output.format(
            "principalSet://iam.googleapis.com/{0}/attribute.aws_role/{1}",
            wif_pool.name,
            name,
        ),
    )

audience = pulumi.Output.format(
    "//iam.googleapis.com/{0}",
    wif_provider.name,
)
pulumi.export("wif_audience", audience)
