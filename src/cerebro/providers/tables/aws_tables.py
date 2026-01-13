"""
AWS provider table implementations.

Exposes AWS security resources as SQL tables following Steampipe patterns.
"""

from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

import structlog

from ...query.registry import register_table
from ...query.schema import ColumnType, SecurityColumn
from ...query.table import ProviderSecurityTable, QueryContext

logger = structlog.get_logger(__name__)

# Production AWS client using boto3
import boto3
from botocore.exceptions import NoCredentialsError


class AWSClient:
    def __init__(self) -> None:
        self._clients: dict[str, Any] = {}

    async def get_client(self, service: str, region: str = "us-east-1") -> Any:
        """Get AWS service client with proper error handling."""
        try:
            if service not in self._clients:
                self._clients[service] = boto3.client(service, region_name=region)
            return self._clients[service]
        except NoCredentialsError:
            logger.error(f"AWS credentials not configured for {service}")
            raise
        except Exception as e:
            logger.error(f"Failed to create AWS {service} client: {e}")
            raise

    async def get_account_id(self) -> str:
        """Get current AWS account ID."""
        try:
            sts = await self.get_client("sts")
            response = sts.get_caller_identity()
            account: str = response["Account"]
            return account
        except Exception as e:
            logger.error(f"Failed to get AWS account ID: {e}")
            return "unknown"


class AWSEc2InstanceTable(ProviderSecurityTable):
    """AWS EC2 instances as a security table."""

    def __init__(self) -> None:
        # Define EC2-specific columns
        ec2_columns = [
            SecurityColumn(
                "instance_id",
                ColumnType.TEXT,
                "EC2 instance ID",
                required=True,
                source_field="InstanceId",
            ),
            SecurityColumn(
                "instance_type",
                ColumnType.TEXT,
                "EC2 instance type",
                source_field="InstanceType",
            ),
            SecurityColumn(
                "state", ColumnType.TEXT, "Instance state", source_field="State.Name"
            ),
            SecurityColumn(
                "public_ip",
                ColumnType.TEXT,
                "Public IP address",
                source_field="PublicIpAddress",
            ),
            SecurityColumn(
                "private_ip",
                ColumnType.TEXT,
                "Private IP address",
                source_field="PrivateIpAddress",
            ),
            SecurityColumn("vpc_id", ColumnType.TEXT, "VPC ID", source_field="VpcId"),
            SecurityColumn(
                "subnet_id", ColumnType.TEXT, "Subnet ID", source_field="SubnetId"
            ),
            SecurityColumn(
                "security_groups",
                ColumnType.JSON,
                "Security group IDs",
                source_field="SecurityGroups",
            ),
            SecurityColumn(
                "key_name", ColumnType.TEXT, "Key pair name", source_field="KeyName"
            ),
            SecurityColumn(
                "iam_instance_profile",
                ColumnType.JSON,
                "IAM instance profile",
                source_field="IamInstanceProfile",
            ),
            SecurityColumn(
                "monitoring",
                ColumnType.JSON,
                "CloudWatch monitoring",
                source_field="Monitoring",
            ),
            SecurityColumn(
                "placement",
                ColumnType.JSON,
                "Placement information",
                source_field="Placement",
            ),
        ]

        super().__init__(
            name="aws_ec2_instance",
            description="AWS EC2 instances with security configuration",
            provider_name="aws",
            columns=ec2_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch EC2 instances from AWS API."""
        client = AWSClient()

        try:
            # Get all regions or filter by region from query context
            regions = ["us-east-1", "us-west-2"]  # Simplified - should get from config

            for region in regions:
                ec2 = await client.get_client("ec2", region)

                # Fetch EC2 instances
                paginator = ec2.get_paginator("describe_instances")
                async for page in paginator.paginate():
                    for reservation in page.get("Reservations", []):
                        for instance in reservation.get("Instances", []):
                            # Add region and account info
                            instance["Region"] = region
                            instance["AccountId"] = await client.get_account_id()
                            instance["Provider"] = "aws"

                            # Add computed fields
                            instance["CreatedAt"] = instance.get("LaunchTime")
                            instance["UpdatedAt"] = datetime.now()

                            # Transform tags
                            tags = {
                                tag["Key"]: tag["Value"]
                                for tag in instance.get("Tags", [])
                            }
                            instance["Tags"] = tags

                            yield instance

        except Exception as e:
            logger.error(f"Error fetching AWS EC2 instances: {e}")
            raise


class AWSIAMUserTable(ProviderSecurityTable):
    """AWS IAM users as a security table."""

    def __init__(self) -> None:
        # Use identity schema with AWS-specific additions
        iam_columns = [
            SecurityColumn(
                "user_name",
                ColumnType.TEXT,
                "IAM username",
                required=True,
                source_field="UserName",
            ),
            SecurityColumn(
                "user_id", ColumnType.TEXT, "IAM user ID", source_field="UserId"
            ),
            SecurityColumn("arn", ColumnType.TEXT, "User ARN", source_field="Arn"),
            SecurityColumn("path", ColumnType.TEXT, "User path", source_field="Path"),
            SecurityColumn(
                "password_last_used",
                ColumnType.TIMESTAMP,
                "Password last used",
                source_field="PasswordLastUsed",
            ),
            SecurityColumn(
                "mfa_enabled",
                ColumnType.BOOLEAN,
                "MFA enabled",
                transform="check_mfa_enabled",
            ),
            SecurityColumn(
                "access_keys",
                ColumnType.JSON,
                "Access keys",
                transform="get_access_keys",
            ),
            SecurityColumn(
                "attached_policies",
                ColumnType.JSON,
                "Attached managed policies",
                transform="get_attached_policies",
            ),
            SecurityColumn(
                "inline_policies",
                ColumnType.JSON,
                "Inline policies",
                transform="get_inline_policies",
            ),
            SecurityColumn(
                "groups",
                ColumnType.JSON,
                "Group memberships",
                transform="get_user_groups",
            ),
        ]

        super().__init__(
            name="aws_iam_user",
            description="AWS IAM users with permissions and security settings",
            provider_name="aws",
            columns=iam_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch IAM users from AWS API."""
        client = AWSClient()

        try:
            iam = await client.get_client("iam")

            # Fetch IAM users
            paginator = iam.get_paginator("list_users")
            async for page in paginator.paginate():
                for user in page.get("Users", []):
                    # Add metadata
                    user["AccountId"] = await client.get_account_id()
                    user["Provider"] = "aws"
                    user["Region"] = "global"  # IAM is global
                    user["Tags"] = {}  # Would need separate API call for user tags

                    # Set timestamps
                    user["CreatedAt"] = user.get("CreateDate")
                    user["UpdatedAt"] = datetime.now()

                    yield user

        except Exception as e:
            logger.error(f"Error fetching AWS IAM users: {e}")
            raise

    def check_mfa_enabled(self, user_data: dict[str, Any]) -> bool:
        """Check if MFA is enabled for user."""
        # This would require additional API calls to list MFA devices
        # Simplified implementation
        return False

    def get_access_keys(self, user_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Get access keys for user."""
        # This would require additional API call
        return []

    def get_attached_policies(self, user_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Get attached managed policies."""
        # This would require additional API call
        return []

    def get_inline_policies(self, user_data: dict[str, Any]) -> list[str]:
        """Get inline policy names."""
        # This would require additional API call
        return []

    def get_user_groups(self, user_data: dict[str, Any]) -> list[str]:
        """Get user group memberships."""
        # This would require additional API call
        return []


class AWSSecurityGroupTable(ProviderSecurityTable):
    """AWS Security Groups as a security table."""

    def __init__(self) -> None:
        sg_columns = [
            SecurityColumn(
                "group_id",
                ColumnType.TEXT,
                "Security group ID",
                required=True,
                source_field="GroupId",
            ),
            SecurityColumn(
                "group_name",
                ColumnType.TEXT,
                "Security group name",
                source_field="GroupName",
            ),
            SecurityColumn(
                "description",
                ColumnType.TEXT,
                "Security group description",
                source_field="Description",
            ),
            SecurityColumn("vpc_id", ColumnType.TEXT, "VPC ID", source_field="VpcId"),
            SecurityColumn(
                "owner_id", ColumnType.TEXT, "Owner account ID", source_field="OwnerId"
            ),
            SecurityColumn(
                "ingress_rules",
                ColumnType.JSON,
                "Ingress rules",
                source_field="IpPermissions",
            ),
            SecurityColumn(
                "egress_rules",
                ColumnType.JSON,
                "Egress rules",
                source_field="IpPermissionsEgress",
            ),
        ]

        super().__init__(
            name="aws_security_group",
            description="AWS Security Groups with ingress and egress rules",
            provider_name="aws",
            columns=sg_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch Security Groups from AWS API."""
        client = AWSClient()

        try:
            regions = ["us-east-1", "us-west-2"]  # Simplified

            for region in regions:
                ec2 = await client.get_client("ec2", region)

                paginator = ec2.get_paginator("describe_security_groups")
                async for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        # Add metadata
                        sg["Region"] = region
                        sg["AccountId"] = await client.get_account_id()
                        sg["Provider"] = "aws"
                        sg["CreatedAt"] = (
                            datetime.now()
                        )  # SGs don't have creation time in API
                        sg["UpdatedAt"] = datetime.now()

                        # Transform tags
                        tags = {tag["Key"]: tag["Value"] for tag in sg.get("Tags", [])}
                        sg["Tags"] = tags

                        yield sg

        except Exception as e:
            logger.error(f"Error fetching AWS Security Groups: {e}")
            raise


def register_aws_tables():
    """Register all AWS tables with the query engine."""
    register_table(AWSEc2InstanceTable(), aliases=["aws_ec2", "ec2_instances"])
    register_table(AWSIAMUserTable(), aliases=["aws_users", "iam_users"])
    register_table(AWSSecurityGroupTable(), aliases=["aws_sg", "security_groups"])
