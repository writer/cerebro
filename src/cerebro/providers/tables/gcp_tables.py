"""
GCP provider table implementations.

Exposes GCP security resources as SQL tables following Steampipe patterns.
"""

import logging
from collections.abc import AsyncGenerator
from datetime import datetime
from typing import Any

from ...query.registry import register_table
from ...query.schema import ColumnType, SecurityColumn
from ...query.table import ProviderSecurityTable, QueryContext

logger = logging.getLogger(__name__)


# Real GCP client implementation
class GCPClient:
    def __init__(self, project_id: str | None = None):
        self.project_id = project_id
        self._compute_client: Any | None = None
        self._storage_client: Any | None = None
        self._iam_client: Any | None = None
        self._credentials: Any | None = None

    async def authenticate(self):
        """Authenticate with GCP using default credentials."""
        try:
            from google.auth import default

            self._credentials, detected_project = default()

            # Use detected project if not explicitly provided
            if not self.project_id:
                self.project_id = detected_project or "default-project"

            return True
        except ImportError:
            logger.error(
                "GCP client libraries not installed. Run: pip install google-cloud-compute google-cloud-storage google-cloud-iam"
            )
            return False
        except Exception as e:
            logger.error(f"GCP authentication failed: {e}")
            return False

    async def get_compute_client(self):
        """Get compute client."""
        if not self._compute_client:
            try:
                from google.cloud import compute_v1

                if not self._credentials:
                    await self.authenticate()
                self._compute_client = compute_v1.InstancesClient(
                    credentials=self._credentials
                )
            except ImportError:
                logger.error("google-cloud-compute not installed")
                raise
        return self._compute_client

    async def get_storage_client(self):
        """Get storage client."""
        if not self._storage_client:
            try:
                from google.cloud import storage  # type: ignore[attr-defined]

                if not self._credentials:
                    await self.authenticate()
                self._storage_client = storage.Client(
                    credentials=self._credentials, project=self.project_id
                )
            except ImportError:
                logger.error("google-cloud-storage not installed")
                raise
        return self._storage_client

    async def get_iam_client(self):
        """Get IAM client."""
        if not self._iam_client:
            try:
                from google.cloud import resourcemanager_v3

                if not self._credentials:
                    await self.authenticate()
                self._iam_client = resourcemanager_v3.ProjectsClient(
                    credentials=self._credentials
                )
            except ImportError:
                logger.error("google-cloud-resource-manager not installed")
                raise
        return self._iam_client

    async def get_project_id(self) -> str:
        """Get project ID."""
        if not self.project_id:
            await self.authenticate()
        return self.project_id or "unknown-project"

    async def list_instances(self):
        """List all compute instances."""
        try:
            from google.cloud import compute_v1

            compute_client = await self.get_compute_client()

            request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
            page_result = compute_client.aggregated_list(request=request)

            for zone, response in page_result:
                if hasattr(response, "instances") and response.instances:
                    for instance in response.instances:
                        # Convert protobuf instance to dict format
                        instance_dict = {
                            "id": str(instance.id),
                            "name": instance.name,
                            "machineType": instance.machine_type,
                            "status": instance.status,
                            "zone": zone,
                            "networkInterfaces": [
                                {
                                    "networkIP": ni.network_i_p,
                                    "accessConfigs": (
                                        [
                                            {"natIP": ac.nat_i_p}
                                            for ac in ni.access_configs
                                        ]
                                        if ni.access_configs
                                        else []
                                    ),
                                }
                                for ni in instance.network_interfaces
                            ],
                            "serviceAccounts": (
                                [
                                    {
                                        "email": sa.email,
                                        "scopes": list(sa.scopes) if sa.scopes else [],
                                    }
                                    for sa in instance.service_accounts
                                ]
                                if instance.service_accounts
                                else []
                            ),
                            "creationTimestamp": instance.creation_timestamp,
                            "tags": (
                                {"items": list(instance.tags.items)}
                                if instance.tags and instance.tags.items
                                else {"items": []}
                            ),
                            "labels": dict(instance.labels) if instance.labels else {},
                        }
                        yield instance_dict
        except Exception as e:
            logger.error(f"Error listing GCP instances: {e}")
            # Fallback to empty results rather than crashing
            return

    async def list_buckets(self):
        """List all storage buckets."""
        try:
            storage_client = await self.get_storage_client()

            for bucket in storage_client.list_buckets():
                # Get IAM policy
                iam_policy = bucket.get_iam_policy()
                bindings = []
                for binding in iam_policy.bindings:
                    bindings.append(
                        {"role": binding["role"], "members": list(binding["members"])}
                    )

                bucket_dict = {
                    "id": bucket.id,
                    "name": bucket.name,
                    "location": bucket.location,
                    "storageClass": bucket.storage_class,
                    "timeCreated": (
                        bucket.time_created.isoformat() if bucket.time_created else None
                    ),
                    "iam": {"bindings": bindings},
                    "publicAccessPrevention": getattr(
                        bucket, "public_access_prevention", "inherited"
                    ),
                    "uniformBucketLevelAccess": (
                        {
                            "enabled": bucket.iam_configuration.uniform_bucket_level_access_enabled
                        }
                        if bucket.iam_configuration
                        else {"enabled": False}
                    ),
                    "versioning": {"enabled": bucket.versioning_enabled},
                }
                yield bucket_dict
        except Exception as e:
            logger.error(f"Error listing GCP buckets: {e}")
            return

    async def list_iam_policy_bindings(self):
        """List IAM policy bindings."""
        try:
            iam_client = await self.get_iam_client()

            # Get project-level IAM policy
            from google.cloud import resourcemanager_v3

            request = resourcemanager_v3.GetIamPolicyRequest(  # type: ignore[attr-defined]
                resource=f"projects/{self.project_id}"
            )

            policy = iam_client.get_iam_policy(request=request)

            for binding in policy.bindings:
                for member in binding.members:
                    binding_dict = {
                        "member": member,
                        "role": binding.role,
                        "resource": f"projects/{self.project_id}",
                        "condition": (
                            binding.condition.expression if binding.condition else None
                        ),
                    }
                    yield binding_dict
        except Exception as e:
            logger.error(f"Error listing GCP IAM bindings: {e}")
            return


class GCPComputeInstanceTable(ProviderSecurityTable):
    """GCP Compute Engine instances as a security table."""

    def __init__(self):
        gce_columns = [
            SecurityColumn(
                "instance_id",
                ColumnType.TEXT,
                "GCE instance ID",
                required=True,
                source_field="id",
            ),
            SecurityColumn(
                "instance_name", ColumnType.TEXT, "Instance name", source_field="name"
            ),
            SecurityColumn(
                "machine_type",
                ColumnType.TEXT,
                "Machine type",
                source_field="machineType",
            ),
            SecurityColumn(
                "status", ColumnType.TEXT, "Instance status", source_field="status"
            ),
            SecurityColumn("zone", ColumnType.TEXT, "GCP zone", source_field="zone"),
            SecurityColumn(
                "network_interfaces",
                ColumnType.JSON,
                "Network interfaces",
                source_field="networkInterfaces",
            ),
            SecurityColumn(
                "external_ip",
                ColumnType.TEXT,
                "External IP address",
                transform="extract_external_ip",
            ),
            SecurityColumn(
                "internal_ip",
                ColumnType.TEXT,
                "Internal IP address",
                transform="extract_internal_ip",
            ),
            SecurityColumn(
                "service_accounts",
                ColumnType.JSON,
                "Service accounts",
                source_field="serviceAccounts",
            ),
            SecurityColumn(
                "scopes", ColumnType.JSON, "OAuth scopes", transform="extract_scopes"
            ),
            SecurityColumn(
                "labels", ColumnType.JSON, "Instance labels", source_field="labels"
            ),
            SecurityColumn(
                "network_tags",
                ColumnType.JSON,
                "Network tags",
                transform="extract_network_tags",
            ),
        ]

        super().__init__(
            name="gcp_compute_instance",
            description="GCP Compute Engine instances with security configuration",
            provider_name="gcp",
            columns=gce_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch GCE instances from GCP API."""
        config = ctx.config or {}
        client = GCPClient(project_id=config.get("gcp_project_id"))

        try:
            # Authenticate if needed
            await client.authenticate()

            async for instance in client.list_instances():
                # Add provider metadata
                instance["provider"] = "gcp"
                instance["account_id"] = await client.get_project_id()
                instance["region"] = "global"
                instance["created_at"] = self._parse_gcp_timestamp(
                    instance.get("creationTimestamp")
                )
                instance["updated_at"] = datetime.now()
                instance["tags"] = instance.get("tags", {}).get("items", [])
                instance["metadata"] = {"gcp_instance_data": instance}

                yield instance

        except Exception as e:
            logger.error(f"Error fetching GCP instances: {e}")
            # Return empty results instead of raising to prevent query engine failures
            return

    def extract_external_ip(self, instance_data: dict[str, Any]) -> str | None:
        """Extract external IP from network interfaces."""
        interfaces = instance_data.get("networkInterfaces", [])
        for interface in interfaces:
            access_configs = interface.get("accessConfigs", [])
            for config in access_configs:
                if "natIP" in config:
                    return config["natIP"]
        return None

    def extract_internal_ip(self, instance_data: dict[str, Any]) -> str | None:
        """Extract internal IP from network interfaces."""
        interfaces = instance_data.get("networkInterfaces", [])
        for interface in interfaces:
            if "networkIP" in interface:
                return interface["networkIP"]
        return None

    def extract_scopes(self, instance_data: dict[str, Any]) -> list[str]:
        """Extract OAuth scopes from service accounts."""
        scopes = []
        service_accounts = instance_data.get("serviceAccounts", [])
        for sa in service_accounts:
            scopes.extend(sa.get("scopes", []))
        return scopes

    def extract_network_tags(self, instance_data: dict[str, Any]) -> list[str]:
        """Extract network tags."""
        return instance_data.get("tags", {}).get("items", [])

    def _parse_gcp_timestamp(self, timestamp_str: str | None) -> datetime | None:
        """Parse GCP timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


class GCPStorageBucketTable(ProviderSecurityTable):
    """GCP Cloud Storage buckets as a security table."""

    def __init__(self):
        bucket_columns = [
            SecurityColumn(
                "bucket_id",
                ColumnType.TEXT,
                "Bucket ID",
                required=True,
                source_field="id",
            ),
            SecurityColumn(
                "bucket_name", ColumnType.TEXT, "Bucket name", source_field="name"
            ),
            SecurityColumn(
                "location", ColumnType.TEXT, "Bucket location", source_field="location"
            ),
            SecurityColumn(
                "storage_class",
                ColumnType.TEXT,
                "Storage class",
                source_field="storageClass",
            ),
            SecurityColumn(
                "public_access_prevention",
                ColumnType.TEXT,
                "Public access prevention",
                source_field="publicAccessPrevention",
            ),
            SecurityColumn(
                "uniform_bucket_access",
                ColumnType.BOOLEAN,
                "Uniform bucket-level access",
                transform="check_uniform_access",
            ),
            SecurityColumn(
                "iam_bindings",
                ColumnType.JSON,
                "IAM policy bindings",
                source_field="iam",
            ),
            SecurityColumn(
                "is_public",
                ColumnType.BOOLEAN,
                "Bucket is publicly accessible",
                transform="check_public_access",
            ),
            SecurityColumn(
                "versioning_enabled",
                ColumnType.BOOLEAN,
                "Versioning enabled",
                transform="check_versioning",
            ),
        ]

        super().__init__(
            name="gcp_storage_bucket",
            description="GCP Cloud Storage buckets with security settings",
            provider_name="gcp",
            columns=bucket_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch storage buckets from GCP API."""
        config = ctx.config or {}
        client = GCPClient(project_id=config.get("gcp_project_id"))

        try:
            # Authenticate if needed
            await client.authenticate()

            async for bucket in client.list_buckets():
                # Add provider metadata
                bucket["provider"] = "gcp"
                bucket["account_id"] = await client.get_project_id()
                bucket["region"] = bucket.get("location", "global")
                bucket["created_at"] = self._parse_gcp_timestamp(
                    bucket.get("timeCreated")
                )
                bucket["updated_at"] = datetime.now()
                bucket["tags"] = {}
                bucket["metadata"] = {"gcp_bucket_data": bucket}

                yield bucket

        except Exception as e:
            logger.error(f"Error fetching GCP storage buckets: {e}")
            return

    def check_uniform_access(self, bucket_data: dict[str, Any]) -> bool:
        """Check if uniform bucket-level access is enabled."""
        uniform_access = bucket_data.get("uniformBucketLevelAccess", {})
        return uniform_access.get("enabled", False)

    def check_public_access(self, bucket_data: dict[str, Any]) -> bool:
        """Check if bucket has public access."""
        iam = bucket_data.get("iam", {})
        bindings = iam.get("bindings", [])

        for binding in bindings:
            members = binding.get("members", [])
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                return True

        return False

    def check_versioning(self, bucket_data: dict[str, Any]) -> bool:
        """Check if versioning is enabled."""
        versioning = bucket_data.get("versioning", {})
        return versioning.get("enabled", False)

    def _parse_gcp_timestamp(self, timestamp_str: str | None) -> datetime | None:
        """Parse GCP timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None


class GCPIAMPolicyTable(ProviderSecurityTable):
    """GCP IAM policy bindings as a security table."""

    def __init__(self):
        iam_columns = [
            SecurityColumn(
                "member",
                ColumnType.TEXT,
                "IAM member",
                required=True,
                source_field="member",
            ),
            SecurityColumn(
                "role", ColumnType.TEXT, "IAM role", required=True, source_field="role"
            ),
            SecurityColumn(
                "resource", ColumnType.TEXT, "Resource", source_field="resource"
            ),
            SecurityColumn(
                "member_type",
                ColumnType.TEXT,
                "Member type (user, serviceAccount, group)",
                transform="extract_member_type",
            ),
            SecurityColumn(
                "is_primitive_role",
                ColumnType.BOOLEAN,
                "Is primitive role",
                transform="check_primitive_role",
            ),
            SecurityColumn(
                "has_condition",
                ColumnType.BOOLEAN,
                "Has conditional binding",
                transform="check_condition",
            ),
            SecurityColumn(
                "condition", ColumnType.JSON, "IAM condition", source_field="condition"
            ),
        ]

        super().__init__(
            name="gcp_iam_policy",
            description="GCP IAM policy bindings and permissions",
            provider_name="gcp",
            columns=iam_columns,
        )

    async def fetch_from_api(
        self, ctx: QueryContext
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Fetch IAM policy bindings from GCP API."""
        config = ctx.config or {}
        client = GCPClient(project_id=config.get("gcp_project_id"))

        try:
            # Authenticate if needed
            await client.authenticate()

            async for binding in client.list_iam_policy_bindings():
                # Add provider metadata
                binding["provider"] = "gcp"
                binding["account_id"] = await client.get_project_id()
                binding["region"] = "global"
                binding["created_at"] = datetime.now()
                binding["updated_at"] = datetime.now()
                binding["tags"] = {}
                binding["metadata"] = {"gcp_iam_data": binding}

                yield binding

        except Exception as e:
            logger.error(f"Error fetching GCP IAM policies: {e}")
            return

    def extract_member_type(self, binding_data: dict[str, Any]) -> str:
        """Extract member type from member string."""
        member = binding_data.get("member", "")
        if member.startswith("user:"):
            return "user"
        elif member.startswith("serviceAccount:"):
            return "serviceAccount"
        elif member.startswith("group:"):
            return "group"
        elif member == "allUsers":
            return "allUsers"
        elif member == "allAuthenticatedUsers":
            return "allAuthenticatedUsers"
        else:
            return "unknown"

    def check_primitive_role(self, binding_data: dict[str, Any]) -> bool:
        """Check if role is a primitive role."""
        role = binding_data.get("role", "")
        primitive_roles = ["roles/owner", "roles/editor", "roles/viewer"]
        return role in primitive_roles

    def check_condition(self, binding_data: dict[str, Any]) -> bool:
        """Check if binding has conditions."""
        return binding_data.get("condition") is not None


def register_gcp_tables():
    """Register all GCP tables with the query engine."""
    register_table(
        GCPComputeInstanceTable(), aliases=["gcp_instances", "gce_instances"]
    )
    register_table(GCPStorageBucketTable(), aliases=["gcp_buckets", "gcs_buckets"])
    register_table(GCPIAMPolicyTable(), aliases=["gcp_iam", "gcp_permissions"])
