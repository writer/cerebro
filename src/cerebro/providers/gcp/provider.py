"""GCP provider implementation."""

from typing import List, Optional, AsyncGenerator
from datetime import datetime
import logging

from ..base import (
    BaseProvider,
    ResourceInfo,
    PrincipalInfo,
    ConfigurationSnapshot,
    IamPermission,
)

logger = logging.getLogger(__name__)


class GCPProvider(BaseProvider):
    """GCP provider for collecting resources, users, and permissions."""

    def __init__(self, account_id, project_id: str, **kwargs):
        """Initialize GCP provider."""
        super().__init__(account_id, **kwargs)
        self.project_id = project_id

    @property
    def name(self) -> str:
        """Get provider name."""
        return "gcp"

    async def authenticate(self) -> bool:
        """Authenticate with GCP."""
        try:
            from google.cloud import compute_v1
            from google.auth import default

            # Attempt to get default credentials
            credentials, project = default()

            # Test authentication with a simple API call
            compute_v1.InstancesClient(credentials=credentials)

            # If we get here, authentication is working
            logger.info(
                f"Successfully authenticated with GCP project: {project or self.project_id}"
            )
            return True

        except ImportError:
            logger.error(
                "GCP client libraries not installed. Run: pip install google-cloud-compute"
            )
            return False
        except Exception as e:
            logger.warning(f"GCP authentication failed: {e}")
            return False

    async def discover_resources(
        self, resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover GCP resources."""
        try:
            from google.cloud import compute_v1
            from google.auth import default

            credentials, _ = default()
            client = compute_v1.InstancesClient(credentials=credentials)

            # List compute instances
            request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
            page_result = client.aggregated_list(request=request)

            for zone, response in page_result:
                if hasattr(response, "instances") and response.instances:
                    for instance in response.instances:
                        yield ResourceInfo(
                            external_id=str(instance.id),
                            resource_type="gcp.compute.instance",
                            name=instance.name,
                            region=zone.split("/")[-1] if zone else "unknown",
                            tags=dict(instance.labels) if instance.labels else {},
                            created_at=datetime.utcnow(),
                            account_id=self.account_id,
                        )

        except ImportError:
            logger.error("GCP client libraries not installed")
            return
        except Exception as e:
            logger.error(f"Failed to discover GCP resources: {e}")
            return

    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover GCP principals (service accounts and users)."""
        try:
            from google.cloud import iam_admin_v1
            from google.auth import default

            credentials, _ = default()
            iam_client = iam_admin_v1.IAMClient(credentials=credentials)

            # List service accounts
            request = iam_admin_v1.ListServiceAccountsRequest(
                name=f"projects/{self.project_id}"
            )

            page_result = iam_client.list_service_accounts(request=request)

            for service_account in page_result:
                yield PrincipalInfo(
                    external_id=service_account.email,
                    principal_type="service_account",
                    display_name=service_account.display_name
                    or service_account.name.split("/")[-1],
                    email=service_account.email,
                    account_id=self.account_id,
                    metadata={
                        "unique_id": service_account.unique_id,
                        "enabled": not service_account.disabled,
                    },
                )

        except ImportError:
            logger.error(
                "GCP IAM client libraries not installed. Run: pip install google-cloud-iam"
            )
            return
        except Exception as e:
            logger.error(f"Failed to discover GCP principals: {e}")
            return

    async def get_resource_configuration(
        self, resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get GCP resource configuration."""
        try:
            from google.cloud import compute_v1
            from google.auth import default

            if resource.resource_type == "gcp.compute.instance":
                credentials, _ = default()
                client = compute_v1.InstancesClient(credentials=credentials)

                # Parse zone from resource region (assuming region contains zone info)
                zone = resource.region

                request = compute_v1.GetInstanceRequest(
                    project=self.project_id, zone=zone, instance=resource.name
                )

                instance = client.get(request=request)

                # Create normalized configuration
                config = {
                    "id": str(instance.id),
                    "name": instance.name,
                    "status": instance.status,
                    "machine_type": (
                        instance.machine_type.split("/")[-1]
                        if instance.machine_type
                        else None
                    ),
                    "zone": zone,
                    "creation_timestamp": instance.creation_timestamp,
                    "network_interfaces": [
                        {
                            "network": (
                                ni.network.split("/")[-1] if ni.network else None
                            ),
                            "subnetwork": (
                                ni.subnetwork.split("/")[-1] if ni.subnetwork else None
                            ),
                            "internal_ip": (
                                ni.network_i_p if hasattr(ni, "network_i_p") else None
                            ),
                            "external_ip": (
                                ni.access_configs[0].nat_i_p
                                if ni.access_configs
                                else None
                            ),
                        }
                        for ni in instance.network_interfaces
                    ],
                    "disks": [
                        {
                            "device_name": disk.device_name,
                            "boot": disk.boot,
                            "auto_delete": disk.auto_delete,
                            "source": (
                                disk.source.split("/")[-1] if disk.source else None
                            ),
                        }
                        for disk in instance.disks
                    ],
                    "service_accounts": (
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
                    "labels": dict(instance.labels) if instance.labels else {},
                    "metadata": (
                        {item.key: item.value for item in instance.metadata.items}
                        if instance.metadata
                        else {}
                    ),
                }

                return ConfigurationSnapshot(
                    resource_external_id=resource.external_id,
                    captured_at=datetime.utcnow(),
                    normalized_config=config,
                )

        except ImportError:
            logger.error("GCP client libraries not installed")
        except Exception as e:
            logger.error(f"Failed to get GCP resource configuration: {e}")

        # Fallback empty configuration
        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config={},
        )

    async def discover_iam_edges(
        self, resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover GCP IAM permissions."""
        try:
            from google.cloud import resourcemanager_v3
            from google.iam.v1 import iam_policy_pb2
            from google.auth import default

            credentials, _ = default()

            # Get IAM policy for the project
            resourcemanager_client = resourcemanager_v3.ProjectsClient(
                credentials=credentials
            )

            # Get IAM policy for the project
            request = iam_policy_pb2.GetIamPolicyRequest(
                resource=f"projects/{self.project_id}"
            )

            policy = resourcemanager_client.get_iam_policy(request=request)

            # Process policy bindings
            for binding in policy.bindings:
                role = binding.role
                for member in binding.members:
                    # Extract principal info from member string
                    # Members are in format: "user:email", "serviceAccount:email", etc.
                    member_type, principal_external_id = (
                        member.split(":", 1) if ":" in member else ("user", member)
                    )

                    # Map GCP roles to simplified permissions
                    permissions = self._map_gcp_role_to_permissions(role)

                    for permission in permissions:
                        yield IamPermission(
                            principal_external_id=principal_external_id,
                            resource_external_id=(
                                resource.external_id
                                if resource
                                else f"projects/{self.project_id}"
                            ),
                            permission=permission,
                            via=f"role:{role}",
                        )

        except ImportError:
            logger.error(
                "GCP Resource Manager client libraries not installed. Run: pip install google-cloud-resource-manager"
            )
            return
        except Exception as e:
            logger.error(f"Failed to discover GCP IAM edges: {e}")
            return

    def _map_gcp_role_to_permissions(self, role: str) -> List[str]:
        """Map GCP IAM role to simplified permission names."""
        # Basic role mapping - in production this would be more comprehensive
        role_mapping = {
            "roles/owner": ["admin", "read", "write", "delete"],
            "roles/editor": ["read", "write"],
            "roles/viewer": ["read"],
            "roles/compute.admin": ["compute.admin", "read", "write"],
            "roles/compute.viewer": ["compute.read", "read"],
            "roles/storage.admin": ["storage.admin", "read", "write"],
            "roles/storage.objectViewer": ["storage.read", "read"],
            "roles/iam.serviceAccountUser": ["iam.serviceAccount.actAs"],
        }

        # Default to the role name if not in mapping
        return role_mapping.get(role, [role.replace("roles/", "")])
