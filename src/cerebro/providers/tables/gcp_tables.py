"""
GCP provider table implementations.

Exposes GCP security resources as SQL tables following Steampipe patterns.
"""

import asyncio
import logging
from typing import AsyncGenerator, Dict, Any, List, Optional
from datetime import datetime

from ...query.table import ProviderSecurityTable, QueryContext
from ...query.registry import register_table
from ...query.schema import SecurityColumn, ColumnType

logger = logging.getLogger(__name__)

# Mock GCP client for demonstration
class GCPClient:
    async def get_client(self, service: str, project_id: str = "demo-project"):
        return MockGCPService()
    
    async def get_project_id(self) -> str:
        return "demo-project-123456"

class MockGCPService:
    async def list_instances(self):
        instances = [{
            "id": "1234567890123456789",
            "name": "web-server-1",
            "machineType": "projects/demo-project/zones/us-central1-a/machineTypes/n1-standard-1",
            "status": "RUNNING",
            "zone": "projects/demo-project/zones/us-central1-a",
            "networkInterfaces": [{
                "accessConfigs": [{"natIP": "34.123.45.67"}],
                "networkIP": "10.128.0.2"
            }],
            "serviceAccounts": [{
                "email": "compute@demo-project.iam.gserviceaccount.com",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
            }],
            "creationTimestamp": "2024-01-01T12:00:00.000-08:00",
            "tags": {"items": ["web", "production"]}
        }]
        for instance in instances:
            yield instance
    
    async def list_buckets(self):
        buckets = [{
            "id": "demo-storage-bucket-123",
            "name": "demo-storage-bucket",
            "location": "US",
            "storageClass": "STANDARD",
            "iam": {
                "bindings": [{
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers"]
                }]
            },
            "publicAccessPrevention": "inherited",
            "uniformBucketLevelAccess": {"enabled": False},
            "timeCreated": "2024-01-01T12:00:00.000Z"
        }]
        for bucket in buckets:
            yield bucket
    
    async def list_iam_policy_bindings(self):
        bindings = [{
            "member": "user:admin@demo-project.com",
            "role": "roles/owner",
            "resource": "projects/demo-project",
            "condition": None
        }, {
            "member": "serviceAccount:compute@demo-project.iam.gserviceaccount.com", 
            "role": "roles/compute.instanceAdmin",
            "resource": "projects/demo-project",
            "condition": None
        }]
        for binding in bindings:
            yield binding


class GCPComputeInstanceTable(ProviderSecurityTable):
    """GCP Compute Engine instances as a security table."""
    
    def __init__(self):
        gce_columns = [
            SecurityColumn("instance_id", ColumnType.TEXT, "GCE instance ID", required=True, source_field="id"),
            SecurityColumn("instance_name", ColumnType.TEXT, "Instance name", source_field="name"),
            SecurityColumn("machine_type", ColumnType.TEXT, "Machine type", source_field="machineType"),
            SecurityColumn("status", ColumnType.TEXT, "Instance status", source_field="status"),
            SecurityColumn("zone", ColumnType.TEXT, "GCP zone", source_field="zone"),
            SecurityColumn("network_interfaces", ColumnType.JSON, "Network interfaces", source_field="networkInterfaces"),
            SecurityColumn("external_ip", ColumnType.TEXT, "External IP address", transform="extract_external_ip"),
            SecurityColumn("internal_ip", ColumnType.TEXT, "Internal IP address", transform="extract_internal_ip"),
            SecurityColumn("service_accounts", ColumnType.JSON, "Service accounts", source_field="serviceAccounts"),
            SecurityColumn("scopes", ColumnType.JSON, "OAuth scopes", transform="extract_scopes"),
            SecurityColumn("labels", ColumnType.JSON, "Instance labels", source_field="labels"),
            SecurityColumn("network_tags", ColumnType.JSON, "Network tags", transform="extract_network_tags"),
        ]
        
        super().__init__(
            name="gcp_compute_instance",
            description="GCP Compute Engine instances with security configuration",
            provider_name="gcp",
            columns=gce_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch GCE instances from GCP API."""
        client = GCPClient()
        
        try:
            gcp_service = await client.get_client("compute")
            
            async for instance in gcp_service.list_instances():
                # Add provider metadata
                instance["provider"] = "gcp"
                instance["account_id"] = await client.get_project_id()
                instance["region"] = "global"
                instance["created_at"] = self._parse_gcp_timestamp(instance.get("creationTimestamp"))
                instance["updated_at"] = datetime.now()
                instance["tags"] = instance.get("tags", {}).get("items", [])
                instance["metadata"] = {"gcp_instance_data": instance}
                
                yield instance
                
        except Exception as e:
            logger.error(f"Error fetching GCP instances: {e}")
            raise
    
    def extract_external_ip(self, instance_data: Dict[str, Any]) -> Optional[str]:
        """Extract external IP from network interfaces."""
        interfaces = instance_data.get("networkInterfaces", [])
        for interface in interfaces:
            access_configs = interface.get("accessConfigs", [])
            for config in access_configs:
                if "natIP" in config:
                    return config["natIP"]
        return None
    
    def extract_internal_ip(self, instance_data: Dict[str, Any]) -> Optional[str]:
        """Extract internal IP from network interfaces."""
        interfaces = instance_data.get("networkInterfaces", [])
        for interface in interfaces:
            if "networkIP" in interface:
                return interface["networkIP"]
        return None
    
    def extract_scopes(self, instance_data: Dict[str, Any]) -> List[str]:
        """Extract OAuth scopes from service accounts."""
        scopes = []
        service_accounts = instance_data.get("serviceAccounts", [])
        for sa in service_accounts:
            scopes.extend(sa.get("scopes", []))
        return scopes
    
    def extract_network_tags(self, instance_data: Dict[str, Any]) -> List[str]:
        """Extract network tags."""
        return instance_data.get("tags", {}).get("items", [])
    
    def _parse_gcp_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse GCP timestamp string."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


class GCPStorageBucketTable(ProviderSecurityTable):
    """GCP Cloud Storage buckets as a security table."""
    
    def __init__(self):
        bucket_columns = [
            SecurityColumn("bucket_id", ColumnType.TEXT, "Bucket ID", required=True, source_field="id"),
            SecurityColumn("bucket_name", ColumnType.TEXT, "Bucket name", source_field="name"),
            SecurityColumn("location", ColumnType.TEXT, "Bucket location", source_field="location"),
            SecurityColumn("storage_class", ColumnType.TEXT, "Storage class", source_field="storageClass"),
            SecurityColumn("public_access_prevention", ColumnType.TEXT, "Public access prevention", source_field="publicAccessPrevention"),
            SecurityColumn("uniform_bucket_access", ColumnType.BOOLEAN, "Uniform bucket-level access", transform="check_uniform_access"),
            SecurityColumn("iam_bindings", ColumnType.JSON, "IAM policy bindings", source_field="iam"),
            SecurityColumn("is_public", ColumnType.BOOLEAN, "Bucket is publicly accessible", transform="check_public_access"),
            SecurityColumn("versioning_enabled", ColumnType.BOOLEAN, "Versioning enabled", transform="check_versioning"),
        ]
        
        super().__init__(
            name="gcp_storage_bucket",
            description="GCP Cloud Storage buckets with security settings",
            provider_name="gcp",
            columns=bucket_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch storage buckets from GCP API."""
        client = GCPClient()
        
        try:
            gcp_service = await client.get_client("storage")
            
            async for bucket in gcp_service.list_buckets():
                # Add provider metadata
                bucket["provider"] = "gcp"
                bucket["account_id"] = await client.get_project_id()
                bucket["region"] = bucket.get("location", "global")
                bucket["created_at"] = self._parse_gcp_timestamp(bucket.get("timeCreated"))
                bucket["updated_at"] = datetime.now()
                bucket["tags"] = {}
                bucket["metadata"] = {"gcp_bucket_data": bucket}
                
                yield bucket
                
        except Exception as e:
            logger.error(f"Error fetching GCP storage buckets: {e}")
            raise
    
    def check_uniform_access(self, bucket_data: Dict[str, Any]) -> bool:
        """Check if uniform bucket-level access is enabled."""
        uniform_access = bucket_data.get("uniformBucketLevelAccess", {})
        return uniform_access.get("enabled", False)
    
    def check_public_access(self, bucket_data: Dict[str, Any]) -> bool:
        """Check if bucket has public access."""
        iam = bucket_data.get("iam", {})
        bindings = iam.get("bindings", [])
        
        for binding in bindings:
            members = binding.get("members", [])
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                return True
        
        return False
    
    def check_versioning(self, bucket_data: Dict[str, Any]) -> bool:
        """Check if versioning is enabled."""
        versioning = bucket_data.get("versioning", {})
        return versioning.get("enabled", False)
    
    def _parse_gcp_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse GCP timestamp string.""" 
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None


class GCPIAMPolicyTable(ProviderSecurityTable):
    """GCP IAM policy bindings as a security table."""
    
    def __init__(self):
        iam_columns = [
            SecurityColumn("member", ColumnType.TEXT, "IAM member", required=True, source_field="member"),
            SecurityColumn("role", ColumnType.TEXT, "IAM role", required=True, source_field="role"),
            SecurityColumn("resource", ColumnType.TEXT, "Resource", source_field="resource"),
            SecurityColumn("member_type", ColumnType.TEXT, "Member type (user, serviceAccount, group)", transform="extract_member_type"),
            SecurityColumn("is_primitive_role", ColumnType.BOOLEAN, "Is primitive role", transform="check_primitive_role"),
            SecurityColumn("has_condition", ColumnType.BOOLEAN, "Has conditional binding", transform="check_condition"),
            SecurityColumn("condition", ColumnType.JSON, "IAM condition", source_field="condition"),
        ]
        
        super().__init__(
            name="gcp_iam_policy",
            description="GCP IAM policy bindings and permissions",
            provider_name="gcp", 
            columns=iam_columns
        )
    
    async def fetch_from_api(self, ctx: QueryContext) -> AsyncGenerator[Dict[str, Any], None]:
        """Fetch IAM policy bindings from GCP API."""
        client = GCPClient()
        
        try:
            gcp_service = await client.get_client("iam")
            
            async for binding in gcp_service.list_iam_policy_bindings():
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
            raise
    
    def extract_member_type(self, binding_data: Dict[str, Any]) -> str:
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
    
    def check_primitive_role(self, binding_data: Dict[str, Any]) -> bool:
        """Check if role is a primitive role."""
        role = binding_data.get("role", "")
        primitive_roles = ["roles/owner", "roles/editor", "roles/viewer"]
        return role in primitive_roles
    
    def check_condition(self, binding_data: Dict[str, Any]) -> bool:
        """Check if binding has conditions."""
        return binding_data.get("condition") is not None


def register_gcp_tables():
    """Register all GCP tables with the query engine."""
    register_table(GCPComputeInstanceTable(), aliases=['gcp_instances', 'gce_instances'])
    register_table(GCPStorageBucketTable(), aliases=['gcp_buckets', 'gcs_buckets'])
    register_table(GCPIAMPolicyTable(), aliases=['gcp_iam', 'gcp_permissions'])
