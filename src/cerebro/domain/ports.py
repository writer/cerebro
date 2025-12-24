"""Domain ports - interfaces for external dependencies."""

from collections.abc import AsyncGenerator
from typing import Any, Protocol
from uuid import UUID

from .entities import (
    CollectionJobEntity,
    ConfigEntity,
    FindingEntity,
    IamPermissionEntity,
    IdentityClusterEntity,
    PrincipalEntity,
    ResourceEntity,
    RuleEntity,
)


class ProviderPort(Protocol):
    """Port for provider integrations."""

    @property
    def name(self) -> str:
        """Get provider name."""
        ...

    async def authenticate(self) -> bool:
        """Authenticate with the provider."""
        ...

    async def discover_resources(
        self, resource_types: list[str] | None = None
    ) -> AsyncGenerator[ResourceEntity, None]:
        """Discover resources from the provider."""
        ...

    async def discover_principals(self) -> AsyncGenerator[PrincipalEntity, None]:
        """Discover principals from the provider."""
        ...

    async def get_resource_configuration(
        self, resource: ResourceEntity
    ) -> ConfigEntity:
        """Get current configuration for a resource."""
        ...

    async def discover_iam_edges(
        self, resource: ResourceEntity | None = None
    ) -> AsyncGenerator[IamPermissionEntity, None]:
        """Discover IAM permissions."""
        ...


class RepositoryPort(Protocol):
    """Port for data persistence."""

    async def save_resources(
        self, account_id: UUID, resources: list[ResourceEntity]
    ) -> dict[str, UUID]:
        """Save resources and return mapping of external_id -> resource_id."""
        ...

    async def save_principals(
        self, account_id: UUID, principals: list[PrincipalEntity]
    ) -> dict[str, UUID]:
        """Save principals and return mapping of external_id -> principal_id."""
        ...

    async def save_configurations(
        self, resource_id_map: dict[str, UUID], configs: list[ConfigEntity]
    ) -> int:
        """Save configuration snapshots."""
        ...

    async def save_iam_permissions(
        self,
        account_id: UUID,
        resource_id_map: dict[str, UUID],
        principal_id_map: dict[str, UUID],
        permissions: list[IamPermissionEntity],
    ) -> int:
        """Save IAM permission edges."""
        ...

    async def get_findings_by_status(
        self, org_id: UUID, status: str, limit: int = 100, offset: int = 0
    ) -> list[FindingEntity]:
        """Get findings by status."""
        ...

    async def save_finding(self, org_id: UUID, finding: FindingEntity) -> UUID:
        """Save a finding."""
        ...

    async def update_finding(self, finding_id: UUID, finding: FindingEntity) -> None:
        """Update an existing finding."""
        ...

    async def save_identity_clusters(
        self, org_id: UUID, clusters: list[IdentityClusterEntity]
    ) -> int:
        """Save identity clusters."""
        ...


class RuleEnginePort(Protocol):
    """Port for rule evaluation."""

    async def compile_rule(self, expression: str) -> Any:
        """Compile a rule expression."""
        ...

    async def evaluate_rule(
        self,
        rule: RuleEntity,
        resource: ResourceEntity | None = None,
        config: ConfigEntity | None = None,
        principal: PrincipalEntity | None = None,
        iam_permission: IamPermissionEntity | None = None,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Evaluate a rule against given entities."""
        ...

    async def evaluate_rules_batch(
        self,
        rules: list[RuleEntity],
        resources: list[ResourceEntity],
        configs: dict[str, ConfigEntity],
        context: dict[str, Any] | None = None,
    ) -> dict[UUID, list[bool]]:
        """Batch evaluate multiple rules against multiple resources."""
        ...


class IdentityStitcherPort(Protocol):
    """Port for identity stitching across providers."""

    async def find_identity_clusters(
        self, org_id: UUID, principals: list[PrincipalEntity]
    ) -> list[IdentityClusterEntity]:
        """Find identity clusters for given principals."""
        ...

    async def get_unified_identity(
        self, principal: PrincipalEntity
    ) -> IdentityClusterEntity | None:
        """Get unified identity for a principal."""
        ...


class NotificationPort(Protocol):
    """Port for notifications and alerts."""

    async def send_finding_alert(
        self, finding: FindingEntity, recipients: list[str]
    ) -> bool:
        """Send alert for a new finding."""
        ...

    async def send_collection_summary(
        self, job: CollectionJobEntity, recipients: list[str]
    ) -> bool:
        """Send collection job summary."""
        ...


class EventPublisherPort(Protocol):
    """Port for publishing domain events."""

    async def publish_resource_discovered(self, resource: ResourceEntity) -> None:
        """Publish resource discovered event."""
        ...

    async def publish_finding_created(self, finding: FindingEntity) -> None:
        """Publish finding created event."""
        ...

    async def publish_configuration_changed(
        self,
        resource: ResourceEntity,
        old_config: ConfigEntity | None,
        new_config: ConfigEntity,
    ) -> None:
        """Publish configuration changed event."""
        ...


class AuditLogPort(Protocol):
    """Port for audit logging."""

    async def log_user_action(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log user action for audit trail."""
        ...

    async def log_system_event(self, event_type: str, details: dict[str, Any]) -> None:
        """Log system event."""
        ...
