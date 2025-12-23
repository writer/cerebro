"""Database-backed configuration and helpers for Serval integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.encryption import SecretEncryptionService
from cerebro.core.models import ServalIntegration


@dataclass
class ServalIntegrationSettings:
    """Decrypted Serval configuration for an organization."""

    org_id: UUID
    api_base_url: str
    team_id: str
    client_id: str
    client_secret: str
    default_status_id: Optional[str]
    default_priority_id: Optional[str]
    default_created_by_user_id: str
    default_requester_user_id: Optional[str]
    default_assigned_user_id: Optional[str]
    status_map: Dict[str, str]
    priority_map: Dict[str, str]
    status_reverse_map: Dict[str, str]
    priority_reverse_map: Dict[str, str]


class ServalIntegrationRepository:
    """Repository for persisting Serval integration configuration."""

    def __init__(
        self,
        db: AsyncSession,
        *,
        encryption_service: SecretEncryptionService | None = None,
    ) -> None:
        self._db = db
        self._encryption = encryption_service or SecretEncryptionService()

    async def get(self, org_id: UUID) -> Optional[ServalIntegrationSettings]:
        """Load decrypted settings for the organization if present."""
        stmt = select(ServalIntegration).where(ServalIntegration.org_id == org_id)
        result = await self._db.execute(stmt)
        record = result.scalar_one_or_none()
        if record is None:
            return None
        return await self._record_to_settings(record)

    async def list_all(self) -> list[ServalIntegrationSettings]:
        """Return decrypted settings for every configured organization."""
        stmt = select(ServalIntegration)
        result = await self._db.scalars(stmt)
        records = list(result)
        settings: list[ServalIntegrationSettings] = []
        for record in records:
            settings.append(await self._record_to_settings(record))
        return settings

    async def upsert(
        self,
        *,
        org_id: UUID,
        api_base_url: str,
        team_id: str,
        client_id: str,
        client_secret: str,
        default_created_by_user_id: str,
        default_status_id: Optional[str] = None,
        default_priority_id: Optional[str] = None,
        default_requester_user_id: Optional[str] = None,
        default_assigned_user_id: Optional[str] = None,
        status_map: Optional[Dict[str, str]] = None,
        priority_map: Optional[Dict[str, str]] = None,
    ) -> ServalIntegrationSettings:
        """Create or update the configuration while rotating stored credentials."""
        encrypted_client_id, encrypted_client_id_dek = (
            await self._encryption.encrypt_secret(client_id)
        )
        encrypted_client_secret, encrypted_client_secret_dek = (
            await self._encryption.encrypt_secret(client_secret)
        )

        stmt = select(ServalIntegration).where(ServalIntegration.org_id == org_id)
        result = await self._db.execute(stmt)
        record = result.scalar_one_or_none()

        settings_payload: Dict[str, Any] = {
            "status_map": status_map or {},
            "priority_map": priority_map or {},
        }

        if record is None:
            record = ServalIntegration(
                org_id=org_id,
                api_base_url=api_base_url,
                team_id=team_id,
                default_status_id=default_status_id,
                default_priority_id=default_priority_id,
                default_created_by_user_id=default_created_by_user_id,
                default_requester_user_id=default_requester_user_id,
                default_assigned_user_id=default_assigned_user_id,
                settings=settings_payload,
                encrypted_client_id=encrypted_client_id,
                encrypted_client_id_dek=encrypted_client_id_dek,
                encrypted_client_secret=encrypted_client_secret,
                encrypted_client_secret_dek=encrypted_client_secret_dek,
            )
            self._db.add(record)
        else:
            record.api_base_url = api_base_url
            record.team_id = team_id
            record.default_status_id = default_status_id
            record.default_priority_id = default_priority_id
            record.default_created_by_user_id = default_created_by_user_id
            record.default_requester_user_id = default_requester_user_id
            record.default_assigned_user_id = default_assigned_user_id
            record.settings = settings_payload
            record.encrypted_client_id = encrypted_client_id
            record.encrypted_client_id_dek = encrypted_client_id_dek
            record.encrypted_client_secret = encrypted_client_secret
            record.encrypted_client_secret_dek = encrypted_client_secret_dek

        await self._db.commit()
        result = await self.get(org_id)
        assert result is not None  # Record was just created/updated
        return result

    async def delete(self, org_id: UUID) -> None:
        """Remove the integration record for the supplied organization."""
        stmt = select(ServalIntegration).where(ServalIntegration.org_id == org_id)
        result = await self._db.execute(stmt)
        record = result.scalar_one_or_none()
        if record is None:
            return
        await self._db.delete(record)
        await self._db.commit()

    async def _record_to_settings(
        self, record: ServalIntegration
    ) -> ServalIntegrationSettings:
        """Convert a SQLAlchemy row into the decrypted settings dataclass."""
        client_id = await self._encryption.decrypt_secret(
            record.encrypted_client_id,
            record.encrypted_client_id_dek,
        )
        client_secret = await self._encryption.decrypt_secret(
            record.encrypted_client_secret,
            record.encrypted_client_secret_dek,
        )

        raw_settings = record.settings or {}
        status_map = dict(raw_settings.get("status_map") or {})
        priority_map = dict(raw_settings.get("priority_map") or {})

        status_reverse_map = {str(v): str(k) for k, v in status_map.items() if v}
        priority_reverse_map = {str(v): str(k) for k, v in priority_map.items() if v}

        return ServalIntegrationSettings(
            org_id=record.org_id,
            api_base_url=record.api_base_url,
            team_id=record.team_id,
            client_id=client_id,
            client_secret=client_secret,
            default_status_id=record.default_status_id,
            default_priority_id=record.default_priority_id,
            default_created_by_user_id=record.default_created_by_user_id,
            default_requester_user_id=record.default_requester_user_id,
            default_assigned_user_id=record.default_assigned_user_id,
            status_map=status_map,
            priority_map=priority_map,
            status_reverse_map=status_reverse_map,
            priority_reverse_map=priority_reverse_map,
        )
