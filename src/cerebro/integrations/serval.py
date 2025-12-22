"""Serval public API client utilities."""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Sequence

import httpx

logger = logging.getLogger(__name__)


def _serialize_datetime(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


@dataclass
class ServalConfig:
    base_url: str
    client_id: str
    client_secret: str
    verify: bool = True
    timeout: float = 30.0
    token_grace_seconds: int = 30

    def __post_init__(self) -> None:
        """Normalize the base URL so consumers can provide forms with or without trailing slash."""
        base = (self.base_url or "https://public.api.serval.com").strip()
        self.base_url = base.rstrip("/") or "https://public.api.serval.com"


class ServalError(RuntimeError):
    """Raised when Serval API interactions fail."""


@dataclass
class _Token:
    value: str
    token_type: str
    expires_at: datetime


class ServalClient:
    """Async client for Serval's public API."""

    def __init__(
        self,
        config: ServalConfig,
        *,
        client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        self._config = config
        self._client = client
        self._owns_client = client is None
        self._token: Optional[_Token] = None
        self._token_lock = asyncio.Lock()

    async def __aenter__(self) -> "ServalClient":
        self._ensure_client_initialized()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _ensure_client_initialized(self) -> None:
        if self._client is None:
            headers = {
                "Accept": "application/json",
            }
            self._client = httpx.AsyncClient(
                base_url=self._config.base_url,
                timeout=self._config.timeout,
                verify=self._config.verify,
                headers=headers,
            )

    def _get_client(self) -> httpx.AsyncClient:
        self._ensure_client_initialized()
        assert self._client is not None  # for mypy
        return self._client

    async def list_tickets(
        self,
        *,
        team_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[dict[str, Any]]:
        """Return tickets filtered by team and updated timestamp for incremental sync."""
        params: Dict[str, Any] = {}
        if team_id:
            params["teamId"] = team_id
        if since is not None:
            since_utc = since.astimezone(timezone.utc)
            params["startTime.seconds"] = str(int(since_utc.timestamp()))
            params["startTime.nanos"] = str(int(since_utc.microsecond * 1000))

        payload = await self._request_json("GET", "/v2/tickets", params=params or None)
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    async def get_ticket(self, ticket_id: str) -> dict[str, Any]:
        payload = await self._request_json("GET", f"/v2/tickets/{ticket_id}")
        data = payload.get("data")
        if isinstance(data, dict):
            return data
        raise ServalError("Serval get ticket response missing data")

    async def create_ticket(
        self,
        *,
        team_id: str,
        name: str,
        description: str,
        created_by_user_id: str,
        assigned_to_user_id: Optional[str] = None,
        requester_user_id: Optional[str] = None,
        parent_ticket_id: Optional[str] = None,
        channel_sync_targets: Optional[Sequence[Dict[str, Any]]] = None,
        created_at: Optional[Any] = None,
    ) -> dict[str, Any]:
        """Create a Serval ticket and return the normalized response payload."""
        payload: Dict[str, Any] = {
            "teamId": team_id,
            "name": name,
            "description": description,
            "createdByUserId": created_by_user_id,
        }
        if assigned_to_user_id:
            payload["assignedToUserId"] = assigned_to_user_id
        if requester_user_id:
            payload["requesterUserId"] = requester_user_id
        if parent_ticket_id:
            payload["parentTicketId"] = parent_ticket_id
        if channel_sync_targets:
            payload["channelSyncTargets"] = list(channel_sync_targets)
        if created_at is not None:
            payload["createdAt"] = _serialize_datetime(created_at)

        data = await self._request_json("POST", "/v2/tickets", json=payload)
        ticket = data.get("data")
        if isinstance(ticket, dict):
            return ticket
        raise ServalError("Serval create ticket response missing data")

    async def update_ticket(
        self,
        ticket_id: str,
        *,
        name: Optional[str] = None,
        description: Optional[str] = None,
        statusId: Optional[str] = None,
        priorityId: Optional[str] = None,
        assignedToUserId: Optional[str] = None,
        labelIds: Optional[list[str]] = None,
        slaStartedAt: Optional[Any] = None,
        slaBreachesAt: Optional[Any] = None,
        escalationLevel: Optional[str] = None,
        requesterUserId: Optional[str] = None,
    ) -> dict[str, Any]:
        """Patch mutable ticket fields and return the updated ticket body."""
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if statusId is not None:
            body["statusId"] = statusId
        if priorityId is not None:
            body["priorityId"] = priorityId
        if assignedToUserId is not None:
            body["assignedToUserId"] = assignedToUserId
        if labelIds is not None:
            body["labelIds"] = labelIds
        if slaStartedAt is not None:
            body["slaStartedAt"] = _serialize_datetime(slaStartedAt)
        if slaBreachesAt is not None:
            body["slaBreachesAt"] = _serialize_datetime(slaBreachesAt)
        if escalationLevel is not None:
            body["escalationLevel"] = escalationLevel
        if requesterUserId is not None:
            body["requesterUserId"] = requesterUserId

        if not body:
            raise ValueError("update_ticket requires at least one field to update")

        data = await self._request_json("PUT", f"/v2/tickets/{ticket_id}", json=body)
        ticket = data.get("data")
        if isinstance(ticket, dict):
            return ticket
        raise ServalError("Serval update ticket response missing data")

    async def list_statuses(
        self, *, team_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Fetch available workflow statuses from Serval."""
        params: Dict[str, Any] = {}
        if team_id:
            params["teamId"] = team_id
        payload = await self._request_json("GET", "/v2/statuses", params=params or None)
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    async def list_priorities(
        self, *, team_id: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Fetch available priority options for configuration surfaces."""
        params: Dict[str, Any] = {}
        if team_id:
            params["teamId"] = team_id
        payload = await self._request_json(
            "GET", "/v2/priorities", params=params or None
        )
        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    async def _ensure_token(self) -> _Token:
        """Return a cached token or refresh it when past the grace window."""
        if self._token and not self._token_expired(self._token):
            return self._token
        async with self._token_lock:
            if self._token and not self._token_expired(self._token):
                return self._token
            token = await self._fetch_token()
            self._token = token
            return token

    def _token_expired(self, token: _Token) -> bool:
        return datetime.now(timezone.utc) >= token.expires_at

    async def _fetch_token(self) -> _Token:
        client = self._get_client()
        headers = {
            "Authorization": self._build_basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        try:
            response = await client.post(
                "/v2/auth/token",
                headers=headers,
                data={"grant_type": "client_credentials"},
            )
            response.raise_for_status()
        except httpx.RequestError as exc:
            raise ServalError(f"Serval token request failed: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise ServalError(
                f"Serval token request failed with status {exc.response.status_code}"
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ServalError("Serval token response was not valid JSON") from exc

        access_token = payload.get("access_token")
        token_type = payload.get("token_type") or "Bearer"
        expires_in = int(payload.get("expires_in") or 0)
        if not access_token:
            raise ServalError("Serval token response missing access_token")
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=max(expires_in - self._config.token_grace_seconds, 1)
        )
        return _Token(value=access_token, token_type=token_type, expires_at=expires_at)

    def _build_basic_auth_header(self) -> str:
        raw = f"{self._config.client_id}:{self._config.client_secret}".encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")
        return f"Basic {encoded}"

    async def _request_json(
        self, method: str, path: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Make an authenticated request and parse the JSON response."""
        response = await self._request(method, path, **kwargs)
        try:
            return response.json()
        except ValueError as exc:
            raise ServalError("Serval API response was not valid JSON") from exc

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Perform the low-level HTTP call with authorization headers injected."""
        token = await self._ensure_token()
        client = self._get_client()
        headers = kwargs.pop("headers", {}) or {}
        headers.setdefault("Authorization", f"{token.token_type} {token.value}")
        headers.setdefault("Accept", "application/json")
        try:
            response = await client.request(method, path, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except httpx.RequestError as exc:
            raise ServalError(f"Serval request error: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text
            if len(detail) > 1024:
                detail = detail[:1024] + "…"
            raise ServalError(
                f"Serval API request to {exc.request.method} {exc.request.url.path} "
                f"failed with status {exc.response.status_code}: {detail}"
            ) from exc


__all__ = [
    "ServalClient",
    "ServalConfig",
    "ServalError",
]
