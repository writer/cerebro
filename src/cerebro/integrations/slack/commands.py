from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs
from uuid import UUID

import structlog
from fastapi import Request
from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.core.models import Finding, Organization
from cerebro.integrations.slack.block_kit import findings_summary_blocks

logger = structlog.get_logger(__name__)


class SlackCommandError(Exception):
    """Raised when a Slack command cannot be processed."""


@dataclass
class SlackSlashCommand:
    """Parsed Slack slash command payload."""

    command: str
    text: str
    user_id: str
    team_id: str
    response_url: str | None = None
    channel_id: str | None = None
    channel_name: str | None = None
    user_name: str | None = None

    @property
    def arguments(self) -> list[str]:
        return [token for token in self.text.strip().split() if token]


@dataclass
class SlackCommandResponse:
    """Normalized Slack command response."""

    text: str | None = None
    response_type: str = "ephemeral"
    blocks: list[dict[str, Any]] | None = None
    attachments: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"response_type": self.response_type}
        if self.text is not None:
            payload["text"] = self.text
        if self.blocks is not None:
            payload["blocks"] = self.blocks
        if self.attachments is not None:
            payload["attachments"] = self.attachments
        return payload


class SlackRequestParser:
    """Parse and validate Slack slash command requests."""

    def __init__(
        self, signing_secret: str | None, tolerance_seconds: int = 300
    ) -> None:
        self.signing_secret = signing_secret
        self.tolerance_seconds = tolerance_seconds

    async def parse(self, request: Request) -> SlackSlashCommand:
        body_bytes = await request.body()
        if not body_bytes:
            raise SlackCommandError("Slack payload was empty.")

        body = body_bytes.decode("utf-8")
        timestamp = request.headers.get("X-Slack-Request-Timestamp")
        signature = request.headers.get("X-Slack-Signature")

        if self.signing_secret:
            self._verify_signature(timestamp, signature, body)
        else:
            logger.warning(
                "slack_signing_secret_missing",
                message="Skipping signature verification for Slack command",
            )

        form = parse_qs(body)

        def _get(key: str, default: str = "") -> str:
            values = form.get(key)
            return values[0] if values else default

        command = _get("command")
        text = _get("text")
        user_id = _get("user_id")
        team_id = _get("team_id")

        if not command or not user_id or not team_id:
            raise SlackCommandError("Missing required Slack command fields.")

        return SlackSlashCommand(
            command=command,
            text=text,
            user_id=user_id,
            team_id=team_id,
            response_url=_get("response_url") or None,
            channel_id=_get("channel_id") or None,
            channel_name=_get("channel_name") or None,
            user_name=_get("user_name") or None,
        )

    def _verify_signature(
        self, timestamp: str | None, signature: str | None, body: str
    ) -> None:
        if not timestamp or not signature:
            raise SlackCommandError("Missing Slack signature headers.")
        if not self.signing_secret:
            raise SlackCommandError("Signing secret not configured.")

        try:
            request_ts = int(timestamp)
        except ValueError as exc:  # pragma: no cover - defensive
            raise SlackCommandError("Invalid Slack timestamp header.") from exc

        current_ts = int(time.time())
        if abs(current_ts - request_ts) > self.tolerance_seconds:
            raise SlackCommandError("Slack request timestamp outside allowable window.")

        basestring = f"v0:{timestamp}:{body}"
        digest = hmac.new(
            self.signing_secret.encode("utf-8"),
            basestring.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        expected_signature = f"v0={digest}"

        if not hmac.compare_digest(expected_signature, signature):
            raise SlackCommandError("Slack signature verification failed.")


class SlackCommandService:
    """Handle Slack slash command actions."""

    def __init__(
        self, *, default_org_id: UUID | None = None, max_findings: int = 5
    ) -> None:
        self.default_org_id = UUID(str(default_org_id)) if default_org_id else None
        self.max_findings = max_findings

    async def handle_command(
        self, payload: SlackSlashCommand, db: AsyncSession
    ) -> SlackCommandResponse:
        args = payload.arguments
        if not args:
            return SlackCommandResponse(text=self._help_text())

        action = args[0].lower()
        if action == "findings":
            severity = args[1].lower() if len(args) > 1 else "critical"
            return await self._handle_findings(severity, payload, db)

        if action == "incident":
            return SlackCommandResponse(
                text="Incident workflows are coming soon. Track progress in Cerebro issue #25."
            )

        if action in {"help", "?"}:
            return SlackCommandResponse(text=self._help_text())

        return SlackCommandResponse(
            text=(
                f"Unknown subcommand `{action}`. Try `/cerebro help` for a list of available commands."
            )
        )

    async def _handle_findings(
        self,
        severity: str,
        payload: SlackSlashCommand,
        db: AsyncSession,
    ) -> SlackCommandResponse:
        normalized = severity.lower()
        allowed = {"critical", "high", "medium", "low", "all"}
        if normalized not in allowed:
            return SlackCommandResponse(
                text=("Invalid severity. Use one of: critical, high, medium, low, all.")
            )

        org = await self._resolve_org(payload.team_id, db)
        if not org:
            return SlackCommandResponse(
                text=(
                    "Could not map this Slack workspace to a Cerebro organization. "
                    "Set SLACK_DEFAULT_ORG_ID or configure a workspace mapping in organization settings."
                )
            )

        stmt: Select[Any] = (
            select(Finding)
            .where(Finding.org_id == org.org_id)
            .where(Finding.status == "open")
            .order_by(Finding.last_seen.desc())
            .limit(self.max_findings)
        )

        if normalized != "all":
            stmt = stmt.where(func.lower(Finding.severity) == normalized)

        result = await db.execute(stmt)
        findings = result.scalars().all()

        if not findings:
            return SlackCommandResponse(
                text=f"No {normalized} findings found for {org.name}."
            )

        severity_label = "All" if normalized == "all" else normalized.capitalize()
        fallback_text, blocks = findings_summary_blocks(
            org_name=org.name,
            severity_label=severity_label,
            findings=findings,
        )

        return SlackCommandResponse(
            text=fallback_text,
            blocks=blocks,
        )

    async def _resolve_org(
        self, team_id: str, db: AsyncSession
    ) -> Organization | None:
        if self.default_org_id:
            org = await db.get(Organization, self.default_org_id)
            if org:
                return org
            logger.warning(
                "slack_default_org_not_found",
                org_id=str(self.default_org_id),
            )

        if not team_id:
            return None

        stmt = (
            select(Organization)
            .where(Organization.slack_config.is_not(None))
            .where(Organization.slack_config["team_id"].astext == team_id)
            .limit(1)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    def _help_text() -> str:
        return (
            "Available commands:\n"
            "• `/cerebro findings [severity]` - show recent findings (severity defaults to critical).\n"
            "• `/cerebro incident <id>` - link an incident to an agent session (coming soon)."
        )
