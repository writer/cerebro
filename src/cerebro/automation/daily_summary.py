"""Automation helpers for daily agent kickoff summaries."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession

from cerebro.agents.models import AgentSession, AgentType
from cerebro.core.models import Account, Finding, Organization

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class FindingDigest:
    """Lightweight representation of a finding for summaries."""

    finding_id: UUID
    title: str
    severity: str
    status: str
    last_seen: datetime
    account: str | None
    provider: str | None
    summary: str | None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["finding_id"] = str(self.finding_id)
        payload["last_seen"] = self.last_seen.isoformat()
        return payload


@dataclass
class DailySummaryResult:
    """Result payload produced after generating the daily summary."""

    org_id: UUID
    org_name: str
    session_id: UUID
    generated_at: datetime
    findings: list[FindingDigest]
    window_hours: int

    def total_findings(self) -> int:
        return len(self.findings)

    def severity_totals(self) -> dict[str, int]:
        counts: dict[str, int] = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in self.findings:
            key = finding.severity.lower()
            if key not in counts:
                counts[key] = 0
            counts[key] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": str(self.org_id),
            "org_name": self.org_name,
            "session_id": str(self.session_id),
            "generated_at": self.generated_at.isoformat(),
            "window_hours": self.window_hours,
            "total_findings": self.total_findings(),
            "severity_totals": self.severity_totals(),
            "findings": [finding.to_dict() for finding in self.findings],
        }


async def _fetch_org(db: AsyncSession, org_id: UUID) -> Organization:
    org = await db.get(Organization, org_id)
    if org is None:
        raise ValueError(f"Organization {org_id} not found")
    return org


async def _load_hot_findings(
    db: AsyncSession,
    org_id: UUID,
    limit: int,
    cutoff: datetime,
) -> list[FindingDigest]:
    severity_mapping = {level: index for index, level in enumerate(SEVERITY_ORDER)}
    severity_case = case(
        severity_mapping,
        value=Finding.severity,
        else_=len(SEVERITY_ORDER),
    )

    stmt = (
        select(
            Finding.finding_id,
            Finding.title,
            Finding.severity,
            Finding.status,
            Finding.last_seen,
            Finding.summary,
            Account.display_name,
            Account.provider,
        )
        .join(Account, Account.account_id == Finding.account_id)
        .where(
            Finding.org_id == org_id,
            Finding.status == "open",
            Finding.last_seen >= cutoff,
        )
        .order_by(severity_case, Finding.last_seen.desc())
        .limit(limit)
    )

    rows = (await db.execute(stmt)).all()

    return [
        FindingDigest(
            finding_id=row[0],
            title=row[1],
            severity=row[2],
            status=row[3],
            last_seen=row[4],
            summary=row[5],
            account=row[6],
            provider=row[7],
        )
        for row in rows
    ]


def _build_session_context(
    findings: Iterable[FindingDigest],
    generated_at: datetime,
    window_hours: int,
) -> dict[str, Any]:
    finding_ids = [str(finding.finding_id) for finding in findings]
    severity_totals: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.lower()
        severity_totals[key] = severity_totals.get(key, 0) + 1

    return {
        "automation": "daily_agent_summary",
        "generated_at": generated_at.isoformat(),
        "time_window_hours": window_hours,
        "finding_ids": finding_ids,
        "severity_totals": severity_totals,
    }


async def generate_daily_summary(
    db: AsyncSession,
    *,
    org_id: UUID,
    created_by: str,
    limit: int = 5,
    window_hours: int = 24,
    title: str | None = None,
) -> DailySummaryResult:
    """Create an agent session seeded with hot findings and return the summary."""

    if limit <= 0:
        raise ValueError("limit must be > 0")
    if window_hours <= 0:
        raise ValueError("window_hours must be > 0")

    org = await _fetch_org(db, org_id)
    generated_at = datetime.now(UTC)
    cutoff = generated_at - timedelta(hours=window_hours)

    findings = await _load_hot_findings(db, org_id, limit, cutoff)

    context = _build_session_context(findings, generated_at, window_hours)
    session = AgentSession(
        org_id=org.org_id,
        agent_type=AgentType.SECURITY_ANALYST,
        created_by=created_by,
        title=title or f"Daily Kickoff — {generated_at:%Y-%m-%d}",
        context=context,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    return DailySummaryResult(
        org_id=org.org_id,
        org_name=org.name,
        session_id=session.id,
        generated_at=generated_at,
        findings=findings,
        window_hours=window_hours,
    )


def build_slack_payload(
    summary: DailySummaryResult,
    *,
    session_url: str | None = None,
) -> dict[str, Any]:
    """Render a Slack message payload summarizing the findings."""

    severity_totals = summary.severity_totals()
    totals_line = (
        ", ".join(
            f"{level.capitalize()}: {count}"
            for level, count in severity_totals.items()
            if count
        )
        or "No open findings"
    )

    fallback_text = (
        f"Daily security summary for {summary.org_name}: {summary.total_findings()} hot "
        f"findings in last {summary.window_hours}h. Session {summary.session_id}"
    )

    findings_lines: list[str] = []
    for finding in summary.findings[:5]:
        account_ref = finding.account or finding.provider or "Unknown account"
        last_seen = finding.last_seen
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        last_seen_text = last_seen.astimezone(UTC).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        findings_lines.append(
            f"• *{finding.severity.upper()}* — {finding.title} ({account_ref})\n"
            f"  Last seen: {last_seen_text}"
        )

    if not findings_lines:
        findings_lines.append("No open findings detected in the selected window.")

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Daily Security Kickoff — {summary.org_name}",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Window:* Last {summary.window_hours}h",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Findings:* {summary.total_findings()}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Severities:* {totals_line}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Session ID:* `{summary.session_id}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(findings_lines)},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Generated at {summary.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
                }
            ],
        },
    ]

    if session_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open Agent Session"},
                        "url": session_url,
                    }
                ],
            }
        )

    return {
        "text": fallback_text,
        "blocks": blocks,
    }
