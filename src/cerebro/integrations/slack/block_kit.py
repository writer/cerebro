from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Tuple

from slack_sdk.models.blocks import (
    ContextBlock,
    DividerBlock,
    HeaderBlock,
    SectionBlock,
)
from slack_sdk.models.blocks.basic_components import MarkdownTextObject, PlainTextObject


def findings_summary_blocks(
    *,
    org_name: str,
    severity_label: str,
    findings: Iterable,
) -> Tuple[str, List[dict]]:
    """Build Block Kit payload for a findings summary.

    Args:
        org_name: Name of the organization the findings belong to.
        severity_label: Human-friendly severity bucket label (e.g. "Critical").
        findings: Iterable of ``Finding`` ORM instances.

    Returns:
        Tuple containing fallback text and the serialized block payload.
    """

    findings_list = list(findings)
    total = len(findings_list)
    header_text = (
        f"Top {total} {severity_label} findings for {org_name}"
        if total
        else f"No {severity_label.lower()} findings for {org_name}"
    )

    blocks: List = [HeaderBlock(text=PlainTextObject(text=header_text, emoji=True))]

    fallback_lines = [header_text]

    if not findings_list:
        return header_text, [block.to_dict() for block in blocks]

    for index, finding in enumerate(findings_list, start=1):
        title = finding.title or "Untitled finding"
        summary = finding.summary or ""
        if summary:
            summary = summary[:160] + ("…" if len(summary) > 160 else "")

        fallback_lines.append(
            f"- {title} ({finding.severity.upper()}, {finding.provider})"
        )

        last_seen = _format_timestamp(finding.last_seen)
        lines = [
            f"*{index}. {title}*",
            f"*Severity:* `{finding.severity.upper()}`   •   *Provider:* `{finding.provider}`",
            f"*Last seen:* {last_seen}   •   *Fingerprint:* `{finding.finding_id}`",
        ]
        if summary:
            lines.append(summary)

        blocks.append(SectionBlock(text=MarkdownTextObject(text="\n".join(lines))))

        context_chunks = []
        if finding.resource_id:
            context_chunks.append(f"Resource ID: `{finding.resource_id}`")
        if finding.principal_id:
            context_chunks.append(f"Principal ID: `{finding.principal_id}`")
        if context_chunks:
            blocks.append(
                ContextBlock(
                    elements=[MarkdownTextObject(text=" • ".join(context_chunks))]
                )
            )

        if index < total:
            blocks.append(DividerBlock())

    blocks.append(
        ContextBlock(
            elements=[
                MarkdownTextObject(
                    text=(
                        "Use `/cerebro findings <severity>` to adjust severity or open Cerebro for deeper triage."
                    )
                )
            ]
        )
    )

    return "\n".join(fallback_lines), [block.to_dict() for block in blocks]


def _format_timestamp(dt: datetime) -> str:
    aware = dt.astimezone(timezone.utc)
    ts = int(aware.timestamp())
    return f"<!date^{ts}^{{date_short_pretty}} at {{time}}|{aware.isoformat()}>"
