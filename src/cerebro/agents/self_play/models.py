"""Data structures supporting agent self-play orchestration."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from cerebro.agents.models import AgentType
from cerebro.agents.models import Base as AgentsBase
from cerebro.core.database_types import JSONType
from cerebro.core.models import Organization


class SelfPlaySpeaker(str, Enum):
    """Participants in a self-play match."""

    CHALLENGER = "challenger"
    RESPONDER = "responder"


@dataclass
class TranscriptEntry:
    """Single turn transcript entry."""

    turn_index: int
    speaker: SelfPlaySpeaker
    message: str
    tool_calls: int
    created_at: datetime
    token_usage: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)
    duration_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["speaker"] = self.speaker.value
        payload["created_at"] = self.created_at.isoformat()
        return payload


@dataclass
class SelfPlayScenario:
    """Configuration describing how to run a self-play match."""

    id: str
    org_id: UUID
    challenger_prompt: str
    responder_prompt: str
    max_turns: int
    max_tool_calls: int
    metadata: dict[str, Any] | None = None
    challenger_agent_type: AgentType = AgentType.SECURITY_ANALYST
    responder_agent_type: AgentType | None = None
    created_by: str | None = None
    title: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.challenger_agent_type, str):
            self.challenger_agent_type = AgentType(self.challenger_agent_type)
        if self.responder_agent_type and isinstance(
            self.responder_agent_type,
            str,
        ):
            self.responder_agent_type = AgentType(self.responder_agent_type)


@dataclass
class TurnOutcome:
    """Normalized data produced from a single turn."""

    message: str
    tool_events: list[dict[str, Any]]
    token_usage: dict[str, Any]
    tool_call_count: int
    raw_message: dict[str, Any] | None = None
    stop_signal: str | None = None
    success_hint: bool | None = None
    duration_ms: float | None = None


@dataclass
class SelfPlayResult:
    """Summary produced after a self-play match completes."""

    match_id: UUID
    scenario_id: str
    turns: int
    tool_calls: int
    success: bool
    fail_reason: str | None
    transcript: list[TranscriptEntry]
    started_at: datetime
    ended_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "match_id": str(self.match_id),
            "scenario_id": self.scenario_id,
            "turns": self.turns,
            "tool_calls": self.tool_calls,
            "success": self.success,
            "fail_reason": self.fail_reason,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "metadata": self.metadata,
            "transcript": [entry.to_dict() for entry in self.transcript],
        }


class SelfPlayMatch(AgentsBase):
    """Persisted record capturing a self-play execution."""

    __tablename__ = "self_play_matches"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
    )
    scenario_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(Organization.__table__.c.org_id, ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    ended_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    turns: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    fail_reason: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    transcript: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONType,
        nullable=False,
        default=list,
    )
    match_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONType,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
