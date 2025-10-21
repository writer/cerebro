"""Coordinate self-play matches between Cerebro agents."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from time import monotonic
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import structlog

from cerebro.agents.analytics_service import AgentAnalyticsService
from cerebro.agents.metrics import record_self_play_match_metrics
from cerebro.agents.models import AgentSession, AgentType, MessageRole
from cerebro.agents.runtime_facade import AgentRuntimeFacade
from cerebro.core.config import Settings, settings
from cerebro.core.database import async_session_factory

from .models import (
    SelfPlayMatch,
    SelfPlayResult,
    SelfPlayScenario,
    SelfPlaySpeaker,
    TranscriptEntry,
    TurnOutcome,
)

_OUTCOME_PATTERN = re.compile(
    r"OUTCOME\s*:\s*(SUCCESS|PASS|WIN|FAIL|FAILURE|ERROR|DRAW)", re.IGNORECASE
)
_TERMINATE_PATTERN = re.compile(r"TERMINATE_SELF_PLAY", re.IGNORECASE)


class SelfPlayOrchestrator:
    """Runs self-play scenarios between challenger and responder sessions."""

    def __init__(
        self,
        runtime_facade: AgentRuntimeFacade,
        *,
        analytics: Any = AgentAnalyticsService,
        config: Settings = settings,
    ) -> None:
        self._runtime_facade = runtime_facade
        self._analytics = analytics
        self._settings = config
        self._logger = structlog.get_logger(__name__)
        self._created_by = getattr(
            config,
            "self_play_created_by",
            "self_play_orchestrator",
        )

    async def run_match(self, scenario: SelfPlayScenario) -> SelfPlayResult:
        """Execute a self-play match for the provided scenario."""

        if not getattr(self._settings, "self_play_enabled", True):
            now = datetime.now(timezone.utc)
            return SelfPlayResult(
                match_id=uuid4(),
                scenario_id=scenario.id,
                turns=0,
                tool_calls=0,
                success=False,
                fail_reason="self_play_disabled",
                transcript=[],
                started_at=now,
                ended_at=now,
                metadata={
                    "scenario_metadata": scenario.metadata or {},
                },
            )

        match_id = uuid4()
        started_at = datetime.now(timezone.utc)
        challenger_type = scenario.challenger_agent_type
        responder_type = scenario.responder_agent_type or challenger_type

        self._logger.info(
            "self_play.match.start",
            match_id=str(match_id),
            scenario_id=scenario.id,
            challenger_agent_type=challenger_type.value,
            responder_agent_type=responder_type.value,
        )

        challenger_session = await self._create_session(
            scenario=scenario,
            match_id=match_id,
            speaker=SelfPlaySpeaker.CHALLENGER,
            agent_type=challenger_type,
        )
        responder_session = await self._create_session(
            scenario=scenario,
            match_id=match_id,
            speaker=SelfPlaySpeaker.RESPONDER,
            agent_type=responder_type,
        )

        await asyncio.gather(
            self._record_event(
                challenger_session,
                "self_play_match_started",
                self._match_event_payload(
                    match_id,
                    scenario,
                    SelfPlaySpeaker.CHALLENGER,
                ),
            ),
            self._record_event(
                responder_session,
                "self_play_match_started",
                self._match_event_payload(
                    match_id,
                    scenario,
                    SelfPlaySpeaker.RESPONDER,
                ),
            ),
        )

        transcript: List[TranscriptEntry] = []
        turn_count = 0
        tool_calls = 0
        stop_reason: Optional[str] = None
        success_hint: Optional[bool] = None

        pending_inputs: Dict[SelfPlaySpeaker, Optional[str]] = {
            SelfPlaySpeaker.CHALLENGER: scenario.challenger_prompt,
            SelfPlaySpeaker.RESPONDER: None,
        }
        initial_prompt_sent = {
            SelfPlaySpeaker.CHALLENGER: False,
            SelfPlaySpeaker.RESPONDER: False,
        }

        max_turns = max(1, scenario.max_turns)
        max_tool_calls = max(0, scenario.max_tool_calls)
        stream_responses = getattr(
            self._settings,
            "self_play_stream_responses",
            True,
        )

        sessions: Dict[SelfPlaySpeaker, AgentSession] = {
            SelfPlaySpeaker.CHALLENGER: challenger_session,
            SelfPlaySpeaker.RESPONDER: responder_session,
        }

        active = SelfPlaySpeaker.CHALLENGER

        while True:
            message = pending_inputs[active]
            if message is None:
                break

            initial_prompt_sent[active] = True
            outcome = await self._play_turn(
                scenario=scenario,
                match_id=match_id,
                session=sessions[active],
                speaker=active,
                message=message,
                turn_index=turn_count,
                stream=stream_responses,
            )
            pending_inputs[active] = None

            turn_count += 1
            tool_calls += outcome.tool_call_count

            transcript.append(
                TranscriptEntry(
                    turn_index=turn_count,
                    speaker=active,
                    message=outcome.message,
                    tool_calls=outcome.tool_call_count,
                    created_at=datetime.now(timezone.utc),
                    token_usage=dict(outcome.token_usage),
                    raw_response=outcome.raw_message or {},
                    duration_ms=outcome.duration_ms,
                )
            )

            if outcome.stop_signal:
                stop_reason = outcome.stop_signal
                success_hint = outcome.success_hint

            if turn_count >= max_turns:
                stop_reason = stop_reason or "max_turns"
            if tool_calls >= max_tool_calls:
                stop_reason = stop_reason or "max_tool_calls"

            if stop_reason:
                break

            next_speaker = (
                SelfPlaySpeaker.RESPONDER
                if active is SelfPlaySpeaker.CHALLENGER
                else SelfPlaySpeaker.CHALLENGER
            )
            next_message = self._build_next_message(
                scenario=scenario,
                speaker=next_speaker,
                opponent_output=outcome.message,
                first_turn=not initial_prompt_sent[next_speaker],
            )
            if next_message is None:
                stop_reason = "empty_response"
                break

            pending_inputs[next_speaker] = next_message
            active = next_speaker

        ended_at = datetime.now(timezone.utc)
        indicated_success = bool(success_hint)
        total_duration_ms = (ended_at - started_at).total_seconds() * 1000.0
        result = await self._finalize_match(
            match_id=match_id,
            scenario=scenario,
            sessions=sessions,
            started_at=started_at,
            ended_at=ended_at,
            turns=turn_count,
            tool_calls=tool_calls,
            stop_reason=stop_reason,
            transcript=transcript,
            indicated_success=indicated_success,
            total_duration_ms=total_duration_ms,
        )

        self._logger.info(
            "self_play.match.complete",
            match_id=str(match_id),
            scenario_id=scenario.id,
            turns=turn_count,
            tool_calls=tool_calls,
            success=result.success,
            stop_reason=stop_reason,
        )

        return result

    async def _create_session(
        self,
        *,
        scenario: SelfPlayScenario,
        match_id: UUID,
        speaker: SelfPlaySpeaker,
        agent_type: AgentType,
    ) -> AgentSession:
        context: Dict[str, Any] = {
            "_self_play": True,
            "scenario_id": scenario.id,
            "match_id": str(match_id),
            "self_play_role": speaker.value,
            "turn_budget": scenario.max_turns,
            "tool_budget": scenario.max_tool_calls,
            "scenario_metadata": scenario.metadata or {},
        }
        metadata = scenario.metadata or {}
        overrides = metadata.get(f"{speaker.value}_context")
        if isinstance(overrides, dict):
            context.update(overrides)

        created_by = scenario.created_by or self._created_by
        title = scenario.title or f"Self-play {scenario.id} ({speaker.value})"

        session = await self._runtime_facade.create_session(
            org_id=scenario.org_id,
            agent_type=agent_type,
            created_by=created_by,
            context=context,
            title=title,
        )
        return session

    async def _play_turn(
        self,
        *,
        scenario: SelfPlayScenario,
        match_id: UUID,
        session: AgentSession,
        speaker: SelfPlaySpeaker,
        message: str,
        turn_index: int,
        stream: bool,
    ) -> TurnOutcome:
        self._logger.info(
            "self_play.turn.start",
            match_id=str(match_id),
            scenario_id=scenario.id,
            speaker=speaker.value,
            turn=turn_index + 1,
        )

        streamed_text: List[str] = []
        streamed_tools: List[Dict[str, Any]] = []
        turn_started = monotonic()

        async for chunk in self._runtime_facade.send_message(
            session=session,
            message=message,
            user_id=self._created_by,
            stream=stream,
        ):
            chunk_type = chunk.get("type")
            if chunk_type == "text":
                content = chunk.get("content")
                if isinstance(content, str):
                    streamed_text.append(content)
            elif chunk_type == "tool_use":
                tool_payload = chunk.get("content")
                if isinstance(tool_payload, dict):
                    streamed_tools.append(tool_payload)

        latest_response = await self._fetch_latest_assistant_message(session)
        outcome = self._normalize_turn_output(
            streamed_text=streamed_text,
            streamed_tools=streamed_tools,
            response_message=latest_response,
        )
        outcome.duration_ms = (monotonic() - turn_started) * 1000.0

        await self._record_event(
            session,
            "self_play_turn",
            {
                "match_id": str(match_id),
                "scenario_id": scenario.id,
                "speaker": speaker.value,
                "turn_index": turn_index + 1,
                "tool_calls": outcome.tool_call_count,
                "token_usage": outcome.token_usage,
                "duration_ms": outcome.duration_ms,
            },
        )

        self._logger.info(
            "self_play.turn.complete",
            match_id=str(match_id),
            scenario_id=scenario.id,
            speaker=speaker.value,
            turn=turn_index + 1,
            tool_calls=outcome.tool_call_count,
        )

        return outcome

    async def _fetch_latest_assistant_message(
        self,
        session: AgentSession,
    ) -> Optional[Dict[str, Any]]:
        messages = await self._runtime_facade.get_session_messages(
            session,
            limit=5,
        )
        for record in messages:
            role = record.get("role")
            if isinstance(role, MessageRole) and role is MessageRole.ASSISTANT:
                return record
            if role == MessageRole.ASSISTANT:
                return record
        return None

    def _normalize_turn_output(
        self,
        *,
        streamed_text: List[str],
        streamed_tools: List[Dict[str, Any]],
        response_message: Optional[Dict[str, Any]],
    ) -> TurnOutcome:
        text = "".join(streamed_text).strip()
        tool_events = list(streamed_tools)
        token_usage: Dict[str, Any] = {}
        raw_message: Optional[Dict[str, Any]] = None

        if response_message:
            raw_message = response_message.get("content")
            if isinstance(raw_message, dict):
                content_blocks = raw_message.get("content")
                if isinstance(content_blocks, list):
                    extracted = self._extract_from_blocks(content_blocks)
                    if extracted["text"]:
                        text = extracted["text"]
                    if extracted["tools"]:
                        tool_events = extracted["tools"]
                tool_calls_declared = raw_message.get("tool_calls")
                if (
                    isinstance(tool_calls_declared, int)
                    and tool_calls_declared >= 0
                ):
                    tool_events = tool_events[:tool_calls_declared]
                token_usage = {
                    "input_tokens": raw_message.get("token_usage", {}).get(
                        "input_tokens"
                    ),
                    "output_tokens": raw_message.get("token_usage", {}).get(
                        "output_tokens"
                    ),
                }
            if not token_usage:
                token_usage = {
                    "input_tokens": response_message.get("input_tokens"),
                    "output_tokens": response_message.get("output_tokens"),
                }

        text = text.strip()
        stop_signal, success_hint = self._detect_stop_signal(text)

        return TurnOutcome(
            message=text,
            tool_events=tool_events,
            token_usage=token_usage,
            tool_call_count=len(tool_events),
            raw_message=raw_message,
            stop_signal=stop_signal,
            success_hint=success_hint,
        )

    def _extract_from_blocks(self, blocks: List[Any]) -> Dict[str, Any]:
        text_parts: List[str] = []
        tools: List[Dict[str, Any]] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text_value = block.get("text")
                if isinstance(text_value, str):
                    text_parts.append(text_value)
            elif block.get("type") == "tool_use":
                tools.append(
                    {
                        "tool_name": block.get("tool_name"),
                        "input": block.get("input"),
                        "tool_call_id": block.get("tool_call_id"),
                    }
                )
        return {
            "text": "".join(text_parts).strip(),
            "tools": tools,
        }

    def _detect_stop_signal(
        self,
        text: str,
    ) -> tuple[Optional[str], Optional[bool]]:
        if not text:
            return None, None

        if _TERMINATE_PATTERN.search(text):
            return "terminate", False

        match = _OUTCOME_PATTERN.search(text)
        if not match:
            return None, None

        outcome = match.group(1).lower()
        if outcome in {"success", "pass", "win"}:
            return "outcome", True
        if outcome == "draw":
            return "outcome", None
        return "outcome", False

    def _build_next_message(
        self,
        *,
        scenario: SelfPlayScenario,
        speaker: SelfPlaySpeaker,
        opponent_output: str,
        first_turn: bool,
    ) -> Optional[str]:
        opponent_output = opponent_output.strip()
        if not opponent_output:
            return None

        metadata = scenario.metadata or {}
        template_key = f"{speaker.value}_followup_template"

        if first_turn and speaker is SelfPlaySpeaker.RESPONDER:
            base_prompt = metadata.get("responder_template")
            if isinstance(base_prompt, str):
                try:
                    return base_prompt.format(
                        challenger_output=opponent_output,
                    )
                except Exception:  # pragma: no cover - formatting resilience
                    return base_prompt
            responder_prompt = scenario.responder_prompt.rstrip()
            return f"{responder_prompt}\n\nChallenger says:\n{opponent_output}"

        template_value = metadata.get(template_key)
        if isinstance(template_value, str):
            try:
                return template_value.format(opponent_output=opponent_output)
            except Exception:  # pragma: no cover
                return template_value

        if first_turn and speaker is SelfPlaySpeaker.CHALLENGER:
            base_prompt = metadata.get("challenger_template")
            if isinstance(base_prompt, str):
                try:
                    return base_prompt.format(responder_output=opponent_output)
                except Exception:  # pragma: no cover
                    return base_prompt

        return opponent_output

    async def _finalize_match(
        self,
        *,
        match_id: UUID,
        scenario: SelfPlayScenario,
        sessions: Dict[SelfPlaySpeaker, AgentSession],
        started_at: datetime,
        ended_at: datetime,
        turns: int,
        tool_calls: int,
        stop_reason: Optional[str],
        transcript: List[TranscriptEntry],
        indicated_success: bool,
        total_duration_ms: float,
    ) -> SelfPlayResult:
        result = SelfPlayResult(
            match_id=match_id,
            scenario_id=scenario.id,
            turns=turns,
            tool_calls=tool_calls,
            success=indicated_success,
            fail_reason=None
            if indicated_success
            else stop_reason or "unknown",
            transcript=transcript,
            started_at=started_at,
            ended_at=ended_at,
            metadata={
                "stop_reason": stop_reason,
                "scenario_metadata": scenario.metadata or {},
                "total_duration_ms": total_duration_ms,
            },
        )

        await asyncio.gather(
            self._record_event(
                sessions[SelfPlaySpeaker.CHALLENGER],
                "self_play_match_completed",
                self._completion_payload(result),
            ),
            self._record_event(
                sessions[SelfPlaySpeaker.RESPONDER],
                "self_play_match_completed",
                self._completion_payload(result),
            ),
        )

        await self._persist_result(result, scenario)
        record_self_play_match_metrics(result.success, result.turns)

        return result

    async def _persist_result(
        self,
        result: SelfPlayResult,
        scenario: SelfPlayScenario,
    ) -> None:
        if not getattr(self._settings, "self_play_persist_results", False):
            return

        async with async_session_factory() as session:
            record = SelfPlayMatch(
                id=result.match_id,
                scenario_id=scenario.id,
                org_id=scenario.org_id,
                started_at=result.started_at,
                ended_at=result.ended_at,
                turns=result.turns,
                tool_calls=result.tool_calls,
                success=result.success,
                fail_reason=result.fail_reason,
                transcript=[entry.to_dict() for entry in result.transcript],
                match_metadata=result.metadata,
            )
            session.add(record)
            try:
                await session.commit()
            except Exception:  # pragma: no cover - defensive rollback
                await session.rollback()
                self._logger.exception(
                    "self_play.persist_failed",
                    match_id=str(result.match_id),
                    scenario_id=scenario.id,
                )
                raise

    async def _record_event(
        self,
        session: AgentSession,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        if not self._analytics:
            return
        try:
            await self._analytics.record_event(
                org_id=session.org_id,
                session_id=session.id,
                event_type=event_type,
                payload=payload,
            )
        except Exception:  # pragma: no cover - analytics resiliency
            self._logger.warning(
                "self_play.analytics_failed",
                session_id=str(session.id),
                event_type=event_type,
            )

    def _match_event_payload(
        self,
        match_id: UUID,
        scenario: SelfPlayScenario,
        speaker: SelfPlaySpeaker,
    ) -> Dict[str, Any]:
        return {
            "match_id": str(match_id),
            "scenario_id": scenario.id,
            "role": speaker.value,
            "max_turns": scenario.max_turns,
            "max_tool_calls": scenario.max_tool_calls,
        }

    def _completion_payload(self, result: SelfPlayResult) -> Dict[str, Any]:
        return {
            "match_id": str(result.match_id),
            "scenario_id": result.scenario_id,
            "turns": result.turns,
            "tool_calls": result.tool_calls,
            "success": result.success,
            "fail_reason": result.fail_reason,
        }
