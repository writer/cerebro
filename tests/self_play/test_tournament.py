from datetime import UTC, datetime
from uuid import uuid4

import pytest

from cerebro.agents.self_play.models import (
    SelfPlayResult,
    SelfPlayScenario,
    SelfPlaySpeaker,
    TranscriptEntry,
)
from cerebro.agents.self_play.tournament import (
    ScenarioProvider,
    TournamentConfig,
    TournamentRunner,
    TournamentScenarioConfig,
)


class DummyOrchestrator:
    def __init__(self, results: list[SelfPlayResult]):
        self._results = results

    async def run_match(self, scenario: SelfPlayScenario) -> SelfPlayResult:
        if not self._results:
            raise AssertionError("No more results queued")
        return self._results.pop(0)


class DummyProvider(ScenarioProvider):
    async def load(self, scenario_id: str) -> SelfPlayScenario:
        return SelfPlayScenario(
            id=scenario_id,
            org_id=uuid4(),
            challenger_prompt="Challenger prompt",
            responder_prompt="Responder prompt",
            max_turns=6,
            max_tool_calls=4,
        )


def _make_result(success: bool, turns: int) -> SelfPlayResult:
    now = datetime.now(UTC)
    return SelfPlayResult(
        match_id=uuid4(),
        scenario_id="scenario-a",
        turns=turns,
        tool_calls=1,
        success=success,
        fail_reason=None if success else "timeout",
        transcript=[
            TranscriptEntry(
                turn_index=1,
                speaker=SelfPlaySpeaker.CHALLENGER,
                message="OUTCOME: SUCCESS" if success else "OUTCOME: FAILURE",
                tool_calls=1,
                created_at=now,
            )
        ],
        started_at=now,
        ended_at=now,
        metadata={},
    )


@pytest.mark.asyncio
async def test_tournament_runner_passes_when_thresholds_met():
    orchestrator = DummyOrchestrator(
        [
            _make_result(True, 4),
            _make_result(True, 5),
        ]
    )
    runner = TournamentRunner(orchestrator, DummyProvider())

    config = TournamentConfig(
        name="regression",
        scenarios=[
            TournamentScenarioConfig(
                scenario_id="scenario-a",
                repetitions=2,
                min_success_rate=0.9,
                max_allowed_turns=6,
            )
        ],
        metadata={},
    )

    result = await runner.run(config)

    assert result.passed is True
    assert result.drift_alerts() == []


@pytest.mark.asyncio
async def test_tournament_runner_flags_drift_on_failure():
    orchestrator = DummyOrchestrator(
        [
            _make_result(True, 7),
            _make_result(False, 8),
        ]
    )
    runner = TournamentRunner(orchestrator, DummyProvider())

    config = TournamentConfig(
        name="regression",
        scenarios=[
            TournamentScenarioConfig(
                scenario_id="scenario-a",
                repetitions=2,
                min_success_rate=0.8,
                max_allowed_turns=6,
            )
        ],
        metadata={},
    )

    result = await runner.run(config)

    assert result.passed is False
    alerts = result.drift_alerts()
    assert len(alerts) == 1
    assert "success rate" in alerts[0]
