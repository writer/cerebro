"""Regression tournaments built on top of self-play."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import structlog

from .models import SelfPlayResult, SelfPlayScenario
from .orchestrator import SelfPlayOrchestrator

logger = structlog.get_logger(__name__)


class ScenarioProvider:
    """Load a `SelfPlayScenario` by identifier."""

    async def load(self, scenario_id: str) -> SelfPlayScenario:  # pragma: no cover - interface only
        raise NotImplementedError


@dataclass(slots=True)
class TournamentScenarioConfig:
    scenario_id: str
    repetitions: int = 1
    min_success_rate: float = 1.0
    max_allowed_turns: Optional[int] = None


@dataclass(slots=True)
class ScenarioRunResult:
    scenario_id: str
    matches: List[SelfPlayResult]
    success_rate: float
    drift_alert: Optional[str]

    @property
    def passed(self) -> bool:
        return self.drift_alert is None


@dataclass(slots=True)
class TournamentConfig:
    name: str
    scenarios: List[TournamentScenarioConfig]
    metadata: Dict[str, object]


@dataclass(slots=True)
class TournamentResult:
    name: str
    scenarios: List[ScenarioRunResult]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.scenarios)

    def drift_alerts(self) -> List[str]:
        alerts: List[str] = []
        for result in self.scenarios:
            if result.drift_alert:
                alerts.append(result.drift_alert)
        return alerts


class TournamentRunner:
    """Execute regression tournaments and evaluate against baselines."""

    def __init__(
        self,
        orchestrator: SelfPlayOrchestrator,
        scenario_provider: ScenarioProvider,
    ) -> None:
        self._orchestrator = orchestrator
        self._scenario_provider = scenario_provider

    async def run(self, config: TournamentConfig) -> TournamentResult:
        scenario_results: List[ScenarioRunResult] = []

        for scenario_cfg in config.scenarios:
            scenario_results.append(
                await self._run_scenario(scenario_cfg)
            )

        return TournamentResult(name=config.name, scenarios=scenario_results)

    async def _run_scenario(self, config: TournamentScenarioConfig) -> ScenarioRunResult:
        scenario = await self._scenario_provider.load(config.scenario_id)
        matches: List[SelfPlayResult] = []

        for idx in range(max(1, config.repetitions)):
            logger.info(
                "self_play.tournament.match_start",
                scenario_id=config.scenario_id,
                iteration=idx + 1,
            )
            result = await self._orchestrator.run_match(scenario)
            matches.append(result)

        success_rate = _calculate_success_rate(matches)
        drift_alert = None

        if success_rate < config.min_success_rate:
            drift_alert = (
                f"Scenario {config.scenario_id} success rate {success_rate:.2f} "
                f"below minimum {config.min_success_rate:.2f}"
            )

        if config.max_allowed_turns is not None:
            max_turns = max(match.turns for match in matches) if matches else 0
            if max_turns > config.max_allowed_turns:
                extra = (
                    f"Scenario {config.scenario_id} exceeded turn budget: "
                    f"{max_turns} > {config.max_allowed_turns}"
                )
                drift_alert = extra if drift_alert is None else f"{drift_alert}; {extra}"

        if drift_alert:
            logger.warning("self_play.tournament.drift", alert=drift_alert)
        else:
            logger.info(
                "self_play.tournament.scenario_passed",
                scenario_id=config.scenario_id,
                success_rate=success_rate,
            )

        return ScenarioRunResult(
            scenario_id=config.scenario_id,
            matches=matches,
            success_rate=success_rate,
            drift_alert=drift_alert,
        )


def _calculate_success_rate(matches: Iterable[SelfPlayResult]) -> float:
    total = 0
    successes = 0
    for match in matches:
        total += 1
        if match.success:
            successes += 1
    if total == 0:
        return 0.0
    return successes / total
