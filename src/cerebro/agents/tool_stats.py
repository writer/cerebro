"""Lightweight in-memory tracking of tool performance statistics."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Iterable, List

if TYPE_CHECKING:
    from cerebro.agents.tools.base import Tool


@dataclass
class _ToolStats:
    success: int = 0
    failure: int = 0
    total_duration: float = 0.0

    @property
    def total(self) -> int:
        return self.success + self.failure

    @property
    def success_rate(self) -> float:
        total = self.total
        if total == 0:
            return 0.5  # neutral prior
        return self.success / total

    @property
    def avg_duration(self) -> float:
        return self.total_duration / max(1, self.total)


class ToolPerformanceTracker:
    """Global tracker for tool effectiveness to aid adaptive ordering."""

    def __init__(self) -> None:
        self._stats: Dict[str, _ToolStats] = {}
        self._lock = asyncio.Lock()

    async def record(
        self,
        *,
        tool_name: str,
        success: bool,
        duration_seconds: float,
    ) -> None:
        async with self._lock:
            stats = self._stats.setdefault(tool_name, _ToolStats())
            if success:
                stats.success += 1
            else:
                stats.failure += 1
            stats.total_duration += duration_seconds

    def sort_tools(
        self,
        tools: Iterable["Tool"],
        agent_type: str,
    ) -> List["Tool"]:
        rankings = self.get_rankings(tools, agent_type)
        ordering = {item["tool_name"]: index for index, item in enumerate(rankings)}
        return sorted(tools, key=lambda tool: ordering.get(tool.name, 0))

    def get_rankings(
        self,
        tools: Iterable["Tool"],
        agent_type: str,
    ) -> List[Dict[str, Any]]:
        rankings: List[Dict[str, Any]] = []
        for tool in tools:
            stats = self._stats.get(tool.name)
            base = 0.5 if stats is None else stats.success_rate
            weight = 1.0 if stats is None else min(1.5, 0.5 + stats.total / 10)
            penalty = 0.0 if stats is None else min(0.2, stats.avg_duration / 30)
            score = (base * weight) - penalty
            rankings.append(
                {
                    "tool_name": tool.name,
                    "score": round(score, 4),
                    "success_rate": base,
                    "observations": stats.total if stats else 0,
                    "avg_duration": stats.avg_duration if stats else 0.0,
                    "agent_type": agent_type,
                }
            )
        rankings.sort(key=lambda item: item["score"], reverse=True)
        return rankings


performance_tracker = ToolPerformanceTracker()
