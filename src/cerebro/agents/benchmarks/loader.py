"""Helpers for loading benchmark definitions from disk."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from .models import BenchmarkCase


def _discover_case_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.glob("*.json")):
        if path.is_file():
            yield path


def load_benchmark_cases(directory: Path) -> list[BenchmarkCase]:
    """Load benchmark case definitions from the provided directory."""

    cases: list[BenchmarkCase] = []
    for file_path in _discover_case_files(directory):
        with file_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        cases.append(BenchmarkCase.model_validate(raw))
    return cases
