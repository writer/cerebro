#!/usr/bin/env python3
"""Select a deterministic shard from a list of Go packages."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


def package_shard(package: str, total: int) -> int:
    digest = hashlib.sha256(package.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % total


def load_weights(path: str) -> dict[str, float]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("weights file must contain a JSON object")
    weights: dict[str, float] = {}
    for package, value in raw.items():
        if not isinstance(package, str):
            raise ValueError("weight package names must be strings")
        if not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"weight for {package!r} must be a positive number")
        weights[package] = float(value)
    return weights


def select_weighted_packages(packages: list[str], total: int, index: int, weights: dict[str, float]) -> list[str]:
    bins: list[tuple[float, list[str]]] = [(0.0, []) for _ in range(total)]
    ordered = sorted(packages, key=lambda package: (-weights.get(package, 1.0), package))
    for package in ordered:
        bin_index = min(range(total), key=lambda candidate: (bins[candidate][0], len(bins[candidate][1]), candidate))
        weight, selected = bins[bin_index]
        selected.append(package)
        bins[bin_index] = (weight + weights.get(package, 1.0), selected)
    return sorted(bins[index][1])


def select_packages(packages: list[str], total: int, index: int, weights: dict[str, float] | None = None) -> list[str]:
    if weights:
        return select_weighted_packages(packages, total, index, weights)
    return [package for package in packages if package_shard(package, total) == index]


def main() -> int:
    parser = argparse.ArgumentParser(description="Select one stable shard from newline-delimited Go packages.")
    parser.add_argument("--total", type=int, required=True, help="Total number of shards.")
    parser.add_argument("--index", type=int, required=True, help="Zero-based shard index to print.")
    parser.add_argument("--weights", help="Optional JSON map of package import path to relative runtime weight.")
    args = parser.parse_args()

    if args.total <= 0:
        parser.error("--total must be positive")
    if args.index < 0 or args.index >= args.total:
        parser.error("--index must be between 0 and --total - 1")

    weights = None
    if args.weights:
        try:
            weights = load_weights(args.weights)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"--weights: {exc}")

    packages = sorted(line.strip() for line in sys.stdin if line.strip())
    for package in select_packages(packages, args.total, args.index, weights):
        print(package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
