#!/usr/bin/env python3
"""Select a deterministic shard from a list of Go packages."""

from __future__ import annotations

import argparse
import hashlib
import sys


def package_shard(package: str, total: int) -> int:
    digest = hashlib.sha256(package.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % total


def select_packages(packages: list[str], total: int, index: int) -> list[str]:
    return [package for package in packages if package_shard(package, total) == index]


def main() -> int:
    parser = argparse.ArgumentParser(description="Select one stable shard from newline-delimited Go packages.")
    parser.add_argument("--total", type=int, required=True, help="Total number of shards.")
    parser.add_argument("--index", type=int, required=True, help="Zero-based shard index to print.")
    args = parser.parse_args()

    if args.total <= 0:
        parser.error("--total must be positive")
    if args.index < 0 or args.index >= args.total:
        parser.error("--index must be between 0 and --total - 1")

    packages = sorted(line.strip() for line in sys.stdin if line.strip())
    for package in select_packages(packages, args.total, args.index):
        print(package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
