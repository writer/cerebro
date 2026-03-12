#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def load_parser():
    try:
        import tomllib  # type: ignore

        return tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore

            return tomllib
        except ImportError:
            return None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_toml.py <path>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"toml file not found: {path}", file=sys.stderr)
        return 1

    parser = load_parser()
    if parser is None:
        print(
            f"skipping TOML parse for {path}: tomllib unavailable on this Python and tomli is not installed",
            file=sys.stderr,
        )
        return 0

    with path.open("rb") as handle:
        parser.load(handle)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
