#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from release_promotion import find_successful_deployment, parse_stable_tag


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check for a successful deployment receipt for an exact release image."
    )
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--environment", required=True)
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--github-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if not args.repository:
        raise RuntimeError("GITHUB_REPOSITORY or --repository is required")
    parse_stable_tag(args.image_tag)
    receipt = find_successful_deployment(
        args.repository,
        environment=args.environment,
        image_tag=args.image_tag,
        image_digest=args.image_digest,
    )
    ready = receipt is not None
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"ready={'true' if ready else 'false'}\n")
            handle.write(f"deployment_url={receipt.target_url if receipt else ''}\n")
    if ready:
        print(
            f"{args.environment} deployed {args.image_tag}@{args.image_digest}: {receipt.target_url}"
        )
    else:
        print(
            f"No successful {args.environment} deployment matches {args.image_tag}@{args.image_digest}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
