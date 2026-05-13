#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


IMAGE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
IMAGE_TAG_LINE_RE = re.compile(r"^(\s*cerebro:imageTag:\s*)(\S+)(\s*)$")


def stack_path(repo_root: Path, stack: str) -> Path:
    return repo_root / "infra" / "aws" / f"Pulumi.{stack}.yaml"


def set_image_tag(path: Path, image_tag: str) -> bool:
    if IMAGE_TAG_RE.match(image_tag) is None:
        raise ValueError(f"image tag {image_tag!r} must look like vX.Y.Z")

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    changed = False
    found = False
    updated: list[str] = []

    for line in lines:
        line_ending = "\n" if line.endswith("\n") else ""
        content = line[:-1] if line_ending else line
        match = IMAGE_TAG_LINE_RE.match(content)
        if match and not found:
            found = True
            old_tag = match.group(2)
            if old_tag != image_tag:
                content = f"{match.group(1)}{image_tag}{match.group(3)}"
                changed = True
        updated.append(f"{content}{line_ending}")

    if not found:
        raise ValueError(f"cerebro:imageTag not found in {path}")

    if changed:
        path.write_text("".join(updated), encoding="utf-8")

    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Set a Cerebro stack image tag.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--stack", required=True, choices=("sec-dev", "go-prod"))
    parser.add_argument("--image-tag", required=True)
    args = parser.parse_args(argv)

    path = stack_path(args.repo_root, args.stack)
    changed = set_image_tag(path, args.image_tag)
    state = "updated" if changed else "already-current"
    print(f"{state}: {path} -> {args.image_tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
