#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


IMAGE_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
IMAGE_TAG_LINE_RE = re.compile(r"^(\s*cerebro:imageTag:\s*)(\S+)(\s*)$")
IMAGE_TAG_VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_DIGEST_LINE_RE = re.compile(r"^(\s*cerebro:imageDigest:\s*)(\S+)(\s*)$")


def stack_path(repo_root: Path, stack: str) -> Path:
    return repo_root / "infra" / "aws" / f"Pulumi.{stack}.yaml"


def parse_image_tag(image_tag: str) -> tuple[int, int, int] | None:
    match = IMAGE_TAG_VERSION_RE.match(image_tag)
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def read_image_tag(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = IMAGE_TAG_LINE_RE.match(line)
        if match:
            return match.group(2)
    raise ValueError(f"cerebro:imageTag not found in {path}")


def read_image_digest(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        match = IMAGE_DIGEST_LINE_RE.match(line)
        if match:
            return match.group(2)
    raise ValueError(f"cerebro:imageDigest not found in {path}")


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


def ensure_image_tag_at_least(path: Path, image_tag: str) -> bool:
    minimum = parse_image_tag(image_tag)
    if minimum is None:
        raise ValueError(f"image tag {image_tag!r} must look like vX.Y.Z")

    current_tag = read_image_tag(path)
    current = parse_image_tag(current_tag)
    if current is None:
        raise ValueError(
            f"current image tag {current_tag!r} in {path} must look like vX.Y.Z"
        )
    if current >= minimum:
        return False
    return set_image_tag(path, image_tag)


def set_image_digest(path: Path, image_digest: str) -> bool:
    if IMAGE_DIGEST_RE.fullmatch(image_digest) is None:
        raise ValueError(
            f"image digest {image_digest!r} must look like sha256:<64 lowercase hex characters>"
        )

    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    has_digest = any(IMAGE_DIGEST_LINE_RE.match(line.rstrip("\n")) for line in lines)
    changed = False
    found = False
    updated: list[str] = []
    for line in lines:
        line_ending = "\n" if line.endswith("\n") else ""
        content = line[:-1] if line_ending else line
        match = IMAGE_DIGEST_LINE_RE.match(content)
        if match and not found:
            found = True
            if match.group(2) != image_digest:
                content = f"{match.group(1)}{image_digest}{match.group(3)}"
                changed = True
        updated.append(f"{content}{line_ending}")
        if not has_digest and not found and IMAGE_TAG_LINE_RE.match(content):
            indent = content[: len(content) - len(content.lstrip())]
            updated.append(f"{indent}cerebro:imageDigest: {image_digest}{line_ending}")
            found = True
            changed = True

    if changed:
        path.write_text("".join(updated), encoding="utf-8")
    return changed


def set_image_release(
    path: Path, image_tag: str, image_digest: str, *, ensure_at_least: bool = False
) -> bool:
    current = parse_image_tag(read_image_tag(path))
    target = parse_image_tag(image_tag)
    if current is None or target is None:
        raise ValueError(f"current and target image tags must look like vX.Y.Z: {path}")
    if ensure_at_least and current > target:
        return False
    tag_changed = set_image_tag(path, image_tag)
    digest_changed = set_image_digest(path, image_digest)
    return tag_changed or digest_changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Set a Cerebro stack image tag.")
    parser.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument("--stack", required=True, choices=("sec-dev", "go-prod"))
    parser.add_argument("--image-tag", required=True)
    parser.add_argument("--image-digest")
    parser.add_argument(
        "--ensure-at-least",
        action="store_true",
        help="Only update when the current stack tag is older.",
    )
    args = parser.parse_args(argv)

    path = stack_path(args.repo_root, args.stack)
    if args.image_digest:
        changed = set_image_release(
            path,
            args.image_tag,
            args.image_digest,
            ensure_at_least=args.ensure_at_least,
        )
    elif args.ensure_at_least:
        changed = ensure_image_tag_at_least(path, args.image_tag)
    else:
        changed = set_image_tag(path, args.image_tag)
    state = "updated" if changed else "already-current"
    print(f"{state}: {path} -> {args.image_tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
