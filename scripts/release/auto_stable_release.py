#!/usr/bin/env python3
"""Resolve the next patch tag and render bounded automatic release notes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def next_patch_tag(releases: object) -> tuple[str, str | None]:
    if not isinstance(releases, list):
        raise ValueError("release inventory must be a JSON array")

    versions: list[tuple[int, int, int, str]] = []
    for release in releases:
        if not isinstance(release, dict):
            continue
        if release.get("draft") or release.get("prerelease"):
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str):
            continue
        match = VERSION_RE.fullmatch(tag)
        if match is None:
            continue
        major, minor, patch = (int(part) for part in match.groups())
        versions.append((major, minor, patch, tag))

    if not versions:
        return "v0.1.0", None

    major, minor, patch, previous = max(versions)
    return f"v{major}.{minor}.{patch + 1}", previous


def render_notes(
    *,
    release_tag: str,
    candidate_sha: str,
    candidate_run_id: str,
    smoke_url: str,
    previous_tag: str | None,
) -> str:
    if VERSION_RE.fullmatch(release_tag) is None:
        raise ValueError("release tag must use vMAJOR.MINOR.PATCH")
    if re.fullmatch(r"[0-9a-f]{40}", candidate_sha) is None:
        raise ValueError("candidate commit must be a full lowercase Git SHA")
    if re.fullmatch(r"[0-9]+", candidate_run_id) is None:
        raise ValueError("candidate run ID must be numeric")
    if (
        re.fullmatch(
            r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+",
            smoke_url,
        )
        is None
    ):
        raise ValueError("smoke URL must identify one GitHub Actions run")

    recovery = previous_tag or "the previously recorded stable release"
    return f"""# Cerebro {release_tag}

## Compatibility

This automatic patch release is bound to repository commit `{candidate_sha}`. Public API, event, package, and storage compatibility are defined by the signed artifacts and generated contracts included in this release rather than by a mutable branch or image tag.

## Migrations

Publication does not execute a data, graph, or schema migration. Deployment consumers must retain their protected preflight and migration gates and apply only migration behavior declared by commit `{candidate_sha}`.

## Configuration

Runtime configuration remains owned by each deployment consumer. The public release contains no credential values, private routes, tenant identifiers, or environment-specific authorization data.

## Content packs

Content-pack compatibility is the versioned state at commit `{candidate_sha}`. Consumers must verify the signed product manifest and bundled contracts before rollout.

## Rollback

No backward action is authorized by this publication. `{recovery}` remains a recovery input only for a separately authorized forward deployment action under normal repository protection.

## Runtime contract

Candidate Build run `{candidate_run_id}` produced the signed `cerebro.release-candidate/v1` bundle. The stable workflow publishes `cerebro.product-release/v1`, including the Rust runtime images, TypeScript Slack companion archive, and TypeScript SDK archive, all bound to commit `{candidate_sha}`.

## Smoke evidence

Ephemeral Cerebro exercised the published candidate images and produced the signed portable receipt used by the stable workflow: {smoke_url}

Evidence mode: `machine_verified_portable`

## Supported versions

Supported runtime profiles, backing services, Rust toolchain, Node runtime, Slack companion package, and TypeScript SDK versions are the repository-pinned versions recorded by commit `{candidate_sha}` and the signed product manifest.
"""


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("release inventory is not valid JSON") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    next_tag = subparsers.add_parser("next-tag")
    next_tag.add_argument("--releases-json", type=Path, required=True)
    next_tag.add_argument("--github-output", type=Path)

    notes = subparsers.add_parser("notes")
    notes.add_argument("--release-tag", required=True)
    notes.add_argument("--candidate-sha", required=True)
    notes.add_argument("--candidate-run-id", required=True)
    notes.add_argument("--smoke-url", required=True)
    notes.add_argument("--previous-tag")
    notes.add_argument("--out", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "next-tag":
            resolved, previous = next_patch_tag(_load_json(args.releases_json))
            if args.github_output is None:
                print(resolved)
            else:
                with args.github_output.open("a", encoding="utf-8") as output:
                    output.write(f"release_tag={resolved}\n")
                    output.write(f"previous_tag={previous or ''}\n")
            return 0

        rendered = render_notes(
            release_tag=args.release_tag,
            candidate_sha=args.candidate_sha,
            candidate_run_id=args.candidate_run_id,
            smoke_url=args.smoke_url,
            previous_tag=args.previous_tag,
        )
        args.out.write_text(rendered, encoding="utf-8")
        return 0
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
