#!/usr/bin/env python3
"""Verify that portable release archives contain this checkout's exact outputs."""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


SDK_PACKAGE = "@writer/cerebro-sdk"
SLACK_PACKAGE = "@writer/cerebro-slack-companion"
MAX_ARCHIVE_MEMBERS = 10_000
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024


class VerificationError(ValueError):
    """Raised when a portable artifact does not match the release checkout."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def load_json_object(data: bytes, label: str) -> dict[str, Any]:
    require(len(data) <= MAX_PACKAGE_BYTES, f"{label} is too large")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is invalid: {exc}") from exc
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def read_file_tree(root: Path, label: str) -> dict[str, bytes]:
    require(root.is_dir(), f"{label} directory is missing: {root}")
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise VerificationError(f"{label} must not contain symbolic links: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            data = path.read_bytes()
            require(len(data) <= MAX_MEMBER_BYTES, f"{label} file is too large: {relative}")
            files[relative] = data
    require(files, f"{label} directory has no files")
    return files


def read_archive_tree(
    archive_path: Path,
    tree_prefix: str,
    label: str,
) -> tuple[dict[str, Any], dict[str, bytes]]:
    package_data: bytes | None = None
    files: dict[str, bytes] = {}
    names: set[str] = set()
    member_count = 0
    prefix = f"package/{tree_prefix}/"

    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                require(member_count <= MAX_ARCHIVE_MEMBERS, f"{label} has too many members")
                member_path = PurePosixPath(member.name)
                require(
                    member.name == member_path.as_posix()
                    and not member_path.is_absolute()
                    and ".." not in member_path.parts
                    and len(member_path.parts) > 1
                    and member_path.parts[0] == "package",
                    f"{label} has an unsafe member: {member.name}",
                )
                require(member.name not in names, f"{label} has a duplicate member: {member.name}")
                names.add(member.name)
                require(
                    member.isfile() or member.isdir(),
                    f"{label} member must be a regular file or directory: {member.name}",
                )
                if member.isdir():
                    continue
                require(member.size <= MAX_MEMBER_BYTES, f"{label} member is too large: {member.name}")
                if member.name != "package/package.json" and not member.name.startswith(prefix):
                    continue
                member_file = archive.extractfile(member)
                require(member_file is not None, f"{label} member cannot be read: {member.name}")
                data = member_file.read(MAX_MEMBER_BYTES + 1)
                require(len(data) <= MAX_MEMBER_BYTES, f"{label} member is too large: {member.name}")
                if member.name == "package/package.json":
                    package_data = data
                else:
                    files[member.name.removeprefix(prefix)] = data
    except VerificationError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise VerificationError(f"{label} is invalid: {exc}") from exc

    require(package_data is not None, f"{label} is missing package/package.json")
    require(files, f"{label} is missing package/{tree_prefix}")
    return load_json_object(package_data, f"{label} package metadata"), files


def require_same_tree(
    expected: dict[str, bytes],
    actual: dict[str, bytes],
    label: str,
) -> None:
    expected_names = set(expected)
    actual_names = set(actual)
    missing = sorted(expected_names - actual_names)
    extra = sorted(actual_names - expected_names)
    require(not missing, f"{label} is missing files: {', '.join(missing)}")
    require(not extra, f"{label} has unexpected files: {', '.join(extra)}")
    changed = sorted(name for name in expected_names if expected[name] != actual[name])
    require(not changed, f"{label} has changed files: {', '.join(changed)}")


def require_bundle_artifact(bundle_root: Path, artifact: Path, label: str) -> Path:
    resolved = artifact.resolve()
    try:
        resolved.relative_to(bundle_root)
    except ValueError as exc:
        raise VerificationError(f"{label} must be inside the bundle root") from exc
    require(resolved.is_file(), f"{label} is missing: {artifact}")
    return resolved


def verify_portable_artifacts(
    repo: Path,
    bundle_root: Path,
    sdk_archive: Path,
    slack_archive: Path,
) -> None:
    repo = repo.resolve()
    bundle_root = bundle_root.resolve()
    require(repo.is_dir(), f"repository root is missing: {repo}")
    require(bundle_root.is_dir(), f"bundle root is missing: {bundle_root}")
    sdk_archive = require_bundle_artifact(bundle_root, sdk_archive, "SDK archive")
    slack_archive = require_bundle_artifact(bundle_root, slack_archive, "Slack companion archive")

    contract_pairs = (
        (repo / "api/openapi.yaml", bundle_root / "cerebro-openapi.yaml", "OpenAPI contract"),
        (
            repo / "schemas/agent-service-lifecycle.schema.json",
            bundle_root / "agent-service-lifecycle.schema.json",
            "agent service lifecycle contract",
        ),
    )
    for source, bundled, label in contract_pairs:
        require(source.is_file(), f"canonical {label} is missing: {source}")
        require(bundled.is_file(), f"bundled {label} is missing: {bundled}")
        require(source.read_bytes() == bundled.read_bytes(), f"bundled {label} does not match the checkout")

    sdk_manifest, sdk_files = read_archive_tree(sdk_archive, "src", "SDK archive")
    slack_manifest, slack_files = read_archive_tree(slack_archive, "dist/src", "Slack companion archive")
    require_same_tree(read_file_tree(repo / "sdk/typescript/src", "SDK source"), sdk_files, "SDK archive")
    require_same_tree(
        read_file_tree(repo / "apps/slack-companion/dist/src", "Slack companion build"),
        slack_files,
        "Slack companion archive",
    )

    sdk_checkout = load_json_object((repo / "sdk/typescript/package.json").read_bytes(), "SDK package.json")
    slack_checkout = load_json_object(
        (repo / "apps/slack-companion/package.json").read_bytes(),
        "Slack companion package.json",
    )
    sdk_version = sdk_checkout.get("version")
    slack_version = slack_checkout.get("version")
    require(sdk_manifest.get("name") == SDK_PACKAGE, "SDK archive has the wrong package name")
    require(sdk_manifest.get("version") == sdk_version, "SDK archive version does not match the checkout")
    require(slack_manifest.get("name") == SLACK_PACKAGE, "Slack companion archive has the wrong package name")
    require(
        slack_manifest.get("version") == slack_version,
        "Slack companion archive version does not match the checkout",
    )
    dependencies = slack_manifest.get("dependencies")
    require(isinstance(dependencies, dict), "Slack companion archive dependencies must be an object")
    require(
        dependencies.get(SDK_PACKAGE) == sdk_version,
        "Slack companion archive must depend on the archived SDK version",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--sdk-archive", type=Path, required=True)
    parser.add_argument("--slack-archive", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        verify_portable_artifacts(
            repo=args.repo,
            bundle_root=args.bundle_root,
            sdk_archive=args.sdk_archive,
            slack_archive=args.slack_archive,
        )
    except (OSError, VerificationError) as exc:
        print(f"portable artifact verification failed: {exc}", file=sys.stderr)
        return 1
    print("portable release contracts, SDK, and Slack archive match the checkout")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
