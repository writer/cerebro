#!/usr/bin/env python3
"""Build and validate a deterministic Cerebro product-release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = "cerebro.product-release/v1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^(candidate-[0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+)$")
IMAGE_RE = re.compile(
    r"^ghcr\.io/[a-z0-9._-]+/[a-z0-9._/-]+:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
PACKAGE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")


class ManifestError(ValueError):
    """Raised when a product-release manifest is incomplete or inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def relative_file(path: Path, bundle_root: Path) -> str:
    try:
        relative = path.resolve().relative_to(bundle_root.resolve())
    except ValueError as exc:
        raise ManifestError(f"artifact {path} is outside bundle root {bundle_root}") from exc
    return relative.as_posix()


def file_record(path: Path, bundle_root: Path) -> dict[str, str]:
    if not path.is_file():
        raise ManifestError(f"artifact does not exist: {path}")
    return {
        "file": relative_file(path, bundle_root),
        "sha256": sha256_file(path),
    }


def archive_record(
    path: Path,
    bundle_root: Path,
    package: str,
    package_version: str,
) -> dict[str, str]:
    record = file_record(path, bundle_root)
    return {
        "kind": "npm-archive",
        "package": package,
        "package_version": package_version,
        **record,
    }


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    bundle_root = args.bundle_root.resolve()
    return {
        "schema_version": SCHEMA_VERSION,
        "channel": args.channel,
        "version": args.version,
        "commit": args.commit,
        "components": {
            "runtime": {
                "kind": "oci-image",
                "image": args.runtime_image,
                "digest": args.runtime_digest,
            },
            "web": {
                "kind": "oci-image",
                "image": args.web_image,
                "digest": args.web_digest,
            },
            "slack_companion": archive_record(
                args.slack_archive,
                bundle_root,
                "@writer/cerebro-slack-companion",
                args.slack_version,
            ),
            "typescript_sdk": archive_record(
                args.sdk_archive,
                bundle_root,
                "@writer/cerebro-sdk",
                args.sdk_version,
            ),
        },
        "contracts": {
            "openapi": file_record(args.openapi, bundle_root),
            "agent_service_lifecycle": file_record(args.lifecycle_schema, bundle_root),
        },
    }


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ManifestError(message)


def validate_file_record(
    record: Any,
    label: str,
    bundle_root: Path | None,
    *,
    archive: bool = False,
) -> None:
    require(isinstance(record, dict), f"{label} must be an object")
    expected = {"file", "sha256"}
    if archive:
        expected |= {"kind", "package", "package_version"}
    require(set(record) == expected, f"{label} has unexpected or missing fields")
    file_name = record.get("file")
    require(isinstance(file_name, str) and file_name != "", f"{label}.file is required")
    path = PurePosixPath(file_name)
    require(not path.is_absolute() and ".." not in path.parts, f"{label}.file must stay inside the bundle")
    require(SHA256_RE.fullmatch(record.get("sha256", "")) is not None, f"{label}.sha256 is invalid")
    if archive:
        require(record.get("kind") == "npm-archive", f"{label}.kind must be npm-archive")
        require(
            record.get("package") in {"@writer/cerebro-slack-companion", "@writer/cerebro-sdk"},
            f"{label}.package is invalid",
        )
        require(
            PACKAGE_VERSION_RE.fullmatch(record.get("package_version", "")) is not None,
            f"{label}.package_version is invalid",
        )
    if bundle_root is not None:
        artifact = bundle_root / path
        require(artifact.is_file(), f"{label} artifact is missing: {file_name}")
        require(sha256_file(artifact) == record["sha256"], f"{label} artifact digest does not match")


def validate_manifest(manifest: Any, bundle_root: Path | None = None) -> None:
    require(isinstance(manifest, dict), "manifest must be an object")
    require(
        set(manifest) == {"schema_version", "channel", "version", "commit", "components", "contracts"},
        "manifest has unexpected or missing fields",
    )
    require(manifest.get("schema_version") == SCHEMA_VERSION, "schema_version is invalid")
    channel = manifest.get("channel")
    version = manifest.get("version")
    commit = manifest.get("commit")
    require(channel in {"candidate", "stable"}, "channel is invalid")
    require(isinstance(version, str) and VERSION_RE.fullmatch(version) is not None, "version is invalid")
    require(isinstance(commit, str) and COMMIT_RE.fullmatch(commit) is not None, "commit is invalid")
    if channel == "candidate":
        require(version == f"candidate-{commit}", "candidate version must identify the manifest commit")
    if channel == "stable":
        require(version.startswith("v"), "stable version must be a release tag")

    components = manifest.get("components")
    require(isinstance(components, dict), "components must be an object")
    require(
        set(components) == {"runtime", "web", "slack_companion", "typescript_sdk"},
        "components has unexpected or missing fields",
    )
    for name in ("runtime", "web"):
        image = components[name]
        require(isinstance(image, dict), f"components.{name} must be an object")
        require(set(image) == {"kind", "image", "digest"}, f"components.{name} has unexpected or missing fields")
        require(image.get("kind") == "oci-image", f"components.{name}.kind must be oci-image")
        require(IMAGE_RE.fullmatch(image.get("image", "")) is not None, f"components.{name}.image is invalid")
        require(DIGEST_RE.fullmatch(image.get("digest", "")) is not None, f"components.{name}.digest is invalid")
        require(image["image"].endswith(f":{version}"), f"components.{name}.image must use the manifest version")

    validate_file_record(components["slack_companion"], "components.slack_companion", bundle_root, archive=True)
    validate_file_record(components["typescript_sdk"], "components.typescript_sdk", bundle_root, archive=True)

    contracts = manifest.get("contracts")
    require(isinstance(contracts, dict), "contracts must be an object")
    require(set(contracts) == {"openapi", "agent_service_lifecycle"}, "contracts has unexpected or missing fields")
    validate_file_record(contracts["openapi"], "contracts.openapi", bundle_root)
    validate_file_record(contracts["agent_service_lifecycle"], "contracts.agent_service_lifecycle", bundle_root)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="write a product-release manifest")
    build.add_argument("--channel", choices=("candidate", "stable"), required=True)
    build.add_argument("--version", required=True)
    build.add_argument("--commit", required=True)
    build.add_argument("--runtime-image", required=True)
    build.add_argument("--runtime-digest", required=True)
    build.add_argument("--web-image", required=True)
    build.add_argument("--web-digest", required=True)
    build.add_argument("--slack-archive", type=Path, required=True)
    build.add_argument("--slack-version", required=True)
    build.add_argument("--sdk-archive", type=Path, required=True)
    build.add_argument("--sdk-version", required=True)
    build.add_argument("--openapi", type=Path, required=True)
    build.add_argument("--lifecycle-schema", type=Path, required=True)
    build.add_argument("--bundle-root", type=Path, required=True)
    build.add_argument("--out", type=Path, required=True)

    validate = subparsers.add_parser("validate", help="validate a product-release manifest")
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--bundle-root", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        if args.command == "build":
            manifest = build_manifest(args)
            validate_manifest(manifest, args.bundle_root.resolve())
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            validate_manifest(manifest, args.bundle_root.resolve() if args.bundle_root else None)
    except (ManifestError, OSError, json.JSONDecodeError) as exc:
        print(f"product release validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
