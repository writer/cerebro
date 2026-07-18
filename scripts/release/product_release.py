#!/usr/bin/env python3
"""Build and validate a deterministic Cerebro product-release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = "cerebro.product-release/v1"
EVENT_SCHEMA_VERSION = "cerebro.product-release-published/v1"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^(candidate-[0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+)$")
IMAGE_RE = re.compile(
    r"^ghcr\.io/[a-z0-9._-]+/[a-z0-9._/-]+:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
)
PACKAGE_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
REPOSITORY_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
MAX_NPM_ARCHIVE_MEMBERS = 10_000
MAX_NPM_PACKAGE_JSON_BYTES = 256 * 1024
NPM_PACKAGE_JSON = "package/package.json"
SDK_REQUIRED_MEMBERS = frozenset(
    {
        "package/src/index.js",
        "package/src/index.ts",
        "package/src/generated/openapi-types.ts",
        "package/src/generated/agent-service-lifecycle.ts",
        "package/src/generated/agent-service-lifecycle-contract.ts",
    }
)
SLACK_REQUIRED_MEMBERS = frozenset(
    {
        "package/dist/src/index.js",
        "package/dist/src/index.d.ts",
    }
)


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


def read_npm_archive_manifest(path: Path, label: str) -> tuple[dict[str, Any], frozenset[str]]:
    members: set[str] = set()
    package_manifest: dict[str, Any] | None = None
    member_count = 0

    try:
        with tarfile.open(path, mode="r|gz") as archive:
            for member in archive:
                member_count += 1
                require(
                    member_count <= MAX_NPM_ARCHIVE_MEMBERS,
                    f"{label} archive has too many members",
                )
                member_path = PurePosixPath(member.name)
                require(
                    member.name == member_path.as_posix()
                    and not member_path.is_absolute()
                    and ".." not in member_path.parts
                    and len(member_path.parts) > 1
                    and member_path.parts[0] == "package",
                    f"{label} archive member is unsafe: {member.name}",
                )
                require(member.name not in members, f"{label} archive has duplicate member: {member.name}")
                members.add(member.name)
                require(
                    member.isfile() or member.isdir(),
                    f"{label} archive member must be a regular file or directory: {member.name}",
                )
                if member.name != NPM_PACKAGE_JSON:
                    continue
                require(member.isfile(), f"{label} {NPM_PACKAGE_JSON} must be a regular file")
                require(package_manifest is None, f"{label} archive has duplicate package metadata")
                require(
                    0 < member.size <= MAX_NPM_PACKAGE_JSON_BYTES,
                    f"{label} package metadata size is invalid",
                )
                package_file = archive.extractfile(member)
                require(package_file is not None, f"{label} package metadata cannot be read")
                package_bytes = package_file.read(MAX_NPM_PACKAGE_JSON_BYTES + 1)
                require(
                    len(package_bytes) <= MAX_NPM_PACKAGE_JSON_BYTES,
                    f"{label} package metadata is too large",
                )
                parsed = json.loads(package_bytes.decode("utf-8"))
                require(isinstance(parsed, dict), f"{label} package metadata must be an object")
                package_manifest = parsed
    except ManifestError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, tarfile.TarError) as exc:
        raise ManifestError(f"{label} archive is invalid: {exc}") from exc

    require(package_manifest is not None, f"{label} archive is missing {NPM_PACKAGE_JSON}")
    return package_manifest, frozenset(members)


def validate_npm_archive(
    record: dict[str, Any],
    label: str,
    bundle_root: Path,
    *,
    expected_package: str,
    required_members: frozenset[str],
) -> dict[str, Any]:
    archive_path = bundle_root / PurePosixPath(record["file"])
    package_manifest, members = read_npm_archive_manifest(archive_path, label)
    require(record["package"] == expected_package, f"{label}.package is invalid")
    require(package_manifest.get("name") == expected_package, f"{label} archive package name does not match")
    require(
        package_manifest.get("version") == record["package_version"],
        f"{label} archive package version does not match",
    )
    missing = sorted(required_members - members)
    require(not missing, f"{label} archive is missing required members: {', '.join(missing)}")
    return package_manifest


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
    require(
        components["slack_companion"]["package"] == "@writer/cerebro-slack-companion",
        "components.slack_companion.package is invalid",
    )
    require(
        components["typescript_sdk"]["package"] == "@writer/cerebro-sdk",
        "components.typescript_sdk.package is invalid",
    )
    if bundle_root is not None:
        sdk_manifest = validate_npm_archive(
            components["typescript_sdk"],
            "components.typescript_sdk",
            bundle_root,
            expected_package="@writer/cerebro-sdk",
            required_members=SDK_REQUIRED_MEMBERS,
        )
        slack_manifest = validate_npm_archive(
            components["slack_companion"],
            "components.slack_companion",
            bundle_root,
            expected_package="@writer/cerebro-slack-companion",
            required_members=SLACK_REQUIRED_MEMBERS,
        )
        slack_dependencies = slack_manifest.get("dependencies")
        require(
            isinstance(slack_dependencies, dict)
            and slack_dependencies.get("@writer/cerebro-sdk") == sdk_manifest.get("version"),
            "components.slack_companion archive must depend on the archived TypeScript SDK version",
        )

    contracts = manifest.get("contracts")
    require(isinstance(contracts, dict), "contracts must be an object")
    require(set(contracts) == {"openapi", "agent_service_lifecycle"}, "contracts has unexpected or missing fields")
    validate_file_record(contracts["openapi"], "contracts.openapi", bundle_root)
    validate_file_record(contracts["agent_service_lifecycle"], "contracts.agent_service_lifecycle", bundle_root)


def build_release_event(args: argparse.Namespace) -> dict[str, str]:
    release_url = f"https://github.com/{args.repository}/releases/tag/{args.release_tag}"
    manifest_url = (
        f"https://github.com/{args.repository}/releases/download/{args.release_tag}/"
        "cerebro-product-release.json"
    )
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "release_tag": args.release_tag,
        "release_commit": args.release_commit,
        "release_url": release_url,
        "manifest_url": manifest_url,
        "manifest_sha256": args.manifest_sha256,
    }


def validate_release_event(event: Any) -> None:
    require(isinstance(event, dict), "release event must be an object")
    require(
        set(event)
        == {
            "schema_version",
            "release_tag",
            "release_commit",
            "release_url",
            "manifest_url",
            "manifest_sha256",
        },
        "release event has unexpected or missing fields",
    )
    require(event.get("schema_version") == EVENT_SCHEMA_VERSION, "release event schema_version is invalid")
    release_tag = event.get("release_tag")
    release_commit = event.get("release_commit")
    release_url = event.get("release_url")
    manifest_url = event.get("manifest_url")
    require(
        isinstance(release_tag, str) and VERSION_RE.fullmatch(release_tag) is not None and release_tag.startswith("v"),
        "release event release_tag is invalid",
    )
    require(
        isinstance(release_commit, str) and COMMIT_RE.fullmatch(release_commit) is not None,
        "release event release_commit is invalid",
    )
    require(
        isinstance(release_url, str) and release_url.startswith("https://github.com/"),
        "release event release_url is invalid",
    )
    repository = release_url.removeprefix("https://github.com/").removesuffix(f"/releases/tag/{release_tag}")
    require(re.fullmatch(REPOSITORY_PATTERN, repository) is not None, "release event repository is invalid")
    require(
        release_url == f"https://github.com/{repository}/releases/tag/{release_tag}",
        "release event release_url is inconsistent",
    )
    require(
        manifest_url
        == f"https://github.com/{repository}/releases/download/{release_tag}/cerebro-product-release.json",
        "release event manifest_url is inconsistent",
    )
    require(
        SHA256_RE.fullmatch(event.get("manifest_sha256", "")) is not None,
        "release event manifest_sha256 is invalid",
    )


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

    event = subparsers.add_parser("event", help="write a product-release consumer event")
    event.add_argument("--repository", required=True)
    event.add_argument("--release-tag", required=True)
    event.add_argument("--release-commit", required=True)
    event.add_argument("--manifest-sha256", required=True)
    event.add_argument("--out", type=Path, required=True)

    validate_event = subparsers.add_parser("validate-event", help="validate a product-release consumer event")
    validate_event.add_argument("event", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        if args.command == "build":
            manifest = build_manifest(args)
            validate_manifest(manifest, args.bundle_root.resolve())
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        elif args.command == "validate":
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            validate_manifest(manifest, args.bundle_root.resolve() if args.bundle_root else None)
        elif args.command == "event":
            event = build_release_event(args)
            validate_release_event(event)
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(event, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            event = json.loads(args.event.read_text(encoding="utf-8"))
            validate_release_event(event)
    except (ManifestError, OSError, json.JSONDecodeError) as exc:
        print(f"product release validation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
