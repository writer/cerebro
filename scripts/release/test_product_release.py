from __future__ import annotations

import argparse
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.release.product_release import (
    EVENT_SCHEMA_VERSION,
    MAX_NPM_PACKAGE_JSON_BYTES,
    ManifestError,
    build_manifest,
    build_release_event,
    validate_manifest,
    validate_release_event,
)


COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
SDK_MEMBERS = {
    "package/src/index.js": "export {};\n",
    "package/src/index.ts": "export {};\n",
    "package/src/generated/openapi-types.ts": "export {};\n",
    "package/src/generated/agent-service-lifecycle.ts": "export {};\n",
    "package/src/generated/agent-service-lifecycle-contract.ts": "export {};\n",
}
SLACK_MEMBERS = {
    "package/dist/src/index.js": "export {};\n",
    "package/dist/src/index.d.ts": "export {};\n",
}


def write_npm_archive(
    path: Path,
    package_manifest: dict[str, object],
    members: dict[str, str],
) -> None:
    write_archive(
        path,
        [("package/package.json", json.dumps(package_manifest)), *members.items()],
    )


def write_archive(path: Path, members: list[tuple[str, str]]) -> None:
    with tarfile.open(path, mode="w:gz") as archive:
        for name, content in members:
            payload = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))


class ProductReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        for name in ("contracts/openapi.yaml", "contracts/lifecycle.json"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name, encoding="utf-8")
        self.write_sdk_archive()
        self.write_slack_archive()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            channel="candidate",
            version=f"candidate-{COMMIT}",
            commit=COMMIT,
            runtime_image=f"ghcr.io/writer/cerebro:candidate-{COMMIT}",
            runtime_digest=DIGEST,
            web_image=f"ghcr.io/writer/cerebro-web:candidate-{COMMIT}",
            web_digest=DIGEST,
            slack_archive=self.root / "slack.tgz",
            slack_version="0.1.0",
            sdk_archive=self.root / "sdk.tgz",
            sdk_version="0.1.0",
            openapi=self.root / "contracts/openapi.yaml",
            lifecycle_schema=self.root / "contracts/lifecycle.json",
            bundle_root=self.root,
        )

    def event_args(self) -> argparse.Namespace:
        return argparse.Namespace(
            repository="writer/cerebro",
            release_tag="v1.2.3",
            release_commit=COMMIT,
            manifest_sha256="c" * 64,
        )

    def write_sdk_archive(
        self,
        *,
        name: str = "@writer/cerebro-sdk",
        version: str = "0.1.0",
        members: dict[str, str] | None = None,
    ) -> None:
        write_npm_archive(
            self.root / "sdk.tgz",
            {"name": name, "version": version},
            SDK_MEMBERS if members is None else members,
        )

    def write_slack_archive(
        self,
        *,
        sdk_version: str = "0.1.0",
    ) -> None:
        write_npm_archive(
            self.root / "slack.tgz",
            {
                "name": "@writer/cerebro-slack-companion",
                "version": "0.1.0",
                "dependencies": {"@writer/cerebro-sdk": sdk_version},
            },
            SLACK_MEMBERS,
        )

    def test_build_is_deterministic_and_validates_bundle_digests(self) -> None:
        manifest = build_manifest(self.args())
        validate_manifest(manifest, self.root)
        first = json.dumps(manifest, indent=2, sort_keys=True)
        second = json.dumps(build_manifest(self.args()), indent=2, sort_keys=True)
        self.assertEqual(first, second)

    def test_rejects_archive_digest_mismatch(self) -> None:
        manifest = build_manifest(self.args())
        (self.root / "slack.tgz").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ManifestError, "artifact digest does not match"):
            validate_manifest(manifest, self.root)

    def test_rejects_archive_with_wrong_embedded_package_identity(self) -> None:
        self.write_sdk_archive(name="@writer/not-cerebro-sdk")
        manifest = build_manifest(self.args())

        with self.assertRaisesRegex(ManifestError, "archive package name does not match"):
            validate_manifest(manifest, self.root)

    def test_rejects_sdk_archive_without_generated_contract_binding(self) -> None:
        members = dict(SDK_MEMBERS)
        del members["package/src/generated/agent-service-lifecycle-contract.ts"]
        self.write_sdk_archive(members=members)
        manifest = build_manifest(self.args())

        with self.assertRaisesRegex(ManifestError, "archive is missing required members"):
            validate_manifest(manifest, self.root)

    def test_rejects_slack_archive_with_another_sdk_version(self) -> None:
        self.write_slack_archive(sdk_version="0.2.0")
        manifest = build_manifest(self.args())

        with self.assertRaisesRegex(ManifestError, "must depend on the archived TypeScript SDK version"):
            validate_manifest(manifest, self.root)

    def test_rejects_archive_with_duplicate_package_metadata(self) -> None:
        package_json = json.dumps({"name": "@writer/cerebro-sdk", "version": "0.1.0"})
        write_archive(
            self.root / "sdk.tgz",
            [
                ("package/package.json", package_json),
                ("package/package.json", package_json),
                *SDK_MEMBERS.items(),
            ],
        )
        manifest = build_manifest(self.args())

        with self.assertRaisesRegex(ManifestError, "archive has duplicate member"):
            validate_manifest(manifest, self.root)

    def test_rejects_archive_with_malformed_package_metadata(self) -> None:
        write_archive(
            self.root / "sdk.tgz",
            [("package/package.json", "{"), *SDK_MEMBERS.items()],
        )
        manifest = build_manifest(self.args())

        with self.assertRaisesRegex(ManifestError, "archive is invalid"):
            validate_manifest(manifest, self.root)

    def test_rejects_oversized_package_metadata(self) -> None:
        write_archive(
            self.root / "sdk.tgz",
            [
                ("package/package.json", "x" * (MAX_NPM_PACKAGE_JSON_BYTES + 1)),
                *SDK_MEMBERS.items(),
            ],
        )
        manifest = build_manifest(self.args())

        with self.assertRaisesRegex(ManifestError, "package metadata size is invalid"):
            validate_manifest(manifest, self.root)

    def test_rejects_candidate_version_for_another_commit(self) -> None:
        manifest = build_manifest(self.args())
        manifest["version"] = "candidate-" + "c" * 40
        with self.assertRaisesRegex(ManifestError, "candidate version"):
            validate_manifest(manifest)

    def test_rejects_bundle_path_traversal(self) -> None:
        manifest = build_manifest(self.args())
        manifest["contracts"]["openapi"]["file"] = "../openapi.yaml"
        with self.assertRaisesRegex(ManifestError, "inside the bundle"):
            validate_manifest(manifest)

    def test_builds_minimal_topology_neutral_release_event(self) -> None:
        event = build_release_event(self.event_args())
        validate_release_event(event)
        self.assertEqual(
            event,
            {
                "schema_version": EVENT_SCHEMA_VERSION,
                "release_tag": "v1.2.3",
                "release_commit": COMMIT,
                "release_url": "https://github.com/writer/cerebro/releases/tag/v1.2.3",
                "manifest_url": (
                    "https://github.com/writer/cerebro/releases/download/v1.2.3/"
                    "cerebro-product-release.json"
                ),
                "manifest_sha256": "c" * 64,
            },
        )

    def test_release_event_rejects_operational_fields(self) -> None:
        event = build_release_event(self.event_args())
        event["environment"] = "example"
        with self.assertRaisesRegex(ManifestError, "unexpected or missing fields"):
            validate_release_event(event)

    def test_release_event_rejects_inconsistent_manifest_url(self) -> None:
        event = build_release_event(self.event_args())
        event["manifest_url"] = event["manifest_url"].replace("v1.2.3", "v1.2.4")
        with self.assertRaisesRegex(ManifestError, "manifest_url is inconsistent"):
            validate_release_event(event)

    def test_release_event_rejects_invalid_manifest_digest(self) -> None:
        event = build_release_event(self.event_args())
        event["manifest_sha256"] = "sha256:" + "c" * 64
        with self.assertRaisesRegex(ManifestError, "manifest_sha256 is invalid"):
            validate_release_event(event)


if __name__ == "__main__":
    unittest.main()
