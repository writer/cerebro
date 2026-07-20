from __future__ import annotations

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.release.verify_portable_artifacts import VerificationError, verify_portable_artifacts


class PortableArtifactVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.bundle = self.root / "bundle"
        self.sdk_archive = self.bundle / "writer-cerebro-sdk-0.1.0.tgz"
        self.slack_archive = self.bundle / "writer-cerebro-slack-companion-0.1.0.tgz"

        self.write("api/openapi.yaml", b"openapi: 3.0.3\n")
        self.write("schemas/agent-service-lifecycle.schema.json", b'{"type":"object"}\n')
        self.write("schemas/product-release.schema.json", b'{"title":"release"}\n')
        self.write("schemas/product-release-published.schema.json", b'{"title":"published"}\n')
        self.write_json(
            "sdk/typescript/package.json",
            {"name": "@writer/cerebro-sdk", "version": "0.1.0"},
        )
        self.write("sdk/typescript/README.md", b"# SDK\n")
        self.write("sdk/typescript/examples/example.ts", b"export const example = true;\n")
        self.write("sdk/typescript/src/index.ts", b"export type * from './generated/openapi-types.ts';\n")
        self.write("sdk/typescript/src/index.js", b"export {};\n")
        self.write("sdk/typescript/src/generated/openapi-types.ts", b"export type Runtime = {};\n")
        self.write("sdk/typescript/src/generated/agent-service-lifecycle.ts", b"export type Event = {};\n")
        self.write(
            "sdk/typescript/src/generated/agent-service-lifecycle-contract.ts",
            b"export type Contract = {};\n",
        )
        self.write_json(
            "apps/slack-companion/package.json",
            {
                "name": "@writer/cerebro-slack-companion",
                "version": "0.1.0",
                "dependencies": {"@writer/cerebro-sdk": "0.1.0"},
            },
        )
        self.write("apps/slack-companion/README.md", b"# Slack companion\n")
        self.write("apps/slack-companion/dist/src/index.js", b"export * from './lifecycle.js';\n")
        self.write("apps/slack-companion/dist/src/index.d.ts", b"export * from './lifecycle.js';\n")
        self.write("apps/slack-companion/dist/src/lifecycle.js", b"export const ready = true;\n")

        self.bundle.mkdir(parents=True)
        (self.bundle / "cerebro-openapi.yaml").write_bytes((self.repo / "api/openapi.yaml").read_bytes())
        (self.bundle / "agent-service-lifecycle.schema.json").write_bytes(
            (self.repo / "schemas/agent-service-lifecycle.schema.json").read_bytes()
        )
        (self.bundle / "product-release.schema.json").write_bytes(
            (self.repo / "schemas/product-release.schema.json").read_bytes()
        )
        (self.bundle / "product-release-published.schema.json").write_bytes(
            (self.repo / "schemas/product-release-published.schema.json").read_bytes()
        )
        self.write_archives()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, data: bytes) -> None:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def write_json(self, relative: str, value: object) -> None:
        self.write(relative, (json.dumps(value, sort_keys=True) + "\n").encode())

    def tree_members(self, root: Path, archive_prefix: str) -> dict[str, bytes]:
        return {
            f"{archive_prefix}/{path.relative_to(root).as_posix()}": path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    def write_archive(
        self,
        path: Path,
        package_manifest: bytes,
        members: dict[str, bytes],
        *,
        duplicate: str | None = None,
        symbolic_link: str | None = None,
    ) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            all_members = {"package/package.json": package_manifest, **members}
            for name, data in all_members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if duplicate is not None:
                data = all_members[duplicate]
                info = tarfile.TarInfo(duplicate)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            if symbolic_link is not None:
                info = tarfile.TarInfo(symbolic_link)
                info.type = tarfile.SYMTYPE
                info.linkname = "package/package.json"
                archive.addfile(info)

    def write_archives(
        self,
        *,
        sdk_overrides: dict[str, bytes] | None = None,
        slack_overrides: dict[str, bytes] | None = None,
        sdk_dependency: str = "0.1.0",
        sdk_manifest_override: bytes | None = None,
        slack_manifest_override: bytes | None = None,
        duplicate_sdk_member: str | None = None,
        slack_symbolic_link: str | None = None,
    ) -> None:
        sdk_members = self.tree_members(self.repo / "sdk/typescript/src", "package/src")
        sdk_members.update(self.tree_members(self.repo / "sdk/typescript/examples", "package/examples"))
        sdk_members["package/README.md"] = (self.repo / "sdk/typescript/README.md").read_bytes()
        sdk_members.update(sdk_overrides or {})
        slack_members = self.tree_members(self.repo / "apps/slack-companion/dist/src", "package/dist/src")
        slack_members["package/README.md"] = (
            self.repo / "apps/slack-companion/README.md"
        ).read_bytes()
        slack_members.update(slack_overrides or {})
        if sdk_dependency != "0.1.0":
            manifest = json.loads((self.repo / "apps/slack-companion/package.json").read_text())
            manifest["dependencies"]["@writer/cerebro-sdk"] = sdk_dependency
            self.write_json("apps/slack-companion/package.json", manifest)
        self.write_archive(
            self.sdk_archive,
            sdk_manifest_override or (self.repo / "sdk/typescript/package.json").read_bytes(),
            sdk_members,
            duplicate=duplicate_sdk_member,
        )
        self.write_archive(
            self.slack_archive,
            slack_manifest_override
            or (self.repo / "apps/slack-companion/package.json").read_bytes(),
            slack_members,
            symbolic_link=slack_symbolic_link,
        )

    def verify(self) -> None:
        verify_portable_artifacts(self.repo, self.bundle, self.sdk_archive, self.slack_archive)

    def test_accepts_exact_contracts_sdk_and_slack_build(self) -> None:
        self.verify()

    def test_rejects_bundled_contract_from_another_checkout(self) -> None:
        (self.bundle / "cerebro-openapi.yaml").write_text("openapi: 3.1.0\n", encoding="utf-8")
        with self.assertRaisesRegex(VerificationError, "OpenAPI contract does not match"):
            self.verify()

    def test_rejects_unchecked_release_contract_from_another_checkout(self) -> None:
        (self.bundle / "product-release.schema.json").write_text(
            '{"title":"tampered"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(VerificationError, "product release contract does not match"):
            self.verify()

    def test_rejects_unchecked_published_contract_from_another_checkout(self) -> None:
        (self.bundle / "product-release-published.schema.json").write_text(
            '{"title":"tampered"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            VerificationError,
            "published product release contract does not match",
        ):
            self.verify()

    def test_rejects_generated_sdk_binding_from_another_checkout(self) -> None:
        self.write_archives(
            sdk_overrides={"package/src/generated/openapi-types.ts": b"export type Runtime = never;\n"}
        )
        with self.assertRaisesRegex(
            VerificationError,
            "SDK archive has changed files: src/generated/openapi-types.ts",
        ):
            self.verify()

    def test_rejects_changed_sdk_example(self) -> None:
        self.write_archives(
            sdk_overrides={"package/examples/example.ts": b"export const example = false;\n"}
        )
        with self.assertRaisesRegex(VerificationError, "changed files: examples/example.ts"):
            self.verify()

    def test_rejects_changed_sdk_package_manifest(self) -> None:
        self.write_archives(
            sdk_manifest_override=b'{"name":"@writer/cerebro-sdk","version":"0.1.0","exports":{}}\n'
        )
        with self.assertRaisesRegex(VerificationError, "changed files: package.json"):
            self.verify()

    def test_rejects_changed_published_readme(self) -> None:
        self.write_archives(sdk_overrides={"package/README.md": b"changed\n"})
        with self.assertRaisesRegex(VerificationError, "changed files: README.md"):
            self.verify()

    def test_rejects_stale_slack_companion_build(self) -> None:
        self.write_archives(
            slack_overrides={"package/dist/src/lifecycle.js": b"export const ready = false;\n"}
        )
        with self.assertRaisesRegex(
            VerificationError,
            "Slack companion archive has changed files: dist/src/lifecycle.js",
        ):
            self.verify()

    def test_rejects_slack_archive_bound_to_another_sdk_version(self) -> None:
        self.write_archives(sdk_dependency="0.2.0")
        with self.assertRaisesRegex(VerificationError, "must depend on the archived SDK version"):
            self.verify()

    def test_rejects_duplicate_archive_member(self) -> None:
        self.write_archives(duplicate_sdk_member="package/src/index.ts")
        with self.assertRaisesRegex(VerificationError, "duplicate member: package/src/index.ts"):
            self.verify()

    def test_rejects_non_regular_archive_member(self) -> None:
        self.write_archives(slack_symbolic_link="package/dist/src/alias.js")
        with self.assertRaisesRegex(VerificationError, "must be a regular file or directory"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
