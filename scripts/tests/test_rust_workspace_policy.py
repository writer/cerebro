import tempfile
import textwrap
import unittest
from pathlib import Path

from scripts import rust_workspace_policy


ROOT = Path(__file__).resolve().parents[2]


class RustWorkspacePolicyTests(unittest.TestCase):
    def test_repository_workspace_satisfies_policy(self):
        self.assertEqual(rust_workspace_policy.validate_workspace(ROOT), [])

    def test_rejects_member_dependency_and_lint_drift(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_manifest(root / "Cargo.toml", self.root_manifest("serde = \"1.0.228\""))
            self.write_manifest(
                root / "member/Cargo.toml",
                """
                [package]
                name = "member"
                version = "0.1.0"

                [dependencies]
                serde = "1.0.229"
                unknown = "2"

                [lints.rust]
                unsafe_code = "allow"
                """,
            )
            errors = rust_workspace_policy.validate_workspace(root)

        self.assertIn("member/Cargo.toml: [lints] must set workspace = true", errors)
        self.assertIn("member/Cargo.toml: dependency serde must inherit with workspace = true", errors)
        self.assertIn(
            "member/Cargo.toml: dependency unknown must be declared in [workspace.dependencies]",
            errors,
        )

    def test_allows_member_features_without_version_override(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_manifest(root / "Cargo.toml", self.root_manifest("serde_json = \"1.0.149\""))
            self.write_manifest(
                root / "member/Cargo.toml",
                """
                [package]
                name = "member"
                version = "0.1.0"

                [dependencies]
                serde_json = { workspace = true, features = ["preserve_order"] }

                [lints]
                workspace = true
                """,
            )
            self.assertEqual(rust_workspace_policy.validate_workspace(root), [])

    def test_rejects_unsafe_allow_outside_audited_boundary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_manifest(root / "Cargo.toml", self.root_manifest("serde = \"1.0.228\""))
            self.write_manifest(
                root / "member/Cargo.toml",
                """
                [package]
                name = "member"
                version = "0.1.0"

                [dependencies]
                serde.workspace = true

                [lints]
                workspace = true
                """,
            )
            (root / "member/src").mkdir(parents=True)
            (root / "member/src/lib.rs").write_text("#![allow(unsafe_code)]\n", encoding="utf-8")
            errors = rust_workspace_policy.validate_workspace(root)

        self.assertIn("member/src/lib.rs: unsafe_code allow is outside the audited ABI boundary", errors)

    @staticmethod
    def root_manifest(dependency: str) -> str:
        return f"""
        [workspace]
        members = ["member"]

        [workspace.dependencies]
        {dependency}

        [workspace.lints.rust]
        unsafe_code = "deny"
        unsafe_op_in_unsafe_fn = "deny"

        [workspace.lints.clippy]
        undocumented_unsafe_blocks = "deny"
        """

    @staticmethod
    def write_manifest(path: Path, contents: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(contents), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
