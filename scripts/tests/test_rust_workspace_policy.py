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

        self.assertIn(
            "member/src/lib.rs: unsafe_code allow or expect is outside the audited ABI boundary",
            errors,
        )

    def test_rejects_combined_and_multiline_unsafe_allows(self):
        for source in (
            "#![allow(unused, unsafe_code)]\n",
            "#![allow(\n  unused,\n  unsafe_code,\n)]\n",
        ):
            with self.subTest(source=source):
                self.assertIn(
                    "member/src/lib.rs: unsafe_code allow or expect is outside the audited ABI boundary",
                    rust_workspace_policy.validate_unsafe_source("member/src/lib.rs", source),
                )

    def test_rejects_expect_unsafe_code_suppression(self):
        errors = rust_workspace_policy.validate_unsafe_source(
            "member/src/lib.rs", "#![expect(unsafe_code)]\nunsafe fn hidden() {}\n"
        )
        self.assertIn(
            "member/src/lib.rs: unsafe_code allow or expect is outside the audited ABI boundary",
            errors,
        )

    def test_rejects_every_unsafe_syntax_outside_audited_modules(self):
        sources = {
            "block": "fn f() { unsafe { call(); } }",
            "fn": "unsafe fn f() {}",
            "impl": "unsafe impl Trait for Type {}",
            "extern": 'unsafe extern "C" { fn f(); }',
            "trait": "unsafe trait Marker {}",
            "attribute": "#[unsafe(no_mangle)] pub extern \"C\" fn f() {}",
        }
        for expected, source in sources.items():
            with self.subTest(expected=expected):
                errors = rust_workspace_policy.validate_unsafe_source("member/src/lib.rs", source)
                self.assertEqual(
                    errors,
                    [
                        "member/src/lib.rs: unsafe syntax is outside the audited ABI boundary: "
                        + expected
                    ],
                )

    def test_ignores_unsafe_text_in_comments_and_literals(self):
        source = '''
        // unsafe fn commented_out() {}
        const NOTE: &str = "#[allow(unsafe_code)] unsafe { ignored(); }";
        const RAW: &str = r#"unsafe impl Ignored for Text {}"#;
        '''
        self.assertEqual(
            rust_workspace_policy.validate_unsafe_source("member/src/lib.rs", source), []
        )

    def test_accepts_only_exact_audited_abi_shapes(self):
        abi_source = '''
        #![allow(unsafe_code)]
        #[unsafe(no_mangle)] pub extern "C" fn version() -> u32 { 1 }
        #[unsafe(no_mangle)] pub extern "C" fn alloc() -> u32 { 0 }
        #[unsafe(no_mangle)] pub extern "C" fn evaluate() -> u32 { 0 }
        '''
        abi_path = "internal/mitre/evaluator/src/wasm_abi.rs"
        self.assertEqual(rust_workspace_policy.validate_unsafe_source(abi_path, abi_source), [])

        widened = abi_source + "unsafe fn extra() {}\n"
        self.assertIn(
            "audited unsafe syntax changed",
            rust_workspace_policy.validate_unsafe_source(abi_path, widened)[0],
        )

    def test_requires_compiler_forbid_for_safe_only_crates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest = self.root_manifest("serde = \"1.0.228\"").replace(
                'members = ["member"]', 'members = ["crates/control-kernel"]'
            )
            self.write_manifest(root / "Cargo.toml", manifest)
            self.write_manifest(
                root / "crates/control-kernel/Cargo.toml",
                """
                [package]
                name = "control-kernel"
                version = "0.1.0"

                [dependencies]
                serde.workspace = true

                [lints]
                workspace = true
                """,
            )
            source = root / "crates/control-kernel/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub fn safe() {}\n", encoding="utf-8")
            errors = rust_workspace_policy.validate_workspace(root)

        self.assertIn(
            "crates/control-kernel/src/lib.rs: safe-only crate must forbid unsafe_code", errors
        )

    def test_rejects_large_crate_root_and_filesystem_in_pure_module(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            manifest = self.root_manifest("serde = \"1.0.228\"").replace(
                'members = ["member"]', 'members = ["tools/graphactiongen"]'
            )
            self.write_manifest(root / "Cargo.toml", manifest)
            self.write_manifest(
                root / "tools/graphactiongen/Cargo.toml",
                """
                [package]
                name = "graphactiongen"
                version = "0.1.0"

                [dependencies]
                serde.workspace = true

                [lints]
                workspace = true
                """,
            )
            source = root / "tools/graphactiongen/src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(
                "mod catalog;\nmod error;\nmod filesystem;\nmod render;\n" + "// growth\n" * 40,
                encoding="utf-8",
            )
            (source / "catalog.rs").write_text("use std::fs;\n", encoding="utf-8")
            errors = rust_workspace_policy.validate_workspace(root)

        self.assertIn(
            "tools/graphactiongen/src/lib.rs: crate root must remain a thin module facade",
            errors,
        )
        self.assertIn(
            "tools/graphactiongen/src/catalog.rs: pure evaluation module must not access filesystem marker std::fs",
            errors,
        )

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
