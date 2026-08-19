import tempfile
import unittest
from pathlib import Path

from scripts import readme_check


class ReadmeCheckTests(unittest.TestCase):
    def test_supported_catalog_source_ids_accepts_both_indentation_styles(self):
        with tempfile.TemporaryDirectory() as tmp:
            catalog_root = Path(tmp)
            (catalog_root / "style-a.yaml").write_text(
                "verification:\n"
                "  attempts:\n"
                "  - classifier_output: supported\n"
                "    assertions:\n"
                "      source_id: style_a\n",
                encoding="utf-8",
            )
            (catalog_root / "style-b.yaml").write_text(
                "verification:\n"
                "  attempts:\n"
                "- classifier_output: supported\n"
                "  assertions:\n"
                "    source_id: style_b\n",
                encoding="utf-8",
            )
            (catalog_root / "unsupported.yaml").write_text(
                "verification:\n"
                "  attempts:\n"
                "- classifier_output: unsupported\n"
                "  assertions:\n"
                "    source_id: excluded\n",
                encoding="utf-8",
            )

            self.assertEqual(
                readme_check.supported_catalog_source_ids(catalog_root),
                {"style_a", "style_b"},
            )

    def test_require_runtime_authority_docs_rejects_missing_command(self):
        readme = "\n".join(
            [
                *readme_check.RUNTIME_AUTHORITY_SNIPPETS,
                *readme_check.RUNTIME_VALIDATION_COMMANDS[:-1],
            ]
        )
        runtime_profiles = "\n".join(
            [
                *readme_check.RUNTIME_AUTHORITY_SNIPPETS,
                "CEREBRO_POSTGRES_DSN=<postgres-dsn-with-tls>",
                "CEREBRO_CAPABILITY_TOKEN_SECRETS=<hmac-secret-1>,<hmac-secret-2>",
            ]
        )

        with self.assertRaisesRegex(SystemExit, "make graph-rebuild-dryrun"):
            readme_check.require_runtime_authority_docs(readme, runtime_profiles)

    def test_require_runtime_authority_docs_accepts_placeholder_only_boundary(self):
        readme = "\n".join(
            [
                *readme_check.RUNTIME_AUTHORITY_SNIPPETS,
                *readme_check.RUNTIME_VALIDATION_COMMANDS,
            ]
        )
        runtime_profiles = "\n".join(
            [
                *readme_check.RUNTIME_AUTHORITY_SNIPPETS,
                "CEREBRO_POSTGRES_DSN=<postgres-dsn-with-tls>",
                "CEREBRO_CAPABILITY_TOKEN_SECRETS=<hmac-secret-1>,<hmac-secret-2>",
            ]
        )

        readme_check.require_runtime_authority_docs(readme, runtime_profiles)


if __name__ == "__main__":
    unittest.main()
