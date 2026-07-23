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


if __name__ == "__main__":
    unittest.main()
