import unittest

from scripts.docs_drift_check import (
    markdown_section,
    rust_migration_ledger_doc_failures,
    table_row_packages,
)


def ledger(*callers: tuple[str, str]) -> dict:
    return {"callers": [{"package": package, "status": status} for package, status in callers]}


def doc(rows: list[str], prose: str = "") -> str:
    table = "\n".join(["| Caller | Query shape | Required Rust capability |", "| --- | --- | --- |", *rows])
    return (
        "# Rust Organizational Platform\n\n## Earlier section\n\n"
        "| `internal/unrelated` | not counted | lives in another section |\n\n"
        "## Remaining compatibility callers\n\nIntro prose.\n\n"
        f"{table}\n\n{prose}\n\n## Next section\n\n"
        "| `internal/also-unrelated` | not counted | lives after the section |\n"
    )


COMPAT_ROWS = [
    "| `internal/findings` graph rules | collect/optional/varlen | aggregations |",
    "| `internal/graphquery` person access | anchor to targets | varlen traversal |",
    "| `internal/graphquery` effective access | fifteen-way union | union variants |",
]
PERMANENT_PROSE = (
    "Two callers are permanent: the `internal/graphagent` ask flow and "
    "`internal/policycandidate` shadow evaluation."
)
LEDGER = ledger(
    ("internal/attackpath", "migrated"),
    ("internal/findings", "compat"),
    ("internal/graphagent", "permanent"),
    ("internal/graphquery", "compat"),
    ("internal/policycandidate", "permanent"),
)


class MarkdownSectionTest(unittest.TestCase):
    def test_section_stops_at_next_heading_of_same_level(self) -> None:
        body = "## A\n\na-body\n\n### A.1\n\nnested\n\n## B\n\nb-body\n"
        self.assertEqual(markdown_section(body, "## A"), "\na-body\n\n### A.1\n\nnested\n")
        self.assertEqual(markdown_section(body, "## B"), "\nb-body")
        self.assertIsNone(markdown_section(body, "## C"))

    def test_table_row_packages_keeps_duplicates_and_ignores_prose(self) -> None:
        section = "prose `internal/prose-only`\n" + "\n".join(COMPAT_ROWS)
        self.assertEqual(
            table_row_packages(section),
            ["internal/findings", "internal/graphquery", "internal/graphquery"],
        )


class RustMigrationLedgerDocTest(unittest.TestCase):
    def test_matching_doc_passes(self) -> None:
        self.assertEqual(rust_migration_ledger_doc_failures(LEDGER, doc(COMPAT_ROWS, PERMANENT_PROSE)), [])

    def test_missing_section_fails(self) -> None:
        failures = rust_migration_ledger_doc_failures(LEDGER, "# Doc\n\n## Other\n")
        self.assertEqual(len(failures), 1)
        self.assertIn("missing section", failures[0])

    def test_migrated_caller_row_fails(self) -> None:
        rows = COMPAT_ROWS + ["| `internal/attackpath` | paths | traversal |"]
        failures = rust_migration_ledger_doc_failures(LEDGER, doc(rows, PERMANENT_PROSE))
        self.assertEqual(len(failures), 1)
        self.assertIn("internal/attackpath", failures[0])
        self.assertIn("'migrated'", failures[0])

    def test_unledgered_row_fails(self) -> None:
        rows = COMPAT_ROWS + ["| `internal/complianceimpact` | lookups | cursors |"]
        failures = rust_migration_ledger_doc_failures(LEDGER, doc(rows, PERMANENT_PROSE))
        self.assertEqual(len(failures), 1)
        self.assertIn("internal/complianceimpact", failures[0])
        self.assertIn("not in the ledger", failures[0])

    def test_compat_caller_without_row_fails(self) -> None:
        rows = [row for row in COMPAT_ROWS if "internal/findings" not in row]
        failures = rust_migration_ledger_doc_failures(LEDGER, doc(rows, PERMANENT_PROSE))
        self.assertEqual(len(failures), 1)
        self.assertIn("internal/findings", failures[0])
        self.assertIn("no row", failures[0])

    def test_permanent_caller_missing_from_prose_fails(self) -> None:
        prose = "Only the `internal/graphagent` ask flow is permanent."
        failures = rust_migration_ledger_doc_failures(LEDGER, doc(COMPAT_ROWS, prose))
        self.assertEqual(len(failures), 1)
        self.assertIn("internal/policycandidate", failures[0])
        self.assertIn("'permanent'", failures[0])

    def test_permanent_caller_named_only_in_table_fails(self) -> None:
        rows = COMPAT_ROWS + ["| `internal/graphagent` probe counts | counts | count RPC |"]
        prose = "`internal/policycandidate` is permanent."
        failures = rust_migration_ledger_doc_failures(LEDGER, doc(rows, prose))
        messages = "\n".join(failures)
        self.assertIn("compatibility callers table lists internal/graphagent", messages)
        self.assertIn("prose does not name it", messages)
        self.assertIn("must not appear as a compatibility callers table row", messages)

    def test_rows_outside_the_section_are_ignored(self) -> None:
        # `internal/unrelated` and `internal/also-unrelated` rows live in neighbouring sections.
        self.assertEqual(rust_migration_ledger_doc_failures(LEDGER, doc(COMPAT_ROWS, PERMANENT_PROSE)), [])


if __name__ == "__main__":
    unittest.main()
