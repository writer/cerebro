import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "rust_migration_ledger_check.py"


def make_repo(root: Path, ledger: dict, go_files: dict[str, str]) -> None:
    ledger_path = root / "docs" / "engineering" / "rust-migration-ledger.json"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
    for rel, text in go_files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def run_check(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        capture_output=True,
        text=True,
    )


COMPAT_GO = "package x\n\nvar _ = RawCypherQueryStore(nil)\n"
CLEAN_GO = "package x\n\nfunc ok() {}\n"


class RustMigrationLedgerCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def ledger(self, callers, infrastructure=()) -> dict:
        return {
            "infrastructure": [{"package": p, "role": "r"} for p in infrastructure],
            "callers": [{"package": p, "status": s} for p, s in callers],
        }

    def test_consistent_ledger_passes(self) -> None:
        make_repo(
            self.root,
            self.ledger([("internal/a", "compat"), ("internal/b", "migrated")], ["internal/ports"]),
            {
                "internal/a/a.go": COMPAT_GO,
                "internal/b/b.go": CLEAN_GO,
                "internal/ports/p.go": COMPAT_GO,
            },
        )
        result = run_check(self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 migrated, 1 compat", result.stdout)

    def test_stale_compat_entry_fails(self) -> None:
        make_repo(self.root, self.ledger([("internal/a", "compat")]), {"internal/a/a.go": CLEAN_GO})
        result = run_check(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no longer references", result.stderr)

    def test_false_migrated_entry_fails(self) -> None:
        make_repo(self.root, self.ledger([("internal/a", "migrated")]), {"internal/a/a.go": COMPAT_GO})
        result = run_check(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("still references", result.stderr)

    def test_unledgered_caller_fails(self) -> None:
        make_repo(self.root, self.ledger([]), {"internal/new/new.go": COMPAT_GO})
        result = run_check(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("without a ledger entry", result.stderr)

    def test_subpackage_is_covered_by_parent_entry(self) -> None:
        make_repo(
            self.root,
            self.ledger([("internal/a", "compat")]),
            {"internal/a/sub/s.go": COMPAT_GO},
        )
        result = run_check(self.root)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_permanent_entry_requires_reference(self) -> None:
        make_repo(self.root, self.ledger([("internal/a", "permanent")]), {"internal/a/a.go": CLEAN_GO})
        result = run_check(self.root)
        self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
