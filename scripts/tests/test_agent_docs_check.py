import tempfile
import unittest
from pathlib import Path

from scripts.agent_docs_check import check_file, instruction_files, makefile_targets


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class AgentDocsCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        write(self.root, "Makefile", "verify: build\n\techo ok\nbuild:\n\techo ok\nsdk-test:\n\techo ok\n")
        write(self.root, "docs/engineering/non-goals.md", "# non goals\n")

    def targets(self) -> set[str]:
        return makefile_targets(self.root)

    def test_clean_file_passes(self) -> None:
        path = write(
            self.root,
            "CLAUDE.md",
            "Run `make verify` then `make sdk-test`.\n"
            "See [non-goals](docs/engineering/non-goals.md) and [site](https://example.com).\n",
        )
        self.assertEqual(check_file(path, self.root, self.targets()), [])

    def test_undefined_make_target_fails(self) -> None:
        path = write(self.root, "CLAUDE.md", "Run `make does-not-exist`.\n")
        problems = check_file(path, self.root, self.targets())
        self.assertEqual(len(problems), 1)
        self.assertIn("does-not-exist", problems[0])

    def test_multi_target_reference_checks_each_token(self) -> None:
        path = write(self.root, "CLAUDE.md", "Run `make verify missing-one`.\n")
        problems = check_file(path, self.root, self.targets())
        self.assertEqual(len(problems), 1)
        self.assertIn("missing-one", problems[0])

    def test_variable_assignments_are_ignored(self) -> None:
        path = write(self.root, "CLAUDE.md", "Run `make verify PR=123`.\n")
        self.assertEqual(check_file(path, self.root, self.targets()), [])

    def test_missing_doc_link_fails(self) -> None:
        path = write(self.root, "AGENTS.md", "See [gone](docs/engineering/gone.md).\n")
        problems = check_file(path, self.root, self.targets())
        self.assertEqual(len(problems), 1)
        self.assertIn("docs/engineering/gone.md", problems[0])

    def test_anchor_links_are_ignored(self) -> None:
        path = write(self.root, "AGENTS.md", "See [section](#scope-discipline).\n")
        self.assertEqual(check_file(path, self.root, self.targets()), [])

    def test_skill_files_are_discovered(self) -> None:
        write(self.root, "CLAUDE.md", "x\n")
        write(self.root, ".claude/skills/example/SKILL.md", "x\n")
        write(self.root, ".factory/skills/example/SKILL.md", "x\n")
        names = {str(p.relative_to(self.root)) for p in instruction_files(self.root)}
        self.assertEqual(
            names,
            {"CLAUDE.md", ".claude/skills/example/SKILL.md", ".factory/skills/example/SKILL.md"},
        )


if __name__ == "__main__":
    unittest.main()
