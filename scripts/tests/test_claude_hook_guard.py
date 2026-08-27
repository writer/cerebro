import unittest

from scripts.claude_hook_guard import GENERATED_ROOTS, ROOT, run_pre


def payload(rel_path: str) -> dict:
    return {"tool_name": "Edit", "tool_input": {"file_path": str(ROOT / rel_path)}}


class ClaudeHookGuardTest(unittest.TestCase):
    def test_generated_roots_exist(self) -> None:
        for root in GENERATED_ROOTS:
            self.assertTrue((ROOT / root).is_dir(), f"stale generated root: {root}")

    def test_blocks_generated_root_edit(self) -> None:
        rel = GENERATED_ROOTS[0] + "/example.rs"
        self.assertEqual(run_pre(payload(rel)), 2)

    def test_blocks_generated_go_suffixes(self) -> None:
        self.assertEqual(run_pre(payload("internal/findings/policy_rule_catalog_x_gen.go")), 2)
        self.assertEqual(run_pre(payload("internal/api/thing.pb.go")), 2)

    def test_allows_regular_source_edit(self) -> None:
        self.assertEqual(run_pre(payload("internal/bootstrap/server.go")), 0)
        self.assertEqual(run_pre(payload("crates/cerebro-platform/src/lib.rs")), 0)

    def test_allows_paths_outside_repo(self) -> None:
        self.assertEqual(
            run_pre({"tool_name": "Write", "tool_input": {"file_path": "/tmp/scratch.go"}}), 0
        )

    def test_missing_file_path_is_ignored(self) -> None:
        self.assertEqual(run_pre({"tool_name": "Edit", "tool_input": {}}), 0)


if __name__ == "__main__":
    unittest.main()
