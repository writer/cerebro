from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.summarize_graph_backfill import render_markdown, summarize_states


def _state(source_id: str, status: str, targets: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "plan_hash": "a" * 64,
        "stack_name": "go-prod",
        "mode": "run",
        "source_id": source_id,
        "status": status,
        "targets": targets,
    }


class SummarizeGraphBackfillTest(unittest.TestCase):
    def test_completed_sources_produce_completed_summary(self) -> None:
        summary = summarize_states(
            [
                _state(
                    "gcp", "completed", [{"status": "completed", "failure_class": ""}]
                ),
                _state(
                    "okta", "completed", [{"status": "completed", "failure_class": ""}]
                ),
            ]
        )

        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["target_counts"], {"completed": 2})
        self.assertEqual(summary["next_actions"], [])

    def test_authentication_failure_produces_one_concrete_action(self) -> None:
        summary = summarize_states(
            [
                _state(
                    "cosmo",
                    "failed",
                    [
                        {"status": "failed", "failure_class": "authentication"},
                        {"status": "blocked", "failure_class": "authentication"},
                    ],
                )
            ]
        )
        markdown = render_markdown(summary)

        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["failure_classes"], {"authentication": 2})
        self.assertEqual(len(summary["next_actions"]), 1)
        self.assertIn("Rotate or correct the source credential", markdown)
        self.assertIn("| `cosmo` | 0 | 1 | 1 | 2 |", markdown)


if __name__ == "__main__":
    unittest.main()
