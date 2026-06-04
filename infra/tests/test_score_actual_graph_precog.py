from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.score_actual_graph_precog import (
    ActualGraphSnapshot,
    compare_snapshots,
    main,
    score_actual_graph,
)


class ScoreActualGraphPrecogTest(unittest.TestCase):
    def test_scores_clean_graph_ok(self) -> None:
        score = score_actual_graph(
            ActualGraphSnapshot(
                stack="test",
                nodes=10000,
                relations=20000,
                relation_counts={
                    "owned_by": 100,
                    "has_classification": 50,
                    "has_finding": 100,
                },
                paths={"topology": {"isolated": 0, "sinks_only": 1000, "sources_only": 1000}, "patterns": []},
            )
        )

        self.assertEqual(score.status, "ok")

    def test_flags_missing_sensitivity_and_sparse_ownership(self) -> None:
        score = score_actual_graph(
            ActualGraphSnapshot(
                stack="test",
                nodes=10000,
                relations=20000,
                relation_counts={"owned_by": 1, "has_finding": 100},
                paths=None,
            )
        )

        self.assertEqual(score.status, "degraded")
        self.assertTrue(any("sensitivity" in finding for finding in score.findings))
        self.assertTrue(any("ownership" in finding for finding in score.findings))
        self.assertTrue(any("path/topology sample unavailable" in finding for finding in score.findings))

    def test_flags_high_attack_and_finding_pressure_as_degraded(self) -> None:
        score = score_actual_graph(
            ActualGraphSnapshot(
                stack="test",
                nodes=10000,
                relations=50000,
                relation_counts={
                    "can_perform": 300,
                    "has_finding": 3000,
                    "owned_by": 100,
                    "tagged_as": 100,
                },
                paths={"topology": {"isolated": 0, "sinks_only": 4500, "sources_only": 1000}, "patterns": []},
            )
        )

        self.assertEqual(score.status, "degraded")
        self.assertTrue(any("attack-path relation pressure" in finding for finding in score.findings))
        self.assertTrue(any("finding-anchor pressure" in finding for finding in score.findings))

    def test_flags_actionable_path_fanout(self) -> None:
        score = score_actual_graph(
            ActualGraphSnapshot(
                stack="test",
                nodes=10000,
                relations=30000,
                relation_counts={"has_finding": 100, "owned_by": 100, "tagged_as": 100},
                paths={
                    "topology": {"isolated": 0, "sinks_only": 1000, "sources_only": 1000},
                    "patterns": [
                        {
                            "count": 5000,
                            "from_type": "a",
                            "first_relation": "affected_by",
                            "via_type": "vuln",
                            "second_relation": "has_finding",
                            "to_type": "finding",
                        }
                    ],
                },
            )
        )

        self.assertTrue(any("actionable path fanout" in f for f in score.findings))

    def test_transitive_patterns_reported_as_gravity_wells(self) -> None:
        score = score_actual_graph(
            ActualGraphSnapshot(
                stack="test",
                nodes=10000,
                relations=30000,
                relation_counts={"has_finding": 100, "owned_by": 100, "tagged_as": 100},
                paths={
                    "topology": {"isolated": 0, "sinks_only": 1000, "sources_only": 1000},
                    "patterns": [
                        {
                            "count": 50000,
                            "from_type": "grc.target",
                            "first_relation": "belongs_to",
                            "via_type": "source",
                            "second_relation": "has_finding",
                            "to_type": "finding",
                        },
                        {
                            "count": 100,
                            "from_type": "a",
                            "first_relation": "affected_by",
                            "via_type": "vuln",
                            "second_relation": "has_finding",
                            "to_type": "finding",
                        },
                    ],
                },
            )
        )

        self.assertTrue(any("gravity well" in f for f in score.findings))
        self.assertFalse(any("actionable path fanout" in f for f in score.findings))
        self.assertGreater(score.metrics.get("gravity_well_ratio", 0), 0.9)

    def test_compare_snapshots_reports_relation_density_skew(self) -> None:
        insights = compare_snapshots(
            [
                ActualGraphSnapshot("a", 10000, 20000, {"has_finding": 100}, None),
                ActualGraphSnapshot("b", 10000, 20000, {"has_finding": 1000}, None),
            ]
        )

        self.assertTrue(any("has_finding" in insight for insight in insights))

    def test_main_scores_snapshot_specs(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rel = Path(tmp.name) / "relations.json"
        rel.write_text(json.dumps({"owned_by": 100, "has_classification": 50}), encoding="utf-8")
        paths = Path(tmp.name) / "paths.json"
        paths.write_text(json.dumps({"topology": {}, "patterns": []}), encoding="utf-8")

        with redirect_stdout(StringIO()):
            status = main(["--snapshot", f"test:10000:20000:{rel}:{paths}"])

        self.assertEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
