from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.score_graph_health_history import load_history, main, score_history


HEADER = (
    "checked_at\tstack\tnodes\trelations\tintegrity_passed\tintegrity_failed\t"
    "graph_relations\tcurrent_ingest_runtimes\tdeclared_runtimes\tmissing_ingest_runtimes\t"
    "counts_task\tintegrity_task\tpaths_task\tingest_runs_task\n"
)


class ScoreGraphHealthHistoryTest(unittest.TestCase):
    def test_score_history_ok_for_stable_full_coverage(self) -> None:
        snapshots = [self._snapshot(i, nodes=1000 + i * 10, relations=2000 + i * 20) for i in range(8)]

        score = score_history(snapshots, required_relations={"belongs_to", "can_reach"})

        self.assertEqual(score.status, "ok")
        self.assertEqual(score.risk_score, 0)

    def test_score_history_warns_on_runtime_gap(self) -> None:
        snapshots = [self._snapshot(i, current=10, declared=10) for i in range(7)]
        snapshots.append(self._snapshot(7, current=8, declared=10))

        score = score_history(snapshots)

        self.assertEqual(score.status, "watch")
        self.assertTrue(any("runtime coverage 8/10" in finding for finding in score.findings))

    def test_score_history_detects_negative_robust_trend_outlier(self) -> None:
        snapshots = [self._snapshot(i, nodes=1000 + i * 10, relations=2000 + i * 20) for i in range(7)]
        snapshots.append(self._snapshot(7, nodes=800, relations=1600))

        score = score_history(snapshots)

        self.assertIn(score.status, {"watch", "degraded"})
        self.assertTrue(any("nodes below robust trend" in finding for finding in score.findings))

    def test_score_history_critical_on_required_relation_missing(self) -> None:
        snapshots = [self._snapshot(i, relations_text="belongs_to") for i in range(8)]

        score = score_history(snapshots, required_relations={"belongs_to", "can_reach"})

        self.assertEqual(score.status, "critical")
        self.assertTrue(any("missing required relations" in finding for finding in score.findings))

    def test_load_history_skips_empty_artifacts(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        empty = Path(tmp.name) / "empty.tsv"
        empty.write_text("", encoding="utf-8")
        valid = Path(tmp.name) / "valid.tsv"
        valid.write_text(HEADER + self._row(0), encoding="utf-8")

        history, skipped = load_history([empty, valid])

        self.assertEqual(len(history["sec-dev"]), 1)
        self.assertEqual(skipped, [empty])

    def test_main_returns_zero_for_watch(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        paths = []
        for i in range(7):
            path = Path(tmp.name) / f"{i}.tsv"
            path.write_text(HEADER + self._row(i, current=10, declared=10), encoding="utf-8")
            paths.append(path)
        latest = Path(tmp.name) / "latest.tsv"
        latest.write_text(HEADER + self._row(7, current=8, declared=10), encoding="utf-8")
        paths.append(latest)

        with redirect_stdout(StringIO()):
            self.assertEqual(main([*(str(path) for path in paths)]), 0)

    def _snapshot(
        self,
        offset: int,
        *,
        nodes: int = 1000,
        relations: int = 2000,
        current: int = 10,
        declared: int = 10,
        relations_text: str = "belongs_to,can_reach",
    ):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / f"{offset}.tsv"
        path.write_text(
            HEADER
            + self._row(
                offset,
                nodes=nodes,
                relations=relations,
                current=current,
                declared=declared,
                relations_text=relations_text,
            ),
            encoding="utf-8",
        )
        history, _ = load_history([path])
        return history["sec-dev"][0]

    def _row(
        self,
        offset: int,
        *,
        nodes: int = 1000,
        relations: int = 2000,
        current: int = 10,
        declared: int = 10,
        relations_text: str = "belongs_to,can_reach",
    ) -> str:
        checked = (datetime(2026, 6, 1, tzinfo=UTC) + timedelta(hours=offset)).isoformat()
        return (
            f"{checked}\tsec-dev\t{nodes}\t{relations}\t8\t0\t{relations_text}\t"
            f"{current}\t{declared}\t\tarn\tarn\tarn\tarn\n"
        )


if __name__ == "__main__":
    unittest.main()
