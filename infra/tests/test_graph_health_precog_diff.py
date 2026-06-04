from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.graph_health_precog_diff import (
    GraphHealthSnapshot,
    find_precog_drift,
    format_json,
    load_snapshot,
    main,
)


HEADER = (
    "checked_at\tstack\tnodes\trelations\tintegrity_passed\tintegrity_failed\t"
    "graph_relations\tcurrent_ingest_runtimes\tdeclared_runtimes\tmissing_ingest_runtimes\t"
    "counts_task\tintegrity_task\tpaths_task\tingest_runs_task\n"
)


class GraphHealthPrecogDiffTest(unittest.TestCase):
    def test_load_snapshot_parses_graph_health_tsv(self) -> None:
        path = self._snapshot_file(
            "2026-06-01T00:00:00Z\tsec-dev\t100\t200\t8\t0\tbelongs_to,can_reach\t34\t36\t\tarn\tarn\tarn\tarn\n"
        )

        snapshot = load_snapshot(path)

        self.assertEqual(snapshot.stack, "sec-dev")
        self.assertEqual(snapshot.nodes, 100)
        self.assertEqual(snapshot.relations, 200)
        self.assertEqual(snapshot.graph_relations, frozenset({"belongs_to", "can_reach"}))

    def test_no_drift_is_clean(self) -> None:
        snapshot = self._snapshot(nodes=100, relations=200)

        self.assertEqual(find_precog_drift(snapshot, snapshot), [])

    def test_integrity_failure_is_error(self) -> None:
        baseline = self._snapshot()
        candidate = self._snapshot(integrity_failed=1)

        findings = find_precog_drift(baseline, candidate)

        self.assertTrue(any(f.severity == "error" and f.check == "integrity" for f in findings))

    def test_relation_disappearance_is_error(self) -> None:
        baseline = self._snapshot(graph_relations=frozenset({"belongs_to", "can_reach", "can_assume"}))
        candidate = self._snapshot(graph_relations=frozenset({"belongs_to", "can_reach"}))

        findings = find_precog_drift(baseline, candidate, required_relations={"can_assume"})

        self.assertTrue(any(f.severity == "error" and "can_assume" in f.message for f in findings))

    def test_optional_relation_disappearance_is_warning(self) -> None:
        baseline = self._snapshot(graph_relations=frozenset({"belongs_to", "can_reach", "can_admin"}))
        candidate = self._snapshot(graph_relations=frozenset({"belongs_to", "can_reach"}))

        findings = find_precog_drift(baseline, candidate)

        self.assertTrue(any(f.severity == "warning" and "can_admin" in f.message for f in findings))

    def test_required_relation_is_error_even_if_missing_from_baseline(self) -> None:
        baseline = self._snapshot(graph_relations=frozenset({"belongs_to"}))
        candidate = self._snapshot(graph_relations=frozenset({"belongs_to"}))

        findings = find_precog_drift(baseline, candidate, required_relations={"can_perform"})

        self.assertTrue(any(f.severity == "error" and "can_perform" in f.message for f in findings))

    def test_count_drop_crossing_threshold_is_warning(self) -> None:
        baseline = self._snapshot(nodes=1000, relations=2000)
        candidate = self._snapshot(nodes=850, relations=1500)

        findings = find_precog_drift(baseline, candidate, node_drop_warning_percent=10, relation_drop_warning_percent=20)

        self.assertTrue(any(f.severity == "warning" and f.check == "nodes" for f in findings))
        self.assertTrue(any(f.severity == "warning" and f.check == "relations" for f in findings))

    def test_ingest_runtime_drop_is_warning_and_missing_history_is_error(self) -> None:
        baseline = self._snapshot(current_ingest_runtimes=36)
        candidate = self._snapshot(current_ingest_runtimes=34, missing_ingest_runtimes=("runtime-a",))

        findings = find_precog_drift(baseline, candidate)

        self.assertTrue(any(f.severity == "warning" and f.check == "ingest_runtimes" for f in findings))
        self.assertTrue(any(f.severity == "error" and "runtime-a" in f.message for f in findings))

    def test_ingest_runtime_coverage_gap_is_warning(self) -> None:
        baseline = self._snapshot(current_ingest_runtimes=34)
        candidate = self._snapshot(current_ingest_runtimes=34)

        findings = find_precog_drift(baseline, candidate)

        self.assertTrue(any(f.severity == "warning" and "34/36" in f.message for f in findings))

    def test_format_json_serializes_sets_and_tuples(self) -> None:
        baseline = self._snapshot()
        candidate = self._snapshot(integrity_failed=1)

        payload = json.loads(format_json(baseline, candidate, find_precog_drift(baseline, candidate)))

        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["candidate"]["graph_relations"], ["belongs_to", "can_reach"])

    def test_main_returns_failure_for_errors(self) -> None:
        baseline = self._snapshot_file(
            "2026-06-01T00:00:00Z\tsec-dev\t100\t200\t8\t0\tbelongs_to,can_reach\t34\t36\t\tarn\tarn\tarn\tarn\n"
        )
        candidate = self._snapshot_file(
            "2026-06-01T01:00:00Z\tsec-dev\t100\t200\t8\t1\tbelongs_to,can_reach\t34\t36\t\tarn\tarn\tarn\tarn\n"
        )

        with redirect_stdout(StringIO()):
            self.assertEqual(main([str(baseline), str(candidate)]), 1)

    def _snapshot_file(self, row: str) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "graph-health-sec-dev.tsv"
        path.write_text(HEADER + row, encoding="utf-8")
        return path

    def _snapshot(
        self,
        *,
        nodes: int = 100,
        relations: int = 200,
        integrity_passed: int = 8,
        integrity_failed: int = 0,
        graph_relations: frozenset[str] = frozenset({"belongs_to", "can_reach"}),
        current_ingest_runtimes: int = 36,
        missing_ingest_runtimes: tuple[str, ...] = (),
    ) -> GraphHealthSnapshot:
        return GraphHealthSnapshot(
            checked_at="2026-06-01T00:00:00Z",
            stack="sec-dev",
            nodes=nodes,
            relations=relations,
            integrity_passed=integrity_passed,
            integrity_failed=integrity_failed,
            graph_relations=graph_relations,
            current_ingest_runtimes=current_ingest_runtimes,
            declared_runtimes=36,
            missing_ingest_runtimes=missing_ingest_runtimes,
        )


if __name__ == "__main__":
    unittest.main()
