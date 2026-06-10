from __future__ import annotations

import json
import sys
import unittest
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.synthetic_lifecycle_probe import (
    LifecycleProbeError,
    emit_synthetic_transcript,
    main,
    validate_transcript,
)


class SyntheticLifecycleProbeTest(unittest.TestCase):
    def test_fixture_validates_reconstructable_idempotent_lifecycle(self) -> None:
        transcript = emit_synthetic_transcript(
            run_ids=["synthetic-run-alpha", "synthetic-run-alpha", "synthetic-run-beta"],
            first_visit_status="linked",
        )

        report = validate_transcript(transcript)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["runs"], 3)
        self.assertEqual(report["idempotent_replays"], 1)
        self.assertEqual(report["distinct_lifecycle_keys"], 2)
        self.assertIn("VAL-CROSS-001", report["assertions"])
        self.assertIn("VAL-CROSS-002", report["assertions"])
        self.assertIn("VAL-CROSS-017", report["assertions"])
        self.assertIn("VAL-CROSS-018", report["assertions"])
        self.assertTrue(all("lifecycle_state" in stage for run in transcript["runs"] for stage in run["stages"]))

    def test_missing_required_canonical_field_fails_with_field_name(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        del transcript["runs"][0]["stages"][2]["tenant_id"]

        with self.assertRaisesRegex(LifecycleProbeError, "tenant_id"):
            validate_transcript(transcript)

    def test_integrity_mismatch_fails_closed(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        transcript["runs"][0]["stages"][4]["evidence_cas_digest"] = "sha256:synthetic-mismatch"

        with self.assertRaisesRegex(LifecycleProbeError, "evidence_cas_digest"):
            validate_transcript(transcript)

    def test_integrity_identity_shape_fails_closed(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        for stage in transcript["runs"][0]["stages"]:
            if stage["stage"] != "source_origin":
                stage["evidence_cas_uri"] = "cas://synthetic/evidence"

        with self.assertRaisesRegex(LifecycleProbeError, "evidence_cas_uri"):
            validate_transcript(transcript)

    def test_integrity_digest_shape_fails_closed(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        for stage in transcript["runs"][0]["stages"]:
            if stage["stage"] != "source_origin":
                stage["evidence_cas_merkle_root"] = "md5:synthetic"

        with self.assertRaisesRegex(LifecycleProbeError, "evidence_cas_merkle_root"):
            validate_transcript(transcript)

    def test_first_visit_orphan_is_valid_only_when_explicit_and_visible(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"], first_visit_status="orphan")

        report = validate_transcript(transcript)

        self.assertEqual(report["first_visit_statuses"], ["orphan"])
        self.assertEqual(report["orphan_or_setup_visible"], 1)

        observability = next(
            stage for stage in transcript["runs"][0]["stages"] if stage["stage"] == "infra_observability"
        )
        observability["first_visit_status"] = "linked"
        observability["link_status"] = "linked"
        with self.assertRaisesRegex(LifecycleProbeError, "does not expose first-visit"):
            validate_transcript(transcript)

    def test_unsupported_lifecycle_state_fails_closed(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        transcript["runs"][0]["stages"][3]["lifecycle_state"] = "paused"

        with self.assertRaisesRegex(LifecycleProbeError, "unsupported"):
            validate_transcript(transcript)

    def test_inconsistent_lifecycle_transition_fails_closed(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        transcript["runs"][0]["stages"][5]["lifecycle_state"] = "projected"

        with self.assertRaisesRegex(LifecycleProbeError, "lifecycle_state must be"):
            validate_transcript(transcript)

    def test_legacy_compatible_record_allows_optional_trace_gap(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"], include_legacy=True)

        legacy = transcript["legacy_records"][0]
        legacy.pop("trace_id")
        legacy.pop("traceparent", None)
        legacy["observability_gap"] = "trace_context_absent"

        report = validate_transcript(transcript)

        self.assertEqual(report["legacy_compatible_records"], 1)

    def test_sensitive_broad_surface_values_are_rejected(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        transcript["runs"][0]["stages"][5]["alert_title"] = "Lifecycle for arn:aws:iam::123456789012:role/example"

        with self.assertRaisesRegex(LifecycleProbeError, "sensitive"):
            validate_transcript(transcript)

    def test_sensitive_numeric_account_ids_are_rejected(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        transcript["runs"][0]["stages"][5]["account"] = 123456789012

        with self.assertRaisesRegex(LifecycleProbeError, "sensitive"):
            validate_transcript(transcript)

    def test_cli_validates_transcript_and_prints_sanitized_summary(self) -> None:
        transcript = emit_synthetic_transcript(run_ids=["synthetic-run-alpha"])
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "transcript.json"
            path.write_text(json.dumps(transcript), encoding="utf-8")

            stdout = StringIO()
            with redirect_stdout(stdout):
                status = main(["--transcript", str(path)])

        self.assertEqual(status, 0)
        output = stdout.getvalue()
        self.assertIn("status\tpass", output)
        self.assertIn("assertion\tVAL-CROSS-001", output)
        self.assertNotIn("arn:aws", output)
        self.assertNotIn("123456789012", output)


if __name__ == "__main__":
    unittest.main()
