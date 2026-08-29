from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_WORKFLOW = ROOT / ".github" / "workflows" / "integration.yml"
TOMBSTONE_GO_TEST = (
    ROOT / "internal" / "statestore" / "postgres" / "tombstone_findings_test.go"
)


def _postgres_test_command() -> str:
    workflow = INTEGRATION_WORKFLOW.read_text(encoding="utf-8")
    step = workflow.split("      - name: Run Postgres integration tests\n", 1)[1]
    return step.split("\n\n", 1)[0]


class IntegrationWorkflowTest(unittest.TestCase):
    def test_postgres_packages_run_one_at_a_time(self) -> None:
        command = _postgres_test_command()

        # All three packages share a single Postgres service, so their test
        # binaries must not run concurrently.
        self.assertIn(" -p 1", command)
        for package in (
            "./internal/statestore/postgres",
            "./internal/findings",
            "./cmd/cerebro",
        ):
            self.assertIn(package, command)

    def test_the_schema_drop_that_makes_serialisation_necessary_still_exists(
        self,
    ) -> None:
        # If this DDL ever leaves the test suite, -p 1 can be revisited; while it
        # is here, concurrent packages can have the findings table pulled out
        # from under them.
        source = TOMBSTONE_GO_TEST.read_text(encoding="utf-8")
        self.assertIn("DROP TABLE IF EXISTS findings", source)

    def test_postgres_job_still_gates_on_the_integration_label(self) -> None:
        workflow = INTEGRATION_WORKFLOW.read_text(encoding="utf-8")
        job = workflow.split("  postgres:\n", 1)[1].split("\n  slack-wake", 1)[0]

        self.assertIn("run-integration", job)
        self.assertIn("image: postgres:17", job)
        self.assertIn("CEREBRO_POSTGRES_DSN:", job)


if __name__ == "__main__":
    unittest.main()
