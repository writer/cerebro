from __future__ import annotations

import json
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ci = load_script("droid_ci_context")
preflight = load_script("droid_preflight_context")
review_context = load_script("droid_review_context")
sast = load_script("droid_sast_context")


class DroidContextScriptTest(unittest.TestCase):
    def test_preflight_selects_infra_review_passes(self) -> None:
        files = [
            "infra/aws/Pulumi.sec-dev.yaml",
            ".github/workflows/infra-deploy.yml",
            "README.md",
        ]

        self.assertTrue(preflight.review_required(files))
        pass_names = [item["name"] for item in preflight.selected_passes(files)]
        self.assertIn("aws-infra-safety", pass_names)
        self.assertIn("workflow-permissions", pass_names)

    def test_ci_redaction_hides_tokens(self) -> None:
        text = "authorization: bearer secret123 token=abc api_key=xyz"
        redacted = ci.redact(text)

        self.assertNotIn("secret123", redacted)
        self.assertNotIn("abc", redacted)
        self.assertNotIn("xyz", redacted)
        self.assertIn("[redacted]", redacted)

    def test_sast_changed_line_parser_tracks_added_lines(self) -> None:
        diff = """diff --git a/.github/workflows/demo.yml b/.github/workflows/demo.yml
--- a/.github/workflows/demo.yml
+++ b/.github/workflows/demo.yml
@@ -1,0 +1,2 @@
+name: demo
+uses: actions/checkout@v4
"""
        lines = sast.parse_changed_lines(diff)

        self.assertEqual(lines[".github/workflows/demo.yml"], {1, 2})

    def test_review_context_merges_preflight_and_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "preflight.json").write_text(
                json.dumps(
                    {
                        "changed_files": ["infra/aws/Pulumi.sec-dev.yaml"],
                        "probe_plan": [{"name": "aws-infra-safety", "why": "aws", "commands": ["validate"]}],
                    }
                ),
                encoding="utf-8",
            )
            (root / "sast.json").write_text(json.dumps({"blocking_findings": []}), encoding="utf-8")
            (root / "ci.json").write_text(json.dumps({"failed_checks": []}), encoding="utf-8")
            (root / "feedback.json").write_text(json.dumps({"active_comments": [{"path": "infra/aws/Pulumi.sec-dev.yaml", "summary": "fix"}]}), encoding="utf-8")
            (root / "passes.json").write_text(json.dumps({"passes": []}), encoding="utf-8")
            (root / "memory.json").write_text(json.dumps({"memories": []}), encoding="utf-8")

            args = type("Args", (), {})()
            args.base = "base"
            args.head = "head"
            args.preflight_json = str(root / "preflight.json")
            args.sast_json = str(root / "sast.json")
            args.ci_json = str(root / "ci.json")
            args.feedback_json = str(root / "feedback.json")
            args.review_passes = str(root / "passes.json")
            args.review_memory = str(root / "memory.json")
            context = review_context.assemble(args)
            markdown = review_context.render_markdown(context)

        self.assertIn("aws-infra-safety", markdown)
        self.assertIn("Active Feedback", markdown)


if __name__ == "__main__":
    unittest.main()
