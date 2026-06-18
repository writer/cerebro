import json
import tempfile
import unittest
from pathlib import Path

import scripts.droid_review_context as ctx

REPO_ROOT = Path(__file__).resolve().parents[2]


class DroidReviewContextTests(unittest.TestCase):
    def test_pass_plan_merges_preflight_and_contract(self):
        preflight = {
            "changed_files": ["internal/graphagent/ask.go", "scripts/droid_ci_context.py"],
            "probe_plan": [{"name": "ask-trajectory", "why": "Ask changed", "commands": ["go test ./internal/graphagent"]}],
        }
        passes_doc = json.loads(
            """
            {"passes":[
              {"name":"ask-trajectory","path_globs":["internal/graphagent/**"],"invariants":["ask"],"commands":["go test ./internal/graphagent"],"required_evidence":["route"]},
              {"name":"workflow-permissions","path_globs":["scripts/**"],"invariants":["workflow"],"commands":["make droid-review-sast"],"required_evidence":["permissions"]}
            ]}
            """
        )
        planned = ctx.pass_plan(preflight, passes_doc, preflight["changed_files"])
        names = [item["name"] for item in planned]
        self.assertIn("ask-trajectory", names)
        self.assertIn("workflow-permissions", names)
        self.assertEqual(names.count("ask-trajectory"), 1)

    def test_relevant_memories_filters_by_path(self):
        memory_doc = {
            "memories": [
                {"id": "ask", "path_globs": ["internal/graphagent/**"], "summary": "ask"},
                {"id": "workflow", "path_globs": [".github/workflows/**"], "summary": "workflow"},
            ]
        }
        memories = ctx.relevant_memories(memory_doc, ["internal/graphagent/ask.go"])
        self.assertEqual([item["id"] for item in memories], ["ask"])

    def test_assemble_writes_markdown_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "preflight.json").write_text(
                json.dumps(
                    {
                        "changed_files": ["internal/graphagent/ask.go"],
                        "probe_plan": [{"name": "ask-trajectory", "why": "ask", "commands": ["go test ./internal/graphagent"]}],
                    }
                ),
                encoding="utf-8",
            )
            (root / "sast.json").write_text(
                json.dumps(
                    {
                        "blocking_findings": [],
                        "tools": [
                            {
                                "name": "deepsec",
                                "scope": "project `cerebro` candidate scan",
                                "status": "completed",
                                "notes": ["Run run-1: 1 candidate(s) across 1 file(s); 1 candidate(s) on changed files."],
                                "findings": [
                                    {
                                        "tool": "deepsec",
                                        "rule": "go-ssrf",
                                        "file": "internal/graphagent/ask.go",
                                        "line": 42,
                                        "severity": "INFO",
                                        "confidence": "SIGNAL",
                                        "message": "http.Get(userURL)",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "ci.json").write_text(json.dumps({"failed_checks": []}), encoding="utf-8")
            (root / "feedback.json").write_text(json.dumps({"active_comments": []}), encoding="utf-8")
            (root / "passes.json").write_text(json.dumps({"passes": []}), encoding="utf-8")
            (root / "memory.json").write_text(json.dumps({"memories": []}), encoding="utf-8")
            args = type("Args", (), {})()
            args.base = "origin/main"
            args.head = "HEAD"
            args.preflight_json = str(root / "preflight.json")
            args.sast_json = str(root / "sast.json")
            args.ci_json = str(root / "ci.json")
            args.feedback_json = str(root / "feedback.json")
            args.review_passes = str(root / "passes.json")
            args.review_memory = str(root / "memory.json")
            context = ctx.assemble(args)
            markdown = ctx.render_markdown(context)
            self.assertIn("Droid Recursive Review Context", markdown)
            self.assertIn("ask-trajectory", markdown)
            self.assertIn("Scanner Context", markdown)
            self.assertIn("deepsec", markdown)
            self.assertIn("go-ssrf", markdown)
            self.assertNotIn("http.Get", markdown)
            self.assertIn("source snippets withheld", markdown)

    def test_fixture_driven_context_contains_pass_memory_feedback(self):
        fixture_root = REPO_ROOT / "tools" / "droidreview" / "testdata" / "review_context"
        args = type("Args", (), {})()
        args.base = "base"
        args.head = "head"
        args.preflight_json = str(fixture_root / "preflight.json")
        args.sast_json = str(fixture_root / "sast.json")
        args.ci_json = str(fixture_root / "ci.json")
        args.feedback_json = str(fixture_root / "feedback.json")
        args.review_passes = str(fixture_root / "passes.json")
        args.review_memory = str(fixture_root / "memory.json")
        context = ctx.assemble(args)
        pass_names = {item["name"] for item in context["pass_plan"]}
        self.assertIn("ask-trajectory", pass_names)
        self.assertIn("workflow-permissions", pass_names)
        self.assertTrue(context["relevant_memory"])
        self.assertEqual(len(context["active_feedback"]), 1)

    def test_default_factory_context_contains_contract_passes(self):
        passes_doc = json.loads((REPO_ROOT / ".factory" / "review-passes.json").read_text(encoding="utf-8"))
        memory_doc = json.loads((REPO_ROOT / ".factory" / "review-memory.json").read_text(encoding="utf-8"))
        files = ["internal/connectorcatalog/catalog/devops-ci-cd.yaml", "internal/compliance/evidence_packet.go"]
        pass_names = {item["name"] for item in ctx.pass_plan({}, passes_doc, files)}
        memory_ids = {item["id"] for item in ctx.relevant_memories(memory_doc, files)}
        self.assertIn("source-definition-contract", pass_names)
        self.assertIn("compliance-policy-packet", pass_names)
        self.assertIn("connector-sourcegen-ready", memory_ids)
        self.assertIn("compliance-packet-single-contract", memory_ids)


if __name__ == "__main__":
    unittest.main()
