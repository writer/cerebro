import unittest

import scripts.post_merge_health as pm


class PostMergeHealthTests(unittest.TestCase):
    def test_summarize_marks_failures(self):
        context = pm.summarize(
            branch="main",
            head_sha="abc",
            runs=[
                {"workflow_name": "CI", "head_sha": "abc", "status": "completed", "conclusion": "failure", "url": "https://ci"},
                {"workflow_name": "Leak Check", "head_sha": "abc", "status": "completed", "conclusion": "success", "url": "https://leak"},
            ],
        )
        self.assertFalse(context["healthy"])
        self.assertEqual(len(context["failed_runs"]), 1)

    def test_summarize_ignores_current_and_prior_health_runs(self):
        context = pm.summarize(
            branch="main",
            head_sha="abc",
            runs=[
                {"id": 1, "workflow_name": "Post-Merge Health", "head_sha": "abc", "status": "in_progress"},
                {"id": 2, "workflow_name": "Post-Merge Health", "head_sha": "abc", "status": "completed", "conclusion": "failure"},
                {"id": 3, "workflow_name": "CI", "head_sha": "abc", "status": "completed", "conclusion": "success"},
            ],
            current_run_id="1",
        )
        self.assertTrue(context["healthy"])
        self.assertEqual(len(context["failed_runs"]), 0)
        self.assertEqual(len(context["pending_runs"]), 0)

    def test_summarize_does_not_fail_for_pending_sibling_runs(self):
        context = pm.summarize(
            branch="main",
            head_sha="abc",
            runs=[
                {"workflow_name": "CI", "head_sha": "abc", "status": "in_progress", "url": "https://ci"},
                {"workflow_name": "Leak Check", "head_sha": "abc", "status": "completed", "conclusion": "success"},
            ],
        )
        self.assertTrue(context["healthy"])
        self.assertEqual(len(context["pending_runs"]), 1)

    def test_summarize_release_lag_is_informational(self):
        context = pm.summarize(
            branch="main",
            head_sha="abc",
            runs=[{"workflow_name": "CI", "head_sha": "abc", "status": "completed", "conclusion": "success"}],
            release_status={
                "latest_tag": "v2.1.399",
                "latest_tag_on_head": False,
                "commits_since_latest_tag": 1,
                "status": "tag_lag",
            },
        )
        self.assertTrue(context["healthy"])
        self.assertEqual(context["release_status"]["status"], "tag_lag")

    def test_render_markdown_mentions_failures_and_release_status(self):
        markdown = pm.render_markdown(
            {
                "branch": "main",
                "head_sha": "abc",
                "healthy": False,
                "failed_runs": [{"workflow_name": "CI", "conclusion": "failure", "url": "https://ci"}],
                "pending_runs": [],
                "release_status": {
                    "latest_tag": "v2.1.399",
                    "latest_tag_on_head": False,
                    "commits_since_latest_tag": 1,
                },
            }
        )
        self.assertIn("Post-Merge Health", markdown)
        self.assertIn("Failures", markdown)
        self.assertIn("https://ci", markdown)
        self.assertIn("v2.1.399", markdown)
        self.assertIn("Release Status", markdown)


if __name__ == "__main__":
    unittest.main()
