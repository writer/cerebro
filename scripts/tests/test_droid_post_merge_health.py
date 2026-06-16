import unittest

import scripts.droid_post_merge_health as pm


class DroidPostMergeHealthTests(unittest.TestCase):
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

    def test_summarize_ignores_current_run(self):
        context = pm.summarize(
            branch="main",
            head_sha="abc",
            runs=[
                {"id": 1, "workflow_name": "Droid Post-Merge Health", "head_sha": "abc", "status": "in_progress"},
                {"id": 2, "workflow_name": "CI", "head_sha": "abc", "status": "completed", "conclusion": "success"},
            ],
            current_run_id="1",
        )
        self.assertTrue(context["healthy"])
        self.assertEqual(len(context["pending_runs"]), 0)

    def test_summarize_does_not_fail_for_pending_sibling_runs(self):
        context = pm.summarize(
            branch="main",
            head_sha="abc",
            runs=[
                {"id": 1, "workflow_name": "CI", "head_sha": "abc", "status": "in_progress", "url": "https://ci"},
                {"id": 2, "workflow_name": "Leak Check", "head_sha": "abc", "status": "completed", "conclusion": "success"},
            ],
        )
        self.assertTrue(context["healthy"])
        self.assertEqual(len(context["pending_runs"]), 1)

    def test_render_markdown_mentions_failures(self):
        markdown = pm.render_markdown(
            {
                "branch": "main",
                "head_sha": "abc",
                "healthy": False,
                "failed_runs": [{"workflow_name": "CI", "conclusion": "failure", "url": "https://ci"}],
                "pending_runs": [],
            }
        )
        self.assertIn("Droid Post-Merge Health", markdown)
        self.assertIn("Failures", markdown)
        self.assertIn("https://ci", markdown)

    def test_classify_droid_review_accepts_finished_comment(self):
        review = pm.classify_droid_review(
            {"number": 42, "author": "alice", "url": "https://pr"},
            [
                {
                    "user": {"login": "factory-droid[bot]"},
                    "body": "**Droid finished @alice's task**\n\nNo actionable findings.",
                    "html_url": "https://comment",
                }
            ],
        )
        self.assertEqual(review["status"], "ok")
        self.assertEqual(review["finished_count"], 1)

    def test_classify_droid_review_rejects_unsuperseded_error(self):
        review = pm.classify_droid_review(
            {"number": 42, "author": "alice", "url": "https://pr"},
            [
                {
                    "user": {"login": "factory-droid[bot]"},
                    "body": "**Droid encountered an error**\n\nFailed to checkout PR #42 branch for review",
                    "html_url": "https://comment",
                }
            ],
        )
        self.assertEqual(review["status"], "error")
        self.assertEqual(review["active_error_count"], 1)

    def test_classify_droid_review_accepts_superseded_error_plus_finished_comment(self):
        review = pm.classify_droid_review(
            {"number": 42, "author": "alice", "url": "https://pr"},
            [
                {
                    "user": {"login": "factory-droid[bot]"},
                    "body": "**Superseded Droid error** -- rerun completed successfully.",
                    "html_url": "https://old-comment",
                },
                {
                    "user": {"login": "factory-droid[bot]"},
                    "body": "**Droid finished @alice's task**\n\nLGTM.",
                    "html_url": "https://new-comment",
                },
            ],
        )
        self.assertEqual(review["status"], "ok")
        self.assertEqual(review["active_error_count"], 0)
        self.assertEqual(review["latest_comment_url"], "https://new-comment")

    def test_classify_droid_review_rejects_stale_in_progress_comment(self):
        review = pm.classify_droid_review(
            {"number": 42, "author": "alice", "url": "https://pr"},
            [
                {
                    "user": {"login": "factory-droid[bot]"},
                    "body": "Droid is reviewing code and running a security check...",
                    "html_url": "https://comment",
                }
            ],
        )
        self.assertEqual(review["status"], "in_progress")
        self.assertEqual(review["active_progress_count"], 1)

    def test_summarize_marks_droid_review_errors_unhealthy(self):
        context = pm.summarize(
            branch="main",
            head_sha="abc",
            runs=[
                {"workflow_name": "CI", "head_sha": "abc", "status": "completed", "conclusion": "success", "url": "https://ci"},
            ],
            pull_requests=[{"number": 42, "url": "https://pr"}],
            droid_reviews=[{"number": 42, "status": "error", "reason": "Droid has an unsuperseded error comment."}],
        )
        self.assertFalse(context["healthy"])
        self.assertEqual(len(context["failed_droid_reviews"]), 1)

    def test_render_markdown_mentions_droid_review_status(self):
        markdown = pm.render_markdown(
            {
                "branch": "main",
                "head_sha": "abc",
                "healthy": False,
                "failed_runs": [],
                "pending_runs": [],
                "droid_reviews": [
                    {
                        "number": 42,
                        "status": "error",
                        "reason": "Droid has an unsuperseded error comment.",
                        "latest_comment_url": "https://comment",
                    }
                ],
                "failed_droid_reviews": [{"number": 42, "status": "error"}],
            }
        )
        self.assertIn("Droid Reviews", markdown)
        self.assertIn("PR #42", markdown)
        self.assertIn("Droid has an unsuperseded error comment.", markdown)


if __name__ == "__main__":
    unittest.main()
