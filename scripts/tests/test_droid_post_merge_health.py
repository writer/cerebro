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


if __name__ == "__main__":
    unittest.main()
