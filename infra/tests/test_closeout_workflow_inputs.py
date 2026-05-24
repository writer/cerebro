"""Discovery proxy for `closeout_workflow_inputs_test.py`.

`unittest discover` defaults to the `test*.py` pattern, which does not match
the spec-mandated filename `closeout_workflow_inputs_test.py`. Re-exporting
the test classes here ensures pre-commit and CI pick the cases up under the
existing discovery rules without forcing a pattern change.
"""

from closeout_workflow_inputs_test import (  # noqa: F401
    CloseoutEcsScriptEnvCaseTest,
    CloseoutEnvMappingTest,
    CloseoutJobsTest,
    CloseoutPreflightOlderThanTest,
    CloseoutWorkflowInputsTest,
    CloseoutWorkflowMetadataTest,
    CloseoutWorkflowNoHardcodedBucketTest,
)
