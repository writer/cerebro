# Canonical compliance work cases

## Ownership

Cerebro owns each compliance work item, its state, owner, version, occurrences, action history, remediation timestamp, and assurance verification receipt. The companion does not create a second compliance queue.

The companion owns the Slack-facing case record, operator approval records, execution attempts, and the links that let an operator return to the canonical work item, affected subject, findings, and assurance decision.

## Operator journey

1. `operator_security_case_list` reads the canonical queue from `GET /grc/work-items`. The operator can filter by work state and owner and continue with the returned cursor.
2. `operator_security_case_open_work_item` reads one item from `GET /grc/work-items/{id}` and creates one durable case. A repeated call for the same work-item ID returns the existing case.
3. `operator_security_case_command` adds the exact action, expected version, rationale, and optional decision ID to the case plan. It does not write to Cerebro.
4. The autonomy runner creates an approval record for `operator_security_case_execute_command`. Execution remains blocked until that exact case step is approved.
5. The approved executor sends the version-checked command to `POST /grc/work-items/{id}/commands` with the findings credential.
6. `operator_security_case_work_item_status` performs an independent read from Cerebro. The runner records whether the returned work item satisfies the step acceptance checks.
7. The case closes when Cerebro returns `resolved`, `accepted`, or `superseded`. A verified resolution also records the assurance decision ID and immutable verification receipt returned by Cerebro.

## Remediation and verification

Remediation and verification are separate commands.

- `remediate` records who completed the change and when it happened. The case then reports `needs_evidence`.
- A post-change assessment produces an AssuranceDecision in Cerebro.
- `verify_assurance` supplies that decision ID with the current work-item version.
- Cerebro validates tenant, program, scope revision, control, objective, subject, source, evaluation time, remediation time, result, evidence, and independent actor before resolving the item.
- The companion trusts the returned verification receipt. Caller-supplied evidence does not replace the evidence derived by Cerebro.

## Compatibility

The existing GitHub security-alert case tools, plans, draft pull-request flow, case states, Slack routes, commands, findings, goals, schedules, and evidence workflows remain available. Canonical work-item cases use the additional `cerebro_work_item` case kind.

## Rollout

1. Deploy the Cerebro work-item list, read, and command API before deploying this companion change.
2. Confirm the companion has a read credential for list and status calls and a findings credential for approved commands.
3. Enable canonical work-item tools for internal security operators first.
4. Open the same work item twice and confirm only one durable case exists.
5. Submit remediation with a stale version and confirm Cerebro rejects it without changing the case state.
6. Submit remediation with the current version, approve the exact goal step, and confirm an independent read reports the new version and remediation timestamp.
7. Attempt assurance verification with a pre-remediation or mismatched decision and confirm the work item stays open.
8. Approve verification with a matching fresh decision and confirm Cerebro returns `resolved` with its verification receipt.
9. Compare canonical queue counts and state totals between direct Cerebro reads and `operator_security_case_list`.

## Rollback

Disable the canonical work-item tools in the assistant tool pack and deploy the prior companion revision. Do not delete durable case records: they contain approval and execution history and do not own canonical work state.

The Cerebro APIs and work queue can remain deployed because existing companion and Cerebro surfaces do not depend on these adapter tools. Operators can continue work directly through Cerebro while the companion adapter is disabled.
