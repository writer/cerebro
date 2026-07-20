# Assurance Decision Contract

An assurance decision is an immutable record of one compliance objective verdict at one decision time. It binds a completed assessment run, the run's exact input manifest, one result from the run's validated result set, the proofs evaluated at decision time, and the fail-closed qualification outcome.

## Durable identity

- Resource IDs use the `assurance-decision-<opaque>` format.
- Every record is tenant scoped.
- `run_id`, `result_id`, and `objective_id` identify the assessed fact.
- `program_id`, `scope_revision_id`, and `plan_revision_id` preserve the governed assessment scope.
- `decision_digest` addresses the qualification outcome.
- `record_digest` addresses the complete immutable record, including its input snapshot and actor.
- An idempotency key identifies one record request. Reusing it with different proof material returns a conflict.

## Write path

The service accepts a decision only when all of these checks pass:

1. The assessment run is complete and has a persisted input hash, result-set hash, result count, and completion time.
2. The supplied manifest matches both the persisted manifest and the run input hash.
3. Result chunks form a contiguous digest chain.
4. Recomputing all chunk results matches the run result-set hash and result count.
5. The supplied objective result matches the selected persisted result.
6. The decision time is not earlier than assessment completion.
7. Recomputing qualification from the input snapshot produces the stored verdict and decision digest.
8. The record time is not earlier than the decision time.

An unqualified verdict can be recorded. It cannot authorize production use because `AuthorizeProductionUse` continues to fail closed.

## Storage boundaries

- JetStream receives `workflow.v1.compliance.assessment_assurance_decision_recorded` before the read projection is updated.
- Postgres stores the immutable current read projection in `compliance_assurance_decisions`.
- The projection can be rebuilt through the existing assessment event replay path.
- Neo4j remains a rebuildable relationship projection. It is not an assurance-decision store of record.
- Evidence payload bytes remain in EvidenceCAS. The decision snapshot carries evidence identifiers, states, collection times, and validity times.

## Rollout gate

Enable decision writes only after the assessment projection contains completed runs and result chunks. A rollout is ready when:

- focused qualification, record, idempotency, tamper, replay, and Postgres schema tests pass;
- race tests pass for the decision record and replay paths;
- architecture checks confirm the existing store boundaries;
- replay in a non-production environment reconstructs the same `record_digest` values.

## Rollback

Disable the decision write route before rolling back application code. Existing events and Postgres rows remain readable data. Do not delete the event kind or table during rollback. A later deployment can replay the events to restore the projection. Because decision rows are immutable and no existing assessment API is replaced, rollback does not require rewriting assessment runs or results.
