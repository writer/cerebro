# Assessment Snapshot Contract

An assessment snapshot records the exact compliance state available after a completed assessment run. It binds the run input manifest, ordered result chunk chain, assurance decisions selected at one cutoff, and referenced evidence identifiers. The snapshot is immutable and content addressed.

Snapshots support later review without copying evidence payloads or creating another source of truth.

## Recorded commitment

Each snapshot records:

- the tenant, program, scope revision, plan revision, and completed run;
- the complete normalized input manifest and its digest;
- the result-set digest, result count, and ordered result chunk references;
- the latest assurance decision for each result at the snapshot cutoff;
- counts for qualified decisions and results without a decision;
- the sorted evidence identifier set and its digest;
- the actor, creation time, idempotency key, request hash, and record digest.

The snapshot event contains identifiers, metadata, digests, and the input manifest. It does not contain raw evidence bytes. Evidence bytes remain in EvidenceCAS.

## Write and replay path

Snapshot creation succeeds only when:

1. The assessment run is complete and its manifest digest matches the stored input hash.
2. Result chunks form a contiguous digest chain.
3. Recomputed results match the run result-set hash and result count.
4. Every selected assurance decision belongs to the same tenant and run, references a result in the run, and passes decision-record validation.
5. Decision and evidence sets can be sorted and content addressed.
6. The idempotency key is unused or already identifies the same tenant and run.

JetStream receives `workflow.v1.compliance.assessment_snapshot_recorded` before Postgres projects the snapshot into `compliance_assessment_snapshots`. Assessment replay rebuilds that projection from the event. Neo4j remains a rebuildable relationship projection and does not store the snapshot record.

## Governed audience lenses

`GET /grc/assessment-lenses` lists the stable lens definitions. `GET /grc/assessment-snapshots/{snapshotID}/lenses/{audience}` revalidates the snapshot commitment and returns a bounded, snapshot-bound view.

The initial audiences are:

| Audience | Work shown first | Suppressed details |
| --- | --- | --- |
| Security | Unsatisfied results, missing decisions, evidence gaps, findings, and next actions | Evidence identifiers and source runtime identifiers |
| Audit | Evidence gaps, pending reviews, decision references, and evidence identifiers | Finding identifiers and source runtime identifiers |
| Platform | Missing evidence, unassessed results, source runtime identifiers, and decision state | Evidence identifiers and finding identifiers |
| Leadership | Material unresolved controls and decision coverage | Decision identifiers, evidence, findings, runtimes, reason codes, and task details |

Lenses do not change tenant authorization, assessment facts, lifecycle state, or storage ownership. They select and order fields from the same verified snapshot. Cursors bind to the snapshot ID and record digest so they cannot be reused after a different snapshot.

## Rollout gate

Enable snapshot writes after all of these checks pass:

- snapshot creation, idempotency, decision-cutoff, field-suppression, tamper, and replay tests;
- Postgres schema and projection tests;
- HTTP tenant-isolation and OpenAPI route-parity tests;
- race tests for snapshot creation and replay;
- a non-production replay that reconstructs the same snapshot `record_digest` values;
- a read check that every lens returns the same snapshot digest and never returns a suppressed field.

## Rollback

Disable snapshot creation before rolling back application code. Existing snapshot and lens reads can remain enabled while the new version is removed from writers. Do not delete the event kind or Postgres table. A later deployment can replay the immutable events to restore the projection.

If lens verification detects a mismatched result, decision, or evidence commitment, return a conflict and stop serving the view. Do not fall back to current mutable state.
