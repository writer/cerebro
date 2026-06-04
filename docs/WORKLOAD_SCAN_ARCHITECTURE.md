# Workload Scan Architecture

Cerebro's agentless workload scanning pipeline should be durable, provider-neutral, and analyzable as an execution resource. It should not rely on in-memory orchestration state beyond the lifetime of one process.

## Goals

- Model workload scan runs, per-volume progress, and cleanup state as typed persisted records.
- Keep provider-specific snapshot/attach APIs behind one execution contract.
- Separate snapshot orchestration from analyzers so filesystem/package/image inspection can evolve independently.
- Guarantee cleanup and reconciliation semantics for leaked snapshots, temporary volumes, and mounts.
- Emit lifecycle events so workload scans can plug into alerting, reports, and graph provenance.

## Execution Pipeline

Current run stages:

1. `queued`
2. `inventory`
3. `snapshot`
4. `share`
5. `create_volume`
6. `attach`
7. `mount`
8. `analyze`
9. `cleanup`
10. `completed` or `failed`

The pipeline is intentionally split so later issues can swap analyzers, transfer modes, or provider implementations without rewriting run-state semantics.

## Persisted Runtime Model

The current bootstrap repository does not ship a dedicated workload-scan runtime package. Workload-scan execution should persist through the shared platform job model and the Postgres state store, not through a scan-specific embedded store.

Persisted records:

- `Job`: one platform execution resource for a submitted workload scan
- `VolumeScanRecord`: per-source-volume progress, artifacts, and cleanup state
- `JobEvent`: append-only lifecycle/event timeline for debugging and API surfacing

This is the current durability boundary:

- run state survives process restarts
- reconciliation can find leaked artifacts from persisted failed/incomplete runs
- cleanup is not dependent on the original process remaining alive

This is intentionally aligned with the three-store architecture: JetStream for events, Postgres for current execution state, and Neo4j/Aura for graph projection.

## Provider Seams

The runtime depends on narrow interfaces:

- `Provider`
- `Mounter`
- `Analyzer`
- `EventEmitter`
- `RunStore`

Current concrete implementations:

- provider, mounter, and analyzer adapters should live behind the platform job execution boundary
- durable state should be stored in Postgres through the shared job tables

This allows the issue stack to progress in layers:

- `#177`: durable orchestration runtime
- `#178`: provider expansion and orchestration hardening
- `#179`: transport/copy strategy improvements
- `#180`: analyzers
- `#181` / `#182`: advisory enrichment and graph/report projection

## AWS Behavior

Current AWS execution path:

- inventory attached EBS volumes for an EC2 instance
- create one snapshot per source volume
- optionally share snapshots cross-account to the scanner account
- create temporary inspection volumes from snapshots in the scanner AZ
- attach those volumes to the scanner instance
- mount read-only on the scanner host
- hand mounted paths to the analyzer contract
- detach/delete temporary volumes and delete snapshots during cleanup

`scanner-zone` is a required scheduling input because EBS temporary volumes are AZ-scoped.

Encrypted cross-account AWS scans add two more behaviors:

- customer-managed source keys receive a short-lived KMS grant for the scanner account before snapshot sharing
- AWS-managed/default EBS keys are not shareable cross-account, so Cerebro first re-encrypts the snapshot onto a customer-managed source key when `--share-kms-key-id` is supplied

Optional AWS CLI knobs for that path:

- `--source-profile` / `--source-role-arn` for source-account snapshot operations
- `--scanner-profile` / `--scanner-role-arn` for scanner-account inspection-volume operations
- `--share-kms-key-id` for a shareable source-account CMK
- `--scanner-snapshot-kms-key-id` when the scanner account wants its own re-encrypted snapshot copy before creating the inspection volume

## Lifecycle Events

The runtime emits webhook-compatible lifecycle events:

- `security.workload_scan.started`
- `security.workload_scan.completed`
- `security.workload_scan.failed`
- `security.workload_scan.reconciled`

These events are a bridge into the broader intelligence/reporting platform without making workload scanning a one-off subsystem.

Successful workload scans are also projected into the security graph during graph activation from the shared execution store. That projection currently creates:
Successful workload scans should project into the security graph from durable scan/job records and emitted lifecycle events. That projection should create:

- `workload_scan` nodes
- `package` nodes
- `vulnerability` nodes
- `instance -> has_scan -> workload_scan`
- `workload_scan -> contains_package -> package`
- `workload_scan -> found_vulnerability -> vulnerability`
- `package -> affected_by -> vulnerability`

Older successful scans for the same workload are retained with temporal supersession (`valid_to` set when a newer scan exists), so historical scan context remains queryable without polluting the current entity posture.

## Operational Constraints

Current controls:

- `WORKLOAD_SCAN_MOUNT_BASE_PATH`
- `WORKLOAD_SCAN_MAX_CONCURRENT_SNAPSHOTS`
- `WORKLOAD_SCAN_CLEANUP_TIMEOUT`
- `WORKLOAD_SCAN_RECONCILE_OLDER_THAN`
- `WORKLOAD_SCAN_TRIVY_BINARY`
- `WORKLOAD_SCAN_GITLEAKS_BINARY`

These are meant to bound:

- local disk usage
- provider-side snapshot fanout
- cleanup latency
- stale-run reconciliation windows

## Known Limits

- The dedicated workload scan runtime is not implemented in this bootstrap repository yet.
- The analyzer now catalogs OS/package/SBOM/secret/config data through the shared filesystem analyzer, but RPM/Windows/deeper ecosystem coverage is still incomplete.
- The execution surface should use first-class platform jobs rather than scan-specific run storage.
- Persisted run state is durable and now hydrates into the security graph on graph activation, but real-time graph refresh still depends on the next graph rebuild/incremental-apply cycle.

## Next Steps

1. Add GCP and Azure providers behind the same `Provider` contract.
2. Expand the vulnerability database with richer distro and advisory sources.
3. Expose run resources and events through the platform API.
4. Project package/vulnerability matches into first-class observations/evidence/claims instead of node/edge projection alone.
5. Add a real-time graph refresh path for `security.workload_scan.completed`.
6. Implement provider adapters on top of the shared platform job backend.
