# Image Scan Architecture

Cerebro's container image scanning pipeline should be durable, registry-neutral, and analyzable as an execution resource. It should not rely on process-local in-memory state for run tracking or root filesystem materialization.

## Goals

- Model image scan runs and event timelines as typed persisted records.
- Reuse the existing registry client surface instead of inventing one-off sync-only paths.
- Resolve multi-arch manifests, config blobs, and layer downloads directly from registries.
- Reconstruct root filesystems safely enough for shared analyzers without requiring a full local image pull.
- Keep execution-state semantics compatible with the existing workload-scan runtime on top of one shared execution store.

## Runtime Model

The runtime persists state through `internal/imagescan.SQLiteRunStore`, which now wraps the shared `internal/executionstore` schema.

Persisted records:

- `RunRecord`: one execution resource for a submitted image scan
- `RunEvent`: append-only lifecycle and debugging timeline
- `FilesystemArtifact`: materialized rootfs metadata, retention, and cleanup timestamps

By default, image scans now use the same `EXECUTION_STORE_FILE` fallback as workload scans. The underlying persistence schema is shared, with `namespace` separating image/function/workload execution resources.

## Execution Pipeline

Current run stages:

1. `queued`
2. `manifest`
3. `materialize`
4. `analyze`
5. `cleanup`
6. `completed` or `failed`

The pipeline is intentionally narrow:

- registry manifest/config/layer mechanics belong in `internal/scanner`
- execution/state handling belongs in `internal/imagescan`
- vulnerability/package/secret analysis depth belongs in later analyzer issues

## Registry Substrate

Current registry support is implemented through the existing scanner clients:

- `ECRClient`
- `GCRClient`
- `ACRClient`

New substrate behavior added for image scanning:

- manifest list / OCI index resolution
- config-blob loading for history, labels, architecture, and base image hints
- direct blob/layer download
- digest-aware manifest resolution

## RootFS Materialization

The local materializer:

- downloads layers in order
- auto-detects gzip/zstd/plain tar payloads
- applies OCI whiteouts, including opaque directory whiteouts
- writes into a bounded rootfs base path
- records file count / byte count / cleanup timestamps

This is the current local durability boundary, not the final distributed executor design.

## Analyzer Contract

The runtime depends on a small analyzer seam:

- `Analyzer`
- current concrete: `FilesystemAnalyzer` backed by the shared `internal/filesystemanalyzer` package plus `scanner.TrivyFilesystemScanner` for vulnerability bridging
- fallback: `NoopAnalyzer`

This now uses the same filesystem cataloger as workload and function scans. The remaining work is deeper vulnerability knowledge and graph contextualization, not inventing another analyzer seam.

## Lifecycle Events

The runtime emits webhook-compatible lifecycle events:

- `security.image_scan.started`
- `security.image_scan.completed`
- `security.image_scan.failed`

These events are the current bridge into later graph ingestion and prioritization work from issue `#182`.

## OSS Patterns Reused

The current implementation intentionally borrows shape from a few mature projects:

- `google/go-containerregistry`: manifest/index resolution and registry-first access patterns
- `regclient/regclient`: layer application and OCI whiteout semantics
- `anchore/syft`: treat a reconstructed filesystem as the stable analysis substrate
- `aquasecurity/trivy`: filesystem-oriented vulnerability scanning instead of forcing a local image daemon path

## Known Limits

- SQLite is durable, but still single-node.
- The rootfs materializer is local-disk based, not yet remote-worker aware.
- The analyzer can now use the persisted vulnerability knowledge pipeline from issue `#181`, but broader source coverage and distro-specific matching are still incomplete.
- Running-workload correlation and graph contextualization are later issues (`#179` / `#182`).

## Next Steps

1. Link image scan runs, packages, and vulnerabilities into the temporal security graph (`#182`).
2. Extend package inventory coverage beyond the current curated ecosystem set.
3. Expand the vulnerability database with richer distro and advisory sources.
4. Expose execution resources over platform APIs instead of CLI-only surfaces.
