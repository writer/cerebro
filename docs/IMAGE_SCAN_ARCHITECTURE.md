# Image Scan Architecture

Cerebro's container image scanning pipeline should be durable, registry-neutral, and analyzable as an execution resource. It should not rely on process-local in-memory state for run tracking or root filesystem materialization.

## Goals

- Model image scan runs and event timelines as typed persisted records.
- Reuse the existing registry client surface instead of inventing one-off sync-only paths.
- Resolve multi-arch manifests, config blobs, and layer downloads directly from registries.
- Reconstruct root filesystems safely enough for shared analyzers without requiring a full local image pull.
- Keep execution-state semantics compatible with platform jobs and the Postgres state store.

## Runtime Model

The current bootstrap repository does not ship a dedicated image-scan runtime package. Image-scan execution should persist through shared platform jobs and Postgres-backed job events.

Persisted records:

- `Job`: one execution resource for a submitted image scan
- `JobEvent`: append-only lifecycle and debugging timeline
- `FilesystemArtifact`: materialized rootfs metadata, retention, and cleanup timestamps

The underlying persistence schema should be shared, with `kind` separating image, function, workload, and advisory execution resources.

## Execution Pipeline

Current run stages:

1. `queued`
2. `manifest`
3. `materialize`
4. `analyze`
5. `cleanup`
6. `completed` or `failed`

The pipeline is intentionally narrow:

- registry manifest/config/layer mechanics belong in provider/scanner adapters
- execution/state handling belongs in the shared platform job service
- vulnerability/package/secret analysis depth belongs in later analyzer issues

## Registry Substrate

Target registry support should be implemented through narrow scanner clients:

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

- The dedicated image scan runtime is not implemented in this bootstrap repository yet.
- The rootfs materializer is local-disk based, not yet remote-worker aware.
- The analyzer can now use the persisted vulnerability knowledge pipeline from issue `#181`, but broader source coverage and distro-specific matching are still incomplete.
- Running-workload correlation and graph contextualization are later issues (`#179` / `#182`).

## Next Steps

1. Link image scan runs, packages, and vulnerabilities into the temporal security graph (`#182`).
2. Extend package inventory coverage beyond the current curated ecosystem set.
3. Expand the vulnerability database with richer distro and advisory sources.
4. Expose execution resources over platform APIs instead of CLI-only surfaces.
