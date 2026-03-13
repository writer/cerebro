# Filesystem Analyzer Architecture

Cerebro's workload filesystem analyzer is now the shared catalog-and-finding substrate for VM snapshot scans, container image scans, and serverless function package scans. It should behave like a reusable cataloger, not a one-off scanner bolted into one runtime.

## Goals

- Inspect one mounted or materialized filesystem and emit one typed analysis report.
- Separate execution orchestration from filesystem cataloging.
- Keep package inventory, secret detection, misconfiguration analysis, and SBOM generation under one contract.
- Treat vulnerability matching as a pluggable layer so the analyzer can use the persisted vulnerability knowledge pipeline from issue `#181` without hard-coding one scanner backend.
- Keep scan runtimes on one shared execution-store schema instead of growing per-runtime persistence silos.

## Current Contract

Primary package:

- `internal/filesystemanalyzer`

Primary output:

- `Report`
- `OSInfo`
- `PackageRecord`
- `SecretFinding`
- `ConfigFinding`
- `MalwareFinding`
- `SBOMDocument`

Current analyzer responsibilities:

- OS identification from `os-release` / distro marker files
- package enumeration for:
  - `dpkg`
  - `apk`
  - Python metadata
  - npm package manifests under `node_modules`
  - `go.sum`
  - `Cargo.lock`
  - `pom.xml`
  - `composer.lock`
  - `packages.config`
- secret detection with regex plus entropy heuristics
- config detection for:
  - SSH root/password auth
  - passwordless sudo
  - writable-path cron execution
  - world-writable directories
  - SUID binaries
  - Docker socket exposure
- CycloneDX-style SBOM component generation
- optional vulnerability bridge through either:
  - native `internal/vulndb` package matching
  - `scanner.FilesystemScanner` fallback
- optional malware bridge through `scanner.MalwareScanner`

## Runtime Integration

The analyzer is now reused by:

- `internal/workloadscan.FilesystemAnalyzer`
- `internal/imagescan.FilesystemAnalyzer`
- `internal/functionscan.FilesystemAnalyzer`

That means the execution runtimes are now responsible for:

- acquisition and materialization
- lifecycle events
- durability and retries
- provider-specific metadata

And the analyzer is responsible for:

- interpreting a mounted filesystem
- emitting package/security inventory
- producing a stable SBOM and finding surface

This is the correct boundary.

## Shared Execution Store

The scan runtimes no longer persist through three independent SQLite schemas hidden behind separate implementations.

Shared package:

- `internal/executionstore`

Current behavior:

- one shared `execution_runs` table keyed by `namespace + run_id`
- one shared `execution_events` table keyed by `namespace + run_id + sequence`
- runtime wrappers in:
  - `internal/workloadscan`
  - `internal/imagescan`
  - `internal/functionscan`

This is still SQLite-backed and single-node, but it is now one execution substrate instead of three similar stores pretending to be separate systems.

## OSS Patterns Reused

Pulled via `gh` from active upstream projects on 2026-03-11:

- `aquasecurity/trivy`
  - inspiration: split analyzers by artifact facet (`os`, `pkg`, `secret`, `config`, `sbom`) instead of one scanner blob
- `anchore/syft`
  - inspiration: catalog packages first, then render SBOM/contracts from that catalog
- `anchore/grype`
  - inspiration: keep ecosystem-specific vulnerability matching separate from package cataloging
- `google/osv-scanner`
  - inspiration: treat advisory matching as a separate knowledge layer over a normalized package inventory
- `openclarity/kubeclarity`
  - inspiration: one analysis surface reused across different workload acquisition paths

The useful takeaway is structural:

- acquire
- materialize
- catalog
- match
- contextualize

Cerebro should keep those stages separate.

## Known Limits

- RPM package parsing is not yet implemented; current package inventory is strongest on Debian/Alpine plus language ecosystems.
- Native advisory matching now exists through `internal/vulndb`, but source breadth and ecosystem-specific version comparators are still incomplete.
- Malware detection is optional and depends on an injected engine/threat-intel backend.
- Windows registry hive parsing is not implemented yet.
- SBOMs are generated as typed in-run documents today, not yet persisted as first-class graph knowledge artifacts.

## Next Steps

1. Extend the vulnerability database with NVD, GitHub Advisory, and distro feeds.
2. Issue `#182`: project scan packages/vulnerabilities/SBOM coverage into the security graph and attack-path context.
3. Extend package coverage for RPM, Ruby gems, and .NET `.deps.json`.
4. Move execution resources and vuln sync jobs onto a multi-worker backend if SQLite becomes the scaling bottleneck.
