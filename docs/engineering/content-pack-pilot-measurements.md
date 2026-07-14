# Signed Content Pack Pilot Measurements

Measured on 2026-07-14 from `origin/main` at `ec89d569` and the pilot worktree. These local measurements establish a repeatable baseline; they are not release service-level objectives.

| Measure | Before | Pilot | Result |
| --- | ---: | ---: | --- |
| Pack artifacts | 0 | 2 | One generated connector catalog and one generated policy rule |
| Pack payload bytes | 0 | 3,496 | Bounded by manifest byte counts and digests |
| Complete pilot artifact bytes | 0 | 6,107 | Includes manifests, signatures, and allowlist |
| Added worktree disk blocks for pack code and tooling | 0 KiB | 76 KiB | No repository split required |
| Kernel binary bytes | 483,735,474 | 483,735,474 | Byte-identical binaries |
| Kernel binary SHA-256 | `9202caa8...0aa5` | `9202caa8...0aa5` | Pack verifier is not linked until runtime activation |
| Warm kernel build sample | 24.58 s | 18.44 s | No observed regression; one local sample is too noisy to claim an improvement |
| `version` startup sample | 6.28 s | 3.61 s | No observed regression; telemetry shutdown variance dominates this sample |
| 100 pack validations | N/A | 0.61 s | About 6.1 ms per two-pack validation |
| Invalid-pack fallback test | N/A | 0.47 s | Embedded selection remained available |

## Method

- Built both kernels with `go build -trimpath ./cmd/cerebro` using separate warm `GOCACHE` directories.
- Compared byte count and SHA-256 of the two binaries.
- Ran the built `version` command once per binary.
- Ran the built `contentpackcheck` binary 100 times against both signed pilot packs.
- Ran `TestResolveKeepsEmbeddedPackWhenExternalPackIsInvalid` with a tampered signature.

## Interpretation

The pilot proves a release boundary without changing the production binary or startup path. The operational cost is artifact validation measured in single-digit milliseconds for two small packs. Repository and build-size reduction cannot be claimed until embedded duplicates are removed after the activation gate.

## Runtime activation measurement

Measured on 2026-07-14 against the signed pilot commit `215d1474` and the runtime activation worktree. Both builds used the same machine and concurrent cold build caches, so the build times are a regression check rather than a throughput benchmark.

| Measure | Signed pilot | Runtime activation | Result |
| --- | ---: | ---: | --- |
| Kernel binary bytes | 483,735,474 | 483,967,442 | +231,968 bytes (0.048%) for selection, parser, fallback, and operator-state paths |
| Cold concurrent kernel build sample | 94.91 s | 94.90 s | No observed regression in this paired sample |
| `version` startup sample | 6.76 s | 3.72 s | No observed regression; telemetry shutdown variance dominates this sample |
| Two-pack signature and allowlist validation | N/A | 2 ms | Signed connector and policy-control packs both accepted |
| Connector parser rejection | N/A | Pass | Embedded connector restored; policy selection remains independent |
| Policy parser rejection | N/A | Pass | Embedded policy restored; connector selection remains independent |

The activation links pack selection into the production `serve` path. Only the DeepSeek catalog and the AI agent tool allowlist policy can cross the boundary. Existing kernel parsers validate both payloads, compiled connector behavior and policy evaluators remain kernel-owned, and every rejection restores embedded content for the affected kind.
