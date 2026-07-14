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

The pilot proves a release boundary without changing the production binary or startup path. The operational cost is artifact validation measured in single-digit milliseconds for two small packs. The next activation change must repeat binary, startup, validation, and rollback measurements after a kernel parser consumes selected pack bytes. Repository and build-size reduction cannot be claimed until embedded duplicates are removed after that activation gate.
