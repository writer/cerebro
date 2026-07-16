# Monorepo Ownership And Boundaries

## Status

This document defines the public repository layout used to consolidate Cerebro runtime and client development. It does not define a deployment topology or authorize a production migration.

## Layout

| Path | Owns | Must not own |
| --- | --- | --- |
| `cmd/`, `internal/`, `sources/` | Go runtime, ports, persistence semantics, source integrations | Browser or chat presentation; environment deployment adapters |
| `schemas/` | Portable, versioned interchange contracts | Environment values or topology-specific policy |
| `sdk/typescript/` | Public TypeScript client and generated contract bindings | Application state or deployment configuration |
| `apps/web/` | Browser application, server-side web boundary, UI tests | Core persistence; environment deployment overlays |
| `apps/slack-companion/` | Slack transport, durable admission, runs, checkpoints, outbox, status, assistance, refinement, and portable conformance tests | Environment deployment overlays; concrete rollout or recovery policy |
| repositories outside this repository | Environment deployment adapters and operational configuration | Portable application behavior or public contract definitions |

## Dependency Direction

```text
apps/web ---------------------> public HTTP/OpenAPI contracts
apps/slack-companion --------> lifecycle schemas + TypeScript SDK + public HTTP contracts
sdk/typescript --------------> generated public schemas
Go runtime ------------------> internal domain packages + public schemas
```

Dependencies do not point from the Go runtime into `apps/`. Applications are built and released independently even when a contract and its consumers change in one pull-request stack.

## Workspace Rules

- The repository uses npm workspaces from the root `package.json` and one root `package-lock.json` for JavaScript and TypeScript packages.
- Application manifests set `private: true`.
- Root commands run checks across every workspace that declares the matching script.
- A workspace may provide narrower local commands, but CI invokes the root workspace check.
- Runtime dependencies require a named owner and a reason in the pull request.

## Public And Operational Split

The public repository contains portable behavior, contracts, generated bindings, fixtures, and conformance tests. It may contain portable container build inputs, but not environment-specific deployment overlays.

The following stay outside this repository:

- concrete environment values and secret addresses;
- account, network, cluster, namespace, and routing configuration;
- rollout thresholds, drain deadlines, and disaster-recovery policy;
- environment-specific adapters that translate portable lifecycle commands into infrastructure actions.

Public tests should use neutral in-memory or fixture adapters. Operational repositories consume the public contracts and prove their own adapters separately.

Within `apps/slack-companion/`, portable ownership is explicit:

- `src/execution/` owns leased turns, checkpoints, effect intent, outcome-unknown reconciliation, and delivery handoff;
- `src/mission/` projects runs onto the native mission, plan, approval, verification, and closure contract;
- `src/operations/` owns scheduled-occurrence continuity and release-safe reconciliation;
- `src/delivery/` owns durable multipart outbox and thread binding;
- `src/transport/` owns topology-neutral Slack ingress and egress boundaries;
- `src/assistance/` owns exact-recipient assistance requests and durable human outcomes;
- `src/improvement/` owns same-candidate, same-draft refinement and invalidation of stale evaluation evidence.

Assistance and refinement records use opaque identities. They must not place raw signals, chat identifiers,
private run identifiers, tenant values, or secret-like input in branch names, draft metadata, logs, or receipts.

## History Migration

- Public repository history may be imported under its final `apps/` prefix only when every historical object passes the current public-boundary scan. Otherwise, import a reviewed current snapshot and retain the source mapping outside the public repository.
- Private repository history is never imported into this public repository.
- A private application contributes only a reviewed portable snapshot whose files pass secret, tenant-data, configuration, and provenance scans.
- Redirect commits in former repositories land only after the corresponding application is available from this repository.

## Change Sequence

1. Land this workspace scaffold and repository boundary tests.
2. Import the public web application and make it pass root workspace checks.
3. Review and land shared public contracts and generated bindings through their owner gate.
4. Add the reviewed portable Slack companion skeleton and durable admission path.
5. Move portable effects and missions onto the shared run, lease, checkpoint, approval, verification, and recovery semantics.
6. Linearize and export the portable operation, delivery, and transport slices as one runnable companion surface.
7. Add exact-recipient assistance and same-draft refinement on that durable surface, with generation fencing and fresh-evidence requirements.
8. Update environment deployment adapters only after the applicable public contract and application changes are available.

Repository mechanics and applications that do not consume a proposed contract may land before that contract is
approved. A contract consumer must not merge ahead of the contract version it reads.

Each step remains independently reviewable and reversible. Consumer changes declare the exact contract version they read and write during a rolling upgrade.
