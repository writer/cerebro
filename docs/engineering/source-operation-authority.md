# Source operation authority

Status: implemented as a build-time control; runtime fencing is not yet wired.

The machine ledger at `docs/engineering/source-operation-authority-ledger.json` answers one question for every built-in runtime source family: which implementation currently owns each operation that can affect provider access, durable state, or product reads? Pull catalogs enter the inventory when they declare `runtime_families`; push catalogs enter it when they explicitly declare `collection_mode: push`. Catalog-only imports and internal event producers do not construct a source runtime and are outside this ledger.

## Authority record

The authority key is `(collection_mode, source_id, family_id, operation)`. Pull operations are `check`, `discover`, `read_page`, `append`, `project`, `checkpoint_commit`, and `product_read`. Push operations are `push_admit`, `append`, `project`, and `product_read`; pull-only operations must be `not_applicable` for push families, and `push_admit` must be `not_applicable` for pull families.

Each resolved family record also names the credential and network owner. The current compatibility authority remains the Go source runtime. The organizational projection remains the product-read authority. A `candidate_kernel` records code that may be shadowed later; it does not grant execution or write authority.

The ledger uses catalog-wide defaults plus exact family overrides. Its inventory count and digest bind those defaults to the reviewed set of source families. Catalog additions, removals, or mode changes fail the check until the ledger inventory is deliberately updated.

## Required invariants

- Exactly one active owner from the closed owner vocabulary is named for every applicable operation.
- Pull and push operations cannot be mixed.
- A Rust candidate is accepted only when it is explicitly credential-free and network-disabled.
- Rust implementation evidence must resolve to checked-in, non-symlink `.rs` files under `crates/`, and required contract markers must still exist.
- Candidate event kind and schema must match the source catalog contract.
- `shadow` and `shadow_disabled` are evidence states, not write authority. Active operation owners remain unchanged until a later, fenced runtime change promotes them.
- The ledger contains no credential value, secret reference, private route, or deployment address.

## Failure states and operator action

`make source-operation-authority-check` fails closed on unknown fields, unknown families, duplicate overrides, inventory drift, invalid pull/push ownership, missing implementation evidence, or event-contract drift. Review the catalog and runtime change, update the smallest exact override or inventory binding, and rerun the check. Do not resolve a failure by assigning both Go and Rust to one operation.

When a candidate becomes eligible for shadow execution, a forward change must add runtime authority generation and digest fencing before host execution and before append, projection, or checkpoint commit. Promotion to Rust authority additionally requires the repository parity threshold and live qualification defined in `docs/engineering/rust-source-runtime-adr.md`. An authority read failure must fail closed; it must never restore a retired writer.

## Day-two procedure

1. Add or change the source catalog and its exact event contract.
2. Run `make source-operation-authority-check` and inspect the reported inventory drift.
3. Decide the active operation owners. Add an exact override only for a deliberate exception or migration candidate.
4. Update the ledger inventory count and digest to the values reported by the checker.
5. Run the focused checker tests, catalog checks, and the repository validation selected for the change.
6. Preserve the existing active owner until runtime fencing, append/projection/checkpoint ordering, parity, and product-read evidence all pass for the exact family and revision.

The ledger is portable repository policy. Credential resolution, secret values, private routes, deployment topology, and environment-specific rollout thresholds remain with their private operational owner.
