# Source operation authority

Status: implemented as a build-time Go compatibility-plane authority and selector contract; it is not runtime truth across all production entry points, and runtime fencing is not yet wired.

The machine ledger at `docs/engineering/source-operation-authority-ledger.json` declares which compatibility-plane owner is expected for each operation of every inventoried source family, together with the expected Go durable and preview selector outcomes. Pull catalogs enter the operation inventory when they declare `runtime_families`; push catalogs enter it when they explicitly declare `collection_mode: push`. Catalog-only imports and internal event producers do not enter the operation inventory. This contract checks Go routing and its declared ownership boundary; the native Rust entry points listed below do not yet consult it.

## Authority record

The authority key is `(collection_mode, source_id, family_id, operation)`. Pull operations are `check`, `discover`, `read_page`, `append`, `project`, `checkpoint_commit`, and `product_read`. Push operations are `push_admit`, `append`, `project`, and `product_read`; pull-only operations must be `not_applicable` for push families, and `push_admit` must be `not_applicable` for pull families.

Each resolved family record also names the credential and network owner. The current compatibility authority remains the Go source runtime. The organizational projection remains the product-read authority. A `candidate_kernel` records code that may be shadowed later; it does not grant execution or write authority.

The ledger uses catalog-wide defaults plus exact family overrides. Its inventory count and digest bind those defaults to the reviewed set of source families. Catalog additions, removals, or mode changes fail the check until the ledger inventory is deliberately updated.

## Runtime selector contract

The ledger declares separate `durable_pull` and `preview` selector-outcome policies. Each policy defaults to the Go compatibility kernel and lists the source families that select the credential-free Rust worker, the family used when configuration omits one, and whether an unknown family stays on Go or enters Rust to fail closed. Kernel selection remains subordinate to the operation owners in the authority record: the Go trusted host owns credentials and network access, and the Go source runtime still owns append, projection, and checkpoint commit.

The checker imports and executes the compiled `sourceworker.RustAuthoritativeFamily` and `sourceworker.PreviewRustFamily` functions. It compares their results with the ledger for every pull and push catalog pair, every pull source with an empty family, every pull source with an unknown-family sentinel, and empty or unknown source sentinels. A selected result must also return the exact normalized family declared by policy. This proves the checked Go selectors produce the reviewed kernel outcomes; changing code and merely refreshing a hash cannot satisfy the contract.

The checker also parses repository non-test Go files, excluding its own self-observation package and dependency or build-output directories, and requires the exact closed reference set. Durable routing may consult `RustAuthoritativeFamily` only from runtime-plan validation, runtime creation, durable read dispatch, worker output conversion, and `PreviewRustFamily`. Preview routing may consult `PreviewRustFamily` only from the source-operations adapter. New direct callers fail the check.

This coverage is intentionally bounded to Go selector routes. It does not make the ledger a runtime authority record or fence every native Rust entry point. The native `sync-source` command and authenticated service route in `crates/cerebro-platform/src/main.rs` dispatch through `crates/cerebro-platform/src/source_runtime_sync.rs` and can publish with `DurableGraphStore::sync_fenced` without consulting this ledger. The separate `publish-source-pages` command in `crates/cerebro-platform/src/source_page_publisher.rs` also remains outside this contract. Closing those paths requires a broader authority-generation and write-fencing change; this selector contract does not claim that promotion.

## Required invariants

- Exactly one active owner from the closed owner vocabulary is named for every applicable operation.
- Pull and push operations cannot be mixed.
- A Rust candidate is accepted only when it is explicitly credential-free and network-disabled.
- Rust implementation evidence must resolve to checked-in, non-symlink `.rs` files under `crates/`, and required contract markers must still exist.
- Candidate event kind and schema must match the source catalog contract.
- Durable and preview policies must match the compiled selector outcome and normalized family for every catalog pair plus empty and unknown sentinels.
- Production Go selector references must match the closed callsite set; test-only calls do not grant a production route.
- Every Rust-kernel selector outcome must retain the declared Go credential, network, append, projection, and checkpoint owners until a separately fenced promotion changes those owners.
- `shadow` and `shadow_disabled` are evidence states, not write authority. Active operation owners remain unchanged until a later, fenced runtime change promotes them.
- The ledger contains no credential value, secret reference, private route, or deployment address.

## Failure states and operator action

`make source-operation-authority-check` fails closed on unknown fields, unknown families, duplicate overrides, inventory drift, selector outcome or normalization drift, direct-callsite drift, invalid pull/push ownership, missing implementation evidence, or event-contract drift. Review the catalog and runtime change, update the smallest exact authority override or selector policy, and rerun the check. Do not resolve a failure by assigning both Go and Rust to one operation.

When a candidate becomes eligible for shadow execution, a forward change must add runtime authority generation and digest fencing before host execution and before append, projection, or checkpoint commit. Promotion to Rust authority additionally requires the repository parity threshold and live qualification defined in `docs/engineering/rust-source-runtime-adr.md`. An authority read failure must fail closed; it must never restore a retired writer.

## Day-two procedure

1. Add or change the source catalog and its exact event contract.
2. Run `make source-operation-authority-check` and inspect any reported inventory, selector outcome, normalization, or callsite drift.
3. Decide the active operation owners. Add an exact override only for a deliberate exception or migration candidate.
4. For deliberate catalog changes, update the ledger inventory count and digest to the values reported by the checker.
5. For deliberate Go routing changes, update the relevant durable or preview rule and the closed callsite contract in the same reviewed change.
6. Run the focused checker and selector tests, catalog checks, and the repository validation selected for the change.
7. Preserve the existing active owner until runtime fencing, append/projection/checkpoint ordering, parity, and product-read evidence all pass for the exact family and revision. Treat the native Rust sync and page-publisher paths as unfenced until that broader change lands.

The ledger is portable repository policy. Credential resolution, secret values, private routes, deployment topology, and environment-specific rollout thresholds remain with their private operational owner.
