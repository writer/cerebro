# rustcarve

`rustcarve` distills a bounded, named Go behavior into a closed migration IR. It reads only repository-relative files declared by a request. It does not execute provider code, resolve credentials, issue graph queries, or translate arbitrary Go or Cypher syntax.

## Entrypoint

```sh
go run ./tools/rustcarve \
  -root . \
  -request tools/rustcarve/testdata/deepseek.request.json \
  -out /tmp/rustcarve-deepseek
```

Use `-check` with a committed output directory to verify deterministic generation.

The canonical closed types are:

- request, migration envelope, source variants, evidence, and deletion manifest: `tools/rustcarve/model.go`
- graph-query IR `graph-query/v1`: `tools/rustcarve/graph_ir.go`
- finding-rule IR `finding-rule/v1`: `tools/rustcarve/finding_ir.go`
- stable rejection codes: `tools/rustcarve/reason.go`
- AST fact extraction, digest binding, scope validation, and receipt gates: `tools/rustcarve/analyze.go`

The JSON decoder rejects unknown request fields. Every IR variant has its own version. The outer envelope is `cerebro.rustcarve.migration-ir/v2`, and receipts bind the converter revision `cerebro.rustcarve/v2`.

## Generated artifacts

Each supported request produces:

- `migration-ir.json`: versioned IR bound to the AST/file facts and fixture digests
- `rust/scaffold.rs`: tenant/workspace scope scaffold and revision constants
- `rust/contracts.rs`: fixture, trace, family, and event contracts
- `rust/parity_test.rs`: revision-bound parity harness
- `registry/standard_source_plan_index.txt`: compiled plan-index row for source variants
- `deletion-manifest.json`: exact paths, imports, and symbols, with eligibility and reason codes
- `schema/closed-contract.json`: machine-readable versions, closed enum sets, canonical Go type paths, receipt fields, and rejection codes

Unsupported behavior produces only `unsupported.json` and exits with status 2.

## Deletion eligibility

Generation is not deletion authority. A deletion manifest is eligible only when:

1. the request declares a Rust-only, fail-closed authority state or a registry-retired state whose remaining authority is still unproven;
2. source variants prove that dynamic Go projection cannot preempt the static fail-closed path;
3. source variants prove that the closed Rust runtime fence covers every catalog runtime family;
4. every required differential receipt is present;
5. every receipt matches the converter revision, subject, behavior kind, Go-facts digest, IR version and digest, Rust implementation revision, evidence digests, input digest, fixture or graph revision, normalized-row output digest, and ordered cursor digest;
6. every receipt reports zero mismatches.

Source variants require a `fixed_fixture` receipt. Graph-query variants require both `fixed_fixture` and `live_safe_local_graph` receipts. Finding rules require an exact `replay` receipt. Adding receipt paths does not change the IR digest, so a first run can produce the digest that later receipts bind.

## Closed variants

`standard-source/v2` and `provider-source/v2` accept only a declared catalog-runtime registration, fail-closed worker registration, or compiled-plan fail-closed metadata registration. The catalog supplies the closed family and event-contract sets. Source requests bind the fixed `internal/sourceprojection/registry.go:RegisterConnectorDefinitions` projection gate and `internal/sourceruntime/sourceworker/pull.go:RustAuthoritativeFamily` runtime gate by file digest; alternate paths or symbols fail closed. The projection check follows same-file helper calls, and the runtime check accepts only an exact source arm that authorizes every catalog family without a restrictive branch. The current Acunetix request models its merged compiled plan; its registry deletion is already complete, while shared projection and runtime-fence gates remain explicit. DeepSeek remains bound to its canonical fixtures and provider oracle.

`graph-query/v1` accepts typed tenant/workspace scope, per-node and per-relationship typed scope bindings, whitelisted relationship kinds, named closed predicates, finite directed hops, normalized UNION outputs, explicit aggregate and limit contracts, typed keyset/graph-revision semantics, deterministic order/dedupe, exact row and public response shapes, fixtures, and exact deletion symbols. Raw or interpolated Cypher is not a field in the IR. Dynamic, unbounded, shape-mismatched, or unknown forms fail closed. Concrete requests cover `complianceimpact.ProjectedGraph`, `policycandidate.grounding`, and the fixed-depth effective-access UNION; their production callers remain outside this tool's ownership.

The effective-access preset accepts exactly five identity arms and three access arms. It fixes every traversal to one hop, binds every node and relation to `tenant_id`, forbids workspace and cursor inputs, bounds case-folded identity substring search to 512 bytes, preserves subject pre-order and pre-limit semantics, and requires a `{tenant_id, graph_revision, truncated, paths}` public response. Its deletion manifest has no targets because the direct graph lane already retired the raw-Cypher symbols; the fixture and live-safe receipt requirements remain available for differential audit evidence.

`finding-rule/v1` accepts closed matcher predicates, typed missing-value behavior, a stable fingerprint contract, explicit lifecycle transitions, graph anchors, observed-at/TTL semantics, a public output contract, replay/counterexample references, authority requirements, and exact deletion symbols. The supplied request distills the existing Tailscale replay corpus without editing its evaluator. Rust scaffold and deletion eligibility remain false until exact replay parity is bound to the same IR, corpus, and tool revisions.

The generated policy-event audit-evidence batch is a canonical unsupported input at `tools/rustcarve/testdata/policy-event-audit-evidence.request.json`. Run it with:

```sh
go run ./tools/rustcarve \
  -root . \
  -request tools/rustcarve/testdata/policy-event-audit-evidence.request.json \
  -out tools/rustcarve/testdata/golden/policy-event-audit-evidence
```

The command is expected to fail closed and emit only `unsupported.json`, with `unsupported_graph_anchor` and `unsupported_lifecycle`. It emits no migration IR, Rust scaffold, parity test, or deletion manifest. The request records the active Go evaluator honestly; it does not weaken `finding-rule/v1` to treat an evaluate-only lifecycle or `AnchorNone` as durable Rust finding authority.

## Stable rejection codes

The initial closed set includes:

`active_go_execution_path`, `active_go_projection_path`, `active_go_registry_path`, `ambiguous_go_owner`, `dynamic_go_callback`, `dynamic_query`, `interpolated_cypher`, `invalid_cursor`, `invalid_limit`, `malformed_json`, `missing_authority_evidence`, `missing_parity_receipt`, `missing_replay_corpus`, `missing_rust_runtime_fence`, `no_deletion_targets`, `nondeterministic_time`, `receipt_binding_mismatch`, `replay_mismatch`, `response_shape_mismatch`, `secret_material`, `side_effecting_matcher`, `unbound_tenant_scope`, `unbound_workspace_scope`, `unbounded_result_limit`, `unbounded_scan`, `unbounded_shape`, `unbounded_traversal`, `union_shape_mismatch`, `unknown_behavior_kind`, `unsupported_aggregate`, `unsupported_graph_anchor`, `unsupported_lifecycle`, `unsupported_predicate`, `unsupported_relation`, `unsupported_registration_shape`, `unsupported_ttl`, `unstable_fingerprint`, and `wrong_scope`.

## Ownership boundary

This tool owns only `tools/rustcarve`, its generated fixtures, and its schema/manifest contracts. It does not edit provider packages, graph-query callers or runtimes, finding evaluators, source projections, or source fixtures/oracles.
