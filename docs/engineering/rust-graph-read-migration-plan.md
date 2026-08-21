# Rust Graph-Read Migration Plan

This plan sequences the removal of caller-supplied Cypher from the Go
services. It builds on [Rust Organizational Platform](rust-organizational-platform.md),
which defines the authority cutover and the compatibility port, and its
"Remaining compatibility callers" table, which lists the per-caller
capability gaps.

## Inventory findings

Four facts shape the plan. Each is verified against the code as of
`9d3721f6c`.

1. **Catalog coverage is complete.** Connector YAML may declare only 17
   projection templates (`ProjectionClass::for_template` in
   `crates/source-catalog/src/lib.rs`), and `CatalogGraphMapper`
   (`crates/source-runtime-next/src/mapper.rs:603`) maps every one of them.
   All ~3,925 cataloged families flow into the organizational graph. There
   is no unmapped-template gap.

2. **The organizational edge vocabulary is three relations wide.** The
   mapper emits `MemberOf` (group membership), `CanAccess` (app
   assignment), and the `represents` identity binding. Nothing else.

3. **The security edge vocabulary is derived data computed in Go.**
   `can_admin`, `can_perform`, `grants_entitlement`, `confers_capability`,
   `same_actor`, `assigned_to`, `tagged_as`, `belongs_to`, and `can_reach`
   are computed from source records by Go connector/projection code and
   written only to the legacy `Entity`/`RELATION` projection. No Rust
   derivation pass exists, so these edges do not exist in the
   organizational graph today.

4. **Findings rules are generated mega-queries.** The policy rule catalog
   (`internal/findings/policy_rule_catalog_*_gen.go`, code-generated)
   embeds Cypher that filters on `attributes_json` substrings, regexes, and
   JSON-fragment matching (`"status":"active"`, `last_login_at` timestamp
   extraction, email-domain checks). These are fixed at build time but
   deeply coupled to the legacy projection's JSON-string attribute model.

Node attributes are not a blocker in the organizational model:
`GraphEntity.properties` is a populated string map
(`mapper.rs:add_properties`), so property predicates are expressible once
the query API supports them. Edges carry no properties in either
projection's Rust surface.

## The fork

Two endgames are consistent with the platform doc. They differ in where
migrated callers read from.

**Path A — grow the organizational schema.** Add `RelationKind` variants
for the derived security relations (`CanAdmin`, `CanPerform`,
`GrantsEntitlement`, `ConfersCapability`, `SameActor`, `AssignedTo`,
`TaggedAs`, `BelongsTo`), port the Go edge-derivation logic into bespoke
Rust mapper passes, extend `QueryFacts`/`FindPaths` with the eight missing
capabilities, replay affected families, and migrate each consumer. This
achieves one graph and one schema. It is also the largest option: the
derivation ports are semantic reimplementations of Go policy-evaluation
code, and every findings rule needs its `attributes_json` semantics
re-expressed against `properties`.

**Path B — bounded legacy-pattern query API.** The Rust store already
serves compatibility catalog RPCs (`ListEntities`, `CountEntityKinds`,
`ListEntityRelations`, `CompareExposureCoverage`) by reading the legacy
projection. Extend that surface with one structured, validated,
bounded pattern-query operation over `Entity`/`RELATION`: node patterns
(entity_type exact/prefix/suffix, urn equality or IN-list, attribute
substring predicates), edge patterns (relation IN-list, direction),
variable-length legs with relation whitelists, aggregations
(count/collect), keyset cursors, optional legs, and union arms — with the
same closed-validation discipline as `QueryFacts` (no caller Cypher text,
hard bounds, deterministic ordering). Each coded caller migrates from a
Cypher string to a structured request. No data migration, no replay, no
derivation port.

**Recommendation: hybrid, B first.** The legacy projection is permanent
regardless — the graphagent ask flow and policycandidate shadow/experiment
evaluation execute runtime-authored Cypher against it and are permanent
compat residents. Since the projection stays, Path B retires
caller-supplied Cypher for every coded caller in weeks instead of months,
and it does not foreclose Path A: access-edge semantics (`CanAdmin`,
`GrantsEntitlement`, `ConfersCapability`) are first-class organizational
concepts and should still enter the org model when the derivation passes
are ported, at which point the security-core consumers re-migrate from the
legacy-pattern API to org-graph operations.

## Capability extensions (both paths share the mechanism)

Every query-side extension touches the same four layers, in order:

1. `proto/cerebro/graph/v1/organizational_graph.proto` — request/response
   fields or messages.
2. `crates/agent-context/src/lib.rs` — query-model types, validation,
   `MAX_*` bounds, rejection codes. No I/O.
3. `crates/organizational-store/src/neo4j.rs` — Cypher statement builders.
   Sole generator; assumes pre-validated input.
4. `crates/cerebro-platform/src/rpc.rs` — proto decode, `GraphRead` call,
   response encode.

Then the Go composite adapter
(`internal/sourcehttp/organizationalgraph/query.go`) gains the matching
method, the consumer migrates, and its Cypher is deleted.

Ranked by unblock power (caller count in parentheses):

| Capability | Callers unblocked |
| --- | --- |
| Attribute substring predicates on node patterns (6) | attackpath, person access, effective access, crown jewel, GRC lifecycle, findings rules |
| Variable-length legs with relation whitelist (4) | attackpath, person access, crown jewel, findings rules |
| Aggregations: count/collect, plus a `CountRelations` RPC (4) | attackpath counts, compliance impact, graphagent probe counts, findings rules |
| URN/agent-key-keyed path endpoints (3) | attackpath, person access, crown jewel |
| Keyset cursors (2) | compliance impact, workflow projection pruning |
| Edge properties in results (2) | compliance impact, policy candidate grounding |
| Union arms and optional legs (2) | effective access, findings rules |

## Wave plan

- **Wave 0 (this doc):** ratify the fork and the capability ranking.
- **Wave 1:** legacy-pattern query API (Path B): proto, validator,
  statement builder, RPC, Go adapter. Migrate attackpath and person access
  first; they exercise substring predicates, varlen whitelists, and
  aggregations, which proves the full surface.
- **Wave 2:** migrate effective access (union arms), crown jewel (batched
  traversal), graphagent probe counts (`CountRelations`).
- **Wave 3:** migrate compliance impact, workflow projection pruning,
  policy candidate grounding (cursors, edge properties).
- **Wave 4:** migrate findings rules. These are generated; the generator
  (`internal/findings` catalog generation) should emit structured requests
  instead of Cypher strings, which retires the largest single body of
  caller Cypher in one mechanical pass.
- **Wave 5 (Path A, elective):** port access-edge derivation into the Rust
  mapper, add the security `RelationKind` variants, replay affected
  families, re-migrate the security-core consumers to org-graph operations.
- **Terminal state:** the raw-Cypher compat port serves exactly two
  callers (graphagent ask, policy candidate shadow/experiment), both
  shape-validated. Everything else is structured.

## Verification requirements

- Every new query capability ships with validator rejection tests
  (unknown type/relation, over-bounds, disconnected pattern) and statement
  snapshot tests.
- Every consumer migration ships with a parity test: the structured
  request's results equal the retired Cypher's results on a fixed fixture.
- Wave 5 replays use the existing consumer deliver-policy machinery
  (`CEREBRO_ORGANIZATIONAL_CONSUMER_DELIVER_POLICY=all` or fenced
  `by_start_sequence`) with a dedicated consumer name, per the platform
  doc's replay rules.
