# Credential And Certificate Lifecycle Contract

Cerebro is the cross-system evidence, finding, correlation, query, and action-routing authority for credential and certificate lifecycle risk. Provider adapters remain responsible for polling their systems. External mutation authorities remain responsible for rotation, renewal, revocation, and deployment.

## Canonical identity

Each governed subject uses:

`urn:cerebro:<tenant>:<credential|certificate>:<encoded authority_id>:<encoded stable_locator>`

`authority_id` identifies the provider authority and scope in which the locator is unique. `stable_locator` identifies the governed slot or deployment target and must survive rotation. A material key ID, certificate ID, fingerprint, or digest is a `ResourceRef.revision`; it must not replace the stable locator in the URN. Provider-controlled URN segments use `urn.EncodeSegment`, so delimiters cannot collapse distinct identities.

An upstream system's local `ResourceRef` shape is not a Cerebro `ResourceRef`. An adapter must explicitly map local identity into the public `cerebro.v1.ResourceRef` contract and prove the tenant, kind, canonical URN, revision, and state.

## Event binding

Adapters publish one protobuf `SecurityLifecycleObservation` in `EventEnvelope.payload`:

- credential: kind `security.credential.lifecycle`, schema `cerebro/security/credential-lifecycle/v1`
- certificate: kind `security.certificate.lifecycle`, schema `cerebro/security/certificate-lifecycle/v1`

`EventEnvelope.occurred_at` equals the observation's `observed_at`. `provider` is an open identifier. `subject_ref` binds the canonical URN, current material revision, and observed state. Owner, governed scope, and supporting claims are references. Secret values, private keys, certificate key material, passwords, passphrases, and bearer tokens are rejected.

## Projection and policy

The Rust append-log consumer admits the exact lifecycle event kind and schema
pair, decodes the protobuf payload, and writes the governed subject into the
existing Postgres current-state and rebuildable Neo4j graph boundaries. Owner,
scope, and evidence references remain metadata-only contract references. When
the policy matches at observation time, the same Rust graph projection writes
a stable open organizational finding entity and an `affects` assertion to the
governed subject. This graph entity is not a GRC `FindingRecord`, evidence
packet, audit packet, or audit preview. Those records remain owned by the
existing GRC/workflow bridge.

The expiry policy distinguishes `unknown`, `compliant`, `expiring`, and `expired`. Missing expiry data is unknown, not a failing control. Expiring and expired states produce one fingerprint-stable finding anchored to the subject URN, so material rotation does not create a second finding.

## Action and verification

An action route says which external action class is appropriate (`rotate_credential` or `renew_certificate`), whether approval is required, and which finding and subject authorize the route. It is not a provider command.

Dispatch acceptance or provider-reported action success does not close the finding. `verified_closed` requires a later source observation that:

- occurred after action completion;
- came from the bound source runtime;
- covers a complete, non-truncated source population;
- no longer matches the expiry policy.

A later compliant observation produces `verified_closed`. A still-matching,
incomplete, truncated, or non-fresh observation produces
`verification_pending`. Remediation outcomes bind the finding, observation
event, source runtime, and evidence claims without becoming execution
authority.

## Operator reads

`SecurityLifecycleQuery` is tenant scoped and caps each page at 500 records. Operators can filter by credential or certificate, current lifecycle state, owner, expiry cutoff, and finding presence. A subject locator lookup derives the canonical URN from subject kind, authority, and stable locator; material revisions are never lookup identity. `SecurityLifecycleRecord` carries the observation, policy evaluations, findings, action routes, and projection time.

`ResolveSecurityLifecycleFinding` is a tenant-scoped graph resolver for a
stable lifecycle finding URN. It requires a ready projection at one graph
revision, follows the durable organizational finding's `affects` edge, and
re-evaluates the subject against current policy before returning a record. It
returns no record for a stale or no-longer-matching finding. The resolver does
not make GRC finding, evidence, audit-packet, or audit-preview routes available.
Its `source_runtime_id` is copied from the durable `affects` assertion
provenance and is never inferred from the finding or subject URN.
Its `source_collection_id` is copied only from the explicit lifecycle
observation attribute of the same name. Older events leave this field empty;
the resolver never substitutes the per-event collection receipt ID. An empty
field is provenance-pending and cannot support verified closure.
Rebuild does not copy a runtime from an arbitrary historical `affects`
assertion onto a current subject. Legacy rows without exact observation
provenance keep the corresponding record fields empty and remain pending.

Query results include filtered aggregate counts, coverage, freshness, and
separate page/source truncation state. Aggregate counts describe the covered
filtered population, not the returned page. Observed `state_counts` preserve
provider state and filter semantics. Effective `policy_state_counts` report
compliant, expiring, expired, or unknown posture after expiry policy
evaluation; an active provider record can therefore count as policy-expired.
`counts_are_exact` is false when the bounded graph read cannot prove full
coverage. `coverage.complete` is also false if the graph revision changes
during the read. The oldest and newest observation timestamps report freshness
without inventing a source SLA.

Forward and backward page tokens order records by canonical subject URN only.
Tokens bind the filter, evaluation time, and graph revision. They are rejected
after a graph revision or filter change instead of silently mixing snapshots.
Material revision changes therefore do not move the stable subject to another
page. Tokens expire after 15 minutes, oversized tokens are rejected before
decode, and reads spanning a graph revision change do not issue continuation
tokens.

The general graph scan remains capped and reports incomplete coverage when it
reaches that cap. Raising that scan bound is not the scale architecture. The
Neo4j projection adds `SecurityLifecycleSubject` only to validated
lifecycle-bearing resources and indexes tenant plus stable subject identity,
subject kind, observed state, owner, and expiry. It stores no provider command,
secret value, credential material, or external mutation authority.

Aggregate and keyset queries share the same tenant, filters, policy evaluation
time, transaction, and start/end graph revision. Indexed coverage reports zero
generic entities scanned and separately reports the complete lifecycle
population. A revision change makes coverage incomplete and truncated,
suppresses both cursors, and marks counts inexact.

Each tenant has a schema-versioned lifecycle projection watermark. Reads use
the index only when the watermark is ready and equals the current graph
revision. Rebuild marks readiness false before rewriting any batch, leaves it
false after failure or revision drift, and marks it true only after a stable
complete pass. Incremental projection advances a ready watermark in the same
transaction that writes entities and the graph revision. Rebuild also refreshes
lifecycle finding labels and stable finding-URN properties, so replay does not
depend on new-format outbox rows.

After deploying the schema, backfill every serving tenant before expecting
indexed reads:

```sh
CEREBRO_TENANT_ID=<tenant> \
CEREBRO_NEO4J_URI=<uri> \
CEREBRO_NEO4J_USERNAME=<username> \
CEREBRO_NEO4J_PASSWORD=<password> \
cerebro-platform rebuild-lifecycle-projection
```

The command is tenant-scoped and idempotent. Until it succeeds, the endpoint
uses the existing truthful bounded fallback and never reports an exact zero
from an unbuilt index.

`cerebro-platform` owns the authenticated Rust HTTP adapter and reads through
the bounded `AgentGraph` capability. Stable identity, metadata admission,
policy evaluation, action routing, query bounds, and verification rules live in
the sealed `cerebro-security-lifecycle` Rust crate. There is no Go lifecycle
authority and no caller-facing endpoint that can mint a verification binding
from caller-selected finding, timing, or policy inputs.
