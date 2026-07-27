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
the policy matches, the same Rust projection writes a stable open finding and
an `affects` assertion to the governed subject.

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
reaches that cap. Raising that scan bound is not the scale architecture. A
durable lifecycle-specific indexed graph query must provide grouped filtered
counts and stable-identity keyset pages before the endpoint can claim
100,000-subject readiness.

`cerebro-platform` owns the authenticated Rust HTTP adapter and reads through
the bounded `AgentGraph` capability. Stable identity, metadata admission,
policy evaluation, action routing, query bounds, and verification rules live in
the sealed `cerebro-security-lifecycle` Rust crate. There is no Go lifecycle
authority and no caller-facing endpoint that can mint a verification binding
from caller-selected finding, timing, or policy inputs.
