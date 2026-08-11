# AI Egress Governance Contract

Cerebro records and evaluates provider-neutral AI egress policy. Endpoint,
proxy, firewall, and cloud controls remain responsible for enforcement. Private
operators remain responsible for registry contents, credentials, routes, and
deployment topology.

## Mandatory invariants

- `ai.egress.observed.v1` observations contain routing metadata and references,
  never prompts, responses, request bodies, credentials, cookies, or headers.
- Registry entries match exact canonical DNS hostnames, ports, transports, and
  optional actor URNs. V1 has no wildcard, suffix, resolved-IP, redirect, or
  display-name authorization.
- Enforce-mode registries default to block. Missing, invalid, stale, or disabled
  registries never produce allow.
- Audit mode records an unapproved request as `AUDIT`; it never represents that
  request as approved.
- Resolved IP addresses are evidence only. Policy is evaluated against the
  canonical destination identity after redirects and aliases are resolved by
  the owning enforcement adapter.
- Host and network observations are independent evidence. One layer reporting
  clean cannot prove another layer is enabled or complete.
- Partial, truncated, stale, disabled, or unavailable coverage cannot support a
  compliant conclusion.
- Provider execution or policy publication is evidence only. Verified closure
  requires a later fresh, complete, non-truncated independent observation.

## Event binding

Adapters publish protobuf `AIEgressObservation` in `EventEnvelope.payload` with:

- kind: `ai.egress.observed.v1`
- schema: `cerebro/ai/egress-observed/v1`
- `EventEnvelope.occurred_at` equal to `AIEgressObservation.observed_at`

`subject_ref` identifies the governed host or workload. `actor_ref` identifies
the requesting identity when known. `workload_ref` identifies the managed task,
agent, browser, or service. The destination holds the canonical hostname, port,
transport, and an optional observed IP address. The decision binds the exact
registry ID, revision, digest, matched entry, reason, and evaluation time.

## Registry lifecycle

An operator publishes immutable `AIEgressRegistrySnapshot` revisions. Private
configuration supplies the approved entries. Each snapshot has a publication
time, expiry, digest, and evidence references. Each entry has a stable ID,
owner, enabled state, exact destinations, optional actor scope, and optional
validity window.

Adapters must reject malformed snapshots before activation and retain the last
known valid snapshot only until its explicit expiry. Expiry fails closed. A
rollback selects an earlier still-valid immutable revision; it does not edit a
published snapshot.

## Deterministic decision procedure

`internal/aiegresspolicy.Evaluate` canonicalizes a DNS hostname to lower case
and removes one trailing dot. It rejects wildcards, IP literals, invalid labels,
allow-by-default registries, duplicate entry IDs, invalid ports, and incomplete
registry identity.

The evaluator then checks registry availability, mode, freshness, enforcement
state, exact hostname, port, transport, actor scope, and entry validity. The
first fully matching entry allows the request. Every other enforce-mode outcome
blocks. Audit mode changes only an unapproved outcome from block to audit.

Enforcement adapters must consume the decision before the connection leaves
the governed boundary. Telemetry-only consumers may evaluate observations but
must not claim they enforced the result.

## Durable findings

The observation contract supports fingerprint-stable findings anchored to the
governed host or workload and control condition:

- unapproved AI destination observed;
- attempted bypass or connection established after a block decision;
- registry unavailable, stale, or disabled;
- required host or network enforcement disabled;
- incomplete or truncated enforcement coverage.

Repeated events attach as evidence to the same current control gap. A later
observation closes a finding only when it comes from the bound source runtime,
is fresh, complete, and non-truncated, and no longer matches the rule. Unknown
coverage remains unknown rather than becoming a passing control.

## Downstream consumers

Metrics systems consume aggregate claims such as evaluated, allowed, blocked,
audited, unapproved, registry-fresh, enforcement-enabled, and coverage-complete.
They do not become policy or finding authorities. Verification systems consume
`AIEgressVerificationBinding` and independently test the governed path; an
enforcement-provider receipt alone cannot produce verified closure.

## Operating procedure

1. Publish a signed or otherwise integrity-bound immutable registry snapshot in
   the private owning system.
2. Validate and stage the snapshot on host and network enforcement points.
3. Activate the same registry revision and digest at every required layer.
4. Emit observations for allow, block, audit, coverage, and control failures.
5. Reconcile Cerebro findings and coverage gaps against the current snapshot.
6. Feed aggregate claims to metrics and verification consumers.
7. Expire or revoke entries through a new registry revision.
8. Require a later complete observation before marking remediation verified.
