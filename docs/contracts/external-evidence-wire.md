# External evidence wire

Cerebro accepts portable evidence from independently deployed producers through
one versioned Rust contract. The contract carries producer identity, tenant and
subject scope, sequence and event-chain state, observation time, evidence
quality, a family-bound payload schema, and detached signature metadata.

The Rust types live in `cerebro-platform-sdk`. They do not own transport,
credentials, trust roots, provider access, persistence, deployment, scheduling,
or graph writes.

## Contract families

| Family | Payload | Authority boundary |
| --- | --- | --- |
| `agent_activity` | Metadata-only agent action, resource, policy revision, and input/outcome digests | Raw prompts, command output, diffs, file contents, and credentials are not payload fields |
| `endpoint_telemetry` | Endpoint observation kind, collector, privacy class, content digest, and evidence references | Endpoint collection and device authentication remain producer-owned |
| `endpoint_session_lease` | Bounded session, repository, capability, policy, audience, expiry, and revocation claims | Token signing, key distribution, and revocation storage remain host-owned |
| `threat_intelligence` | Normalized indicator verdict, bounded scores, source counts, freshness, and promotion reason | Lookup stores and feeds remain external; only gated evidence enters the graph candidate path |
| `remediation_outcome` | Existing action operation, target, state, idempotency, and provider/verification receipt digests | Provider execution and approval transport remain external adapters |
| `metric_snapshot` | Versioned metric value, unit, source evidence, truncation state, and snapshot digest | A snapshot is verified only with fresh, complete, non-truncated evidence |
| `scanner_finding` | Scanner/rule identity, source revision, validation state, subject, and evidence digest/reference | Scanner execution and raw source evidence remain outside Cerebro |
| `connector_manifest` | Declarative connector identity, objects, capabilities, and deterministic input/compiled digests | Provider I/O still travels through the Source CDK |
| `agent_capability` | Agent capability, tool allow-list, closed maximum action stage, evidence sources, and definition digest | Model execution and provider configuration remain external |

Credential and certificate lifecycle payloads continue to use the existing
`SecurityLifecycleObservation` protobuf and `cerebro-security-lifecycle` Rust
authority. Actions continue to use `ActionProposal`, `ActionOperation`, and
their decision and verification receipts. The external wire references those
authorities rather than redefining them.

## Admission rules

- `schema_version` must be `cerebro.external-event/v1`.
- Each family accepts exactly one payload schema in v1.
- IDs, references, collections, payload depth, payload nodes, and serialized
  payload bytes are bounded before persistence.
- Event sequences start at one; zero cannot enter the admission path.
- Observation time cannot precede occurrence time.
- Omitted evidence quality means `partial` and `unknown`; it cannot authorize a
  graph promotion, verified metric, or external action.
- Truncated endpoint or metric payloads cannot claim complete evidence.
- Threat promotion expires at the declared boundary and requires bound source
  events plus evidence references.
- Canonical digests and signing material use RFC 8785 JSON. Signature values are
  excluded from domain-separated signing material.
- Receipt outcomes and reasons must agree. Accepted and duplicate receipts carry
  the admitted event digest.

The wire does not make an accepted event a graph fact. Source admission,
normalization, policy evaluation, append-log persistence, and graph projection
remain separate stages.
