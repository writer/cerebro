# Endpoint Security Platform Integration

This document defines how Writer's endpoint security systems connect through
Cerebro without becoming separate data islands.

## Systems

| System | Primary role | Cerebro boundary |
| --- | --- | --- |
| `trusted-endpoint` | Metadata-only endpoint posture, AI-session/workflow risk, repo/worktree context, GRC evidence, trust-gate evidence | `trusted_endpoint` source runtime claims plus trusted endpoint telemetry events |
| `secheck` | Local vulnerability validation, explanation, and human-approved package remediation | Device-authenticated endpoint findings reads and `/platform/telemetry/ingest` |
| Security/Kairos agents | Multi-agent security analysis, drift response, and action planning | Graph/finding reads plus workflow action/outcome writes |
| MDM/EDR sources | Device inventory, application inventory, vulnerabilities, and endpoint threat posture | Source runtimes such as `kandji`, `kolide`, and `sentinelone` |

## Canonical Endpoint Identity

Cerebro owns the canonical endpoint identity record. Endpoint producers should
send all identifiers they know, but they should not mint independent endpoint
IDs for graph joins.

| Priority | Identifier | Produced by | Used for |
| --- | --- | --- | --- |
| 1 | `device_id` | Cerebro device-auth enrollment | Primary authenticated endpoint key and API path key |
| 2 | `hardware_uuid` | `secheck`, MDM, platform helper, device auth | Stable correlation across MDM, EDR, and endpoint agents |
| 3 | `serial_number` | `secheck`, MDM, EDR | Fallback matching when hardware UUID is unavailable |
| 4 | `hostname` | All endpoint agents and MDM/EDR sources | Last-resort correlation and analyst display |
| 5 | `trusted_endpoint_agent_id` | `trusted-endpoint` | Agent instance and control-plane state key |
| 6 | Provider IDs | Kandji, Kolide, SentinelOne, Intune, other sources | Source-specific provenance and repair of ambiguous joins |

Graph projection should preserve provider IDs as attributes or alias entities,
but durable endpoint risk joins should converge on the Cerebro `device_id` when
the device has enrolled. Before enrollment, use the tuple:

```text
tenant_id + hardware_uuid + serial_number + hostname
```

## Source Runtime Contract

Trusted Endpoint has a first-class Cerebro source ID:

```text
source_id: trusted_endpoint
runtime_id: trusted-endpoint
```

The source is push-oriented. It does not poll endpoint agents. Producers write
claims to `/source-runtimes/{runtimeID}/claims` and may emit normalized endpoint
telemetry through device-auth ingest. The source catalog declares these event
families:

| Event family | Purpose |
| --- | --- |
| `trusted_endpoint.agent_identity` | Endpoint agent identity and alias evidence |
| `trusted_endpoint.host_posture` | Bounded posture and heartbeat summaries |
| `trusted_endpoint.repo_worktree_context` | Metadata-only repo/worktree risk context |
| `trusted_endpoint.ai_session_summary` | AI-agent session metadata and risk score |
| `trusted_endpoint.ai_workflow_risk` | Static AI workflow risk metadata |
| `trusted_endpoint.security_finding` | Endpoint-local security findings or verification results |
| `trusted_endpoint.grc_evidence` | Control evidence for audit and compliance surfaces |
| `trusted_endpoint.trust_gate_decision` | Allow/deny/review decisions and reasons |
| `trusted_endpoint.action_outcome` | Human-approved remediation or workflow action results |

## Telemetry Normalization

Device telemetry enters Cerebro through:

```text
POST /platform/telemetry/ingest
```

The raw request remains bounded and idempotent at the device-auth layer. Before
the request is accepted, Cerebro normalizes the envelope into `trusted_endpoint`
event envelopes:

| Input shape | Normalized event |
| --- | --- |
| `posture` object | `trusted_endpoint.host_posture` |
| event with `finding_id` | `trusted_endpoint.security_finding` |
| other event | `trusted_endpoint.action_outcome` |

This keeps endpoint telemetry compatible with source-runtime replay and graph
projection without writing high-volume raw telemetry directly into the graph.

## Trust-Gate Loop

Trust gates should be bidirectional:

1. `trusted-endpoint` continues to make local high-risk action decisions from
   online status, active endpoint findings, repo/worktree risk, AI-session
   risk, and evidence freshness.
2. Cerebro stores the same evidence as `trusted_endpoint` claims/events so
   graph queries can include endpoint posture in cloud/SaaS/identity risk.
3. Cerebro-initiated high-risk workflows should query the graph for the
   endpoint, repo, identity, package, and finding neighborhood before an
   automated action is approved.
4. If required endpoint evidence is missing or stale, Cerebro should request a
   targeted Trusted Endpoint refresh rather than approving from stale context.
5. Every trust-gate decision and downstream action outcome should be emitted
   back as evidence so future policy and agent decisions can learn from it.

## Security/Kairos Agent Loop

Security and Kairos agents should treat Cerebro as the evidence and action
ledger:

| Agent step | Cerebro integration |
| --- | --- |
| Plan or triage | Read findings and graph neighborhoods |
| Investigate | Read source-runtime claims, graph paths, and finding evidence |
| Recommend | Write `/platform/knowledge/actions` recommendation records |
| Execute | Use the responsible actuator, such as `secheck` for local package remediation, or the finding-scoped `endpoint.cerebro.revoke_device` graph action for Cerebro device-auth revocation |
| Close loop | Write `/platform/knowledge/outcomes` and endpoint telemetry action outcomes |

Agents should not directly mutate endpoint state unless the responsible endpoint
actuator enforces its local safety model. For `secheck`, that means the MCP
`auto_fix_vulnerability` tool still requires `user_approved: true`; for Cerebro
device-auth revocation, the graph action still requires an eligible finding,
`cerebro.graph_actions.write`, and the action-ladder approval contract.

## Privacy And Retention Boundaries

- Do not send prompts, diffs, shell output, file contents, secrets, or raw
  AI-session transcripts into endpoint telemetry.
- Do not store raw high-volume endpoint telemetry permanently in the graph.
- Promote bounded observations, findings, evidence, and action outcomes.
- Keep raw provider payloads in short-retention storage or replay streams when
  deeper incident pivoting is required.
