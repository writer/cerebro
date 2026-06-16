# Cerebro Agent Platform Contract

This document defines Cerebro's security-agent platform contract: how agent-facing capabilities should grow without
losing auditability, replayability, tenant safety, or public-repo clarity.

The machine-readable vocabulary lives in `internal/agentplatform`.

## North Star

Cerebro agents should explain and operate on security knowledge through typed contracts, governed capabilities,
bounded execution, and eval-backed change discipline. The graph, findings, evidence, runtime events, connectors, and
Ask trajectories remain the source of truth. LLM output is an interface over that substrate, not the substrate itself.

## Contract Domains

| Domain | Cerebro equivalent | Principle |
| --- | --- | --- |
| Contract-first runtime | `internal/graphagent`, `internal/ports`, ask trajectories, workflow events | Agent execution is typed, replayable, and isolated from product-specific orchestration. |
| Evals as product infrastructure | Ask eval scripts, security-agent evals, trace-linked fixtures, local regression reports | Every agent capability has a measurable regression surface before it becomes a default workflow. |
| Capabilities as governed artifacts | Policy catalogs, source catalogs, finding rules, graph-agent tools, future security skills | Reusable behavior is packaged, versioned, reviewed, and selected for a reason. |
| Execution behind ports | Runtime response, source runtime sync, workflow event projection, side-effect adapters | Stateful or risky work happens through explicit adapters with limits, cancellation, and audit. |
| Streaming and replay discipline | SSE Ask events, trajectory persistence, append-log replay, workflow projection | Live execution, durable records, and replay/debug views use one ordered event vocabulary. |
| Connector identity and OAuth boundaries | Connector catalog, credential stores, MCP OAuth, tenant-scoped API auth | Integrations are authenticated channels with clear public/private surfaces and token ownership. |
| Knowledge with provenance and budgets | Graph query, knowledge service, citations, evidence pointers, source scopes | Retrieved context is bounded, cited, instruction-safe, and non-blocking when unavailable. |

## Runtime Contract

Agent-facing runtime code should keep these boundaries:

- Raw request input is parsed before entering agent logic.
- Consumer-visible events have stable names and documented payloads.
- Durable trajectory or workflow records are append-only.
- Provider, graph, store, telemetry, and connector dependencies sit behind interfaces.
- A logical run has one trace id, ordered events, and one terminal outcome.
- Product-specific UI decisions do not leak into runtime packages.

This matches the current Cerebro direction: `graphagent.Event` defines the live Ask stream, `ports.AskTrajectoryStore`
records replayable events, and graph/query behavior stays behind ports.

## Eval Contract

New or changed agent capabilities should ship with at least one of:

- A local golden or adversarial eval fixture.
- A rubric that can fail for unsafe, unsupported, uncited, or ungrounded answers.
- A trace-linked diagnostic path for reviewing failures.
- A model/provider comparison when model behavior is the risk.

Default-on behavior should not rely only on manual review. If the capability can affect findings, evidence, controls,
or remediation recommendations, its eval should check grounding and unsupported-action refusal.

## Capability Contract

Cerebro capabilities should be artifacts, not hidden prompt fragments:

- Policies, finding rules, source definitions, graph tools, and future security skills have ids and versions.
- Selection is explainable: why this capability was considered, used, or skipped.
- Ownership and review state are visible where the capability can influence agent output.
- Capability output is evidence or guidance until a governed workflow promotes it.

## Execution Contract

Agents should never get an unmediated side-effect surface. Execution belongs behind adapters that report:

- Scope and tenant.
- Limits and timeouts.
- Cancellation state.
- Output truncation.
- Result provenance.
- Whether the result is advisory, evidence, or an accepted state change.

This keeps Cerebro aligned with its current runtime-response and workflow-event posture: side effects are explicit
events or API operations, not implicit LLM behavior.

## Streaming And Replay Contract

Live user experience and debugging should converge on the same ordered facts:

- SSE streams are for live UX.
- Durable trajectories or append-log records are the replay source.
- Payload redaction and truncation are explicit.
- Runtime debugger views should show what was requested, what was retrieved, what was executed, and what was persisted.
- Replays should be able to reproduce planner/query/summary behavior without private deployment context.

## Connector And OAuth Contract

Connector work should preserve hard boundaries:

- Public ingress, private service calls, and MCP surfaces are distinct.
- Tokens have an owner surface and declared scopes.
- Tenant and principal are checked before service logic.
- Credential storage and credential use remain separate concerns.
- Browser-visible status can describe readiness without exposing sensitive identifiers.
- Connectors and OAuth are first-class infrastructure, not per-feature glue. New connector-backed agent capabilities
  should use the shared catalog, credential store, OAuth, MCP, and tenant-scope contracts unless a reviewed exception
  creates a safer or narrower boundary.

## Knowledge And Memory Contract

Retrieved context must be useful without becoming a prompt-injection or data-leak channel:

- Bound context by item count and byte budget.
- Preserve source URNs, scopes, and citation status.
- Treat retrieved text as data, not instructions.
- Fail open for Ask availability when context systems are unavailable, but expose the fallback reason.
- Ingest or cache best-effort data only when provenance and tenant scope are clear.

## What Not To Do

Cerebro should not hide durable behavior in prompts, bypass connector identity boundaries, create one-off OAuth flows,
or give agents unmediated execution surfaces. The platform discipline is the product: typed boundaries, evals,
capability governance, execution ports, ordered streams, connector identity, and provenance-bounded knowledge.
