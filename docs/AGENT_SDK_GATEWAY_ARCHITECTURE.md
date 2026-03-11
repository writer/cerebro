# Agent SDK Gateway Architecture

This document describes the Agent SDK gateway that exposes Cerebro's shared graph and intelligence primitives to external AI agent frameworks without creating a second tool universe.

## Goal

Expose one curated Cerebro tool registry through multiple transports:

- HTTP-native typed endpoints under `/api/v1/agent-sdk/*`
- generic tool discovery and invocation under `/api/v1/agent-sdk/tools`
- MCP JSON-RPC + SSE transport under `/api/v1/mcp`
- existing NATS publication for Ensemble and remote orchestrators

The shared registry lives in `internal/app` via `App.AgentSDKTools()`. API, MCP, and NATS all consume the same tool definitions.

Generated contract artifacts:

- `docs/AGENT_SDK_AUTOGEN.md`
- `docs/AGENT_SDK_CONTRACTS.json`

## Design Rules

- One canonical tool catalog, many transports.
- Public SDK tool IDs stay stable even if internal tool names differ.
- Generic invocation and MCP must enforce per-tool permissions, not just route-level permissions.
- Typed HTTP wrappers may delegate to existing platform handlers when that preserves lifecycle events and writeback behavior.
- Report, quality, leverage, policy-check, and world-model write paths should reuse existing graph/policy substrate instead of rebuilding business logic inside the gateway.

## Public Surface

### Typed HTTP routes

- `GET /api/v1/agent-sdk/context/{entity_id}`
- `POST /api/v1/agent-sdk/report`
- `GET /api/v1/agent-sdk/quality`
- `GET /api/v1/agent-sdk/leverage`
- `GET /api/v1/agent-sdk/templates`
- `POST /api/v1/agent-sdk/check`
- `POST /api/v1/agent-sdk/simulate`
- `POST /api/v1/agent-sdk/observations`
- `POST /api/v1/agent-sdk/claims`
- `POST /api/v1/agent-sdk/decisions`
- `POST /api/v1/agent-sdk/outcomes`
- `POST /api/v1/agent-sdk/annotations`
- `POST /api/v1/agent-sdk/identity/resolve`
- `GET /api/v1/agent-sdk/schema/nodes`
- `GET /api/v1/agent-sdk/schema/edges`

### Generic tool routes

- `GET /api/v1/agent-sdk/tools`
- `POST /api/v1/agent-sdk/tools/{tool_id}:call`

### MCP transport

- `GET /api/v1/mcp`
- `POST /api/v1/mcp`

Implemented MCP methods:

- `initialize`
- `tools/list`
- `tools/call`
- `resources/list`
- `resources/read`

Implemented MCP resources:

- `cerebro://agent-sdk/catalog`
- `cerebro://schema/node-kinds`
- `cerebro://schema/edge-kinds`
- `cerebro://tools/catalog`
- `cerebro://reports/catalog`

## Public Tool IDs

Core stable IDs:

- `cerebro_context` -> `insight_card`
- `cerebro_report` -> `cerebro.intelligence_report`
- `cerebro_quality` -> `cerebro.graph_quality_report`
- `cerebro_leverage` -> `cerebro.graph_leverage_report`
- `cerebro_templates` -> `cerebro.graph_query_templates`
- `cerebro_check` -> `evaluate_policy`
- `cerebro_simulate` -> `simulate`
- `cerebro_observe` -> `cerebro.record_observation`
- `cerebro_claim` -> `cerebro.write_claim`
- `cerebro_decide` -> `cerebro.record_decision`
- `cerebro_outcome` -> `cerebro.record_outcome`
- `cerebro_annotate` -> `cerebro.annotate_entity`
- `cerebro_resolve_identity` -> `cerebro.resolve_identity`

Non-core tools still publish through the same catalog with deterministic public IDs derived from internal tool names.

## Permission Model

Route scopes:

- `sdk.context.read`
- `sdk.enforcement.run`
- `sdk.worldmodel.write`
- `sdk.schema.read`
- `sdk.invoke`
- `sdk.admin`

Two checks matter:

1. route-level RBAC gates access to the namespace
2. generic invoke and MCP perform per-tool permission checks so `sdk.invoke` is not a privilege bypass

## Credential and Attribution Model

The gateway now supports two API credential forms:

- legacy `API_KEYS` for simple key -> user mapping
- structured `API_CREDENTIALS_JSON` for stable credential IDs, client IDs, rate buckets, names, and kinds

Structured credentials are the durable model for SDK consumers because they provide:

- stable `api_credential_id` and `api_client_id`
- credential kind/name for audit and routing
- rate-limit bucketing without coupling to raw secret values
- request attribution that can be propagated into graph writes and report-run events

Managed Agent SDK credentials now live behind an explicit admin control surface:

- `GET /api/v1/admin/agent-sdk/credentials`
- `POST /api/v1/admin/agent-sdk/credentials`
- `GET /api/v1/admin/agent-sdk/credentials/{credential_id}`
- `POST /api/v1/admin/agent-sdk/credentials/{credential_id}:rotate`
- `POST /api/v1/admin/agent-sdk/credentials/{credential_id}:revoke`

This keeps raw key material out of config-only workflows and makes scoped rotation/revocation auditable.

Agent SDK write surfaces enrich request metadata before delegating to platform handlers:

- `sdk_client_id`
- `api_credential_id`
- `api_credential_kind`
- `api_credential_name`
- `traceparent`
- `agent_sdk_tool_id`
- `agent_sdk_surface`

This keeps the platform write path canonical while preserving SDK-specific attribution.

## Transport Boundary

Typed HTTP wrappers are for frameworks that want stable REST contracts.

Generic tool discovery/call and MCP are for frameworks that want dynamic discovery and JSON Schema driven execution.

Both are backed by the same catalog and should stay behaviorally aligned.

`cerebro_report` is the main proof point for this boundary:

- typed REST and MCP both resolve to the same durable `ReportRun` substrate
- async execution returns a stable status resource instead of an ad hoc task blob
- MCP progress is emitted as `notifications/progress` bound to the same report-run lifecycle
- section completion and section payload emissions are streamed over both MCP (`notifications/report_section`) and platform SSE (`/api/v1/platform/intelligence/reports/{id}/runs/report_run:{run_id}/stream`)

## Contract Governance

The Agent SDK surface now has explicit machine-readable governance:

- `docs/AGENT_SDK_CONTRACTS.json` is the canonical generated catalog
- `docs/AGENT_SDK_AUTOGEN.md` is the human-readable projection of the same source
- `go run ./scripts/check_agent_sdk_contract_compat/main.go` enforces non-breaking catalog evolution
- `make agent-sdk-docs-check` and `make agent-sdk-contract-compat` are wired into CI

This keeps public tool IDs, MCP resources, and execution semantics from drifting silently across transports.

## OAuth Resource Metadata

Agent SDK and MCP clients can now discover protected-resource metadata at:

- `GET /.well-known/oauth-protected-resource`

The response advertises:

- resource base URL
- configured authorization servers
- supported `sdk.*` scopes
- bearer transport method
- Agent SDK and MCP endpoint URLs
- MCP protocol version

This gives external SDK consumers one stable place to discover auth metadata without hard-coding Cerebro-specific headers or scope lists.

## Generated External SDK Packages

The generated contract catalog now produces language package surfaces directly in-repo:

- `sdk/go/cerebro`
- `sdk/python/cerebro_sdk`
- `sdk/typescript`

Generation is deterministic through:

- `go run ./scripts/generate_agent_sdk_packages/main.go`
- `make agent-sdk-packages-check`

Validation now includes:

- Go compile check for the generated package
- Python module syntax check plus `pyproject.toml` parse check
- TypeScript compile check via `tsc --noEmit`

## Current MCP Contract Basis

The implemented MCP transport is aligned to the official Model Context Protocol Streamable HTTP shape documented as of March 10, 2026, including protocol version `2025-06-18`, JSON-RPC 2.0 request dispatch, `tools/*`, and `resources/*` methods.

## What Is Implemented Now

- shared tool export via `App.AgentSDKTools()`
- new curated tools:
  - `evaluate_policy`
  - `cerebro.write_claim`
- HTTP discovery + generic invoke
- typed HTTP wrappers for the core SDK methods
- MCP JSON-RPC + SSE compatibility layer
- progress notifications for long-running report executions
- section-level report notifications and SSE report-run streams
- generated Agent SDK contract docs + compatibility checks
- structured SDK credential support with stable attribution fields
- admin-managed scoped credential lifecycle and OAuth protected-resource metadata
- in-repo Go client bindings for tool discovery/call, report execution, and MCP transport
- generated external Go/Python/TypeScript SDK packages
- schema/resources for node kinds, edge kinds, tool catalog, report catalog, and generated SDK catalog
- dedicated `sdk.*` RBAC scopes

## Follow-On Tracks

1. Generated package publishing workflow, semantic versioning, and changelog emission from compatibility diffs.
2. Section-level cache/attempt/backoff telemetry plus streaming for simulation-heavy tools beyond report runs.
3. SDK-client usage analytics, approval-pressure reporting, and per-tool/per-tenant throttling policies.
4. Signed request support and richer OAuth discovery metadata per tool/resource.
5. Generated framework adapters for LangChain, CrewAI, OpenAI Agents, and Vercel AI SDK.
