# Agent SDK Gateway Architecture

This document describes the Agent SDK gateway that exposes Cerebro's shared graph and intelligence primitives to external AI agent frameworks without creating a second tool universe.

## Goal

Expose one curated Cerebro tool registry through multiple transports:

- HTTP-native typed endpoints under `/api/v1/agent-sdk/*`
- generic tool discovery and invocation under `/api/v1/agent-sdk/tools`
- MCP JSON-RPC + SSE transport under `/api/v1/mcp`
- existing NATS publication for Ensemble and remote orchestrators

The shared registry lives in `internal/app` via `App.AgentSDKTools()`. API, MCP, and NATS all consume the same tool definitions.

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

- `cerebro://schema/node-kinds`
- `cerebro://schema/edge-kinds`
- `cerebro://tools/catalog`

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

## Transport Boundary

Typed HTTP wrappers are for frameworks that want stable REST contracts.

Generic tool discovery/call and MCP are for frameworks that want dynamic discovery and JSON Schema driven execution.

Both are backed by the same catalog and should stay behaviorally aligned.

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
- schema resources for node/edge kinds and tool catalog
- dedicated `sdk.*` RBAC scopes

## Follow-On Tracks

1. Generated Go/Python/TypeScript SDKs from OpenAPI + tool catalog.
2. MCP progress notifications and long-running streaming for reports/simulations.
3. SDK-client specific API key provisioning, rate limits, and attribution.
4. `.well-known/oauth-protected-resource` and richer MCP auth metadata.
5. Generated framework adapters for LangChain, CrewAI, OpenAI Agents, and Vercel AI SDK.
