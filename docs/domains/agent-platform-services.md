# Agent Platform Services

This document covers the agent platform service packages in Cerebro that support Agent-to-Agent (A2A) task gatewaying, AI-assisted artifact authoring, and source coverage context for agent evidence packets.

It complements [Agent Platform Contract](agent-platform-contract.md), [Architecture](../reference/architecture.md), and [Findings Platform Architecture](findings-platform-architecture.md).

## Packages Covered

- `internal/a2agateway` — Agent-to-Agent JSON-RPC gateway
- `internal/agentauthoring` — AI-assisted security artifact authoring
- `internal/agentplatformcoverage` — source coverage context for agents

## a2agateway — A2A JSON-RPC Gateway

`internal/a2agateway` implements an Agent-to-Agent (A2A) JSON-RPC gateway handler. It accepts `SendMessage`, `GetTask`, and `ListTasks` requests, resolves tenant and scope context, authorizes evidence packets, and manages A2A tasks as jobs in the job store.

### Key Types

- `Handler` — the A2A JSON-RPC handler with Store, Card, Resolver, CoverageContext, Authorizer, and idempotency config
- `ResolvedContext` — resolved tenant, actor, and scope context
- `Resolver`, `CoverageContextFunc`, `EvidenceAuthorizer`, `RequestedTenantRecorder` — function type ports
- `requestError` — internal error type with JSON-RPC error codes

### Key Exports

- `Handler.Respond()` — dispatches A2A JSON-RPC methods
- `Handler.sendMessage()` — processes an inbound agent message, creating evidence packet tasks
- `Handler.getTask()` — retrieves a single A2A task
- `Handler.listTasks()` — lists A2A tasks with filtering
- `Handler.createEvidencePacketTask()` — creates and processes agent-evidence-packet jobs

### Boundaries

- Durable task lifecycle behavior stays in this domain package
- Bootstrap only wires the HTTP boundary into the gateway handler
- Tenant context is forced from authenticated principal; cross-tenant access is rejected before task creation
- Evidence packet authorization is delegated to the `EvidenceAuthorizer` port

### Dependencies

`agentplatform`, `ports`, `telemetry`

### RBAC Ownership

`job_manager` (jobs write for task creation), `admin` (cross-tenant operations)

## agentauthoring — AI-Assisted Artifact Authoring

`internal/agentauthoring` provides AI-assisted authoring of structured security artifacts from natural-language prompts. It drafts policy finding rules (validated via the finding DSL) and connector definitions (validated, classified, and dry-run source-generated).

### Key Types

- `Service` — the authoring service with a `StructuredDraftModel` and output directory
- `StructuredDraftModel` — interface for LLM/structured JSON drafting
- `StructuredDraftRequest` — prompt and schema context for the model
- `PolicyRuleDraftRequest` / `PolicyRuleDraftResult` — policy rule drafting types
- `ConnectorDefinitionDraftRequest` / `ConnectorDefinitionDraftResult` — connector definition drafting types

### Key Exports

- `Service.DraftPolicyRule()` — drafts, validates, normalizes, and formats a policy finding rule to YAML
- `Service.DraftConnectorDefinition()` — drafts, normalizes, classifies, validates, and dry-run generates a connector definition

### Boundaries

- Draft generation, validation, normalization, and formatting stay behind this package
- Policy rule validation delegates to `internal/findingdsl`
- Connector definition validation and dry-run generation delegate to `internal/connectordefinitions` and `internal/sourcegen`
- The `StructuredDraftModel` interface allows pluggable LLM backends

### Dependencies

`connectordefinitions`, `findingdsl`, `sourcegen`

### RBAC Ownership

`finding_manager` (policy rule authoring), `connector_manager` (connector definitions write), `admin` (knowledge write)

## agentplatformcoverage — Agent Coverage Context

`internal/agentplatformcoverage` bridges source coverage data into the agent platform's `AgentCoverageContext`. It evaluates CDK coverage contracts against source runtime observations and produces blind-spot summaries for agent evidence packets.

### Key Exports

- `FromRuntimeStore()` — builds coverage context from a source runtime list store
- `FromRuntimes()` — builds coverage context from a registry and runtime list
- `FromReport()` — converts a `sourcecoverage.Report` into an `AgentCoverageContext` with top blind spots

### Boundaries

- Coverage context shaping for agent consumption stays behind this package
- Coverage evaluation logic is owned by `internal/sourcecoverage`
- Agent evidence packet structure is owned by `internal/agentplatform`
- This package is the bridge between the two

### Dependencies

`agentplatform`, `ports`, `sourcecdk`, `sourcecoverage`; protobuf types from `gen/cerebro/v1`

### RBAC Ownership

`source_manager` (reports run, sources preview), `analyst` (risk scoring), `viewer` (read)

## Code Map

- `internal/a2agateway/gateway.go` — A2A JSON-RPC handler and task management
- `internal/agentauthoring/authoring.go` — AI-assisted drafting service for policy rules and connector definitions
- `internal/agentplatformcoverage/context.go` — source coverage to agent context bridge
