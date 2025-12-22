# Agents + Tools Deep Dive (2025-12)

This document captures how Cerebro’s agent runtime works, how tools are registered/executed/audited, and how memory is persisted and retrieved.

The intent is to preserve operational and security reasoning behind the design.

---

## 1) Module map

### Runtime

- `src/cerebro/agents/runtime.py`: `CerebroClaudeRuntime` (Claude Code SDK integration)
- `src/cerebro/agents/runtime_facade.py`: selects runtime implementation (Claude/OpenAI/etc)
- `src/cerebro/agents/runtime_common.py`: persistence mixins + shared helpers
- `src/cerebro/agents/mcp_bridge.py`: MCP server wrapper around Cerebro tools

### Service layer

- `src/cerebro/agents/service.py`: `AgentSessionService` (API/CLI-facing orchestration)
- `src/cerebro/agents/repositories.py`: DB repositories (sessions, approvals, memory)
- `src/cerebro/agents/review_service.py`: review workflow for tool approvals

### Tool system

- `src/cerebro/agents/tools/base.py`: `StructuredTool`, `ToolResult`, permission levels
- `src/cerebro/agents/tools/__init__.py`: `tool_registry`
- `src/cerebro/agents/tools/*`: concrete tools

### Memory

- `src/cerebro/agents/memory_store.py`: embedding-backed memory store
- `src/cerebro/agents/memory_utils.py`: token estimates, hashing, summarization
- `src/cerebro/agents/models.py`: `AgentMemoryEntry`, `AgentSessionContext`, etc.

---

## 2) Runtime: Claude integration details

### 2.1 Session creation

`CerebroClaudeRuntime.create_session()`:

- injects automatic org + system context into `session.context` via `_prepare_session_context()`
- persists the session via `AgentRuntimePersistenceMixin._persist_session()`

Rationale:

- Keeps initial prompts consistent across sessions.
- Prevents “tools without context” failure modes.

### 2.2 Sending messages

`CerebroClaudeRuntime.send_message()` pipeline (simplified):

1. Begin telemetry span (`_begin_runtime_operation`)
2. Retrieve memory snippets (`_retrieve_memory_snippets`)
3. Persist user message (append-only)
4. Build `AgentContext` (org_id, user_id, permissions, provider scope)
5. Compute allowed tools and rankings
6. Build an MCP server from tools (`create_cerebro_mcp_server`)
7. Create `ClaudeAgentOptions` with:
   - `system_prompt` from `build_security_agent_prompt(...)`
   - `mcp_servers={"cerebro": ...}`
   - `allowed_tools=["mcp__cerebro__<tool>", ...]`
   - optional `metadata` (when supported by SDK)
8. Stream back assistant output and tool calls

Important: tool calls are **SDK-driven** via MCP; Cerebro provides the tool catalog and executes calls.

---

## 3) Tool execution + safety model

### 3.1 Tool interface

Tools typically subclass `StructuredTool` and declare:

- `tool_name`
- `tool_description`
- `input_model` / `output_model` (Pydantic)
- `required_permission` (`READ_ONLY`, `WRITE_SAFE`, `DESTRUCTIVE`, ...)

Return values are wrapped in a `ToolResult` containing:

- `success: bool`
- `data: dict | None`
- `error: str | None`
- `metadata: dict`

### 3.2 Permission gating

The runtime filters tools by `AgentContext.permission_level`, so different agent types can have different capabilities.

The “approval workflow” exists for potentially dangerous actions:

- tools can create `ToolApproval` records
- a reviewer can approve/reject
- the executor only runs destructive calls when approved

Code anchor: `src/cerebro/agents/service.py` + `ToolApprovalRepository`.

### 3.3 Auditing

The system is designed to be append-only / auditable:

- user messages are stored (`AgentMessage`)
- assistant messages are stored
- tool invocations and results are stored and can be reviewed
- analytics events are recorded via `AgentAnalyticsService`

This is a core platform requirement: tool calls can trigger real operational actions.

---

## 4) Memory system

### 4.1 Two layers of “memory”

1. **Embedding-backed memory snippets** (`AgentMemoryEntry`)
   - automatically ingested from conversation messages
   - used to retrieve relevant context for new messages
2. **Explicit remembered facts/preferences** (`AgentSessionContext`)
   - written via `RememberContextTool` (`tools/session_memory.py`)
   - intended for user preferences and durable facts

### 4.2 Embedding store behavior

`src/cerebro/agents/memory_store.py:AgentMemoryStore`:

- Optional OpenAI embeddings (`settings.enable_agent_memory_embeddings` + `settings.openai_api_key`).
- Fallback lexical hashing (`HashingVectorizer`) when embeddings disabled/unavailable.
- Hybrid scoring combines:
  - embedding similarity
  - lexical similarity
  - recency/decay
  - scope boosts (session/incident/finding)

Notable operational guardrails:

- deduplication by `content_hash` (`sha1` via `hash_text`)
- probabilistic pruning to cap storage
- max entries per org/session (config-driven)

### 4.3 Decay model

Memory entries decay over time using half-life style scoring; accesses “refresh” entries.

This keeps prompts small and avoids “prompt bloat” while still preserving important context.

---

## 5) Key tools worth understanding

### 5.1 `get_system_context`

File: `src/cerebro/agents/tools/system_context.py`

Purpose:

- Give the agent runtime environment context: DB connectivity, environment variables, provider health, system metrics.

Notes:

- Detects DB dialect to query version appropriately.
- Masks `DATABASE_URL` to avoid leaking secrets.
- Should remain **read-only**.

### 5.2 Session memory tools

File: `src/cerebro/agents/tools/session_memory.py`

- `remember_context`: writes durable org-scoped facts/preferences.
- `get_session_history`: lists recent sessions, optionally with messages + learned context.

Security note: this is org-scoped and should never leak between orgs.

---

## 6) Observability + performance

The runtime records:

- tool ranking + usage frequency (`tool_stats.performance_tracker`)
- runtime metadata events (`record_runtime_metadata_event`)

For production operations, the key missing pieces usually are:

- end-to-end tracing across API → runtime → tool → DB/provider
- tool-level latency and error budgets

---

## 7) Common failure modes

1. **SDK tool metadata changes**: the Claude SDK changes available fields; runtime uses reflection to detect `metadata` support.
2. **Memory embedding dependency drift**:
   - missing `openai` dependency
   - invalid keys
   - embedding model changes
3. **Approval deadlocks**: destructive tools blocked waiting on a reviewer; ensure UI/ops supports approvals.
4. **Async DB sessions + tool calls**: tools using sync libraries must not block the event loop.

---

## 8) Hardening roadmap (recommended)

1. **Stronger tool sandboxing**:
   - per-tool timeouts
   - per-org rate limiting
   - concurrency caps
2. **Tool input validation**:
   - strict schemas
   - maximum list sizes
   - explicit allowlists for dangerous identifiers
3. **Memory privacy guarantees**:
   - explicit org_id filters in every memory query
   - tests that attempt cross-org leakage
4. **Deterministic tool audit format**:
   - normalize timestamps
   - store request/response payloads consistently
