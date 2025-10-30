# Cerebro AI Agents

This document explains how the Cerebro agent runtime works, how it maps to the existing CLI and REST interfaces, and the controls that govern conversational access to the platform.

| Interface | Entry Points | Shared Components |
| --- | --- | --- |
| CLI | `cerebro findings list`, `cerebro query …` | Tool registry, CEL policy engine, audit log |
| REST API | `/api/v1/findings`, `/api/v1/query/execute` | Same services and database models |
| Agents | Conversational session (`runtime.send_message`) | Tool executor, transaction layer, audit trail |

Each interface calls the same toolchain and persists to the same PostgreSQL-backed audit tables. Agents add a natural language layer on top of these primitives.

## Overview

Agents provide natural language access to findings, audit data, compliance frameworks, incident workflows, SQL queries, CEL-based rules, and other security automation. All invocations pass through audited tooling, CEL policies, and permission checks before touching data.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude AI (Sonnet latest)               │
│                    via Claude Code SDK                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ SDK Messages
                  │ (AssistantMessage, SystemMessage, etc.)
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              CerebroClaudeRuntime                            │
│  • Session management                                        │
│  • Message streaming                                         │
│  • Token tracking                                            │
│  • Error handling                                            │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ MCP Server
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              MCP Bridge (mcp_bridge.py)                      │
│  • Converts Cerebro Tools → SDK MCP Tools                   │
│  • Handles tool invocation format                           │
│  • Maps results back to SDK format                          │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ Tool Execution
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              ToolExecutor (base.py)                          │
│  • CEL policy enforcement                                    │
│  • Permission level checks                                   │
│  • Dry-run mode enforcement                                  │
│  • Audit logging                                             │
└─────────────────┬───────────────────────────────────────────┘
                  │
                  │ Database Operations
                  │
┌─────────────────▼───────────────────────────────────────────┐
│              Cerebro Database                                │
│  • Findings                                                  │
│  • Audit Events                                              │
│  • Config Snapshots                                          │
│  • IAM Edges                                                 │
└──────────────────────────────────────────────────────────────┘
```

# Key Components

### CerebroClaudeRuntime (`runtime.py`)

Coordinates model interactions and tool execution.

- Session lifecycle management (`create_session`, `close_session`)
- Streaming responses with interleaved tool execution (`send_message`)
- Metrics helpers (token usage, execution times)
- Persistent storage of messages in append-only tables

### MCP Bridge (`mcp_bridge.py`)

Adapts Cerebro tools to Claude's Model Context Protocol.

- Wraps tool callables with SDK metadata
- Translates input/output schemas
- Normalizes exceptions and validation errors

### Tool System (`tools/`)

The CLI, REST API, and agents all rely on the same tool registry. Every tool exposes:

- Pydantic-based request/response schemas
- Permission level metadata (`READ_ONLY`, `WRITE_SAFE`, `WRITE_DESTRUCTIVE`, `ADMIN`)
- CEL policy hooks and dry-run enforcement
- Structured audit logging via `AgentAuditEvent`

Representative categories include findings management, analysis, timeline construction, SQL queries, and remediation actions.

### Audit System (`audit.py`)

Maintains an org-scoped record of every tool invocation:

- Distinct audit model for agent activity
- Helpers to query by session, organization, or timeframe
- Execution time metrics captured alongside payloads

## Agent Types

Agents use predefined prompts tailored to common workflows.

| Agent Type | Typical Use |
| --- | --- |
| `SECURITY_ANALYST` | Finding triage, risk summaries, remediation recommendations |
| `INCIDENT_RESPONDER` | Timeline creation, containment steps, evidence capture |
| `IDENTITY_ADVISOR` | Privilege analysis, escalation tracing, identity hygiene |
| `COMPLIANCE_ADVISOR` | Framework mapping, control validation, evidence prep |
| `ATTACK_PATH_ANALYST` | Attack path modelling, choke point discovery |

Agent tasks run on the same infrastructure as the API and workers, inheriting shared secrets, KMS configuration, and deployment lifecycle.

## Controls and Guardrails

- **Dry-run first** – mutating tools default to preview mode and require explicit confirmation.
- **Permission levels** – each session includes a permission tier; tools enforce minimums before executing.
- **CEL policies** – inputs pass through org-defined expressions for contextual authorization and validation.
- **Provider scoping** – session contexts restrict queries and tool lookups to allowed providers.
- **Comprehensive audit trail** – every invocation records arguments, caller, execution time, and result.

```python
from cerebro.agents.runtime import CerebroClaudeRuntime
from cerebro.agents.models import AgentType

# Create runtime
runtime = CerebroClaudeRuntime(
    model=os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-latest"),
    temperature=0.1,
)

# Create agent session
session = await runtime.create_session(
    org_id=your_org_id,
    agent_type=AgentType.SECURITY_ANALYST,
    created_by="user@example.com",
    context={
        "provider_scope": ["aws", "github"],
        "finding_ids": [],
    },
    title="Investigate High Severity Findings"
)

# Send message and stream response
async for response in runtime.send_message(
    session=session,
    message="List all high severity AWS findings from the last 7 days",
    user_id="user@example.com",
    stream=True
):
    if response["type"] == "text":
        print(response["content"])
    elif response["type"] == "tool_use":
        print(f"Tool: {response['content']['tool_name']}")
```

## Configuration

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | Yes | Claude runtime API key |
| `OPENAI_API_KEY` | Optional | Enables OpenAI runtime fallback |
| `DATABASE_URL` | Optional | Override default Postgres connection |
| `CLAUDE_MODEL` | Optional | Claude model override (default `claude-3-5-sonnet-latest`) |

### Agent Context

When creating sessions, provide context:

```python
context = {
    # Limit to specific cloud providers
    "provider_scope": ["aws", "gcp"],

    # Pre-load specific findings
    "finding_ids": [uuid1, uuid2],

    # Link to an incident
    "incident_id": incident_uuid,

    # Custom CEL context
    "environment": "production",
    "region": "us-east-1",
}
```

## Database Schema

### agent_sessions
```sql
CREATE TABLE agent_sessions (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES orgs(org_id),
    agent_type VARCHAR(50) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    title VARCHAR(255),
    context JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### agent_messages
```sql
CREATE TABLE agent_messages (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES agent_sessions(id),
    role VARCHAR(20) NOT NULL,  -- 'user' | 'assistant'
    content JSONB NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### agent_audit_events
```sql
CREATE TABLE agent_audit_events (
    event_id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES orgs(org_id),
    session_id UUID NOT NULL REFERENCES agent_sessions(id),
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    agent_type VARCHAR(50) NOT NULL,
    tool_name VARCHAR(100),
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    event_data JSONB NOT NULL DEFAULT '{}',
    execution_time_ms FLOAT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Testing

See `tests/agents/test_agent_integration.py` for integration coverage.

```bash
# Run all agent tests
pytest tests/agents/ -v

# Run specific test
pytest tests/agents/test_agent_integration.py::TestAgentTools::test_findings_list -v

# Run with coverage
pytest tests/agents/ --cov=src/cerebro/agents --cov-report=html
```

## Performance Considerations

- **Token usage** – typical requests range from 500–2000 input tokens; multi-tool workflows can reach 8000 tokens. Use `get_session_metrics()` to monitor usage.
- **Response time** – simple queries complete in 2–5 seconds; complex multi-tool timelines may take 10–30 seconds.
- **Indexes** – ensure the following indexes exist in production deployments:
```sql
CREATE INDEX idx_agent_messages_session_created
    ON agent_messages(session_id, created_at);

CREATE INDEX idx_agent_audit_events_org_occurred
    ON agent_audit_events(org_id, occurred_at);

CREATE INDEX idx_findings_org_status_severity
    ON findings(org_id, status, severity);
```

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| "MCP server not found" | Verify tools are registered in `tools/__init__.py`; inspect `tool_registry.list_tools()` output. |
| "Permission denied" | Confirm the session `permission_level` meets the tool requirement. |
| "CEL policy evaluation failed" | Review policy syntax and ensure required context fields are supplied. |
| Tool execution timeout | Increase the Claude SDK timeout and inspect database performance metrics. |

## Related Documentation

- [Agent fixes summary](./fixes-summary.md)
- [Agent architecture](../architecture/agents.md)
- [Tool development guide](./tools.md)
- [Security model](../architecture/security.md)

## Support

File issues or feature requests at <https://github.com/WriterInternal/cerebro/issues>.
- Internal Wiki: (link to internal docs)
- Team Chat: #cerebro-agents