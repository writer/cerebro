# Cerebro AI Agents

**AI Agents are a PRIMARY INTERFACE to Cerebro, not a bolt-on feature.**

Cerebro provides three first-class interfaces to the same security engine:
- **CLI** - Command-line operations (`cerebro findings list`)
- **REST API** - Programmatic access (`GET /api/v1/findings`)
- **AI Agents** - Conversational interface (`"Show me critical findings"`)

All three interfaces access the **same 7 tools**, query the **same PostgreSQL database**, write to the **same audit trail**, and execute through the **same security engine**.

## What Makes This Deep Integration?

When an agent executes `findings_list` tool, it's not calling a separate agent-specific API. It's using the **exact same** findings engine that powers `cerebro findings list` and `GET /api/v1/findings`. The agent system is a **natural language wrapper** around Cerebro's core security capabilities.

**Same Platform, Different Interface:**
- Agent uses `query` tool → Same Zero-ETL SQL engine as CLI/API
- Agent uses `security_analysis` tool → Same analysis engine across all interfaces
- Agent updates finding status → Same audit log as API/CLI writes
- Agent builds timeline → Same incident response data as other interfaces

## Overview

The agent system enables natural language interaction with all of Cerebro's capabilities: security findings, audit logs, compliance frameworks, incident response workflows, SQL queries, CEL rules, and security analysis. All agent operations are audited, policy-controlled, and designed with security-first principles.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude AI (Sonnet 4.5)                  │
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

## Key Components

### 1. CerebroClaudeRuntime (`runtime.py`)

The main runtime that orchestrates Claude interactions:

- **Session Management**: Creates and manages agent sessions with context
- **Message Streaming**: Streams Claude responses with real-time tool execution
- **MCP Integration**: Uses Claude SDK's MCP server pattern for tool calling
- **Token Tracking**: Monitors input/output tokens for cost management
- **Database Persistence**: Stores all messages in append-only log

**Key Methods**:
```python
async def create_session(org_id, agent_type, created_by, context) -> AgentSession
async def send_message(session, message, user_id, stream=False) -> AsyncIterator
async def get_session_messages(session_id, limit, offset) -> List[Dict]
async def get_session_metrics(session_id) -> Dict
```

### 2. MCP Bridge (`mcp_bridge.py`)

Converts Cerebro's Tool abstraction to Claude SDK's MCP tool format:

- **Tool Conversion**: Wraps Cerebro tools with SDK `@tool` decorator
- **Input Schema Translation**: Converts Pydantic schemas to SDK format
- **Result Formatting**: Formats ToolResult as SDK-compatible content blocks
- **Error Handling**: Translates exceptions to SDK error format

**Key Functions**:
```python
def cerebro_tool_to_mcp(cerebro_tool, context, executor) -> Callable
def create_cerebro_mcp_server(tools, context, executor) -> MCPServer
```

### 3. Tool System (`tools/`)

**7 Specialized Security Tools** shared across CLI, API, and Agents:

1. **FindingsListTool** (`findings_list`) - Query and filter security findings with complex filters
2. **FindingStatusUpdateTool** (`finding_update_status`) - Update finding status with audit trail
3. **QueryTool** (`query`) - Execute SQL queries against 15+ security tables (Zero-ETL)
4. **TimelineTool** (`timeline`) - Build incident timelines from audit events and findings
5. **RulesTool** (`rules`) - Compile, test, and manage CEL security rules
6. **SecurityAnalysisTool** (`security_analysis`) - 4 analysis types: attack surface, risk scoring, compliance gaps, posture assessment
7. **RemediationTool** (`remediation_suggestions`) - Intelligent step-by-step remediation with effort estimates

Every tool is accessible via:
- **CLI**: `cerebro [tool-name] [args]`
- **REST API**: `POST /api/v1/[tool-endpoint]`
- **AI Agents**: Agent invokes tool by name

All tools inherit from `Tool` base class with:
- Input/output schema validation (Pydantic)
- Permission level requirements
- CEL policy enforcement
- Dry-run mode support
- Comprehensive audit logging

### 4. Audit System (`audit.py`)

Org-scoped audit logging for agent operations:

- **AgentAuditEvent Model**: Separate from provider audit events
- **Event Logging**: Tracks all tool invocations with full context
- **Query Helpers**: Session and org-level audit trail queries
- **Performance Tracking**: Execution time monitoring

## Agent Types

Cerebro supports specialized agent types with tailored system prompts:

| Agent Type | Focus | Expertise |
|-----------|-------|-----------|
| **SECURITY_ANALYST** | Triage, risk assessment, remediation | Vulnerability assessment, compliance mapping |
| **INCIDENT_RESPONDER** | Timeline building, containment, evidence | Digital forensics, incident coordination |
| **IDENTITY_ADVISOR** | IAM analysis, privilege escalation | Identity governance, access controls |
| **COMPLIANCE_ADVISOR** | Framework mapping, compliance reports | CIS Controls, NIST, SOC 2 |
| **ATTACK_PATH_ANALYST** | Attack modeling, choke points | Threat modeling, defensive architecture |

## Security Features

### 1. Dry-Run Mode (Default)

All destructive operations default to dry-run:
- Returns preview of what would be changed
- Requires explicit approval to execute
- Enforced at ToolExecutor level

### 2. Permission Levels

Hierarchical permission model:
- `READ_ONLY`: Query data only
- `WRITE_SAFE`: Non-destructive updates
- `WRITE_DESTRUCTIVE`: Can modify/delete data (requires approval)
- `ADMIN`: Full system access

### 3. CEL Policy Enforcement

Dynamic policy evaluation using Common Expression Language:
- Org-level policies
- Input validation rules
- Context-aware authorization
- Integration with Cerebro's rule engine

### 4. Provider Scope

Restrict tools to specific cloud providers:
- Configured per session context
- Filters all query results
- Prevents cross-provider access violations

### 5. Audit Trail

Complete append-only audit log:
- Every tool invocation logged
- Session-level traceability
- Org-wide audit queries
- Performance metrics

## Usage Example

```python
from cerebro.agents.runtime import CerebroClaudeRuntime
from cerebro.agents.models import AgentType

# Create runtime
runtime = CerebroClaudeRuntime(
    model="claude-3-5-sonnet-20241022",
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

```bash
# Required: Claude API key
export ANTHROPIC_API_KEY=sk-ant-...

# Optional: Database connection
export DATABASE_URL=postgresql://...

# Optional: Override default model
export CLAUDE_MODEL=claude-3-5-sonnet-20241022
```

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

See `tests/agents/test_agent_integration.py` for comprehensive integration tests:

```bash
# Run all agent tests
pytest tests/agents/ -v

# Run specific test
pytest tests/agents/test_agent_integration.py::TestAgentTools::test_findings_list -v

# Run with coverage
pytest tests/agents/ --cov=src/cerebro/agents --cov-report=html
```

## Performance Considerations

### Token Usage

- Average query: 500-2000 input tokens
- Tool-heavy responses: 3000-8000 total tokens
- Monitor via `get_session_metrics()`

### Response Times

- Simple queries: 2-5 seconds
- Complex multi-tool operations: 10-30 seconds
- Timeline building: 15-45 seconds

### Database Optimization

Recommended indexes:
```sql
CREATE INDEX idx_agent_messages_session_created
    ON agent_messages(session_id, created_at);

CREATE INDEX idx_agent_audit_events_org_occurred
    ON agent_audit_events(org_id, occurred_at);

CREATE INDEX idx_findings_org_status_severity
    ON findings(org_id, status, severity);
```

## Troubleshooting

### Common Issues

**1. "MCP server not found"**
- Ensure tools are registered in `tools/__init__.py`
- Check `tool_registry.list_tools()` returns expected tools

**2. "Permission denied"**
- Verify `AgentContext.permission_level` is sufficient
- Check tool's `permission_level` property

**3. "CEL policy evaluation failed"**
- Review CEL expression syntax
- Validate context variables are available
- Check logs for detailed CEL error

**4. "Tool execution timeout"**
- Increase Claude SDK timeout
- Check database query performance
- Review audit logs for slow operations

## Future Enhancements

- [ ] Multi-session context sharing
- [ ] Tool approval workflow UI
- [ ] Custom tool plugins via MCP
- [ ] Agent performance analytics dashboard
- [ ] Automated incident response workflows
- [ ] Integration with ticketing systems

## Related Documentation

- [Agent Fixes Summary](./fixes-summary.md) - Detailed implementation history
- [Architecture Overview](../architecture/agents.md) - System design
- [Tool Development Guide](./tools.md) - Creating custom tools
- [Security Model](../architecture/security.md) - Security architecture

## Support

For issues or questions:
- GitHub Issues: https://github.com/haasonsaas/cerebro/issues
- Internal Wiki: (link to internal docs)
- Team Chat: #cerebro-agents