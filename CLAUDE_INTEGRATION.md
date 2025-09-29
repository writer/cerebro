# Cerebro Claude Code SDK Integration

This document describes the comprehensive integration of Claude Code SDK with Cerebro's security system of record, providing AI-powered security agents with deep knowledge of findings, incidents, and compliance frameworks.

## 🎯 Overview

The integration adds specialized security agents to Cerebro that can:

- **Analyze & Triage Findings**: Intelligent analysis of security findings with risk scoring and clustering
- **Incident Response**: Build timelines, coordinate containment, and collect evidence  
- **Identity Governance**: Review IAM configurations and privilege escalation paths
- **Compliance Mapping**: Map findings to CIS, NIST, CWE frameworks and generate reports
- **Attack Path Analysis**: Model attack paths and recommend defensive measures

## 🏗️ Architecture

### Core Components

```
cerebro/
├── .claude/                    # Claude Code SDK configuration
│   ├── agents/                # Specialized agent definitions
│   ├── commands/              # Slash commands for common workflows
│   └── settings.json          # Claude SDK settings and tool permissions
├── src/cerebro/agents/        # Agent implementation
│   ├── models.py             # SQLAlchemy models for sessions/messages/approvals
│   ├── runtime.py            # Claude SDK integration layer
│   ├── service.py            # High-level orchestration services
│   ├── routers.py            # FastAPI endpoints
│   └── tools/                # Security-focused agent tools
│       ├── base.py           # Tool framework with CEL policy enforcement
│       ├── findings.py       # Finding management and analysis
│       ├── rules.py          # CEL rule testing and creation
│       ├── query.py          # Temporal query access
│       └── timeline.py       # Incident timeline construction
```

### Data Flow

1. **Session Creation**: User creates agent session via API/CLI with security context
2. **Message Processing**: Claude processes messages using registered security tools
3. **Tool Execution**: Each tool call is CEL-checked, audited, and executed safely
4. **Approval Workflow**: Destructive actions enter approval queue or run in dry-run
5. **Audit Trail**: All messages, tool calls, and outcomes stored in append-only tables

## 🔧 Features

### Agent Types

- **Security Analyst**: Finding triage, risk assessment, clustering, remediation guidance
- **Incident Responder**: Timeline construction, containment planning, evidence collection
- **Identity Advisor**: IAM analysis, privilege review, identity stitching insights
- **Compliance Advisor**: Framework mapping, compliance reporting, control assessments
- **Attack Path Analyst**: Attack modeling, defensive recommendations, risk mitigation

### Safety & Security

- **CEL Policy Enforcement**: Every tool call validated against security policies
- **Dry-Run by Default**: Destructive actions preview changes before execution
- **Human-in-the-Loop**: Critical actions require explicit approval workflow
- **Append-Only Audit**: Complete audit trail of all agent interactions
- **Org Scoping**: All actions strictly scoped to requesting organization
- **Credential Security**: No secrets exposed in logs or responses

### Tool Capabilities

- **Finding Management**: Query, update, cluster, and analyze security findings
- **Temporal Queries**: Access configuration snapshots and audit trails over time
- **Provider Integration**: Safe interactions with AWS, GitHub, GCP, Azure APIs
- **Rule Engine**: Create and test CEL rules for policy enforcement
- **Timeline Construction**: Build incident timelines from multi-source data
- **Evidence Collection**: Package forensic data with chain of custody

## 📡 API Endpoints

### Agent Sessions
- `POST /api/v1/agents/sessions` - Create new agent session
- `GET /api/v1/agents/sessions` - List organization sessions
- `GET /api/v1/agents/sessions/{id}` - Get session with messages
- `POST /api/v1/agents/sessions/{id}/messages` - Send message (streaming)
- `DELETE /api/v1/agents/sessions/{id}` - Delete session

### Tool Approvals
- `GET /api/v1/agents/approvals` - List pending approvals
- `GET /api/v1/agents/approvals/{id}` - Get approval details
- `POST /api/v1/agents/approvals/{id}/approve` - Approve tool action
- `POST /api/v1/agents/approvals/{id}/reject` - Reject tool action

### Analytics
- `GET /api/v1/agents/analytics/usage` - Agent usage analytics
- `GET /api/v1/agents/health` - Service health status

## 🛠️ Usage Examples

### Creating a Security Analysis Session

```bash
# Create session for finding analysis
curl -X POST /api/v1/agents/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "agent_type": "security_analyst",
    "title": "High Severity Finding Triage",
    "context": {
      "finding_ids": ["f-123", "f-456"],
      "provider_scope": ["aws", "github"]
    }
  }'
```

### Incident Response Session

```bash
# Create IR session for incident investigation  
curl -X POST /api/v1/agents/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "agent_type": "incident_responder", 
    "title": "Data Exfiltration Investigation",
    "context": {
      "incident_id": "inc-789",
      "time_window": {"hours_before": 24, "hours_after": 2}
    }
  }'
```

### Streaming Conversation

```bash
# Send message with streaming response
curl -X POST /api/v1/agents/sessions/abc-123/messages \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: text/event-stream" \
  -d '{
    "message": "Analyze the critical findings and provide remediation plan",
    "stream": true
  }'
```

## 🎯 Slash Commands

The integration provides powerful slash commands for common workflows:

### `/triage-findings`
Analyze and prioritize security findings with clustering and risk scoring.

```
/triage-findings --org "Acme Corp" --severity critical,high --limit 20
```

### `/investigate-incident` 
Build comprehensive incident timeline with forensic analysis.

```
/investigate-incident inc-2024-001 --window 48 --deep-dive
```

## 🔐 Security Model

### Permission Levels
- **Read-Only**: Query findings, configurations, audit data
- **Write-Safe**: Update finding status, create rules (draft)
- **Write-Destructive**: Modify resources, rotate credentials
- **Admin**: Full system access (reserved)

### CEL Policy Examples

```javascript
// AWS key disable - only for high severity incidents
tools.aws.disable_access_key: 
  has(context.incident_id) && 
  context.incident.severity in ['critical', 'high'] &&
  resource.owner == org.id

// Rule creation - always draft unless approved
tools.rules.create:
  inputs.status == 'draft' || 
  has(approval) && approval.approved == true
```

### Audit Trail

Every agent interaction generates audit events:

```sql
-- Agent sessions with full context
SELECT * FROM agent_sessions 
WHERE org_id = 'org-123' 
ORDER BY created_at DESC;

-- Tool invocations with policy decisions
SELECT 
  ti.tool_name,
  ti.status,
  ti.cel_policy_key,
  ti.cel_result,
  ti.input_data->'action' as action
FROM tool_invocations ti
JOIN agent_sessions s ON ti.session_id = s.id
WHERE s.org_id = 'org-123';

-- Approval workflow audit
SELECT 
  ta.requested_by,
  ta.decided_by,
  ta.status,
  ta.decision_reason,
  ti.tool_name
FROM tool_approvals ta
JOIN tool_invocations ti ON ta.tool_invocation_id = ti.id;
```

## 📊 Monitoring & Observability

### Key Metrics
- **Token Usage**: Input/output tokens by agent type and session
- **Tool Invocations**: Success rates, errors, approval rates by tool
- **Response Times**: End-to-end latency for different agent operations
- **User Adoption**: Active users, session counts, feature usage

### Health Checks
- Claude SDK connectivity and model availability
- Database connection and query performance  
- Tool registry initialization and permissions
- MCP server status (if configured)

## 🚀 Deployment

### Environment Variables

```bash
# Claude API Configuration
ANTHROPIC_API_KEY=sk-ant-...
CLAUDE_MODEL=claude-3-5-sonnet-20241022
CLAUDE_MAX_TOKENS=8192

# Optional: Third-party API providers  
CLAUDE_CODE_USE_BEDROCK=0
CLAUDE_CODE_USE_VERTEX=0

# Agent Configuration
AGENT_PERMISSION_MODE=requireApproval
AGENT_DEFAULT_DRY_RUN=true
AGENT_SESSION_TIMEOUT_HOURS=24
```

### Database Migration

```bash
# Create agent tables
uv run alembic revision --autogenerate -m "Add agent models"
uv run alembic upgrade head
```

### Service Startup

```bash
# Start API server with agent routes
uv run uvicorn cerebro.api.main:app --reload

# CLI access to agents
uv run python -m cerebro.cli agents --help
```

## 📝 Development

### Adding New Tools

1. Create tool class implementing `Tool` interface:

```python
class MyTool(Tool):
    @property
    def name(self) -> str:
        return "my_tool"
    
    @property  
    def permission_level(self) -> ToolPermissionLevel:
        return ToolPermissionLevel.READ_ONLY
    
    async def execute(self, inputs: BaseModel, context: AgentContext) -> ToolResult:
        # Implementation
        return ToolResult(success=True, data=result)
```

2. Register tool in `tools/__init__.py`
3. Add CEL policies if needed
4. Create unit tests

### Adding New Agent Types

1. Add enum value to `AgentType`
2. Create agent definition in `.claude/agents/`
3. Add system prompt in `runtime.py`
4. Update API documentation

### Testing

```bash
# Unit tests
uv run pytest tests/agents/ -v

# Integration tests with real Claude API
uv run pytest tests/integration/test_agents.py -v --integration

# Load testing
uv run pytest tests/performance/test_agent_performance.py -v
```

## 📚 Next Steps

1. **Enhanced Provider Tools**: Add more AWS/GCP/Azure management capabilities
2. **Custom MCP Servers**: Integrate with external security tools via MCP
3. **Multi-Turn Conversations**: Support for longer, context-aware conversations
4. **Agent Collaboration**: Enable multiple agents to work together on complex tasks
5. **Advanced Analytics**: ML-powered insights on agent effectiveness and usage patterns

---

The Claude Code SDK integration transforms Cerebro into an intelligent security platform where AI agents provide expert-level analysis, automate routine tasks, and accelerate incident response - all while maintaining the strict security, audit, and compliance standards required for enterprise security operations.
